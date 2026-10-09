# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Netmiko device transport (network-CLI over SSH).

The ``netmiko`` implementation of the SDK ``Transport`` I/O surface, registered
under the ``hegemony.device_transports`` entry-point group. The host constructs
it from a resolved :class:`DeviceConnectionSpec` and injects its cancellation
registry, so this wheel never touches the platform's secret pipeline or
settings.
"""

import asyncio
import contextlib
import logging
import os
import re
import socket
import tempfile
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from functools import partial
from typing import Any, TypeVar

from hegemony_step_sdk import (
    ConnectionCancellationRegistry,
    DeviceConnectionSpec,
    HostKeyRejectedError,
    HostKeyVerifier,
    TransportOutputSink,
)

try:
    from netmiko import ConnectHandler
    from netmiko.exceptions import (
        NetmikoAuthenticationException,
        NetmikoTimeoutException,
        ReadTimeout,
    )
except ImportError:
    # Netmiko unavailable - provide stubs for type checking
    ConnectHandler: Any = None
    NetmikoAuthenticationException: type[Exception] = Exception
    NetmikoTimeoutException: type[Exception] = Exception
    ReadTimeout: type[Exception] = TimeoutError

try:
    # Netmiko's own SSH library; used only for the optional jump-host hop.
    import paramiko
except ImportError:
    paramiko: Any = None

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

#: How long the executor thread waits for the host's verifier, which runs on
#: the event loop the transport was called from.
_VERIFIER_TIMEOUT_SECONDS = 60.0


def _known_hosts_name(host: str, port: int) -> str:
    """The name paramiko looks a host's keys up under: ``[host]:port`` off port 22."""
    return host if port == 22 else f"[{host}]:{port}"


def _key_line(key: Any) -> str:
    """``<type> <base64>`` of a paramiko public key."""
    return f"{key.get_name()} {key.get_base64()}"


def _paramiko_keys(host: str, port: int, keys: tuple[str, ...]) -> list[Any]:
    """The trusted keys of ``host:port``, parsed by paramiko."""
    parsed = []
    for line in keys:
        entry = paramiko.hostkeys.HostKeyEntry.from_line(f"{_known_hosts_name(host, port)} {line}")
        if entry is None or entry.key is None:
            raise ValueError(f"a trusted SSH host key of {host}:{port} cannot be read")
        parsed.append(entry.key)
    return parsed


def _set_host_keys(client: Any, host: str, port: int, keys: tuple[str, ...] | None) -> None:
    """Make a paramiko client accept only ``keys`` from ``host:port``; None accepts any."""
    if keys is None:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return
    host_keys = client.get_host_keys()
    for key in _paramiko_keys(host, port, keys):
        host_keys.add(_known_hosts_name(host, port), key.get_name(), key)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())


def _write_known_hosts(host: str, port: int, keys: tuple[str, ...]) -> str:
    """A private known_hosts file holding ``keys`` for ``host:port``; returns its path.

    netmiko builds its paramiko client itself and takes host keys only from a
    file (``alt_key_file``).
    """
    _paramiko_keys(host, port, keys)  # a key paramiko would skip fails here, by name
    fd, path = tempfile.mkstemp(prefix="hegemony-known-hosts-")
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.writelines(f"{_known_hosts_name(host, port)} {line}\n" for line in keys)
    return path


def _bad_host_key(exc: BaseException | None) -> Any | None:
    """The paramiko ``BadHostKeyException`` behind ``exc``, if any.

    netmiko re-raises paramiko's SSH errors as its own timeout error, so the
    host-key failure is looked for along the exception chain.
    """
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        if isinstance(exc, paramiko.BadHostKeyException):
            return exc
        exc = exc.__cause__ or exc.__context__
    return None


def _presented_key(sock: Any, timeout: float) -> str:
    """The key the host at the end of ``sock`` presents: a key exchange, no login."""
    try:
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=timeout)
            return _key_line(transport.get_remote_server_key())
        finally:
            transport.close()
    finally:
        with contextlib.suppress(Exception):
            sock.close()


class _NullCancellationRegistry:
    """No-op cancellation registry used when the host tracks no cancellation."""

    def register(self, key: str | None, connection: Any) -> None:  # noqa: D102
        pass

    def unregister(self, key: str | None, connection: Any) -> None:  # noqa: D102
        pass

    def is_cancelled(self, key: str | None) -> bool:  # noqa: D102
        return False


_NULL_CANCELLATION = _NullCancellationRegistry()

# Common Cisco IOS-XE error patterns in command output
CISCO_ERROR_PATTERNS = [
    "% Invalid input detected",
    "% Incomplete command",
    "% Ambiguous command",
    "% Unknown command",
    "% Bad IP address",
    "% Invalid range",
    "% Permission denied",
    "% Access denied",
    "% Authorization failed",
    "% This command is not authorized",
    "% Error in authentication",
    "% Interface does not exist",
    "Command rejected",
    "Command authorization failed",
    "Invalid input:",
    "Translating",  # DNS lookup for invalid command
]


def _detect_cli_error(output: str) -> str | None:
    """Detect CLI error patterns in command output.

    Returns the error message if an error pattern is found, None otherwise.
    """
    if not output:
        return None

    for pattern in CISCO_ERROR_PATTERNS:
        if pattern in output:
            # Extract a meaningful error snippet (first line with the pattern)
            for line in output.splitlines():
                if pattern in line:
                    return line.strip()
            return pattern
    return None


#: Attribute under which the bastion client rides its device connection, so
#: every existing disconnect path tears the hop down with the session.
_JUMP_CLIENT_ATTR = "_hegemony_jump_client"


def _safe_disconnect(connection) -> None:
    """Safely disconnect a Netmiko connection, suppressing all errors.

    Netmiko's disconnect() and Paramiko's close() can raise decode errors
    when reading from a closed connection. We use socket-level shutdown
    to forcefully close without triggering any reads. A jump-host client
    riding the connection is closed with it — but only *after* the device
    session it carries. The device socket is a direct-tcpip channel of the
    bastion transport, so closing the bastion first pulls that channel out
    from under the shutdown below and leaves the device session to be reaped
    by the peer's timeout rather than closed cleanly.
    """
    if not connection:
        return

    bastion = getattr(connection, _JUMP_CLIENT_ATTR, None)

    try:
        # Get the underlying socket and shut it down forcefully
        # This prevents any read attempts that could trigger decode errors
        transport = getattr(connection, "remote_conn_pre", None)
        if transport is not None:
            sock = getattr(transport, "sock", None)
            if sock is not None:
                # Ignore shutdown errors - socket may already be closed or in error state
                with contextlib.suppress(Exception):
                    sock.shutdown(socket.SHUT_RDWR)
                with contextlib.suppress(Exception):
                    sock.close()

            # Stop the transport thread
            with contextlib.suppress(Exception):
                transport.close()

        # Close the channel if it exists
        channel = getattr(connection, "remote_conn", None)
        if channel is not None:
            with contextlib.suppress(Exception):
                channel.close()

    except Exception:
        # Final catch-all
        pass
    finally:
        # Last: the hop the device session rode on.
        if bastion is not None:
            with contextlib.suppress(Exception):
                bastion.close()


@dataclass
class SSHResult:
    """Result from SSH command execution."""

    command: str
    output: str
    exit_code: int
    error: str | None = None
    latency_ms: float = 0.0


# Map inventory platform strings to Netmiko device_type values.
PLATFORM_TO_NETMIKO = {
    "ios-xe": "cisco_ios",
    "ios-xr": "cisco_xr",
    "eos": "arista_eos",
    "junos": "juniper_junos",
}


#: Lines that open a config block. Only ``end`` closes one: ``exit`` inside a
#: block leaves a sub-mode on the device and is sent like any config line.
_CONFIG_ENTER_COMMANDS = ("configure terminal", "conf t", "config t")

#: Error of a result for a command not run because an earlier one failed.
_SKIPPED_ERROR = "Skipped: earlier command failed"

#: Error of a result for a command not run because the run was cancelled.
_CANCELLED_ERROR = "Skipped: the run was cancelled"

#: Config lines that start free text (a banner, a macro body, a certificate's
#: hex), which the device takes without a prompt after each line. netmiko
#: waits for the echo and the prompt after every line it checks, so, like
#: netmiko's own ``bypass_commands`` for a banner, a block holding one is
#: sent without those checks: each line then waits for the channel to go
#: quiet instead.
_FREE_TEXT_ENTRY = re.compile(
    r"^\s*(?:banner|macro\s+name|crypto\s+(?:pki|ca)\s+certificate\s+chain)\s",
    re.IGNORECASE,
)


def _is_mode_wrapper(command: str) -> bool:
    """'configure terminal' / 'end': the transport switches modes itself."""
    command_lower = command.strip().lower()
    return command_lower in _CONFIG_ENTER_COMMANDS or command_lower == "end"


def _is_save_command(command_lower: str) -> bool:
    """'write ...' / 'copy run ...': always run at privilege-exec."""
    return command_lower.startswith("write") or command_lower.startswith("copy run")


#: What IOS asks before a copy to startup-config, unless 'file prompt quiet'
#: is set: the destination file name, then on some platforms a confirmation
#: to overwrite it. Enter takes the answer the device offers.
_COPY_QUESTION = r"(?:Destination filename \[[^\]\n]*\]\?|\[confirm\])"

#: A copy to startup-config asks at most these two questions.
_MAX_COPY_ANSWERS = 2


def _is_startup_copy(command: str) -> bool:
    """'copy <source> startup-config', the destination in any abbreviation."""
    words = command.lower().split()
    if len(words) != 3 or words[0] != "copy":
        return False
    destination = words[2].removeprefix("nvram:")
    return len(destination) >= 3 and "startup-config".startswith(destination)


def _plan_config_set(commands: list[str]) -> list[tuple[bool, list[int]]]:
    """Split a config command set into ordered steps of command indexes.

    A step is ``(True, indexes)`` for a config block, sent in one stay in
    config mode, or ``(False, [index])`` for one command run at
    privilege-exec. A block opens at 'configure terminal' and closes only at
    'end'; both wrappers belong to their block. A save command inside a block
    splits it and runs between the two halves. Running the steps in turn
    keeps the order the commands were written in.
    """
    steps: list[tuple[bool, list[int]]] = []
    block: list[int] | None = None
    in_config = False
    for idx, cmd in enumerate(commands):
        cmd_lower = cmd.strip().lower()
        if cmd_lower in _CONFIG_ENTER_COMMANDS:
            in_config = True
        if cmd_lower == "end" and not in_config:
            # Nothing to close: a block of one wrapper, which sends nothing.
            steps.append((True, [idx]))
        elif in_config and not _is_save_command(cmd_lower):
            if block is None:
                block = []
                steps.append((True, block))
            block.append(idx)
            if cmd_lower == "end":
                in_config = False
                block = None
        else:
            block = None
            steps.append((False, [idx]))
    return steps


def _skipped(command: str, reason: str) -> SSHResult:
    """Result for a command not run, with ``reason`` as its error."""
    return SSHResult(command=command, output="", exit_code=-1, error=reason)


def _next_prompt(
    output: str, start: int, answers: dict[str, str], answered: set[str]
) -> tuple[str | None, str, int]:
    """The first prompt in ``output`` from ``start`` that is not answered yet.

    Matches ignore case. Returns ``(prompt, answer, resume)``: the prompt and
    its answer, or None and "" when none is there, and where the next scan
    starts. That is just past the prompt found, so a second question in the
    same output is found next; or, when none was found, the last characters
    of ``output`` that could begin a prompt, so a prompt that one read cut in
    two is found once the rest arrives. The prompt found joins ``answered``.
    """
    output_lower = output.lower()
    found: tuple[int, str, str] | None = None
    for prompt, answer in answers.items():
        key = prompt.lower()
        if not key or key in answered:
            continue
        index = output_lower.find(key, start)
        if index >= 0 and (found is None or index < found[0]):
            found = (index, prompt, answer)
    if found is None:
        longest = max((len(prompt) for prompt in answers), default=1)
        return None, "", max(start, len(output_lower) - longest + 1)
    index, prompt, answer = found
    answered.add(prompt.lower())
    return prompt, answer, index + len(prompt)


class SSHTransport:
    """SSH transport client for network device CLI access using Netmiko."""

    #: check_type-style id claimed under the hegemony.device_transports group.
    transport_id = "netmiko"

    #: Feature flag the host checks before passing ``output_sink`` (Phase B
    #: live streaming): hosts that predate sinks never pass the kwarg, and
    #: hosts that support them skip wheels without this attribute.
    supports_output_sink = True

    #: Feature flag the host checks before passing ``host_key_verifier``, as
    #: for the output sink.
    supports_host_key_verifier = True

    def __init__(
        self,
        spec: DeviceConnectionSpec,
        *,
        cancellation_registry: ConnectionCancellationRegistry | None = None,
        step_run_id: str | None = None,
        output_sink: TransportOutputSink | None = None,
        host_key_verifier: HostKeyVerifier | None = None,
    ):
        """Initialize the netmiko transport from a resolved connection spec.

        Args:
            spec: Fully-resolved connection parameters (credentials already
                resolved by the host).
            cancellation_registry: Host registry used to force-close live
                connections on cancellation; a no-op registry is used when None.
            step_run_id: Key under which connections register for cancellation.
            output_sink: Optional host-built sink for live output streaming.
                Netmiko runs in an executor thread, so chunks are pushed via
                the sink's thread-safe entry point. Only timing-mode commands
                stream (``send_command`` is prompt-based and yields no partial
                output).
            host_key_verifier: The host's SSH host-key trust. Each hop accepts
                only the keys it names; None connects without a host-key check.
                Netmiko runs in an executor thread, so the verifier is called
                on the event loop the transport's async methods run on.
        """
        if ConnectHandler is None:
            raise ImportError(
                "netmiko is required for the netmiko transport. Install with: pip install netmiko"
            )

        self.host = spec.host
        self.port = spec.port
        self.step_run_id = step_run_id
        self._cancellation_registry: ConnectionCancellationRegistry = (
            cancellation_registry if cancellation_registry is not None else _NULL_CANCELLATION
        )
        self._output_sink = output_sink
        #: Duck-typed flag handlers read to skip duplicate completed-output
        #: emissions for paths this transport streams live.
        self.streams_timing_output = output_sink is not None

        self.username = spec.username or None
        self.password = spec.password
        self.secret = spec.enable_secret

        # Validate username is provided (fail fast)
        if not self.username:
            raise ValueError("SSH username required (device access_config.ssh.username_ref)")

        self.platform = spec.platform
        self.device_type = PLATFORM_TO_NETMIKO.get(spec.platform, "cisco_ios")
        self.connect_timeout = spec.connect_timeout
        self.command_timeout = spec.command_timeout
        self.jump_host = spec.jump_host
        self._host_key_verifier = host_key_verifier
        #: The event loop of the latest async call, for the verifier.
        self._loop: asyncio.AbstractEventLoop | None = None

    async def _run_in_thread(self, func: Callable[[], _T]) -> _T:
        """Run blocking netmiko code in the default executor."""
        loop = asyncio.get_running_loop()
        self._loop = loop
        return await loop.run_in_executor(None, func)

    def _from_loop(self, coroutine: Coroutine[Any, Any, _T]) -> _T:
        """Run a verifier coroutine on the caller's event loop; wait in this thread."""
        loop = self._loop
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if loop is None or loop is running or loop.is_closed():
            coroutine.close()
            raise RuntimeError(
                "the SSH host-key check needs the event loop the transport was called "
                "from, and connections open in an executor thread"
            )
        future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        try:
            return future.result(timeout=_VERIFIER_TIMEOUT_SECONDS)
        except BaseException:
            future.cancel()
            raise

    def _hop_keys(
        self, host: str, port: int, *, dial: Callable[[float], Any], timeout: float
    ) -> tuple[str, ...] | None:
        """The keys hop ``host:port`` may present; None connects without a check.

        On first contact the key the host presents is fetched over a fresh
        ``dial(timeout)`` stream without logging in, and recorded through the
        verifier, so the login that follows accepts only that key and no
        credential is sent before it is recorded.
        """
        verifier = self._host_key_verifier
        if verifier is None:
            return None
        keys = self._from_loop(verifier.trusted_keys(host, port))
        if keys is None or keys:
            return keys
        presented = _presented_key(dial(timeout), timeout)
        self._from_loop(verifier.learn(host, port, presented))
        return (presented,)

    def _refusal(
        self, exc: BaseException, host: str, port: int, keys: tuple[str, ...] | None
    ) -> HostKeyRejectedError | None:
        """The error to raise when ``exc`` is hop ``host:port`` failing its key check.

        paramiko compares the key the host presents with the trusted ones and
        raises ``BadHostKeyException``, which carries the presented key.
        """
        verifier = self._host_key_verifier
        if verifier is None or keys is None:
            return None
        bad = _bad_host_key(exc)
        if bad is None:
            return None
        return self._from_loop(verifier.rejected(host, port, _key_line(bad.key)))

    def _dial_device(self, bastion: Any, timeout: float) -> Any:
        """A fresh stream to the device: a socket, or a channel of the bastion."""
        if bastion is None:
            return socket.create_connection((self.host, self.port), timeout=timeout)
        transport = bastion.get_transport()
        if transport is None:
            raise OSError("bastion SSH transport unavailable")
        return transport.open_channel(
            "direct-tcpip", (self.host, self.port), ("127.0.0.1", 0), timeout=timeout
        )

    def _stream_from_thread(self, text: Any) -> None:
        """Push a session chunk to the live-output sink (executor thread)."""
        if self._output_sink is None or not text:
            return
        try:
            self._output_sink.push_from_thread(str(text))
        except Exception:  # noqa: BLE001 - streaming must never fail the command
            logger.debug("output sink push failed", exc_info=True)

    def _stream_flush_from_thread(self) -> None:
        """Drain any buffered live output at the end of a streamed command."""
        if self._output_sink is None:
            return
        try:
            self._output_sink.flush_from_thread()
        except Exception:  # noqa: BLE001 - best-effort tail flush
            logger.debug("output sink flush failed", exc_info=True)

    @staticmethod
    def _load_jump_private_key(pem: str):
        """Parse a PEM private key for the bastion login (any paramiko type)."""
        import io

        for key_cls in (
            paramiko.Ed25519Key,
            paramiko.ECDSAKey,
            paramiko.RSAKey,
        ):
            with contextlib.suppress(Exception):
                return key_cls.from_private_key(io.StringIO(pem))
        raise ValueError("unsupported jump-host private key format")

    def _open_jump_channel(self):
        """SSH session #1 to the bastion plus a direct-tcpip channel to the device.

        Only bastion credentials are presented here (design-dind-sandbox.md
        §11.1); the device session runs inside the returned channel with device
        credentials only. The bastion's host key is checked like the device's.
        """
        jump = self.jump_host
        assert jump is not None
        if paramiko is None:  # pragma: no cover - netmiko always brings paramiko
            raise ImportError("paramiko is required for jump-host support")
        logger.info(f"Connecting to jump host {jump.host}:{jump.port} as {jump.username}")
        keys = self._hop_keys(
            jump.host,
            jump.port,
            dial=lambda timeout: socket.create_connection((jump.host, jump.port), timeout=timeout),
            timeout=self.connect_timeout,
        )
        client = paramiko.SSHClient()
        _set_host_keys(client, jump.host, jump.port, keys)
        started = time.perf_counter()
        # When the inventory supplies a key, present exactly that one and
        # nothing else — an agent or an on-disk key silently substituting for
        # the configured credential is the opposite of what was asked for.
        # With no key configured, fall back to the agent and the default
        # identities, matching what the asyncssh transport does by omitting
        # client_keys: otherwise a bastion reachable only by agent key cannot
        # be reached at all from this transport.
        explicit_key = self._load_jump_private_key(jump.private_key) if jump.private_key else None
        try:
            try:
                client.connect(
                    jump.host,
                    port=jump.port,
                    username=jump.username or None,
                    password=jump.password or None,
                    pkey=explicit_key,
                    allow_agent=explicit_key is None,
                    look_for_keys=explicit_key is None,
                    timeout=self.connect_timeout,
                )
            except Exception as exc:
                refusal = self._refusal(exc, jump.host, jump.port, keys)
                if refusal is None:
                    raise
                raise refusal from exc
            transport = client.get_transport()
            if transport is None:
                raise OSError("bastion SSH transport unavailable")
            channel = transport.open_channel(
                "direct-tcpip",
                (self.host, self.port),
                ("127.0.0.1", 0),
                timeout=self._remaining_connect_budget(started),
            )
        except BaseException:
            with contextlib.suppress(Exception):
                client.close()
            raise
        return client, channel, self._remaining_connect_budget(started)

    def _remaining_connect_budget(self, started: float) -> float:
        """What is left of ``connect_timeout`` since ``started``, floored.

        ``connect_timeout`` is one budget for reaching the device, not a
        per-hop allowance: charging it separately to the bastion login, the
        direct-tcpip channel and the device login lets a slow bastion stretch
        a 30 s setting into 90 s of real waiting. The floor keeps a bastion
        that ate the whole budget surfacing as a device-connect timeout rather
        than an immediate zero-timeout failure that hides which hop was slow.
        """
        return max(self.connect_timeout - (time.perf_counter() - started), 1.0)

    def _connect_device(self):
        """Open the netmiko connection, via the bastion channel when one is set.

        The bastion client rides the returned connection under
        ``_JUMP_CLIENT_ATTR`` so ``_safe_disconnect`` tears the hop down with
        the session — call sites stay hop-agnostic.
        """
        assert ConnectHandler is not None  # Validated in __init__
        bastion = None
        device_timeout = None
        if self.jump_host is not None:
            bastion, channel, device_timeout = self._open_jump_channel()
        known_hosts_file = None
        try:
            keys = self._hop_keys(
                self.host,
                self.port,
                dial=partial(self._dial_device, bastion),
                timeout=self.connect_timeout if device_timeout is None else device_timeout,
            )
            params = self._get_connection_params(connect_timeout=device_timeout)
            if bastion is not None:
                params["sock"] = channel
            if keys is not None:
                # Only the trusted keys, from a file of their own: no system or
                # user known_hosts, and an unknown key is refused, not added.
                known_hosts_file = _write_known_hosts(self.host, self.port, keys)
                params.update(
                    ssh_strict=True,
                    system_host_keys=False,
                    alt_host_keys=True,
                    alt_key_file=known_hosts_file,
                )
            try:
                connection = ConnectHandler(**params)
            except Exception as exc:
                refusal = self._refusal(exc, self.host, self.port, keys)
                if refusal is None:
                    raise
                raise refusal from exc
        except BaseException:
            if bastion is not None:
                with contextlib.suppress(Exception):
                    bastion.close()
            raise
        finally:
            if known_hosts_file is not None:
                with contextlib.suppress(OSError):
                    os.unlink(known_hosts_file)
        if bastion is not None:
            setattr(connection, _JUMP_CLIENT_ATTR, bastion)
        return connection

    def _get_connection_params(self, *, connect_timeout: float | None = None) -> dict[str, Any]:
        """Get Netmiko connection parameters."""
        params = {
            "device_type": self.device_type,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "timeout": self.connect_timeout if connect_timeout is None else connect_timeout,
            "global_delay_factor": 1,
            "fast_cli": True,
        }
        if self.secret:
            params["secret"] = self.secret
        return params

    def _is_config_command_set(self, commands: list[str]) -> bool:
        """
        Check if commands are a configuration command set.

        A config command set starts with 'configure terminal' (or 'conf t' /
        'config t'); see ``_plan_config_set`` for how it is run. The first
        non-blank command decides, so a leading blank line does not turn
        configuration mode off.
        """
        first_cmd = next((cmd.strip().lower() for cmd in commands if cmd.strip()), "")
        return first_cmd in _CONFIG_ENTER_COMMANDS

    def _skip_reason(self) -> str:
        """Why the commands after a failure are not run.

        Cancelling the run closes the session, so the command running then
        fails; the rest are skipped because of the cancellation, not that
        failure.
        """
        if self._cancellation_registry.is_cancelled(self.step_run_id):
            return _CANCELLED_ERROR
        return _SKIPPED_ERROR

    def _run_exec_command(self, connection, command: str) -> SSHResult:
        """Run one command at privilege-exec; a CLI error pattern gives exit code 1."""
        start = time.perf_counter()
        try:
            if not command.strip():
                connection.write_channel("\n")
                raw_output = connection.read_channel()
            elif _is_startup_copy(command):
                raw_output = self._send_startup_copy(connection, command)
            else:
                raw_output = connection.send_command(
                    command,
                    read_timeout=self.command_timeout,
                    strip_prompt=True,
                    strip_command=True,
                )
        except Exception as e:
            latency_ms = (time.perf_counter() - start) * 1000
            logger.error(f"Command on {self.host} failed: {type(e).__name__}")
            return SSHResult(
                command=command,
                output="",
                exit_code=-1,
                error=str(e),
                latency_ms=latency_ms,
            )
        latency_ms = (time.perf_counter() - start) * 1000

        # Ensure output is always a string
        output: str
        if raw_output is None:
            output = ""
            logger.warning(f"Command on {self.host} returned no output (connection issue?)")
        else:
            output = str(raw_output)

        # Check for CLI error patterns in output
        cli_error = None if not command.strip() else _detect_cli_error(output)
        if cli_error:
            logger.warning(f"Command on {self.host} returned a CLI error")
            return SSHResult(
                command=command,
                output=output,
                exit_code=1,  # Non-zero for CLI error
                error=cli_error,
                latency_ms=latency_ms,
            )
        logger.info(f"Command on {self.host} completed in {latency_ms:.0f}ms")
        return SSHResult(command=command, output=output, exit_code=0, latency_ms=latency_ms)

    def _send_startup_copy(self, connection, command: str) -> str:
        """Run a copy to startup-config, answering its questions with Enter.

        Waiting for the prompt alone, as send_command does, runs into the
        command timeout while the device asks for the destination file name,
        so each read also stops at the questions such a copy asks. The output
        keeps neither the command echo nor the trailing prompt, like
        send_command's.
        """
        prompt = connection.find_prompt()
        expect = f"{re.escape(prompt)}|{_COPY_QUESTION}"
        question_at_end = re.compile(rf"{_COPY_QUESTION}\s*\Z")
        chunk = str(
            connection.send_command(
                command,
                expect_string=expect,
                read_timeout=self.command_timeout,
                strip_prompt=False,
                strip_command=True,
            )
        )
        output = chunk
        answers = 0
        while question_at_end.search(chunk):
            if answers == _MAX_COPY_ANSWERS:
                raise RuntimeError("The device kept asking questions about the copy")
            answers += 1
            chunk = str(
                connection.send_command(
                    "",
                    expect_string=expect,
                    read_timeout=self.command_timeout,
                    strip_prompt=False,
                    strip_command=False,
                    cmd_verify=False,
                )
            )
            output += chunk
        lines = output.rstrip().splitlines()
        if lines and lines[-1].strip() == prompt.strip():
            lines.pop()
        return "\n".join(lines)

    def _run_config_block(self, connection, block: list[str]) -> list[SSHResult]:
        """Send one config block a line at a time; one result per line.

        Each line is its own send_config_set, so the device's answer to it
        is checked before the next line goes out: at the first line the
        device rejects the block stops, and every line after it is recorded
        as skipped, not sent. The first call enters config mode and the last
        one leaves it, as a single config set would, so the mode wrappers
        are not sent and get an empty result.
        """
        sent = [idx for idx, cmd in enumerate(block) if not _is_mode_wrapper(cmd)]
        if not sent:
            return [SSHResult(command=cmd, output="", exit_code=0) for cmd in block]
        cmd_verify = not any(_FREE_TEXT_ENTRY.match(block[idx]) for idx in sent)

        results: list[SSHResult] = []
        transcript = ""
        last_run: SSHResult | None = None
        skip_reason: str | None = None
        line_number = 0
        block_start = time.perf_counter()
        for idx, cmd in enumerate(block):
            if skip_reason is not None:
                results.append(_skipped(cmd, skip_reason))
                continue
            if _is_mode_wrapper(cmd):
                results.append(SSHResult(command=cmd, output="", exit_code=0))
                continue
            line_number += 1
            mode_options: dict[str, bool] = {}
            if idx != sent[0]:
                mode_options["enter_config_mode"] = False
            if idx != sent[-1]:
                mode_options["exit_config_mode"] = False
            start = time.perf_counter()
            try:
                output = connection.send_config_set(
                    [cmd],
                    read_timeout=self.command_timeout,
                    cmd_verify=cmd_verify,
                    **mode_options,
                )
            except Exception as e:
                latency_ms = (time.perf_counter() - start) * 1000
                logger.error(
                    f"Config line {line_number} of {len(sent)} on {self.host} failed: "
                    f"{type(e).__name__}"
                )
                last_run = SSHResult(
                    command=cmd,
                    output="",
                    exit_code=-1,
                    error=self._exception_error(e),
                    latency_ms=latency_ms,
                )
                results.append(last_run)
                skip_reason = self._skip_reason()
                continue
            latency_ms = (time.perf_counter() - start) * 1000
            output = "" if output is None else str(output)
            transcript += output
            config_error = _detect_cli_error(output)
            last_run = SSHResult(
                command=cmd,
                output="",
                exit_code=1 if config_error else 0,
                error=config_error,
                latency_ms=latency_ms,
            )
            results.append(last_run)
            if config_error:
                logger.warning(
                    f"Config line {line_number} of {len(sent)} on {self.host} returned a CLI error"
                )
                skip_reason = self._skip_reason()
        if skip_reason is None:
            block_ms = (time.perf_counter() - block_start) * 1000
            logger.info(f"Config block of {len(sent)} lines ran on {self.host} in {block_ms:.0f}ms")

        # The block's whole session transcript goes on exactly one result,
        # the last line that ran, as the transcript of a single config set
        # did: the handler joins the outputs into one evidence artifact.
        if last_run is not None:
            last_run.output = transcript
        return results

    def _exception_error(self, error: Exception) -> str:
        """The error text of a command that raised ``error``.

        netmiko's ReadTimeout names the pattern it waited for, and for a
        command's echo that is the command itself, regex-escaped: a secret in
        it would then no longer match the host's redaction of secret values.
        """
        if isinstance(error, ReadTimeout):
            return f"Timed out after {self.command_timeout:g} seconds reading the device's answer"
        return str(error)

    def _execute_commands_sync(self, commands: list[str]) -> list[SSHResult]:
        """
        Execute commands synchronously using Netmiko.

        This runs in a thread pool to avoid blocking the event loop.
        Automatically detects config mode vs show commands and uses
        appropriate Netmiko methods.
        """
        results: list[SSHResult] = []
        connection = None

        try:
            # Connect to device
            logger.info(f"Connecting to {self.host}:{self.port} as {self.username}")
            connect_start = time.perf_counter()
            connection = self._connect_device()
            connect_time = (time.perf_counter() - connect_start) * 1000
            logger.info(f"Connected to {self.host} in {connect_time:.0f}ms")

            # Register connection for cancellation support
            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            # Enter enable mode if we have a secret
            if self.secret:
                connection.enable()

            if self._is_config_command_set(commands):
                # Config blocks and exec commands run in the order written.
                # After the first failure nothing more runs, so a save
                # command never stores a half-applied change.
                skip_reason: str | None = None
                for is_config, indexes in _plan_config_set(commands):
                    step = [commands[idx] for idx in indexes]
                    if skip_reason is not None:
                        results.extend(_skipped(cmd, skip_reason) for cmd in step)
                        continue
                    if is_config:
                        step_results = self._run_config_block(connection, step)
                    else:
                        step_results = [self._run_exec_command(connection, step[0])]
                    results.extend(step_results)
                    if any(r.exit_code != 0 for r in step_results):
                        skip_reason = self._skip_reason()
            else:
                # Execute show/exec commands individually
                for command in commands:
                    results.append(self._run_exec_command(connection, command))

        except NetmikoAuthenticationException as e:
            logger.error(f"Authentication failed to {self.host}: {e}")
            for command in commands:
                results.append(
                    SSHResult(
                        command=command,
                        output="",
                        exit_code=-1,
                        error=f"Authentication failed: {e}",
                        latency_ms=0.0,
                    )
                )
        except NetmikoTimeoutException as e:
            logger.error(f"Connection timeout to {self.host}: {e}")
            for command in commands:
                results.append(
                    SSHResult(
                        command=command,
                        output="",
                        exit_code=-1,
                        error=f"Connection timeout: {e}",
                        latency_ms=0.0,
                    )
                )
        except Exception as e:
            logger.error(f"SSH connection to {self.host}:{self.port} failed: {e}")
            for command in commands:
                results.append(
                    SSHResult(
                        command=command,
                        output="",
                        exit_code=-1,
                        error=f"SSH connection failed: {e}",
                        latency_ms=0.0,
                    )
                )
        finally:
            # Unregister from cancellation registry before disconnect
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            _safe_disconnect(connection)

        return results

    def _scp_put_sync(
        self,
        *,
        local_path: str,
        dest_fs: str,
        dest_filename: str,
        overwrite: bool = False,
    ) -> dict:
        """
        Transfer file to device using SCP (sync version for thread pool).

        Uses Netmiko's file_transfer functionality.
        """
        from netmiko import file_transfer

        connection = None
        start_time = time.perf_counter()

        try:
            logger.info(f"SCP upload to {self.host}: {local_path} -> {dest_fs}{dest_filename}")
            connection = self._connect_device()

            # Register connection for cancellation support
            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            # Enter enable mode if we have a secret
            if self.secret:
                connection.enable()

            # Perform file transfer
            transfer_result = file_transfer(
                connection,
                source_file=local_path,
                dest_file=dest_filename,
                file_system=dest_fs,
                direction="put",
                overwrite_file=overwrite,
            )

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            return {
                "transferred": transfer_result.get("file_transferred", False),
                "verified": transfer_result.get("file_verified", False),
                "exists": transfer_result.get("file_exists", False),
                "elapsed_ms": elapsed_ms,
            }

        except Exception as e:
            logger.error(f"SCP transfer to {self.host} failed: {e}")
            raise
        finally:
            # Unregister from cancellation registry before disconnect
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            _safe_disconnect(connection)

    async def scp_put(
        self,
        *,
        local_path: str,
        dest_fs: str,
        dest_filename: str,
        overwrite: bool = False,
    ) -> dict:
        """
        Transfer file to device using SCP.

        Args:
            local_path: Path to local file
            dest_fs: Destination filesystem (e.g., 'flash:', 'bootflash:')
            dest_filename: Filename on device
            overwrite: Whether to overwrite if exists

        Returns:
            Dict with: transferred, verified, exists, elapsed_ms
        """
        result = await self._run_in_thread(
            partial(
                self._scp_put_sync,
                local_path=local_path,
                dest_fs=dest_fs,
                dest_filename=dest_filename,
                overwrite=overwrite,
            ),
        )
        return result

    def _http_transfer_sync(
        self,
        *,
        url: str,
        dest_fs: str,
        dest_filename: str,
        timeout_seconds: int = 3600,
    ) -> dict:
        """
        Transfer file to device using HTTP/HTTPS copy command (sync version).

        Device pulls the file directly from the URL using:
            copy https://url flash:filename

        This is preferred over SCP as it doesn't require SCP server config on the device.

        Args:
            url: Presigned HTTP/HTTPS URL to the file
            dest_fs: Destination filesystem (e.g., 'flash:', 'bootflash:')
            dest_filename: Filename on device
            timeout_seconds: Maximum time to wait for transfer completion

        Returns:
            Dict with: transferred, output, elapsed_ms
        """
        connection = None
        start_time = time.perf_counter()

        try:
            logger.info(f"HTTP transfer to {self.host}: {dest_fs}{dest_filename}")
            connection = self._connect_device()

            # Register connection for cancellation support
            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            # Enter enable mode if we have a secret
            if self.secret:
                connection.enable()

            # Build the copy command
            # Format: copy http://url flash:filename
            #
            # NOTE: For Cisco IOS, URLs with '?' characters trigger help mode.
            # We avoid this by using redirect URLs from the API (no query params).
            # The API returns HTTP 302 redirect to presigned S3 URLs.
            copy_cmd = f"copy {url} {dest_fs}{dest_filename}"

            # Use write_channel directly to send the escaped command
            # (send_command_timing might not handle Ctrl+V properly)
            connection.write_channel(copy_cmd + "\n")
            time.sleep(1)  # Give device time to process

            # Read initial output
            output = connection.read_channel()

            # Handle potential prompts:
            # - "Destination filename [...]?" - just press enter
            # - "Overwrite? [confirm]" - send 'y' or '\n'
            # - VRF selection - device specific

            # Wait for prompts or progress, handle them
            max_wait = timeout_seconds  # Use caller-provided timeout
            poll_interval = 2
            waited = 0
            dest_filename_handled = False
            overwrite_handled = False

            while waited < max_wait:
                # Check for cancellation first - exit immediately if cancelled
                if self._cancellation_registry.is_cancelled(self.step_run_id):
                    logger.info(f"HTTP transfer cancelled for step {self.step_run_id}")
                    return {
                        "transferred": False,
                        "output": output + "\n[CANCELLED]",
                        "elapsed_ms": (time.perf_counter() - start_time) * 1000,
                    }

                # Check for completion/error indicators FIRST (before prompt handling)
                # This ensures we exit the loop when transfer completes or fails
                if any(
                    indicator in output
                    for indicator in [
                        "bytes copied",
                        "%Error",
                        "Error opening",
                        "Invalid",
                        "not found",
                        "timed out",
                        "refused",
                        "Could not",
                        "Incomplete command",
                        "Broken pipe",
                    ]
                ):
                    break

                # Check for destination filename prompt (only handle once)
                if "Destination filename" in output and not dest_filename_handled:
                    logger.debug("Handling destination filename prompt")
                    connection.write_channel("\n")
                    time.sleep(1)
                    output += connection.read_channel()
                    dest_filename_handled = True
                    continue

                # Check for overwrite prompt (only handle once)
                # Check recent output only to avoid infinite loops
                recent_output = output[-500:] if len(output) > 500 else output
                if not overwrite_handled and (
                    "Overwrite?" in recent_output or "[confirm]" in recent_output.lower()
                ):
                    logger.debug("Handling overwrite/confirm prompt")
                    connection.write_channel("\n")
                    time.sleep(1)
                    output += connection.read_channel()
                    overwrite_handled = True
                    continue

                # Read more output
                time.sleep(poll_interval)
                waited += poll_interval
                more_output = connection.read_channel()
                if more_output:
                    output += more_output
                    # Log progress (last 100 chars, strip sensitive data)
                    progress = more_output[-100:] if len(more_output) > 100 else more_output
                    if "!" in progress:  # Progress indicator
                        logger.debug("HTTP transfer in progress...")

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            # Check for errors first (more specific matches)
            error_patterns = [
                "%Error",
                "Error opening",
                "Error reading",
                "Invalid",
                "not found",
                "refused",
                "Could not",
                "Broken pipe",
                "timed out",
            ]
            has_error = any(err in output for err in error_patterns)

            if has_error:
                # Not the output: the device echoes the copy command and its URL.
                logger.error(f"HTTP transfer to {self.host} failed")
                return {
                    "transferred": False,
                    "output": output,
                    "elapsed_ms": elapsed_ms,
                }

            # Check for success indicators
            # "bytes copied" is the definitive success indicator for IOS copy
            transferred = "bytes copied" in output.lower()

            return {
                "transferred": transferred,
                "output": output,
                "elapsed_ms": elapsed_ms,
            }

        except Exception as e:
            logger.error(f"HTTP transfer to {self.host} failed: {type(e).__name__}")
            raise
        finally:
            # Unregister from cancellation registry before disconnect
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            _safe_disconnect(connection)

    async def http_transfer(
        self,
        *,
        url: str,
        dest_fs: str,
        dest_filename: str,
        timeout_seconds: int = 3600,
    ) -> dict:
        """
        Transfer file to device using HTTP/HTTPS copy command.

        Device pulls the file directly from the URL. This is preferred over SCP
        as it doesn't require SCP server configuration on the device.

        Args:
            url: Presigned HTTP/HTTPS URL to the file
            dest_fs: Destination filesystem (e.g., 'flash:', 'bootflash:')
            dest_filename: Filename on device
            timeout_seconds: Maximum time to wait for transfer completion

        Returns:
            Dict with: transferred, output, elapsed_ms
        """
        result = await self._run_in_thread(
            partial(
                self._http_transfer_sync,
                url=url,
                dest_fs=dest_fs,
                dest_filename=dest_filename,
                timeout_seconds=timeout_seconds,
            ),
        )
        return result

    def _execute_command_timing_sync(
        self,
        command: str,
        *,
        read_timeout: float = 120.0,
        delay_factor: int = 2,
        expect: list[str] | None = None,
        answers: dict[str, str] | None = None,
        wait_for_patterns: list[str] | None = None,
    ) -> SSHResult:
        """
        Execute a command using timing mode (sync version for thread pool).

        Uses send_command_timing for commands that may prompt or run long.
        Automatically handles known prompts with configured answers.

        Args:
            wait_for_patterns: If provided, keep reading until one of these patterns
                appears in output OR read_timeout is reached. Critical for long-running
                commands like IOS-XE install that have long pauses between output.
        """
        connection = None
        start_time = time.perf_counter()
        combined_output = ""

        try:
            logger.info(f"Executing timing command on {self.host}")
            connection = self._connect_device()

            # Register connection for cancellation support
            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            # Enter enable mode if we have a secret
            if self.secret:
                connection.enable()

            # Command boundary marker for the live view (same exposure as the
            # Phase A events' attrs.command labelling).
            self._stream_from_thread(f"$ {command}\n")

            # Initial command send using timing mode
            # delay_factor controls how long to wait between read attempts - higher values
            # wait longer before deciding the command is done (critical for install commands)
            raw_output = connection.send_command_timing(
                command,
                delay_factor=delay_factor,
                read_timeout=read_timeout,
            )
            # Ensure output is always a string
            if raw_output is None:
                logger.warning(f"Command on {self.host} returned no output (connection issue?)")
            else:
                combined_output += str(raw_output)
                self._stream_from_thread(raw_output)

            # Prompts answered so far, lower-cased. Both phases below share
            # it: a question already in the first output is answered once,
            # not again when waiting for patterns starts.
            answered_prompts: set[str] = set()

            # Handle prompts if answers provided (case-insensitive matching)
            # Track which prompts have been answered to avoid repeating
            if answers:
                max_prompt_iterations = 10
                iterations = 0

                while iterations < max_prompt_iterations:
                    # Check for cancellation
                    if self._cancellation_registry.is_cancelled(self.step_run_id):
                        logger.info(f"Command cancelled for step {self.step_run_id}")
                        combined_output += "\n[CANCELLED]"
                        break

                    iterations += 1
                    prompt_matched = False

                    # Check against combined_output with case-insensitive matching
                    output_lower = combined_output.lower()
                    for prompt_pattern, answer in answers.items():
                        # Skip prompts we've already answered
                        if prompt_pattern.lower() in answered_prompts:
                            continue
                        if prompt_pattern.lower() in output_lower:
                            logger.info(f"Matched prompt '{prompt_pattern}', sending answer")
                            answered_prompts.add(prompt_pattern.lower())
                            raw_answer_output = connection.send_command_timing(
                                answer,
                                delay_factor=1,
                                read_timeout=read_timeout,
                            )
                            # Ensure answer output is always a string
                            combined_output += (
                                str(raw_answer_output) if raw_answer_output is not None else ""
                            )
                            self._stream_from_thread(raw_answer_output)
                            prompt_matched = True
                            break

                    if not prompt_matched:
                        # No more prompts to answer
                        break

            # If wait_for_patterns specified, keep reading until pattern found or timeout
            # This is critical for long-running commands like IOS-XE install that have
            # long pauses (30-60+ seconds) between output chunks
            if wait_for_patterns:
                logger.info(f"Waiting for patterns: {wait_for_patterns}")
                logger.info(f"Initial output: {len(combined_output)} chars")
                pattern_found = False
                read_interval = 2.0  # Check every 2 seconds
                last_log_time = time.perf_counter()
                log_interval = 30.0  # Log progress every 30 seconds
                # Track position in output up to which we've processed prompts
                prompt_check_start_pos = 0

                # Check for prompts in initial output BEFORE entering the loop
                # Prompts may already be present from send_command_timing;
                # the ones the answers loop above answered are skipped.
                while answers:
                    prompt, answer, prompt_check_start_pos = _next_prompt(
                        combined_output, prompt_check_start_pos, answers, answered_prompts
                    )
                    if prompt is None:
                        break
                    logger.info(f"Matched prompt '{prompt}' in initial output, sending answer")
                    connection.write_channel(answer + "\n")
                    time.sleep(0.5)

                while (time.perf_counter() - start_time) < read_timeout:
                    # Check for cancellation at start of each iteration
                    if self._cancellation_registry.is_cancelled(self.step_run_id):
                        logger.info(f"Wait for patterns cancelled for step {self.step_run_id}")
                        combined_output += "\n[CANCELLED]"
                        break

                    # Check if any pattern already in output
                    for pattern in wait_for_patterns:
                        if pattern.lower() in combined_output.lower():
                            logger.info(f"Found expected pattern: {pattern}")
                            pattern_found = True
                            break

                    if pattern_found:
                        break

                    # Read more from channel
                    time.sleep(read_interval)
                    try:
                        more_output = connection.read_channel()
                        if more_output:
                            logger.debug(f"Read additional output: {len(more_output)} chars")
                            combined_output += more_output
                            self._stream_from_thread(more_output)

                            # Handle prompts that appear during long-running commands
                            # This is critical for IOS-XE install which prompts mid-execution
                            # IMPORTANT: Only check NEW output to avoid re-answering old prompts
                            while answers:
                                # Only output not scanned yet (see _next_prompt)
                                prompt, answer, prompt_check_start_pos = _next_prompt(
                                    combined_output,
                                    prompt_check_start_pos,
                                    answers,
                                    answered_prompts,
                                )
                                if prompt is None:
                                    break
                                logger.info(
                                    f"Matched prompt '{prompt}' in new output, sending answer"
                                )
                                connection.write_channel(answer + "\n")
                                time.sleep(0.5)  # Brief pause after answering

                        # Log progress periodically so we can see what's happening
                        current_time = time.perf_counter()
                        if current_time - last_log_time > log_interval:
                            elapsed = int(current_time - start_time)
                            logger.info(
                                f"Still waiting for patterns after {elapsed}s. "
                                f"Output length: {len(combined_output)}"
                            )
                            last_log_time = current_time

                    except Exception as read_err:
                        logger.warning(f"Error reading channel: {read_err}")
                        # Connection may have dropped (e.g., reboot) - that's expected
                        break

                if not pattern_found:
                    logger.warning(
                        f"Timeout waiting for patterns after {read_timeout}s. "
                        f"Output length: {len(combined_output)}"
                    )

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            # Check for CLI error patterns
            cli_error = _detect_cli_error(combined_output)
            if cli_error:
                return SSHResult(
                    command=command,
                    output=combined_output,
                    exit_code=1,
                    error=cli_error,
                    latency_ms=elapsed_ms,
                )

            return SSHResult(
                command=command,
                output=combined_output,
                exit_code=0,
                latency_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Timing command failed on {self.host}: {type(e).__name__}")
            return SSHResult(
                command=command,
                output=combined_output,
                exit_code=-1,
                error=str(e),
                latency_ms=elapsed_ms,
            )
        finally:
            self._stream_flush_from_thread()
            # Unregister from cancellation registry before disconnect
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            _safe_disconnect(connection)

    async def execute_command_timing(
        self,
        command: str,
        *,
        read_timeout: float = 120.0,
        delay_factor: int = 2,
        expect: list[str] | None = None,
        answers: dict[str, str] | None = None,
        wait_for_patterns: list[str] | None = None,
    ) -> SSHResult:
        """
        Execute a command using timing mode for interactive/long-running commands.

        Uses send_command_timing which doesn't wait for a prompt pattern.
        Suitable for upgrade commands that may prompt or trigger reboot.

        Args:
            command: CLI command to execute
            read_timeout: Time to wait for output
            delay_factor: Multiplier for inter-read delays (higher = wait longer
                before deciding command is done). For install commands that have
                long pauses between output, use 20-60.
            expect: Optional list of expected patterns (for logging)
            answers: Map of prompt patterns to answers (auto-reply to known prompts)
            wait_for_patterns: If provided, keep reading from channel until one of
                these patterns appears OR read_timeout is reached. Use for long-running
                commands like 'install add file ... activate commit' that output status
                over several minutes.

        Returns:
            SSHResult with combined output
        """
        result = await self._run_in_thread(
            partial(
                self._execute_command_timing_sync,
                command,
                read_timeout=read_timeout,
                delay_factor=delay_factor,
                expect=expect,
                answers=answers,
                wait_for_patterns=wait_for_patterns,
            ),
        )
        return result

    async def execute_command(self, command: str) -> SSHResult:
        """
        Execute a single CLI command via SSH.

        Args:
            command: CLI command to execute

        Returns:
            SSHResult with command output
        """
        results = await self.execute_commands([command])
        return (
            results[0]
            if results
            else SSHResult(
                command=command,
                output="",
                exit_code=-1,
                error="No result returned",
            )
        )

    async def execute_commands(self, commands: list[str]) -> list[SSHResult]:
        """
        Execute multiple CLI commands via SSH.

        Opens a single SSH session and executes all commands sequentially.
        Uses Netmiko for proper Cisco CLI handling (prompts, enable mode, etc.)

        Args:
            commands: List of CLI commands to execute

        Returns:
            List of SSHResult for each command
        """
        if not commands:
            return []

        # Run blocking Netmiko code in thread pool
        results = await self._run_in_thread(partial(self._execute_commands_sync, commands))
        return results
