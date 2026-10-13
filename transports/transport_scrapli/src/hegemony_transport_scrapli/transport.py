# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Scrapli device transport (network-CLI over SSH, asyncssh-backed).

The ``scrapli`` implementation of the SDK ``Transport`` I/O surface, registered
under the ``hegemony.device_transports`` entry-point group. The host constructs
it from a resolved :class:`DeviceConnectionSpec` and injects its cancellation
registry, so this wheel never touches the platform's secret pipeline or
settings.

Runs ``AsyncScrapli`` over scrapli's asyncssh transport plugin — natively async
(no thread pool), and no paramiko in the dependency tree (scrapli's paramiko
extra caps ``paramiko<4``, which would drag the whole install onto an old
paramiko; asyncssh is already the platform's SSH library).

Command execution (single, batch, config sets, timing mode) is implemented on
scrapli's core network drivers; file staging (``scp_put``/``http_transfer``)
is netmiko-only for now and raises :class:`NotImplementedError` — select the
netmiko transport for staging steps.
"""

import asyncio
import contextlib
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from hegemony_step_sdk import (
    ConnectionCancellationRegistry,
    DeviceConnectionSpec,
    HostKeyRejectedError,
    HostKeyVerifier,
    SshAlgorithmRecorder,
    SshAlgorithms,
    TransportOutputSink,
)

try:
    from scrapli import AsyncScrapli
    from scrapli.exceptions import (
        ScrapliAuthenticationFailed,
        ScrapliTimeout,
    )
except ImportError:
    # Scrapli unavailable - provide stubs for type checking
    AsyncScrapli: Any = None
    ScrapliAuthenticationFailed: type[Exception] = Exception
    ScrapliTimeout: type[Exception] = Exception

try:
    # Already a dependency via scrapli's asyncssh transport plugin; imported
    # directly only for the optional jump-host hop.
    import asyncssh
except ImportError:
    asyncssh: Any = None

logger = logging.getLogger(__name__)

#: Attribute under which the bastion connection rides its scrapli connection,
#: so every existing close path tears the tunnel down with the session.
_JUMP_TUNNEL_ATTR = "_hegemony_jump_tunnel"


def _agreed_algorithms(connection: Any) -> SshAlgorithms:
    """What the key exchange of asyncssh connection ``connection`` agreed on.

    asyncssh has no accessor for the agreed key exchange, but keeps both
    sides' KEXINIT messages for the exchange hash; the agreement follows from
    them (:meth:`SshAlgorithms.from_kexinit`).
    """
    return SshAlgorithms.from_kexinit(connection._client_kexinit, connection._server_kexinit)


class _NullCancellationRegistry:
    """No-op cancellation registry used when the host tracks no cancellation."""

    def register(self, key: str | None, connection: Any) -> None:  # noqa: D102
        pass

    def unregister(self, key: str | None, connection: Any) -> None:  # noqa: D102
        pass

    def is_cancelled(self, key: str | None) -> bool:  # noqa: D102
        return False


_NULL_CANCELLATION = _NullCancellationRegistry()

#: How long a refused connection may spend fetching the key the host presents,
#: so the report names it. Best effort: the refusal stands either way.
_PRESENTED_KEY_TIMEOUT_SECONDS = 5.0


def _openssh_line(key: Any) -> str:
    """``<type> <base64>`` of an asyncssh public key, without the comment."""
    return " ".join(key.export_public_key("openssh").decode("ascii").split()[:2])


def _import_host_keys(host: str, port: int, keys: tuple[str, ...]) -> list[Any]:
    """The trusted keys of ``host:port``, imported for asyncssh."""
    try:
        return [asyncssh.import_public_key(line) for line in keys]
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise ValueError(f"a trusted SSH host key of {host}:{port} cannot be read: {exc}") from exc


def _known_hosts(
    host: str, port: int, keys: tuple[str, ...] | None
) -> tuple[list[Any], list[Any], list[Any]] | None:
    """asyncssh's ``known_hosts`` for one hop: its trusted keys, or None for no check.

    With a key list, asyncssh offers the host only those keys' algorithms and
    fails the key exchange on any other key, before authentication starts.
    """
    if keys is None:
        return None
    return (_import_host_keys(host, port, keys), [], [])


async def _presented_key(
    host: str, port: int, *, tunnel: Any, timeout: float, algorithms: list[str] | None = None
) -> str | None:
    """The key ``host:port`` presents, fetched by a key exchange alone (no login)."""
    key = await asyncio.wait_for(
        asyncssh.get_server_host_key(
            host,
            port,
            tunnel=tunnel if tunnel is not None else (),
            server_host_key_algs=algorithms or (),
        ),
        timeout=timeout,
    )
    return _openssh_line(key) if key is not None else None


# Common Cisco IOS-XE error patterns in command output (same vocabulary as the
# netmiko transport, so handlers see identical error surfacing either way).
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


async def _safe_close(connection) -> None:
    """Close a scrapli connection (and its jump tunnel), suppressing errors."""
    if not connection:
        return
    with contextlib.suppress(Exception):
        await connection.close()
    tunnel = getattr(connection, _JUMP_TUNNEL_ATTR, None)
    if tunnel is not None:
        with contextlib.suppress(Exception):
            tunnel.close()
        with contextlib.suppress(Exception):
            await tunnel.wait_closed()


@dataclass
class ScrapliResult:
    """Result from scrapli command execution (SDK ``CommandResult`` shape)."""

    command: str
    output: str
    exit_code: int
    error: str | None = None
    latency_ms: float = 0.0


# Map inventory platform strings to scrapli core platform names.
PLATFORM_TO_SCRAPLI = {
    "ios-xe": "cisco_iosxe",
    "ios-xr": "cisco_iosxr",
    "nxos": "cisco_nxos",
    "eos": "arista_eos",
    "junos": "juniper_junos",
}

#: timeout_transport for timing-mode connections: each channel read returns (or
#: times out) within this window, which sets the poll cadence for prompt answers,
#: wait-for-pattern checks, and cancellation checks.
_TIMING_POLL_SECONDS = 2.5

#: In timing mode without wait_for_patterns, the command is considered settled
#: after this many consecutive empty reads (mirrors send_command_timing's
#: "read until quiet" semantics).
_QUIET_READS_DONE = 3


#: Lines that open a config block. Only ``end`` closes one: ``exit`` inside a
#: block leaves a sub-mode on the device and is sent like any config line.
_CONFIG_ENTER_COMMANDS = ("configure terminal", "conf t", "config t")

#: Error of a result for a command not run because an earlier one failed.
_SKIPPED_ERROR = "Skipped: earlier command failed"

#: Error of a result for a command not run because the run was cancelled.
_CANCELLED_ERROR = "Skipped: the run was cancelled"


def _is_sent(command: str) -> bool:
    """False for blank lines and the 'configure terminal' / 'end' wrappers.

    scrapli's send_configs enters and leaves config mode itself, and results
    cover only the lines actually sent.
    """
    command_lower = command.strip().lower()
    return bool(command_lower) and command_lower not in (*_CONFIG_ENTER_COMMANDS, "end")


def _is_save_command(command_lower: str) -> bool:
    """'write ...' / 'copy run ...': always run at privilege-exec."""
    return command_lower.startswith("write") or command_lower.startswith("copy run")


#: What IOS asks before a copy to startup-config, unless 'file prompt quiet'
#: is set: the destination file name, then on some platforms a confirmation
#: to overwrite it, as send_interactive patterns (anchored, so read as
#: regular expressions). Enter takes the answer the device offers.
_COPY_QUESTION_PATTERNS = [r"^Destination filename \[[^\]\n]*\]\?\s*$", r"^.*\[confirm\]\s*$"]

#: Output that ends with one of those questions.
_COPY_QUESTION_AT_END = re.compile(r"(?:Destination filename \[[^\]\n]*\]\?|\[confirm\])\s*\Z")

#: A copy to startup-config asks at most these two questions.
_MAX_COPY_ANSWERS = 2


def _is_startup_copy(command: str) -> bool:
    """'copy <source> startup-config', the destination in any abbreviation."""
    words = command.lower().split()
    if len(words) != 3 or words[0] != "copy":
        return False
    destination = words[2].removeprefix("nvram:")
    return len(destination) >= 3 and "startup-config".startswith(destination)


def _plan_config_set(commands: list[str]) -> list[tuple[bool, list[str]]]:
    """Split a config command set into ordered steps of lines to send.

    A step is ``(True, lines)`` for a config block, sent with one
    send_configs, or ``(False, [line])`` for one command run at
    privilege-exec. A block opens at 'configure terminal' and closes only at
    'end'. A save command inside a block splits it and runs between the two
    halves. Running the steps in turn keeps the order the commands were
    written in. Same rules as the netmiko transport.
    """
    steps: list[tuple[bool, list[str]]] = []
    block: list[str] | None = None
    in_config = False
    for cmd in commands:
        cmd_lower = cmd.strip().lower()
        if cmd_lower in _CONFIG_ENTER_COMMANDS:
            in_config = True
        if in_config and not _is_save_command(cmd_lower):
            if block is None:
                block = []
                steps.append((True, block))
            if _is_sent(cmd):
                block.append(cmd)
            if cmd_lower == "end":
                in_config = False
                block = None
        elif _is_sent(cmd):
            block = None
            steps.append((False, [cmd]))
    return [(is_config, lines) for is_config, lines in steps if lines]


def _skipped(command: str, reason: str) -> ScrapliResult:
    """Result for a command not run, with ``reason`` as its error."""
    return ScrapliResult(command=command, output="", exit_code=-1, error=reason)


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


class ScrapliTransport:
    """SSH transport client for network device CLI access using scrapli."""

    #: check_type-style id claimed under the hegemony.device_transports group.
    transport_id = "scrapli"

    #: Feature flag the host checks before passing ``output_sink`` (Phase B
    #: live streaming): hosts that predate sinks never pass the kwarg, and
    #: hosts that support them skip wheels without this attribute.
    supports_output_sink = True

    #: Feature flag the host checks before passing ``host_key_verifier``, as
    #: for the output sink.
    supports_host_key_verifier = True

    #: Feature flag the host checks before passing ``ssh_algorithm_recorder``.
    supports_ssh_algorithm_recorder = True

    def __init__(
        self,
        spec: DeviceConnectionSpec,
        *,
        cancellation_registry: ConnectionCancellationRegistry | None = None,
        step_run_id: str | None = None,
        output_sink: TransportOutputSink | None = None,
        host_key_verifier: HostKeyVerifier | None = None,
        ssh_algorithm_recorder: SshAlgorithmRecorder | None = None,
    ):
        """Initialize the scrapli transport from a resolved connection spec.

        Args:
            spec: Fully-resolved connection parameters (credentials already
                resolved by the host).
            cancellation_registry: Host registry used to force-close live
                connections on cancellation; a no-op registry is used when None.
            step_run_id: Key under which connections register for cancellation.
            output_sink: Optional host-built sink for live output streaming.
                Scrapli is natively async, so timing-mode reads push chunks
                straight to the sink. Only timing-mode commands stream
                (driver ``send_command`` is prompt-based and yields no
                partial output).
            host_key_verifier: The host's SSH host-key trust. Each hop accepts
                only the keys it names. Without one the transport refuses to
                connect; it never connects unchecked on its own. A verifier that
                answers None for a host (checks switched off) is the opt-out.
            ssh_algorithm_recorder: The host's record of what each hop's key
                exchange agreed on, told once the hop is logged in.
        """
        if AsyncScrapli is None:
            raise ImportError(
                "scrapli is required for the scrapli transport. "
                "Install with: pip install 'scrapli[asyncssh]'"
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
        self.scrapli_platform = PLATFORM_TO_SCRAPLI.get(spec.platform, "cisco_iosxe")
        self.connect_timeout = spec.connect_timeout
        self.command_timeout = spec.command_timeout
        self.jump_host = spec.jump_host
        self._host_key_verifier = host_key_verifier
        self._ssh_algorithm_recorder = ssh_algorithm_recorder

    async def _stream_push(self, text: str) -> None:
        """Push a session chunk to the live-output sink (event loop)."""
        if self._output_sink is None or not text:
            return
        try:
            await self._output_sink.push(text)
        except Exception:  # noqa: BLE001 - streaming must never fail the command
            logger.debug("output sink push failed", exc_info=True)

    async def _stream_flush(self) -> None:
        """Drain any buffered live output at the end of a streamed command."""
        if self._output_sink is None:
            return
        try:
            await self._output_sink.flush()
        except Exception:  # noqa: BLE001 - best-effort tail flush
            logger.debug("output sink flush failed", exc_info=True)

    def _get_connection_params(
        self, *, timeout_transport: float | None = None, connect_timeout: float | None = None
    ) -> dict[str, Any]:
        """Get scrapli connection parameters.

        Args:
            timeout_transport: Per-read transport timeout override; timing mode
                uses a short value so channel polls return promptly.
            connect_timeout: Socket timeout for the device hop. Defaults to the
                full budget; the bastion path passes what its own hop left.
        """
        params: dict[str, Any] = {
            "platform": self.scrapli_platform,
            "host": self.host,
            "port": self.port,
            "auth_username": self.username,
            "auth_password": self.password,
            "auth_strict_key": False,
            # asyncssh: already the platform's SSH library, and scrapli's
            # paramiko extra would cap paramiko <4 for the whole install.
            "transport": "asyncssh",
            "timeout_socket": (
                self.connect_timeout if connect_timeout is None else connect_timeout
            ),
            "timeout_ops": self.command_timeout,
        }
        if self.secret:
            # Scrapli escalates to privilege-exec itself using auth_secondary.
            params["auth_secondary"] = self.secret
        if timeout_transport is not None:
            params["timeout_transport"] = timeout_transport
        return params

    async def _hop_keys(
        self, host: str, port: int, *, tunnel: Any, timeout: float
    ) -> tuple[str, ...] | None:
        """The keys hop ``host:port`` may present; None connects without a check.

        On first contact the key the host presents is fetched without logging
        in and recorded through the verifier, so the login that follows
        accepts only that key and no credential is sent before it is recorded.
        Without a verifier the hop is refused before it is dialled.
        """
        verifier = self._host_key_verifier
        if verifier is None:
            raise HostKeyRejectedError(
                f"refusing to connect to {host}:{port}: no SSH host-key verifier was given, "
                "so the key the host presents cannot be checked"
            )
        keys = await verifier.trusted_keys(host, port)
        if keys is None or keys:
            return keys
        presented = await _presented_key(host, port, tunnel=tunnel, timeout=timeout)
        if presented is None:
            raise HostKeyRejectedError(
                f"{host}:{port} completed its key exchange without a host key, "
                "so there is no key to trust"
            )
        await verifier.learn(host, port, presented)
        return (presented,)

    async def _refusal(
        self,
        exc: BaseException,
        host: str,
        port: int,
        keys: tuple[str, ...] | None,
        *,
        tunnel: Any,
    ) -> HostKeyRejectedError | None:
        """The error to raise when ``exc`` is hop ``host:port`` failing its key check.

        ``HostKeyNotVerifiable`` is a key of a trusted type that does not
        match. A key exchange that found no common host-key algorithm is a
        mismatch too when the host now presents a key of another type. The
        presented key is fetched again (best effort) so the report names it.
        scrapli's asyncssh transport lets both errors through unwrapped.
        """
        verifier = self._host_key_verifier
        if verifier is None or keys is None:
            return None
        if isinstance(exc, asyncssh.HostKeyNotVerifiable):
            algorithms = [
                algorithm.decode("ascii")
                for key in _import_host_keys(host, port, keys)
                for algorithm in key.sig_algorithms
            ]
            presented = await self._presented_key_or_none(
                host, port, tunnel=tunnel, algorithms=algorithms
            )
        elif isinstance(exc, asyncssh.KeyExchangeFailed):
            presented = await self._presented_key_or_none(host, port, tunnel=tunnel)
            if presented is None or presented in keys:
                return None
        else:
            return None
        return await verifier.rejected(host, port, presented)

    @staticmethod
    async def _presented_key_or_none(
        host: str, port: int, *, tunnel: Any, algorithms: list[str] | None = None
    ) -> str | None:
        """The key ``host:port`` presents now, or None when it cannot be fetched."""
        try:
            return await _presented_key(
                host,
                port,
                tunnel=tunnel,
                timeout=_PRESENTED_KEY_TIMEOUT_SECONDS,
                algorithms=algorithms,
            )
        except Exception:  # noqa: BLE001 - the report is best effort
            logger.debug("could not fetch the SSH host key of %s:%d", host, port, exc_info=True)
            return None

    def _record_algorithms(self, connection: Any, host: str, port: int) -> None:
        """Tell the host what hop ``host:port`` agreed on; never fails the connection."""
        recorder = self._ssh_algorithm_recorder
        if recorder is None:
            return
        try:
            recorder.record(host, port, _agreed_algorithms(connection))
        except Exception:  # noqa: BLE001 - the record is evidence, not a condition
            logger.debug("could not record the SSH algorithms of %s:%s", host, port, exc_info=True)

    async def _connect_jump(self):
        """SSH session #1 to the bastion (design-dind-sandbox.md §11.1).

        Only bastion credentials are presented here; the device session runs
        tunneled with device credentials only. The bastion's host key is
        checked like the device's.
        """
        jump = self.jump_host
        assert jump is not None
        if asyncssh is None:  # pragma: no cover - scrapli[asyncssh] brings it
            raise ImportError("asyncssh is required for jump-host support")
        logger.info(f"Connecting to jump host {jump.host}:{jump.port} as {jump.username}")
        keys = await self._hop_keys(jump.host, jump.port, tunnel=None, timeout=self.connect_timeout)
        # Only pass client_keys when the inventory actually supplied one.
        # asyncssh reads an explicit None as "do not attempt public-key auth"
        # and clears agent_path with it, so passing None would silently strip
        # the agent and default-key auth the device hop still gets.
        key_options = (
            {"client_keys": [asyncssh.import_private_key(jump.private_key)]}
            if jump.private_key
            else {}
        )
        try:
            tunnel = await asyncssh.connect(
                jump.host,
                port=jump.port,
                username=jump.username or None,
                password=jump.password or None,
                **key_options,
                known_hosts=_known_hosts(jump.host, jump.port, keys),
                connect_timeout=self.connect_timeout,
            )
        except Exception as exc:
            refusal = await self._refusal(exc, jump.host, jump.port, keys, tunnel=None)
            if refusal is None:
                raise
            raise refusal from exc
        self._record_algorithms(tunnel, jump.host, jump.port)
        return tunnel

    async def _open_connection(self, *, timeout_transport: float | None = None):
        """Construct and open a scrapli connection (via the bastion when set)."""
        assert AsyncScrapli is not None  # Validated in __init__
        tunnel = None
        device_timeout = None
        if self.jump_host is not None:
            started = time.perf_counter()
            tunnel = await self._connect_jump()
            # One budget across both hops, as the asyncssh transport does.
            # Charging connect_timeout to the bastion login and again to
            # timeout_socket lets a slow bastion double the caller's deadline.
            device_timeout = max(self.connect_timeout - (time.perf_counter() - started), 1.0)
        try:
            keys = await self._hop_keys(
                self.host, self.port, tunnel=tunnel, timeout=device_timeout or self.connect_timeout
            )
            # scrapli's asyncssh transport merges transport_options["asyncssh"]
            # straight into asyncssh.connect(), after its own known_hosts=None:
            # the bastion session rides the device connection as its tunnel,
            # and the trusted keys replace scrapli's unchecked default.
            asyncssh_options: dict[str, Any] = {}
            if tunnel is not None:
                asyncssh_options["tunnel"] = tunnel
            known_hosts = _known_hosts(self.host, self.port, keys)
            if known_hosts is not None:
                asyncssh_options["known_hosts"] = known_hosts
        except BaseException:
            if tunnel is not None:
                with contextlib.suppress(Exception):
                    tunnel.close()
            raise
        params = self._get_connection_params(
            timeout_transport=timeout_transport, connect_timeout=device_timeout
        )
        if asyncssh_options:
            params["transport_options"] = {"asyncssh": asyncssh_options}
        connection = AsyncScrapli(**params)
        logger.info(f"Connecting to {self.host}:{self.port} as {self.username}")
        connect_start = time.perf_counter()
        try:
            try:
                await connection.open()
            except Exception as exc:
                refusal = await self._refusal(exc, self.host, self.port, keys, tunnel=tunnel)
                if refusal is None:
                    raise
                raise refusal from exc
        except BaseException:
            if tunnel is not None:
                with contextlib.suppress(Exception):
                    tunnel.close()
            raise
        if tunnel is not None:
            # Ride the tunnel on the connection so every close path tears
            # both down.
            setattr(connection, _JUMP_TUNNEL_ATTR, tunnel)
        # scrapli's asyncssh transport holds the asyncssh connection.
        self._record_algorithms(connection.transport.session, self.host, self.port)
        connect_time = (time.perf_counter() - connect_start) * 1000
        logger.info(f"Connected to {self.host} in {connect_time:.0f}ms")
        return connection

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

    @staticmethod
    def _result_from_response(command: str, response: Any) -> ScrapliResult:
        """Map one scrapli ``Response`` onto the SDK result shape."""
        return ScrapliTransport._result_from_responses(command, [response])

    @staticmethod
    def _result_from_responses(
        command: str, responses: list[Any], output: str | None = None
    ) -> ScrapliResult:
        """Map the scrapli ``Response``s of one command onto the SDK result shape.

        ``output`` replaces the responses' joined text when given.
        """
        if output is None:
            output = "\n".join(r.result for r in responses if r.result)
        latency_ms = sum(float(getattr(r, "elapsed_time", 0.0) or 0.0) for r in responses) * 1000
        cli_error = _detect_cli_error(output)
        if any(r.failed for r in responses) or cli_error:
            return ScrapliResult(
                command=command,
                output=output,
                exit_code=1,
                error=cli_error or "Command failed (scrapli failed_when match)",
                latency_ms=latency_ms,
            )
        return ScrapliResult(
            command=command,
            output=output,
            exit_code=0,
            latency_ms=latency_ms,
        )

    async def _send_exec_command(self, connection, command: str) -> ScrapliResult:
        """Run one command at privilege-exec; a CLI error pattern gives exit code 1."""
        try:
            if _is_startup_copy(command):
                result = await self._send_startup_copy(connection, command)
            else:
                result = self._result_from_response(command, await connection.send_command(command))
        except Exception as e:
            logger.error(f"Command on {self.host} failed: {type(e).__name__}")
            return ScrapliResult(command=command, output="", exit_code=-1, error=str(e))
        if result.exit_code == 0:
            logger.info(f"Command on {self.host} completed in {result.latency_ms:.0f}ms")
        else:
            logger.warning(f"Command on {self.host} returned a CLI error")
        return result

    async def _send_startup_copy(self, connection, command: str) -> ScrapliResult:
        """Run a copy to startup-config, answering its questions with Enter.

        Waiting for the prompt alone, as send_command does, runs into the
        command timeout while the device asks for the destination file name,
        so each read also stops at the questions such a copy asks. The output
        keeps neither the command echo nor the trailing prompt, like
        send_command's.
        """
        exec_prompt = connection.privilege_levels[connection.default_desired_privilege_level]
        responses = []
        channel_input = command
        while True:
            response = await connection.send_interactive(
                [(channel_input, exec_prompt.pattern)],
                interaction_complete_patterns=_COPY_QUESTION_PATTERNS,
            )
            responses.append(response)
            if not _COPY_QUESTION_AT_END.search(response.result or ""):
                break
            if len(responses) > _MAX_COPY_ANSWERS:
                raise RuntimeError("The device kept asking questions about the copy")
            channel_input = ""
        lines = "\n".join(r.result for r in responses if r.result).splitlines()
        if lines and lines[0].strip() == command.strip():
            lines.pop(0)
        if lines and re.search(exec_prompt.pattern, lines[-1], flags=re.I):
            lines.pop()
        return self._result_from_responses(command, responses, "\n".join(lines).strip())

    async def _send_config_block(self, connection, block: list[str]) -> list[ScrapliResult]:
        """Send one config block with send_configs; one result per line."""
        try:
            responses = await connection.send_configs(block, stop_on_failed=True)
        except Exception as e:
            logger.error(f"Config set on {self.host} failed: {type(e).__name__}")
            return [
                ScrapliResult(command=cmd, output="", exit_code=-1, error=str(e)) for cmd in block
            ]
        # MultiResponse is list-like: one Response per attempted config
        # command; with stop_on_failed a failure truncates it.
        results = [
            self._result_from_response(cmd, response)
            for cmd, response in zip(block, responses, strict=False)
        ]
        for line_number, result in enumerate(results, start=1):
            if result.exit_code != 0:
                logger.warning(f"Config line {line_number} of {len(block)} on {self.host} failed")
        if len(results) < len(block):
            reason = self._skip_reason()
            results.extend(_skipped(cmd, reason) for cmd in block[len(results) :])
        return results

    async def execute_commands(self, commands: list[str]) -> list[ScrapliResult]:
        """
        Execute multiple CLI commands via SSH.

        Opens a single SSH session and executes all commands sequentially.
        Automatically detects config mode vs show commands and uses the
        appropriate scrapli methods (send_configs vs send_command).

        Args:
            commands: List of CLI commands to execute

        Returns:
            List of ScrapliResult for each command
        """
        if not commands:
            return []

        results: list[ScrapliResult] = []
        connection = None

        try:
            connection = await self._open_connection()

            # Register connection for cancellation support
            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            if self._is_config_command_set(commands):
                # Config blocks and exec commands run in the order written.
                # After the first failure or a cancellation nothing more
                # runs, so a save command never stores a half-applied change.
                skip_reason: str | None = None
                for is_config, step in _plan_config_set(commands):
                    if skip_reason is not None:
                        results.extend(_skipped(cmd, skip_reason) for cmd in step)
                        continue
                    if self._cancellation_registry.is_cancelled(self.step_run_id):
                        results.append(
                            ScrapliResult(
                                command=step[0], output="", exit_code=-1, error="Cancelled"
                            )
                        )
                        results.extend(_skipped(cmd, _CANCELLED_ERROR) for cmd in step[1:])
                        skip_reason = _CANCELLED_ERROR
                        continue
                    if is_config:
                        step_results = await self._send_config_block(connection, step)
                    else:
                        step_results = [await self._send_exec_command(connection, step[0])]
                    results.extend(step_results)
                    if any(r.exit_code != 0 for r in step_results):
                        skip_reason = self._skip_reason()
            else:
                for command in commands:
                    if not command.strip():
                        continue
                    if self._cancellation_registry.is_cancelled(self.step_run_id):
                        results.append(
                            ScrapliResult(
                                command=command, output="", exit_code=-1, error="Cancelled"
                            )
                        )
                        break
                    results.append(await self._send_exec_command(connection, command))

        except ScrapliAuthenticationFailed as e:
            logger.error(f"Authentication failed to {self.host}: {e}")
            results = [
                ScrapliResult(
                    command=command,
                    output="",
                    exit_code=-1,
                    error=f"Authentication failed: {e}",
                )
                for command in commands
            ]
        except ScrapliTimeout as e:
            logger.error(f"Connection timeout to {self.host}: {e}")
            results = [
                ScrapliResult(
                    command=command,
                    output="",
                    exit_code=-1,
                    error=f"Connection timeout: {e}",
                )
                for command in commands
            ]
        except Exception as e:
            logger.error(f"SSH connection to {self.host}:{self.port} failed: {e}")
            results = [
                ScrapliResult(
                    command=command,
                    output="",
                    exit_code=-1,
                    error=f"SSH connection failed: {e}",
                )
                for command in commands
            ]
        finally:
            # Unregister from cancellation registry before disconnect
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            await _safe_close(connection)

        return results

    async def execute_command(self, command: str) -> ScrapliResult:
        """
        Execute a single CLI command via SSH.

        Args:
            command: CLI command to execute

        Returns:
            ScrapliResult with command output
        """
        results = await self.execute_commands([command])
        return (
            results[0]
            if results
            else ScrapliResult(
                command=command,
                output="",
                exit_code=-1,
                error="No result returned",
            )
        )

    async def _read_channel_chunk(self, connection) -> str | None:
        """One bounded channel read.

        Returns the decoded text (empty when nothing arrived within the poll
        window), or None on a hard read error (connection dropped, e.g. device
        reboot) so the caller can stop polling instead of spinning.
        """
        try:
            chunk = await connection.channel.read()
        except ScrapliTimeout:
            return ""
        except Exception as read_err:
            logger.warning(f"Error reading channel: {read_err}")
            return None
        if not chunk:
            return ""
        return chunk.decode(errors="replace") if isinstance(chunk, bytes) else str(chunk)

    async def execute_command_timing(
        self,
        command: str,
        *,
        read_timeout: float = 120.0,
        delay_factor: int = 2,
        expect: list[str] | None = None,
        answers: dict[str, str] | None = None,
        wait_for_patterns: list[str] | None = None,
    ) -> ScrapliResult:
        """
        Execute a command in timing mode for interactive/long-running commands.

        Writes the command on the raw channel and reads until quiet, a
        wait_for_pattern appears, or read_timeout — answering known prompts
        along the way. Same semantics as the netmiko transport's timing mode;
        ``delay_factor`` is accepted for surface parity but the poll cadence is
        fixed by the timing connection's transport timeout.

        Args:
            command: CLI command to execute
            read_timeout: Overall deadline for the timing session
            delay_factor: Accepted for parity with the netmiko transport
            expect: Optional list of expected patterns (for logging)
            answers: Map of prompt patterns to answers (auto-reply to known prompts)
            wait_for_patterns: If provided, keep reading until one of these
                patterns appears OR read_timeout is reached

        Returns:
            ScrapliResult with combined output
        """
        del delay_factor, expect  # surface parity with the netmiko transport
        connection = None
        start_time = time.perf_counter()
        combined_output = ""

        try:
            logger.info(f"Executing timing command on {self.host}")
            # Short per-read transport timeout so the loop below polls promptly.
            connection = await self._open_connection(timeout_transport=_TIMING_POLL_SECONDS)

            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            # Command boundary marker for the live view (same exposure as the
            # Phase A events' attrs.command labelling).
            await self._stream_push(f"$ {command}\n")
            connection.channel.write(command + "\n")

            pattern_found = False
            quiet_reads = 0
            answered_prompts: set[str] = set()
            prompt_check_start_pos = 0
            last_log_time = time.perf_counter()
            log_interval = 30.0

            while (time.perf_counter() - start_time) < read_timeout:
                if self._cancellation_registry.is_cancelled(self.step_run_id):
                    logger.info(f"Timing command cancelled for step {self.step_run_id}")
                    combined_output += "\n[CANCELLED]"
                    break

                chunk = await self._read_channel_chunk(connection)
                if chunk is None:
                    # Hard read error: connection is gone (expected on reboot).
                    break
                if chunk:
                    combined_output += chunk
                    await self._stream_push(chunk)
                    quiet_reads = 0
                else:
                    quiet_reads += 1

                # Answer known prompts, each at most once, scanning only output
                # not scanned yet (see _next_prompt), so a prompt echoed in
                # scrollback is not re-answered.
                while answers:
                    prompt, answer, prompt_check_start_pos = _next_prompt(
                        combined_output, prompt_check_start_pos, answers, answered_prompts
                    )
                    if prompt is None:
                        break
                    logger.info(f"Matched prompt '{prompt}', sending answer")
                    connection.channel.write(answer + "\n")

                if wait_for_patterns:
                    for pattern in wait_for_patterns:
                        if pattern.lower() in combined_output.lower():
                            logger.info(f"Found expected pattern: {pattern}")
                            pattern_found = True
                            break
                    if pattern_found:
                        break
                    current_time = time.perf_counter()
                    if current_time - last_log_time > log_interval:
                        elapsed = int(current_time - start_time)
                        logger.info(
                            f"Still waiting for patterns after {elapsed}s. "
                            f"Output length: {len(combined_output)}"
                        )
                        last_log_time = current_time
                elif quiet_reads >= _QUIET_READS_DONE:
                    # No target pattern: the command is settled once the
                    # channel stays quiet (send_command_timing semantics).
                    break

            if wait_for_patterns and not pattern_found:
                logger.warning(
                    f"Timeout waiting for patterns after {read_timeout}s. "
                    f"Output length: {len(combined_output)}"
                )

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            cli_error = _detect_cli_error(combined_output)
            if cli_error:
                return ScrapliResult(
                    command=command,
                    output=combined_output,
                    exit_code=1,
                    error=cli_error,
                    latency_ms=elapsed_ms,
                )

            return ScrapliResult(
                command=command,
                output=combined_output,
                exit_code=0,
                latency_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Timing command failed on {self.host}: {type(e).__name__}")
            return ScrapliResult(
                command=command,
                output=combined_output,
                exit_code=-1,
                error=str(e),
                latency_ms=elapsed_ms,
            )
        finally:
            await self._stream_flush()
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            await _safe_close(connection)

    async def scp_put(
        self,
        *,
        local_path: str,
        dest_fs: str,
        dest_filename: str,
        overwrite: bool = False,
    ) -> dict:
        """SCP staging is not supported by the scrapli transport.

        Netmiko's file-transfer machinery has no scrapli equivalent; staging
        steps should run over the netmiko transport (the default).
        """
        raise NotImplementedError(
            "scp_put is not supported by the scrapli transport; "
            "use the netmiko transport (device access_config.ssh.transport) for staging steps"
        )

    async def http_transfer(
        self,
        *,
        url: str,
        dest_fs: str,
        dest_filename: str,
        timeout_seconds: int = 3600,
    ) -> dict:
        """HTTP copy staging is not supported by the scrapli transport.

        The interactive ``copy <url> <fs>`` dialogue is implemented in the
        netmiko transport only; staging steps should run over netmiko.
        """
        raise NotImplementedError(
            "http_transfer is not supported by the scrapli transport; "
            "use the netmiko transport (device access_config.ssh.transport) for staging steps"
        )
