# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""AsyncSSH device transport (exec channels over SSH).

The ``asyncssh`` implementation of the SDK ``Transport`` I/O surface,
registered under the ``hegemony.device_transports`` entry-point group. Aimed at
server-like devices (Linux hosts, whitebox NOS, appliances with a real shell):
each command runs on its own SSH exec channel and reports a genuine exit code,
instead of the prompt-scraping network-CLI model netmiko/scrapli implement.

Runs natively async — no thread pool — so step cancellation propagates as
plain coroutine cancellation; the injected cancellation registry is still
honored at safe points for parity with the blocking transports. The host
constructs this transport from a resolved :class:`DeviceConnectionSpec`, so
this wheel never touches the platform's secret pipeline or settings.
"""

import asyncio
import contextlib
import logging
import os
import posixpath
import shlex
import time
from dataclasses import dataclass
from typing import Any

from hegemony_step_sdk import (
    ConnectionCancellationRegistry,
    DeviceConnectionSpec,
    HostKeyRejectedError,
    HostKeyVerifier,
    TransportOutputSink,
)

try:
    import asyncssh
except ImportError:
    # AsyncSSH unavailable - provide a stub for type checking
    asyncssh: Any = None

logger = logging.getLogger(__name__)


class _NullCancellationRegistry:
    """No-op cancellation registry used when the host tracks no cancellation."""

    def register(self, key: str | None, connection: Any) -> None:  # noqa: D102
        pass

    def unregister(self, key: str | None, connection: Any) -> None:  # noqa: D102
        pass

    def is_cancelled(self, key: str | None) -> bool:  # noqa: D102
        return False


_NULL_CANCELLATION = _NullCancellationRegistry()


@dataclass
class ExecResult:
    """Result from one exec-channel command (SDK ``CommandResult`` shape)."""

    command: str
    output: str
    exit_code: int
    error: str | None = None
    latency_ms: float = 0.0


#: Poll window for timing-mode PTY reads; sets the cadence for prompt answers,
#: wait-for-pattern checks, and cancellation checks.
_TIMING_POLL_SECONDS = 2.0

#: In timing mode without wait_for_patterns, the command is considered settled
#: after this many consecutive empty reads (matches the CLI transports).
_QUIET_READS_DONE = 3


#: Attribute under which the bastion connection rides its device connection,
#: so every existing close path tears the tunnel down with the session.
_JUMP_TUNNEL_ATTR = "_hegemony_jump_tunnel"

#: First lines that make a command list a configuration session (same as the
#: CLI transports).
_CONFIG_ENTER_COMMANDS = ("configure terminal", "conf t", "config t")

#: Error of a result for a command not run because an earlier one failed.
_SKIPPED_ERROR = "Skipped: earlier command failed"

#: Error of a result for a command not run because the run was cancelled.
_CANCELLED_ERROR = "Skipped: the run was cancelled"


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


def _is_config_session(commands: list[str]) -> bool:
    """True when the first non-blank command enters configuration mode."""
    first = next((cmd.strip().lower() for cmd in commands if cmd.strip()), "")
    return first in _CONFIG_ENTER_COMMANDS


def _skipped(command: str, reason: str) -> ExecResult:
    """Result for a command not run, with ``reason`` as its error."""
    return ExecResult(command=command, output="", exit_code=-1, error=reason)


async def _close_connection(connection) -> None:
    """Close an asyncssh connection (and its jump tunnel), suppressing errors.

    ``close()`` only starts the shutdown; awaiting ``wait_closed()`` lets both
    sessions finish tearing down instead of racing the event loop's end.
    """
    if not connection:
        return
    with contextlib.suppress(Exception):
        connection.close()
    with contextlib.suppress(Exception):
        await connection.wait_closed()
    tunnel = getattr(connection, _JUMP_TUNNEL_ATTR, None)
    if tunnel is not None:
        with contextlib.suppress(Exception):
            tunnel.close()
        with contextlib.suppress(Exception):
            await tunnel.wait_closed()


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


class AsyncSSHTransport:
    """SSH exec-channel transport for server-like devices using asyncssh."""

    #: check_type-style id claimed under the hegemony.device_transports group.
    transport_id = "asyncssh"

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
        """Initialize the asyncssh transport from a resolved connection spec.

        Args:
            spec: Fully-resolved connection parameters (credentials already
                resolved by the host). ``enable_secret`` is ignored — exec
                channels have no enable mode; use sudo in the command itself.
            cancellation_registry: Host registry checked at safe points; a
                no-op registry is used when None. (Cancellation also arrives
                naturally as coroutine cancellation on this transport.)
            step_run_id: Key under which connections register for cancellation.
            output_sink: Optional host-built sink for live output streaming.
                Only PTY timing-mode commands stream; the exec-channel path
                (``execute_commands``) deliberately stays buffered — it batches
                commands whose text may carry credentials (config pushes), and
                streaming would require per-command markers that echo them.
            host_key_verifier: The host's SSH host-key trust. Each hop accepts
                only the keys it names. Without one the transport refuses to
                connect; it never connects unchecked on its own. A verifier that
                answers None for a host (checks switched off) is the opt-out.
        """
        if asyncssh is None:
            raise ImportError(
                "asyncssh is required for the asyncssh transport. "
                "Install with: pip install asyncssh"
            )

        self.host = spec.host
        self.port = spec.port
        self.step_run_id = step_run_id
        self._cancellation_registry: ConnectionCancellationRegistry = (
            cancellation_registry if cancellation_registry is not None else _NULL_CANCELLATION
        )
        self._output_sink = output_sink
        #: Duck-typed flag handlers read to skip duplicate completed-output
        #: emissions for paths this transport streams live (timing mode only).
        self.streams_timing_output = output_sink is not None

        self.username = spec.username or None
        self.password = spec.password

        # Validate username is provided (fail fast)
        if not self.username:
            raise ValueError("SSH username required (device access_config.ssh.username_ref)")

        self.platform = spec.platform
        self.connect_timeout = spec.connect_timeout
        self.command_timeout = spec.command_timeout
        self.jump_host = spec.jump_host
        self._host_key_verifier = host_key_verifier

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

    async def _connect_jump(self):
        """Open SSH session #1 to the bastion (design-dind-sandbox.md §11.1).

        Only bastion credentials are presented here — device credentials stay
        confined to the tunneled device session, and vice versa. The bastion's
        host key is checked like the device's.
        """
        jump = self.jump_host
        assert jump is not None
        logger.info(f"Connecting to jump host {jump.host}:{jump.port} as {jump.username}")
        keys = await self._hop_keys(jump.host, jump.port, tunnel=None, timeout=self.connect_timeout)
        # Only pass client_keys when the inventory actually supplied one.
        # asyncssh reads an explicit None as "do not attempt public-key auth"
        # and clears agent_path with it, so passing None would silently strip
        # the agent and default-key auth the device hop below still gets.
        key_options = (
            {"client_keys": [asyncssh.import_private_key(jump.private_key)]}
            if jump.private_key
            else {}
        )
        try:
            return await asyncssh.connect(
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

    async def _connect(self):
        """Open an asyncssh connection from the spec (via the bastion when set)."""
        logger.info(f"Connecting to {self.host}:{self.port} as {self.username}")
        connect_start = time.perf_counter()
        tunnel = None
        if self.jump_host is not None:
            tunnel = await self._connect_jump()
        try:
            keys = await self._hop_keys(
                self.host, self.port, tunnel=tunnel, timeout=self.connect_timeout
            )
            # One connect budget across both hops: the device hop gets
            # whatever the bastion hop left of connect_timeout (floored so a
            # slow bastion still surfaces as a device-connect timeout, not a
            # zero timeout).
            remaining = self.connect_timeout - (time.perf_counter() - connect_start)
            device_timeout = max(remaining, 1.0) if tunnel is not None else self.connect_timeout
            try:
                connection = await asyncssh.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    # Empty password falls back to key/agent auth.
                    password=self.password or None,
                    known_hosts=_known_hosts(self.host, self.port, keys),
                    connect_timeout=device_timeout,
                    # SSH session #2 runs inside a direct-tcpip channel of
                    # session #1: end-to-end encrypted, the bastion never sees
                    # credentials or content. () = asyncssh's "no tunnel"
                    # sentinel.
                    tunnel=tunnel if tunnel is not None else (),
                )
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
            # Ride the tunnel on the connection so every close path (finally
            # blocks, cancellation registry force-close) tears both down.
            setattr(connection, _JUMP_TUNNEL_ATTR, tunnel)
        connect_time = (time.perf_counter() - connect_start) * 1000
        logger.info(f"Connected to {self.host} in {connect_time:.0f}ms")
        return connection

    def _skip_reason(self) -> str:
        """Why the commands after a failure are not run.

        Cancelling the run closes the connection, so the command running then
        fails; the rest are skipped because of the cancellation, not that
        failure.
        """
        if self._cancellation_registry.is_cancelled(self.step_run_id):
            return _CANCELLED_ERROR
        return _SKIPPED_ERROR

    @staticmethod
    def _result_from_completed(command: str, completed: Any, latency_ms: float) -> ExecResult:
        """Map one asyncssh completed process onto the SDK result shape."""
        stdout = str(completed.stdout or "")
        stderr = str(completed.stderr or "")
        exit_code = completed.exit_status if completed.exit_status is not None else -1
        output = stdout
        if stderr:
            output = f"{output}\n{stderr}" if output else stderr
        error = None
        if exit_code != 0:
            error = stderr.strip() or f"Command exited with status {exit_code}"
        return ExecResult(
            command=command,
            output=output,
            exit_code=exit_code,
            error=error,
            latency_ms=latency_ms,
        )

    async def execute_commands(self, commands: list[str]) -> list[ExecResult]:
        """
        Execute multiple commands over one SSH connection, one exec channel each.

        In a configuration session (the first non-blank command is
        'configure terminal' or an abbreviation) nothing runs after the first
        failure or a cancellation, as on the CLI transports: the commands left
        are recorded as skipped, so a later save never stores a change that
        failed part way. Otherwise every command runs.

        Args:
            commands: List of commands to execute

        Returns:
            List of ExecResult for each command
        """
        if not commands:
            return []

        results: list[ExecResult] = []
        connection = None
        try:
            connection = await self._connect()

            # Register connection for cancellation support
            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            config_session = _is_config_session(commands)
            skip_reason: str | None = None
            for command in commands:
                if not command.strip():
                    continue
                if skip_reason is not None:
                    results.append(_skipped(command, skip_reason))
                    continue
                if self._cancellation_registry.is_cancelled(self.step_run_id):
                    results.append(
                        ExecResult(command=command, output="", exit_code=-1, error="Cancelled")
                    )
                    if not config_session:
                        break
                    skip_reason = _CANCELLED_ERROR
                    continue
                start = time.perf_counter()
                try:
                    completed = await asyncio.wait_for(
                        connection.run(command, check=False),
                        timeout=self.command_timeout,
                    )
                    latency_ms = (time.perf_counter() - start) * 1000
                    result = self._result_from_completed(command, completed, latency_ms)
                    if result.exit_code == 0:
                        logger.info(f"Command on {self.host} completed in {latency_ms:.0f}ms")
                    else:
                        logger.warning(f"Command on {self.host} exited {result.exit_code}")
                except TimeoutError:
                    latency_ms = (time.perf_counter() - start) * 1000
                    result = ExecResult(
                        command=command,
                        output="",
                        exit_code=-1,
                        error=f"Command timeout after {self.command_timeout}s",
                        latency_ms=latency_ms,
                    )
                    logger.error(f"Command on {self.host} timed out")
                except Exception as e:
                    latency_ms = (time.perf_counter() - start) * 1000
                    result = ExecResult(
                        command=command,
                        output="",
                        exit_code=-1,
                        error=str(e),
                        latency_ms=latency_ms,
                    )
                    logger.error(f"Command on {self.host} failed: {type(e).__name__}")
                results.append(result)
                if config_session and result.exit_code != 0:
                    skip_reason = self._skip_reason()

        except asyncssh.PermissionDenied as e:
            logger.error(f"Authentication failed to {self.host}: {e}")
            results = [
                ExecResult(
                    command=command,
                    output="",
                    exit_code=-1,
                    error=f"Authentication failed: {e}",
                )
                for command in commands
            ]
        except (OSError, TimeoutError) as e:
            logger.error(f"Connection to {self.host}:{self.port} failed: {e}")
            results = [
                ExecResult(
                    command=command,
                    output="",
                    exit_code=-1,
                    error=f"SSH connection failed: {e}",
                )
                for command in commands
            ]
        except Exception as e:
            logger.error(f"SSH connection to {self.host}:{self.port} failed: {e}")
            results = [
                ExecResult(
                    command=command,
                    output="",
                    exit_code=-1,
                    error=f"SSH connection failed: {e}",
                )
                for command in commands
            ]
        finally:
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            await _close_connection(connection)

        return results

    async def execute_command(self, command: str) -> ExecResult:
        """
        Execute a single command via SSH.

        Args:
            command: Command to execute

        Returns:
            ExecResult with command output
        """
        results = await self.execute_commands([command])
        return (
            results[0]
            if results
            else ExecResult(
                command=command,
                output="",
                exit_code=-1,
                error="No result returned",
            )
        )

    @staticmethod
    async def _read_pty_chunk(process) -> str | None:
        """One bounded PTY read.

        Returns the decoded text (empty when nothing arrived within the poll
        window), or None on a hard read error (channel lost) so the caller can
        stop polling instead of spinning until the deadline.
        """
        try:
            chunk = await asyncio.wait_for(process.stdout.read(4096), timeout=_TIMING_POLL_SECONDS)
        except TimeoutError:
            return ""
        except Exception as read_err:
            logger.warning(f"Error reading PTY: {read_err}")
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
    ) -> ExecResult:
        """
        Execute a command on a PTY for interactive/long-running commands.

        Reads until the process exits, the channel stays quiet, a
        wait_for_pattern appears, or read_timeout — answering known prompts
        along the way. Same semantics as the CLI transports' timing mode;
        ``delay_factor`` is accepted for surface parity.

        Args:
            command: Command to execute
            read_timeout: Overall deadline for the timing session
            delay_factor: Accepted for parity with the netmiko transport
            expect: Optional list of expected patterns (for logging)
            answers: Map of prompt patterns to answers (auto-reply to known prompts)
            wait_for_patterns: If provided, keep reading until one of these
                patterns appears OR read_timeout is reached

        Returns:
            ExecResult with combined output
        """
        del delay_factor, expect  # surface parity with the netmiko transport
        connection = None
        process = None
        start_time = time.perf_counter()
        combined_output = ""

        try:
            logger.info(f"Executing timing command on {self.host}")
            connection = await self._connect()

            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            # Command boundary marker for the live view (same exposure as the
            # Phase A events' attrs.command labelling).
            await self._stream_push(f"$ {command}\n")
            # A PTY so the remote side prompts interactively (sudo, confirm, …).
            process = await connection.create_process(command, term_type="vt100")

            pattern_found = False
            quiet_reads = 0
            answered_prompts: set[str] = set()
            prompt_check_start_pos = 0

            while (time.perf_counter() - start_time) < read_timeout:
                if self._cancellation_registry.is_cancelled(self.step_run_id):
                    logger.info(f"Timing command cancelled for step {self.step_run_id}")
                    combined_output += "\n[CANCELLED]"
                    break

                chunk = await self._read_pty_chunk(process)
                if chunk is None:
                    # Hard read error: the channel is gone.
                    break
                if chunk:
                    combined_output += chunk
                    await self._stream_push(chunk)
                    quiet_reads = 0
                else:
                    quiet_reads += 1

                # Answer known prompts, each at most once, scanning only output
                # not scanned yet (see _next_prompt).
                while answers:
                    prompt, answer, prompt_check_start_pos = _next_prompt(
                        combined_output, prompt_check_start_pos, answers, answered_prompts
                    )
                    if prompt is None:
                        break
                    logger.info(f"Matched prompt '{prompt}', sending answer")
                    process.stdin.write(answer + "\n")

                if wait_for_patterns:
                    for pattern in wait_for_patterns:
                        if pattern.lower() in combined_output.lower():
                            logger.info(f"Found expected pattern: {pattern}")
                            pattern_found = True
                            break
                    if pattern_found:
                        break

                # Process ended and the channel is drained — nothing more to read.
                if process.exit_status is not None and not chunk:
                    break

                if not wait_for_patterns and quiet_reads >= _QUIET_READS_DONE:
                    break

            if wait_for_patterns and not pattern_found:
                logger.warning(
                    f"Timeout waiting for patterns after {read_timeout}s. "
                    f"Output length: {len(combined_output)}"
                )

            elapsed_ms = (time.perf_counter() - start_time) * 1000

            exit_status = process.exit_status
            if exit_status is not None and exit_status != 0:
                return ExecResult(
                    command=command,
                    output=combined_output,
                    exit_code=exit_status,
                    error=f"Command exited with status {exit_status}",
                    latency_ms=elapsed_ms,
                )

            return ExecResult(
                command=command,
                output=combined_output,
                exit_code=0,
                latency_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            logger.error(f"Timing command failed on {self.host}: {type(e).__name__}")
            return ExecResult(
                command=command,
                output=combined_output,
                exit_code=-1,
                error=str(e),
                latency_ms=elapsed_ms,
            )
        finally:
            await self._stream_flush()
            if process is not None:
                with contextlib.suppress(Exception):
                    process.terminate()
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            await _close_connection(connection)

    @staticmethod
    def _dest_path(dest_fs: str, dest_filename: str) -> str:
        """Join a destination directory and filename (server-style paths).

        ``dest_fs`` is a directory here (e.g. ``/var/tmp``), not a network-OS
        filesystem token like ``flash:`` — those devices use the CLI transports.
        """
        return posixpath.join(dest_fs, dest_filename) if dest_fs else dest_filename

    async def scp_put(
        self,
        *,
        local_path: str,
        dest_fs: str,
        dest_filename: str,
        overwrite: bool = False,
    ) -> dict:
        """
        Transfer a file to the remote host over SFTP.

        Args:
            local_path: Path to local file
            dest_fs: Destination directory on the remote host
            dest_filename: Filename on the remote host
            overwrite: Whether to overwrite if exists

        Returns:
            Dict with: transferred, verified, exists, elapsed_ms
        """
        dest = self._dest_path(dest_fs, dest_filename)
        connection = None
        start_time = time.perf_counter()
        try:
            logger.info(f"SFTP upload to {self.host}: {local_path} -> {dest}")
            connection = await self._connect()
            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            async with connection.start_sftp_client() as sftp:
                exists = await sftp.exists(dest)
                if exists and not overwrite:
                    return {
                        "transferred": False,
                        "verified": False,
                        "exists": True,
                        "elapsed_ms": (time.perf_counter() - start_time) * 1000,
                    }

                await sftp.put(local_path, dest)

                remote_size = (await sftp.stat(dest)).size
                verified = remote_size == os.path.getsize(local_path)

            return {
                "transferred": True,
                "verified": verified,
                "exists": True,
                "elapsed_ms": (time.perf_counter() - start_time) * 1000,
            }
        except Exception as e:
            logger.error(f"SFTP transfer to {self.host} failed: {e}")
            raise
        finally:
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            await _close_connection(connection)

    async def http_transfer(
        self,
        *,
        url: str,
        dest_fs: str,
        dest_filename: str,
        timeout_seconds: int = 3600,
    ) -> dict:
        """
        Download a URL to the remote host by running curl there.

        The remote host pulls the file directly (mirrors the CLI transports'
        ``copy <url> <fs>`` semantics); requires curl on the remote host.

        Args:
            url: Presigned HTTP/HTTPS URL to the file
            dest_fs: Destination directory on the remote host
            dest_filename: Filename on the remote host
            timeout_seconds: Maximum time to wait for transfer completion

        Returns:
            Dict with: transferred, output, elapsed_ms
        """
        dest = self._dest_path(dest_fs, dest_filename)
        command = (
            f"curl -fsSL --max-time {int(timeout_seconds)} "
            f"-o {shlex.quote(dest)} {shlex.quote(url)}"
        )
        connection = None
        start_time = time.perf_counter()
        try:
            logger.info(f"HTTP transfer on {self.host}: {dest}")
            connection = await self._connect()
            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

            completed = await asyncio.wait_for(
                connection.run(command, check=False),
                timeout=timeout_seconds + 30,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            stdout = str(completed.stdout or "")
            stderr = str(completed.stderr or "")
            output = f"{stdout}\n{stderr}".strip()
            transferred = completed.exit_status == 0
            if not transferred:
                logger.error(
                    f"HTTP transfer on {self.host} failed: curl exited {completed.exit_status}"
                )

            return {
                "transferred": transferred,
                "output": output,
                "elapsed_ms": elapsed_ms,
            }
        except Exception as e:
            logger.error(f"HTTP transfer on {self.host} failed: {type(e).__name__}")
            raise
        finally:
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            await _close_connection(connection)
