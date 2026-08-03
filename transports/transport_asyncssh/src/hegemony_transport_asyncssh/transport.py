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

from hegemony_step_sdk import ConnectionCancellationRegistry, DeviceConnectionSpec

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


class AsyncSSHTransport:
    """SSH exec-channel transport for server-like devices using asyncssh."""

    #: check_type-style id claimed under the hegemony.device_transports group.
    transport_id = "asyncssh"

    def __init__(
        self,
        spec: DeviceConnectionSpec,
        *,
        cancellation_registry: ConnectionCancellationRegistry | None = None,
        step_run_id: str | None = None,
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

        self.username = spec.username or None
        self.password = spec.password

        # Validate username is provided (fail fast)
        if not self.username:
            raise ValueError("SSH username required (device access_config.ssh.username_ref)")

        self.platform = spec.platform
        self.connect_timeout = spec.connect_timeout
        self.command_timeout = spec.command_timeout
        self.jump_host = spec.jump_host

    async def _connect_jump(self):
        """Open SSH session #1 to the bastion (design-dind-sandbox.md §11.1).

        Only bastion credentials are presented here — device credentials stay
        confined to the tunneled device session, and vice versa.
        """
        jump = self.jump_host
        assert jump is not None
        logger.info(f"Connecting to jump host {jump.host}:{jump.port} as {jump.username}")
        client_keys = None
        if jump.private_key:
            client_keys = [asyncssh.import_private_key(jump.private_key)]
        return await asyncssh.connect(
            jump.host,
            port=jump.port,
            username=jump.username or None,
            password=jump.password or None,
            client_keys=client_keys,
            # Deliberately unpinned, matching the device hop below: the
            # platform's trust model is that device inventory (which supplies
            # the bastion endpoint and credentials) is the source of truth.
            # Host-key pinning would land on both hops together via a
            # host_key_policy field once the ssh section grows one.
            known_hosts=None,
            connect_timeout=self.connect_timeout,
        )

    async def _connect(self):
        """Open an asyncssh connection from the spec (via the bastion when set)."""
        logger.info(f"Connecting to {self.host}:{self.port} as {self.username}")
        connect_start = time.perf_counter()
        tunnel = None
        if self.jump_host is not None:
            tunnel = await self._connect_jump()
        # One connect budget across both hops: the device hop gets whatever
        # the bastion hop left of connect_timeout (floored so a slow bastion
        # still surfaces as a device-connect timeout, not a zero timeout).
        remaining = self.connect_timeout - (time.perf_counter() - connect_start)
        device_timeout = max(remaining, 1.0) if tunnel is not None else self.connect_timeout
        try:
            connection = await asyncssh.connect(
                self.host,
                port=self.port,
                username=self.username,
                # Empty password falls back to key/agent auth.
                password=self.password or None,
                known_hosts=None,
                connect_timeout=device_timeout,
                # SSH session #2 runs inside a direct-tcpip channel of session
                # #1: end-to-end encrypted, the bastion never sees credentials
                # or content. () = asyncssh's "no tunnel" sentinel.
                tunnel=tunnel if tunnel is not None else (),
            )
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

            for command in commands:
                if not command.strip():
                    continue
                if self._cancellation_registry.is_cancelled(self.step_run_id):
                    results.append(
                        ExecResult(command=command, output="", exit_code=-1, error="Cancelled")
                    )
                    break
                start = time.perf_counter()
                try:
                    completed = await asyncio.wait_for(
                        connection.run(command, check=False),
                        timeout=self.command_timeout,
                    )
                    latency_ms = (time.perf_counter() - start) * 1000
                    result = self._result_from_completed(command, completed, latency_ms)
                    results.append(result)
                    if result.exit_code == 0:
                        logger.info(f"Command '{command}' completed in {latency_ms:.0f}ms")
                    else:
                        logger.warning(
                            f"Command '{command}' exited {result.exit_code}: {result.error}"
                        )
                except TimeoutError:
                    latency_ms = (time.perf_counter() - start) * 1000
                    results.append(
                        ExecResult(
                            command=command,
                            output="",
                            exit_code=-1,
                            error=f"Command timeout after {self.command_timeout}s",
                            latency_ms=latency_ms,
                        )
                    )
                    logger.error(f"Command '{command}' timed out")
                except Exception as e:
                    latency_ms = (time.perf_counter() - start) * 1000
                    results.append(
                        ExecResult(
                            command=command,
                            output="",
                            exit_code=-1,
                            error=str(e),
                            latency_ms=latency_ms,
                        )
                    )
                    logger.error(f"Command '{command}' failed: {e}")

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
            logger.info(f"Executing timing command on {self.host}: {command[:50]}...")
            connection = await self._connect()

            if self.step_run_id:
                self._cancellation_registry.register(self.step_run_id, connection)

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
                    quiet_reads = 0
                else:
                    quiet_reads += 1

                # Answer known prompts, each at most once, scanning only new output.
                if answers:
                    new_output_lower = combined_output[prompt_check_start_pos:].lower()
                    for prompt_pattern, answer in answers.items():
                        pattern_lower = prompt_pattern.lower()
                        if pattern_lower in answered_prompts:
                            continue
                        if pattern_lower in new_output_lower:
                            logger.info(f"Matched prompt '{prompt_pattern}', sending answer")
                            answered_prompts.add(pattern_lower)
                            process.stdin.write(answer + "\n")
                            break
                    prompt_check_start_pos = len(combined_output)

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
                    f"Output so far: {combined_output[-500:] if combined_output else '(empty)'}"
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
            logger.error(f"Timing command failed on {self.host}: {e}")
            return ExecResult(
                command=command,
                output=combined_output,
                exit_code=-1,
                error=str(e),
                latency_ms=elapsed_ms,
            )
        finally:
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
                logger.error(f"HTTP transfer failed: {output}")

            return {
                "transferred": transferred,
                "output": output,
                "elapsed_ms": elapsed_ms,
            }
        except Exception as e:
            logger.error(f"HTTP transfer on {self.host} failed: {e}")
            raise
        finally:
            if self.step_run_id and connection:
                self._cancellation_registry.unregister(self.step_run_id, connection)
            await _close_connection(connection)
