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

import contextlib
import logging
import time
from dataclasses import dataclass
from typing import Any

from hegemony_step_sdk import (
    ConnectionCancellationRegistry,
    DeviceConnectionSpec,
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


class _NullCancellationRegistry:
    """No-op cancellation registry used when the host tracks no cancellation."""

    def register(self, key: str | None, connection: Any) -> None:  # noqa: D102
        pass

    def unregister(self, key: str | None, connection: Any) -> None:  # noqa: D102
        pass

    def is_cancelled(self, key: str | None) -> bool:  # noqa: D102
        return False


_NULL_CANCELLATION = _NullCancellationRegistry()

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


class ScrapliTransport:
    """SSH transport client for network device CLI access using scrapli."""

    #: check_type-style id claimed under the hegemony.device_transports group.
    transport_id = "scrapli"

    #: Feature flag the host checks before passing ``output_sink`` (Phase B
    #: live streaming): hosts that predate sinks never pass the kwarg, and
    #: hosts that support them skip wheels without this attribute.
    supports_output_sink = True

    def __init__(
        self,
        spec: DeviceConnectionSpec,
        *,
        cancellation_registry: ConnectionCancellationRegistry | None = None,
        step_run_id: str | None = None,
        output_sink: TransportOutputSink | None = None,
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

    async def _connect_jump(self):
        """SSH session #1 to the bastion (design-dind-sandbox.md §11.1).

        Only bastion credentials are presented here; the device session runs
        tunneled with device credentials only. Host keys are not pinned —
        same trust model as the device hop (inventory is the source of truth).
        """
        jump = self.jump_host
        assert jump is not None
        if asyncssh is None:  # pragma: no cover - scrapli[asyncssh] brings it
            raise ImportError("asyncssh is required for jump-host support")
        logger.info(f"Connecting to jump host {jump.host}:{jump.port} as {jump.username}")
        # Only pass client_keys when the inventory actually supplied one.
        # asyncssh reads an explicit None as "do not attempt public-key auth"
        # and clears agent_path with it, so passing None would silently strip
        # the agent and default-key auth the device hop still gets.
        key_options = (
            {"client_keys": [asyncssh.import_private_key(jump.private_key)]}
            if jump.private_key
            else {}
        )
        return await asyncssh.connect(
            jump.host,
            port=jump.port,
            username=jump.username or None,
            password=jump.password or None,
            **key_options,
            known_hosts=None,
            connect_timeout=self.connect_timeout,
        )

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
        params = self._get_connection_params(
            timeout_transport=timeout_transport, connect_timeout=device_timeout
        )
        if tunnel is not None:
            # scrapli's asyncssh transport merges transport_options["asyncssh"]
            # straight into asyncssh.connect(), so the bastion session rides
            # the device connection as its tunnel.
            params["transport_options"] = {"asyncssh": {"tunnel": tunnel}}
        connection = AsyncScrapli(**params)
        logger.info(f"Connecting to {self.host}:{self.port} as {self.username}")
        connect_start = time.perf_counter()
        try:
            await connection.open()
        except BaseException:
            if tunnel is not None:
                with contextlib.suppress(Exception):
                    tunnel.close()
            raise
        if tunnel is not None:
            # Ride the tunnel on the connection so every close path tears
            # both down.
            setattr(connection, _JUMP_TUNNEL_ATTR, tunnel)
        connect_time = (time.perf_counter() - connect_start) * 1000
        logger.info(f"Connected to {self.host} in {connect_time:.0f}ms")
        return connection

    def _is_config_command_set(self, commands: list[str]) -> bool:
        """
        Check if commands are a configuration command set.

        Config commands start with 'configure terminal' and end with 'end' or 'exit'.
        """
        if not commands:
            return False
        first_cmd = commands[0].strip().lower()
        return first_cmd in ("configure terminal", "conf t", "config t")

    @staticmethod
    def _result_from_response(command: str, response: Any) -> ScrapliResult:
        """Map one scrapli ``Response`` onto the SDK result shape."""
        output = response.result if response.result is not None else ""
        latency_ms = float(getattr(response, "elapsed_time", 0.0) or 0.0) * 1000
        cli_error = _detect_cli_error(output)
        if response.failed or cli_error:
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

    def _split_config_set(self, commands: list[str]) -> tuple[list[str], list[str]]:
        """Split a config command set into config commands and post commands.

        Strips the 'configure terminal' / 'end' framing (scrapli's send_configs
        enters and leaves config mode itself); 'write memory'-style commands and
        anything outside config mode run afterwards at privilege-exec.
        """
        config_commands: list[str] = []
        post_commands: list[str] = []
        in_config = False
        for cmd in commands:
            cmd_lower = cmd.strip().lower()
            if not cmd_lower:
                continue
            if cmd_lower in ("configure terminal", "conf t", "config t"):
                in_config = True
            elif cmd_lower in ("end", "exit") and in_config:
                in_config = False
            elif cmd_lower.startswith("write") or cmd_lower.startswith("copy run"):
                post_commands.append(cmd)
            elif in_config:
                config_commands.append(cmd)
            else:
                post_commands.append(cmd)
        return config_commands, post_commands

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
                config_commands, post_commands = self._split_config_set(commands)

                config_failed = False
                if config_commands:
                    responses = await connection.send_configs(config_commands, stop_on_failed=True)
                    # MultiResponse is list-like: one Response per attempted
                    # config command; with stop_on_failed a failure truncates it.
                    for cmd, response in zip(config_commands, responses, strict=False):
                        result = self._result_from_response(cmd, response)
                        results.append(result)
                        if result.exit_code != 0:
                            config_failed = True
                            logger.warning(f"Config command '{cmd}' failed: {result.error}")
                    unattempted = config_commands[len(list(responses)) :]
                    for cmd in unattempted:
                        config_failed = True
                        results.append(
                            ScrapliResult(
                                command=cmd,
                                output="",
                                exit_code=-1,
                                error="Skipped: earlier config command failed",
                            )
                        )

                # Post commands (write memory, ...) only run on config success,
                # mirroring the netmiko transport's semantics.
                if config_failed:
                    logger.warning("Skipping post-config commands due to config failure")
                else:
                    for cmd in post_commands:
                        if self._cancellation_registry.is_cancelled(self.step_run_id):
                            results.append(
                                ScrapliResult(
                                    command=cmd, output="", exit_code=-1, error="Cancelled"
                                )
                            )
                            break
                        response = await connection.send_command(cmd)
                        results.append(self._result_from_response(cmd, response))
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
                    try:
                        response = await connection.send_command(command)
                        result = self._result_from_response(command, response)
                        results.append(result)
                        if result.exit_code == 0:
                            logger.info(
                                f"Command '{command}' completed in {result.latency_ms:.0f}ms"
                            )
                        else:
                            logger.warning(
                                f"Command '{command}' returned CLI error: {result.error}"
                            )
                    except Exception as e:
                        results.append(
                            ScrapliResult(
                                command=command,
                                output="",
                                exit_code=-1,
                                error=str(e),
                            )
                        )
                        logger.error(f"Command '{command}' failed: {e}")

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
            logger.info(f"Executing timing command on {self.host}: {command[:50]}...")
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

                # Answer known prompts, each at most once, scanning only new
                # output so a prompt echoed in scrollback is not re-answered.
                if answers:
                    new_output_lower = combined_output[prompt_check_start_pos:].lower()
                    for prompt_pattern, answer in answers.items():
                        pattern_lower = prompt_pattern.lower()
                        if pattern_lower in answered_prompts:
                            continue
                        if pattern_lower in new_output_lower:
                            logger.info(f"Matched prompt '{prompt_pattern}', sending answer")
                            answered_prompts.add(pattern_lower)
                            connection.channel.write(answer + "\n")
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
                    current_time = time.perf_counter()
                    if current_time - last_log_time > log_interval:
                        elapsed = int(current_time - start_time)
                        logger.info(
                            f"Still waiting for patterns after {elapsed}s. "
                            f"Output length: {len(combined_output)}, last 200 chars: "
                            f"{combined_output[-200:] if combined_output else '(empty)'}"
                        )
                        last_log_time = current_time
                elif quiet_reads >= _QUIET_READS_DONE:
                    # No target pattern: the command is settled once the
                    # channel stays quiet (send_command_timing semantics).
                    break

            if wait_for_patterns and not pattern_found:
                logger.warning(
                    f"Timeout waiting for patterns after {read_timeout}s. "
                    f"Output so far: {combined_output[-500:] if combined_output else '(empty)'}"
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
            logger.error(f"Timing command failed on {self.host}: {e}")
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
