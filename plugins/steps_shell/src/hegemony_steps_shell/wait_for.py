# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ShellWaitForHandler: run a shell command until its output matches a pattern.

The server counterpart of ``netcli.wait_for``: after a reboot or a package
install, wait until a service is really up. Each host keeps one shell
connection (``services.open_shell``) for every poll, and opens a new one
when the old one is lost. The polling itself is in :mod:`.waiting`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    StepKind,
    command_label,
    for_each_target_device,
)
from hegemony_step_sdk.ssh import SshSecurityConfig

from . import waiting
from .execute import _open_shell, build_command, command_template_errors

logger = logging.getLogger(__name__)


class _CommandFields(BaseModel):
    """The command and its interpreter, declared first so the form shows them first."""

    command: str = Field(
        default="",
        min_length=1,
        title="Command",
        description=(
            "One command run on every poll, such as 'systemctl is-active nginx'. "
            "Its standard output is checked against Pattern; a non-zero exit "
            "code never counts as met. A {{ }} value must end with | quote and "
            "stand outside quotes, as in shell.execute."
        ),
        json_schema_extra={"x_placeholder": "systemctl is-active nginx", "x_col_span": 2},
    )
    shell: Literal["default", "sh", "bash", "pwsh"] = Field(
        default="default",
        title="Interpreter",
        description="How the command is wrapped on the remote host, as in shell.execute",
        json_schema_extra={
            "x_option_labels": {
                "default": "Login shell (as-is)",
                "sh": "sh -c",
                "bash": "bash -c",
                "pwsh": "pwsh -NoProfile -Command",
            }
        },
    )


class ShellWaitForConfig(SshSecurityConfig, waiting.WaitForFields, _CommandFields):
    """Config for ``shell.wait_for``."""

    model_config = ConfigDict(extra="allow")


class _ShellSession:
    """One host's shell connection, as :class:`waiting.DeviceSession`."""

    def __init__(
        self,
        ctx: HandlerContext,
        device: dict[str, Any],
        config: ShellWaitForConfig,
        remote_command: str,
        deadline: float,
    ) -> None:
        self._ctx = ctx
        self._device = device
        self._config = config
        self._original = config.command
        self._remote_command = remote_command
        self._deadline = deadline
        self._transport: Any = None

    def _left(self, limit: float) -> float:
        """``limit``, cut to the time left before the deadline (at least a second)."""
        return max(min(float(limit), self._deadline - waiting.monotonic()), 1.0)

    async def connect(self) -> None:
        services = self._ctx.require_services()
        self._transport = await _open_shell(
            services,
            self._device,
            self._config.allow_legacy_ssh,
            connect_timeout=self._left(self._config.connect_timeout_seconds),
        )

    async def run(self) -> waiting.Poll:
        transport = self._transport
        await self._ctx.emit_output(
            f"$ {self._original}\n", device=self._device, command=self._original
        )
        try:
            result = await transport.run(
                self._remote_command,
                timeout=self._left(self._config.command_timeout_seconds),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a lost connection; the loop reconnects
            # The shell transport raises when the connection drops or the
            # command runs out of time; either way a new connection follows.
            return waiting.Poll(lost=True, error=str(exc) or type(exc).__name__)
        # Live view, as shell.execute writes it, unless the transport already
        # streamed the output. The host redacts every platform-resolved secret
        # from these events.
        if not getattr(transport, "streams_exec_output", False):
            if result.stdout:
                await self._ctx.emit_output(
                    result.stdout, stream="stdout", device=self._device, command=self._original
                )
            if result.stderr:
                await self._ctx.emit_output(
                    result.stderr, stream="stderr", device=self._device, command=self._original
                )
        if result.exit_code < 0:
            # No exit status: the process or the connection died under it.
            return waiting.Poll(lost=True, error="the command ended without an exit status")
        if result.exit_code != 0:
            detail = (result.stderr or result.stdout or "").strip().splitlines()
            first_line = detail[0] if detail else ""
            return waiting.Poll(
                output=result.stdout or "",
                error=f"exit {result.exit_code}" + (f" ({first_line})" if first_line else ""),
            )
        return waiting.Poll(output=result.stdout or "", ok=True)

    async def close(self) -> None:
        transport, self._transport = self._transport, None
        if transport is not None:
            try:
                await transport.close()
            except Exception:  # noqa: BLE001 - closing is best-effort
                logger.debug("shell transport close failed", exc_info=True)


class ShellWaitForHandler(BaseHandler):
    """Run a shell command on each host until its output matches, or time runs out."""

    handler_id = "shell.wait_for"
    supported_kinds = [StepKind.WAIT]
    display_name = "Wait For Shell Output"
    description = "Run a shell command until its output matches a pattern (after a reboot)."
    category = "Checks"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = ShellWaitForConfig
    output_fields = waiting.OUTPUT_FIELDS
    default_config = {
        "shell": "default",
        "until": "matches",
        "match_scope": "output",
        "poll_interval_seconds": 10,
        "max_wait_seconds": 600,
        "stable_polls": 1,
    }
    run_timeout_field = "max_wait_seconds"
    run_timeout_margin_seconds = waiting.RUN_TIMEOUT_MARGIN_SECONDS

    def template_errors(self, config: dict[str, Any]) -> list[str]:
        """Refuse a command whose ``{{ }}`` values would not be single literal words."""
        command = config.get("command")
        if not isinstance(command, str):
            return []
        return command_template_errors([command], config.get("shell", "default"))

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )
        try:
            config = self.parse_config(ctx.config, ShellWaitForConfig)
        except InvalidConfigError as exc:
            return exc.result()
        try:
            remote_command = build_command(config.command, shell=config.shell)
        except ValueError as exc:
            return HandlerResult(success=False, error=str(exc), summary="Shell configuration error")

        started = waiting.monotonic()
        deadline = started + config.max_wait_seconds

        async def _wait(device: dict[str, Any]) -> waiting.DeviceWait:
            device_name = str(device.get("name") or device.get("id") or device.get("mgmt_host"))

            async def emit(line: str) -> None:
                await ctx.emit_output(line + "\n", device=device, command=config.command)

            if not device.get("mgmt_host"):
                return waiting.DeviceWait(name=device_name, error="no mgmt_host configured")
            session = _ShellSession(ctx, device, config, remote_command, deadline)
            return await waiting.wait_on_device(
                session, config, name=device_name, started=started, deadline=deadline, emit=emit
            )

        waits = await for_each_target_device(
            target_devices, _wait, max_parallel=config.max_parallel_devices
        )
        return waiting.step_result(
            waits, target_devices, config, command_label(config.command), config.command
        )
