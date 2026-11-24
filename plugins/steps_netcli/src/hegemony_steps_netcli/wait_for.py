# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""WaitForCliHandler: run a CLI command until its output matches a pattern.

For the time after a reload or an install, when a device answers on the
network (``probe.wait_reachable``) but is not ready yet. Each device keeps
one login for every poll (the transport's held session), and logs in again
when the device drops it. The polling itself is in :mod:`.waiting`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

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
from hegemony_step_sdk.ssh import SshSecurityConfig, configure_ssh_security

from . import waiting
from .transcript import command_transcript, was_skipped

logger = logging.getLogger(__name__)


class _CommandField(BaseModel):
    """The command, declared first so the form shows it first."""

    command: str = Field(
        default="",
        min_length=1,
        title="Command",
        description=(
            "One exec-mode command run on every poll, such as 'show install "
            "summary'. Its output is checked against Pattern. Use {{ variable }} "
            "syntax for flow inputs."
        ),
        json_schema_extra={"x_placeholder": "show install summary", "x_col_span": 2},
    )


class WaitForCliConfig(SshSecurityConfig, waiting.WaitForFields, _CommandField):
    """Config for ``netcli.wait_for``."""

    model_config = ConfigDict(extra="allow")


#: How the transports word a login that failed, when they log in per command.
_LOGIN_FAILURES = ("SSH connection failed", "Connection timeout")


class _CliSession:
    """One device's held CLI session, as :class:`waiting.DeviceSession`."""

    def __init__(
        self, ctx: HandlerContext, device: dict[str, Any], transport: Any, command: str
    ) -> None:
        self._ctx = ctx
        self._device = device
        self._transport = transport
        self._command = command
        # A transport without held sessions logs in for every command; the
        # step still works, one login per poll.
        self._held = getattr(transport, "supports_held_session", False) is True

    async def connect(self) -> None:
        if self._held:
            await self._transport.open_session()

    async def run(self) -> waiting.Poll:
        results = list(await self._transport.execute_commands([self._command]))
        if not results:
            return waiting.Poll(lost=True, error="the transport returned no result")
        result = results[0]
        if not was_skipped(result):
            # Live view, as netcli.execute writes it. The host redacts every
            # platform-resolved secret from these events.
            await self._ctx.emit_output(
                command_transcript(result.command, result.output),
                device=self._device,
                command=result.command,
            )
        if result.exit_code == 0:
            return waiting.Poll(output=result.output or "", ok=True)
        if result.exit_code > 0:
            # The device printed an error (% Invalid input): the session is fine.
            return waiting.Poll(output=result.output or "", error=result.error)
        # -1: the transport could not finish the command. Either the device
        # closed the session (disconnected, or session_open is now False) or
        # it did not answer in time; a new login settles both.
        error = result.error or "the command did not complete"
        if not self._held:
            # This transport logs in for every command, and reports a failed
            # login only by its error text.
            if error.startswith("Authentication failed"):
                raise waiting.WaitAborted(error)
            if error.startswith(_LOGIN_FAILURES):
                return waiting.Poll(lost=True, error=error, had_session=False)
        if getattr(result, "disconnected", False) is True or (
            self._held and getattr(self._transport, "session_open", True) is False
        ):
            error = "the device closed the session"
        return waiting.Poll(lost=True, error=error)

    async def close(self) -> None:
        if self._held:
            try:
                await self._transport.close_session()
            except Exception:  # noqa: BLE001 - closing is best-effort
                logger.debug("closing the held CLI session failed", exc_info=True)


class WaitForCliHandler(BaseHandler):
    """Run a CLI command on each device until its output matches, or time runs out."""

    handler_id = "netcli.wait_for"
    supported_kinds = [StepKind.WAIT]
    display_name = "Wait For CLI Output"
    description = (
        "Run a CLI command until its output matches a pattern (after a reload or install)."
    )
    category = "Checks"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = WaitForCliConfig
    output_fields = waiting.OUTPUT_FIELDS
    default_config = {
        "until": "matches",
        "match_scope": "output",
        "poll_interval_seconds": 10,
        "max_wait_seconds": 600,
        "stable_polls": 1,
    }
    run_timeout_field = "max_wait_seconds"
    run_timeout_margin_seconds = waiting.RUN_TIMEOUT_MARGIN_SECONDS

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )
        try:
            config = self.parse_config(ctx.config, WaitForCliConfig)
        except InvalidConfigError as exc:
            return exc.result()
        command = config.command.strip()

        services = ctx.require_services()
        started = waiting.monotonic()
        deadline = started + config.max_wait_seconds

        async def _wait(device: dict[str, Any]) -> waiting.DeviceWait:
            device_name = str(device.get("name") or device.get("id") or device.get("mgmt_host"))

            async def emit(line: str) -> None:
                await ctx.emit_output(line + "\n", device=device, command=command)

            if not device.get("mgmt_host"):
                return waiting.DeviceWait(name=device_name, error="no mgmt_host configured")
            try:
                # step_run_id registers the session, so cancelling the run closes it.
                transport = services.connect(
                    device,
                    platform=device.get("platform"),
                    connect_timeout=float(config.connect_timeout_seconds),
                    command_timeout=float(config.command_timeout_seconds),
                    step_run_id=ctx.step_run_id,
                )
                configure_ssh_security(transport, config.allow_legacy_ssh)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reported as the device's error
                return waiting.DeviceWait(name=device_name, error=str(exc))
            session = _CliSession(ctx, device, transport, command)
            return await waiting.wait_on_device(
                session, config, name=device_name, started=started, deadline=deadline, emit=emit
            )

        waits = await for_each_target_device(
            target_devices, _wait, max_parallel=config.max_parallel_devices
        )
        return waiting.step_result(waits, target_devices, config, command_label(command), command)
