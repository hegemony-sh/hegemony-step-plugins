# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``napalm.rollback``: return to the configuration before the last NAPALM commit."""

from __future__ import annotations

from typing import Any

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
)

from .common import (
    DeviceOutcome,
    NapalmConnectionConfig,
    SessionUnavailable,
    build_result,
    log_line,
    max_parallel_field,
    napalm_session,
    no_targets,
    run_per_device,
    unavailable,
)

HANDLER_ID = "napalm.rollback"


class NapalmRollbackConfig(NapalmConnectionConfig):
    """Config for ``napalm.rollback``."""

    max_parallel_devices: int = max_parallel_field(1)


class NapalmRollbackHandler(BaseHandler):
    """Return each device to the configuration it had before the last NAPALM commit."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "NAPALM Rollback"
    description = "Return devices to the configuration before the last NAPALM commit."
    category = "Actions"
    targeting = HandlerTargeting(ips=False)
    config_model = NapalmRollbackConfig
    default_config: dict[str, Any] = {}
    output_fields = (
        OutputField("devices", "Each device's result by name: ok, error and driver", "object"),
        OutputField("truncated", "Output texts cut short, as device.key (always empty)", "list"),
    )

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, NapalmRollbackConfig)
        except InvalidConfigError as exc:
            return exc.result()

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            async with napalm_session(ctx, device, config) as session:
                outcome.output["driver"] = session.driver
                await log_line(ctx, device, "rollback")
                await session.rollback()

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except SessionUnavailable as exc:
            return unavailable(exc)
        passed = sum(outcome.ok for outcome in outcomes)
        return build_result(outcomes, summary=f"napalm rollback: {passed}/{len(outcomes)} devices")
