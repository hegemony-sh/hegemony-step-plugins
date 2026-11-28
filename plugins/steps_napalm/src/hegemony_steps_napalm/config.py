# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``napalm.config``: change configuration with NAPALM's candidate workflow.

Load a candidate (merged into the running configuration, or replacing it),
show the difference, then discard it (dry run, or nothing to change) or
commit it. A commit with Confirm Within set is a confirmed commit: the
device rolls it back by itself unless it is confirmed in time, and the step
confirms it only once a second, new session shows the device can still be
managed.
"""

from __future__ import annotations

import contextlib
from typing import Any, Literal

from pydantic import Field, field_validator

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    NapalmSession,
    OutputField,
    StepKind,
)

from .common import (
    DeviceOutcome,
    NapalmConnectionConfig,
    NapalmStepError,
    SessionUnavailable,
    build_result,
    describe_error,
    log_line,
    max_parallel_field,
    napalm_session,
    no_targets,
    run_per_device,
    text_evidence,
    unavailable,
)

HANDLER_ID = "napalm.config"

#: Confirm Within bounds, in seconds. Cisco IOS takes whole minutes only.
MIN_REVERT_SECONDS = 60
MAX_REVERT_SECONDS = 24 * 3600


class NapalmConfigConfig(NapalmConnectionConfig):
    """Config for ``napalm.config``."""

    config: str = Field(
        min_length=1,
        title="Configuration",
        description=(
            "The configuration in the device's own syntax. Templates such as "
            "{{ inputs.service_address }} are filled in before it is sent."
        ),
        json_schema_extra={
            "x_widget": "textarea",
            "x_rows": 10,
            "x_col_span": 2,
            "x_placeholder": "interface Loopback100\n ip address 192.0.2.1 255.255.255.255",
        },
    )
    mode: Literal["merge", "replace"] = Field(
        default="merge",
        title="Mode",
        description=(
            "Merge adds the lines to the running configuration. Replace makes the text the "
            "whole configuration: anything it leaves out is removed. Defaults to merge."
        ),
        json_schema_extra={
            "x_option_labels": {"merge": "Merge into running", "replace": "Replace running"}
        },
    )
    dry_run: bool = Field(
        default=False,
        title="Dry run",
        description=(
            "Only show the difference, then discard it: nothing on the device changes. "
            "Use it before an approval, and commit in a later step."
        ),
    )
    revert_in_seconds: int = Field(
        default=0,
        ge=0,
        le=MAX_REVERT_SECONDS,
        title="Confirm Within (sec)",
        description=(
            "0 commits at once. Otherwise a confirmed commit: the device rolls the change "
            "back by itself after this long unless the step confirms it, which it does once a "
            "new session shows the device can still be managed. A multiple of 60, at least 60. "
            "Arista EOS supports it; Cisco IOS needs the archive feature; Cisco NX-OS does "
            "not support it."
        ),
    )
    max_parallel_devices: int = max_parallel_field(1)

    @field_validator("revert_in_seconds")
    @classmethod
    def _whole_minutes(cls, value: int) -> int:
        if value and (value < MIN_REVERT_SECONDS or value % 60):
            raise ValueError("Confirm Within must be 0, or a multiple of 60 of at least 60")
        return value


CHANGE_OUTPUT_FIELDS = (
    OutputField(
        "devices",
        "Each device's result by name: ok, error, driver, diff (cut short when long), "
        "changed, committed and confirmed",
        "object",
    ),
    OutputField("truncated", "Output texts cut short, as device.key", "list"),
)


class NapalmConfigHandler(BaseHandler):
    """Change each device's configuration with NAPALM: diff, then commit or discard."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "NAPALM Config"
    description = (
        "Change device configuration with NAPALM: merge or replace, diff, dry run and "
        "confirmed commit."
    )
    category = "Actions"
    targeting = HandlerTargeting(ips=False)
    config_model = NapalmConfigConfig
    default_config = {"mode": "merge", "dry_run": False, "revert_in_seconds": 0}
    output_fields = CHANGE_OUTPUT_FIELDS

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, NapalmConfigConfig)
        except InvalidConfigError as exc:
            return exc.result()

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            outcome.text_keys = ("diff",)
            outcome.output.update(changed=False, committed=False, confirmed=False)
            async with napalm_session(ctx, device, config) as session:
                outcome.output["driver"] = session.driver
                await self._change(ctx, device, config, session, outcome)

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except SessionUnavailable as exc:
            return unavailable(exc)
        passed = sum(outcome.ok for outcome in outcomes)
        changed = sum(bool(outcome.output.get("changed")) for outcome in outcomes)
        verb = "would change" if config.dry_run else "changed"
        return build_result(
            outcomes,
            summary=(
                f"napalm config {config.mode}: {passed}/{len(outcomes)} devices ok, "
                f"{changed} {verb}"
            ),
        )

    async def _change(
        self,
        ctx: HandlerContext,
        device: dict[str, Any],
        config: NapalmConfigConfig,
        session: NapalmSession,
        outcome: DeviceOutcome,
    ) -> None:
        loaded = False
        try:
            await log_line(ctx, device, f"load {config.mode} candidate")
            loaded = True
            await session.load_config(config.config, replace=config.mode == "replace")
            await log_line(ctx, device, "compare_config")
            diff = (await session.compare_config()).strip()
        except BaseException:
            if loaded:
                with contextlib.suppress(Exception):
                    await session.discard_config()
            raise
        outcome.output["diff"] = diff
        outcome.output["changed"] = bool(diff)
        outcome.evidence.append(
            text_evidence(device, "napalm diff", diff or "(no difference)", command="napalm diff")
        )
        if config.dry_run or not diff:
            await log_line(ctx, device, "discard_config")
            await session.discard_config()
            return
        if not config.revert_in_seconds:
            await log_line(ctx, device, "commit_config")
            await session.commit_config()
            outcome.output["committed"] = True
            return
        await self._confirmed_commit(ctx, device, config, session, outcome)

    async def _confirmed_commit(
        self,
        ctx: HandlerContext,
        device: dict[str, Any],
        config: NapalmConfigConfig,
        session: NapalmSession,
        outcome: DeviceOutcome,
    ) -> None:
        revert_in = config.revert_in_seconds
        await log_line(ctx, device, f"commit_config (rolls back in {revert_in} s unless confirmed)")
        await session.commit_config(revert_in=revert_in)
        outcome.output["committed"] = True
        try:
            # The proof the change left the device manageable: a new login.
            async with napalm_session(ctx, device, config) as check:
                await check.get("facts")
        except Exception as exc:  # noqa: BLE001 - reported, and the change undone
            await log_line(ctx, device, "no new session after the commit; rolling back")
            try:
                await session.rollback()
                outcome.output["rolled_back"] = True
                undone = "rolled back now"
            except Exception:  # noqa: BLE001 - the device's own timer still runs
                undone = f"the device rolls it back within {revert_in} s"
            raise NapalmStepError(
                f"a new session after the commit failed ({describe_error(exc)}); {undone}"
            ) from exc
        await log_line(ctx, device, "confirm_commit")
        await session.confirm_commit()
        outcome.output["confirmed"] = True
