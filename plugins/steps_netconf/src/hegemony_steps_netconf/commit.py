# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``netconf.commit`` and ``netconf.cancel_commit``: settle a pending confirmed commit.

A change step with Commit "confirm in a later step" leaves a confirmed commit
pending on each device, under a persist id it puts in its output
(``devices.<name>.persist_id``). These steps read that output by the change
step's id and, for each target device, confirm the commit
(``<commit><persist-id>``) or roll it back (``<cancel-commit><persist-id>``)
from a new session (RFC 6241, :confirmed-commit:1.1).
"""

from __future__ import annotations

import contextlib
from collections import Counter
from typing import Any

from pydantic import Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
)

from .client import CAP_CONFIRMED_11, NetconfError, RpcFailed, RpcTimeout
from .common import (
    DeviceOutcome,
    NetconfConnectionConfig,
    SessionUnavailable,
    build_result,
    device_label,
    max_parallel_field,
    netconf_session,
    no_targets,
    run_per_device,
    unavailable,
)


class SettleConfig(NetconfConnectionConfig):
    """Config for ``netconf.commit`` and ``netconf.cancel_commit``."""

    change_step: str = Field(
        default="",
        title="Change Step",
        description=(
            "The netconf.edit_config or cisco.iosxe.config_replace step that left the "
            "commit pending (Commit: confirm in a later step). Its output names each "
            "device's persist id."
        ),
        json_schema_extra={"x_widget": "step-select", "x_placeholder": "Select the change step..."},
    )
    max_parallel_devices: int = max_parallel_field(10)


class ConfirmConfig(SettleConfig):
    """Config for ``netconf.commit``."""

    save_config: bool = Field(
        default=False,
        title="Save to startup",
        description=(
            "After confirming, save running to startup: copy-config when the device has a "
            "startup datastore, else Cisco's save-config RPC. A change step with Save to "
            "startup on is saved here even when this is off."
        ),
    )


def _device_entries(step_output: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Device name -> that device's entry in a change step's output."""
    output = (
        step_output.get("output") if isinstance(step_output.get("output"), dict) else step_output
    )
    devices = output.get("devices") if isinstance(output, dict) else None
    if not isinstance(devices, dict):
        return {}
    return {str(name): entry for name, entry in devices.items() if isinstance(entry, dict)}


def _entry_for(
    device: dict[str, Any], entries: dict[str, dict[str, Any]], *, shared_name: bool
) -> dict[str, Any] | None:
    """This device's entry, matched exactly; raise when the name could be another device's.

    The change step keys a device by name, by ``name (id)`` when several
    devices share the name, and by ``name #2`` for a second device with the
    same name and no id. A persist id must never be sent to the wrong device.
    """
    name = device_label(device)
    if device.get("id") and f"{name} ({device['id']})" in entries:
        return entries[f"{name} ({device['id']})"]
    if shared_name or f"{name} #2" in entries:
        raise NetconfError(
            f"several devices are named {name!r}, so this device's result cannot be told "
            "apart; give the devices distinct names or ids"
        )
    return entries.get(name)


class _SettleHandler(BaseHandler):
    """Common execution of confirm and cancel."""

    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    category = "Actions"
    targeting = HandlerTargeting(ips=False)
    output_fields = (
        OutputField(
            "devices",
            "Each device's result by name: ok, error, persist_id, skipped (nothing was "
            "pending) and the outcome",
            "object",
        ),
        OutputField("truncated", "Output texts cut short, as device.key", "list"),
    )
    _verb = ""
    #: The settings model the step parses (config_model, typed for the code below).
    settings_model: type[SettleConfig] = SettleConfig

    async def _settle(
        self, session: Any, persist_id: str, config: Any, entry: dict[str, Any]
    ) -> dict[str, Any]:
        raise NotImplementedError

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, self.settings_model)
        except InvalidConfigError as exc:
            return exc.result()
        change_step = config.change_step.strip()
        if not change_step:
            return HandlerResult(
                success=False,
                error="'change_step' is required: choose the step that left the commit pending",
                summary="Config validation failed",
            )
        outputs = await ctx.require_services().fetch_run_step_outputs(ctx.run_id)
        step_output = outputs.get(change_step)
        if not isinstance(step_output, dict):
            return HandlerResult(
                success=False,
                error=f"step {change_step!r} has no output in this run",
                summary=f"Nothing to {self._verb}",
            )
        entries = _device_entries(step_output)
        names = Counter(device_label(device) for device in devices)

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            entry = _entry_for(device, entries, shared_name=names[device_label(device)] > 1)
            if entry is None:
                raise NetconfError(f"step {change_step!r} has no result for this device")
            persist_id = str(entry.get("persist_id") or "") if entry.get("pending") else ""
            if not persist_id:
                if entry.get("ok") is False:
                    raise NetconfError(
                        f"step {change_step!r} failed on this device, so no commit is pending"
                    )
                # Unchanged (or committed at once): there is nothing to settle.
                outcome.output = {"skipped": True}
                return
            async with netconf_session(ctx, device, config) as session:
                if not session.supports(CAP_CONFIRMED_11):
                    raise NetconfError("the device has no :confirmed-commit:1.1 capability")
                try:
                    outcome.output = await self._settle(session, persist_id, config, entry)
                except RpcFailed as exc:
                    raise NetconfError(
                        f"{exc}. The commit may already have been confirmed, cancelled, or "
                        "rolled back when its confirm timeout ran out"
                    ) from None
            outcome.output["persist_id"] = persist_id
            if entry.get("save_requested"):
                outcome.output["save_requested"] = True
            if outcome.output.get("save_error"):
                raise NetconfError(
                    "the commit was confirmed, but saving it to startup failed: "
                    + str(outcome.output["save_error"])
                )

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except SessionUnavailable as exc:
            return unavailable(exc)
        done = sum(outcome.ok for outcome in outcomes)
        return build_result(
            outcomes, summary=f"netconf {self._verb}: {done}/{len(outcomes)} devices"
        )


class NetconfCommitHandler(_SettleHandler):
    """Confirm the commit an earlier change step left pending."""

    handler_id = "netconf.commit"
    display_name = "NETCONF Confirm Commit"
    description = "Confirm the commit an earlier NETCONF change step left pending."
    config_model = ConfirmConfig
    settings_model = ConfirmConfig
    _verb = "commit"

    async def _settle(
        self, session: Any, persist_id: str, config: Any, entry: dict[str, Any]
    ) -> dict[str, Any]:
        # A confirming commit commits whatever the candidate holds (RFC 6241
        # 8.4), and another session may have staged edits since the change
        # step unlocked it. Hold the candidate and confirm only when it is
        # exactly the pending running configuration.
        try:
            await session.lock("candidate")
        except RpcFailed as exc:
            raise NetconfError(
                f"another session holds the candidate ({exc}); not confirming while it may "
                "stage other changes"
            ) from None
        try:
            # Compared in canonical form: a device may format the two
            # datastores differently even when they hold the same configuration.
            running = (await session.get_config("running")).canonical_data()
            candidate = (await session.get_config("candidate")).canonical_data()
            if candidate != running:
                raise NetconfError(
                    "the candidate holds changes that are not part of the pending commit "
                    "(another session staged them); not confirming. Discard them on the "
                    "device, or cancel the commit"
                )
            try:
                await session.commit(persist_id=persist_id)
            except RpcTimeout as exc:
                raise NetconfError(
                    f"{exc}; the device may already have confirmed the commit, so check its "
                    "configuration before running the step again"
                ) from None
        finally:
            with contextlib.suppress(Exception):
                await session.unlock("candidate")
        result: dict[str, Any] = {"confirmed": True, "saved": ""}
        if config.save_config or entry.get("save_requested"):
            try:
                result["saved"] = await session.save_config()
            except Exception as exc:  # noqa: BLE001 - the commit is confirmed either way
                result["save_error"] = str(exc) or type(exc).__name__
        return result


class NetconfCancelCommitHandler(_SettleHandler):
    """Roll back the commit an earlier change step left pending."""

    handler_id = "netconf.cancel_commit"
    display_name = "NETCONF Cancel Commit"
    description = "Roll back the commit an earlier NETCONF change step left pending."
    config_model = SettleConfig
    settings_model = SettleConfig
    _verb = "cancel-commit"

    async def _settle(
        self, session: Any, persist_id: str, config: Any, entry: dict[str, Any]
    ) -> dict[str, Any]:
        await session.cancel_commit(persist_id)
        return {"cancelled": True}
