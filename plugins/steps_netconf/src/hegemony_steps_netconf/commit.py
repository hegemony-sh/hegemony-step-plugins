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

from .client import CAP_CONFIRMED_11, NetconfError, RpcFailed
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
            "The change step (such as netconf.edit_config) that left the "
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
    """This device's entry, matched exactly; raise when it could be another device's.

    Each entry records the ``device_id`` it was made for; a device with an id
    matches that, never a display key. A device without one matches its name
    only when no other device can share it. A persist id must never be sent to
    the wrong device.
    """
    name = device_label(device)
    device_id = str(device.get("id") or "")
    if device_id:
        matches = [
            entry for entry in entries.values() if str(entry.get("device_id") or "") == device_id
        ]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise NetconfError(f"step results name the device id {device_id!r} more than once")
    if shared_name or f"{name} #2" in entries:
        raise NetconfError(
            f"several devices are named {name!r}, so this device's result cannot be told "
            "apart; give the devices distinct names or ids"
        )
    entry = entries.get(name)
    recorded = str(entry.get("device_id") or "") if entry is not None else ""
    if entry is not None and recorded != device_id:
        raise NetconfError(
            f"the result for {name!r} was recorded for another device "
            f"(id {recorded or 'none'}), so its persist id is not sent to this one"
        )
    return entry


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
            # A commit whose reply was lost may be pending under its persist id:
            # settle it too (the device refuses the id when nothing is pending).
            settleable = entry.get("pending") or entry.get("commit_uncertain")
            persist_id = str(entry.get("persist_id") or "") if settleable else ""
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
                    saving = getattr(config, "save_config", False) or entry.get("save_requested")
                    hint = (
                        ". If an earlier attempt confirmed it, running is not saved yet: save "
                        "it to startup (netconf.rpc with save-config or copy-config)"
                        if saving and self._verb == "commit"
                        else ""
                    )
                    raise NetconfError(
                        f"{exc}. The commit may already have been confirmed, cancelled, or "
                        f"rolled back when its confirm timeout ran out{hint}"
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
                f"the candidate cannot be locked ({exc}): another session holds it or has "
                "changes staged in it, so the commit is not confirmed. Discard those changes "
                "on the device, or cancel the commit"
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
            except RpcFailed:
                raise  # refused: reported below with what it can mean
            except Exception as exc:
                raise NetconfError(
                    f"{exc}; the device may already have confirmed the commit, so check its "
                    "configuration before running the step again"
                ) from None
            result: dict[str, Any] = {"confirmed": True, "saved": ""}
            if config.save_config or entry.get("save_requested"):
                # Still holding the candidate: no other session can commit (and
                # so put an unconfirmed change in running) before the save copies
                # running to startup.
                try:
                    result["saved"] = await session.save_config()
                except Exception as exc:  # noqa: BLE001 - the commit is confirmed either way
                    result["save_error"] = str(exc) or type(exc).__name__
            return result
        finally:
            with contextlib.suppress(Exception):
                await session.unlock("candidate")


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
