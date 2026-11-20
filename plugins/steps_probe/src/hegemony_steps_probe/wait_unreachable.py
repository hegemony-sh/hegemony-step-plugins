# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""WaitUnreachableHandler: wait until devices stop answering.

The counterpart of ``probe.wait_reachable``, for the moment after a step
started a reload: a device can keep answering from its old software for a
while, so a wait for it to come back can pass before it ever went away.
Polls run through ``ctx.services.run_probe`` like the other probe steps.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Self

from pydantic import Field, model_validator

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    InvalidConfigError,
    OutputField,
    ProbeResult,
    StepKind,
    for_each_target_device,
)

from .checks import CheckUnavailable
from .targets import all_probe_targets
from .wait_reachable import WaitReachableConfig
from .waiting import CheckMisconfigured, missing_host, poll_port, poll_target

logger = logging.getLogger(__name__)

#: Failures that say the check itself could not run - a proxy that refused
#: us, a probe that crashed, a ping binary that is missing - not that the
#: target stopped answering. They never count as down, so a broken proxy
#: cannot pass the step for a device that is still up.
INCONCLUSIVE_ERRORS = frozenset({"socks_error", "exception", "error", "command_not_found"})


class WaitUnreachableConfig(WaitReachableConfig):
    """Config for ``probe.wait_unreachable``.

    The check, port, poll and proxy settings are ``probe.wait_reachable``'s;
    the two fields below take its place in the form with this step's meaning.
    """

    max_wait_seconds: int = Field(
        default=300,
        ge=1,
        title="Max Wait (sec)",
        description=(
            "Overall deadline for the wait, in seconds. The step fails once "
            "this much time passes without every target having been down for "
            "Down For (sec). Defaults to 300. The step's timeout is raised to "
            "cover it."
        ),
    )
    stable_seconds: int = Field(
        default=10,
        ge=0,
        title="Down For (sec)",
        description=(
            "How long a target must fail every poll before it counts as down, "
            "in seconds, so one lost packet is not taken for a reload; must be "
            "shorter than Max Wait (sec). 0 counts the first failed poll. A "
            "target that answers again restarts its count. Defaults to 10."
        ),
    )

    @model_validator(mode="after")
    def _window_fits_the_wait(self) -> Self:
        """Refuse a down window that cannot end before the deadline."""
        if self.stable_seconds >= self.max_wait_seconds:
            raise ValueError(
                f"stable_seconds ({self.stable_seconds}) must be shorter than "
                f"max_wait_seconds ({self.max_wait_seconds}), or no target can "
                "stay down long enough before the deadline"
            )
        return self


class WaitUnreachableHandler(BaseHandler):
    """Handler for waiting until devices stop answering."""

    handler_id = "probe.wait_unreachable"
    supported_kinds = [StepKind.WAIT]
    display_name = "Wait Unreachable"
    description = "Wait until targets stop answering, such as after a reload starts."
    category = "Checks"
    config_model = WaitUnreachableConfig
    default_config = {
        "check_type": "tcp_connect",
        "max_wait_seconds": 300,
        "stable_seconds": 10,
        "poll_interval_seconds": 5,
    }
    run_timeout_field = "max_wait_seconds"
    output_fields = (
        OutputField(
            "went_down",
            "Targets that answered at first and then stopped answering",
            "list",
        ),
        OutputField(
            "already_down",
            "Targets that never answered during the wait",
            "list",
        ),
        OutputField("still_up", "Targets not down when the step ended", "list"),
        OutputField("elapsed_seconds", "Seconds the wait took", "float"),
    )

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Wait for every target to fail its polls for the down window."""
        target_devices = all_probe_targets(ctx)
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices or IPs configured",
                summary="Missing targets",
            )
        try:
            config = self.parse_config(ctx.config, WaitUnreachableConfig)
        except InvalidConfigError as exc:
            return exc.result()
        missing = missing_host(target_devices)
        if missing is not None:
            return missing

        check_type = config.check_type
        max_wait_seconds = config.max_wait_seconds
        down_seconds = config.stable_seconds
        services = ctx.require_services()
        loop = asyncio.get_running_loop()
        started = loop.time()
        deadline = started + max_wait_seconds
        count = len(target_devices)

        def _name(device: dict[str, Any]) -> str:
            return str(device.get("name") or device.get("mgmt_host"))

        # Per target: when its current run of failed polls began (None while
        # it answers), when it was confirmed down (it stays down for this
        # step once confirmed: a quick reload can bring it back before the
        # others go down), whether it ever answered, and the latest reason a
        # poll could not tell.
        down_since: list[float | None] = [None] * count
        down_at: list[float | None] = [None] * count
        answered: list[bool] = [False] * count
        unclear: list[str | None] = [None] * count
        attempts = 0

        def _output() -> dict[str, Any]:
            went_down, already_down, still_up = [], [], []
            for index, device in enumerate(target_devices):
                if down_at[index] is None:
                    still_up.append(_name(device))
                elif answered[index]:
                    went_down.append(_name(device))
                else:
                    already_down.append(_name(device))
            return {
                "went_down": went_down,
                "already_down": already_down,
                "still_up": still_up,
                "elapsed_seconds": round(loop.time() - started, 3),
            }

        def _timed_out() -> HandlerResult:
            answering, unclear_names, partway = [], [], []
            for index, device in enumerate(target_devices):
                if down_at[index] is not None:
                    continue
                name = _name(device)
                if unclear[index] is not None:
                    unclear_names.append(f"{name} ({unclear[index]})")
                elif down_since[index] is None:
                    answering.append(name)
                else:
                    partway.append(name)
            reasons = []
            if answering:
                reasons.append(f"still answering: {', '.join(answering)}")
            if partway:
                reasons.append(f"not yet down for {down_seconds}s: {', '.join(partway)}")
            if unclear_names:
                reasons.append(f"the check could not run: {', '.join(unclear_names)}")
            return HandlerResult(
                success=False,
                error=f"Timeout waiting for targets to go down - {'; '.join(reasons)}",
                summary=f"Targets still reachable after {max_wait_seconds}s",
                output=_output(),
                metrics={"attempts": attempts, "elapsed_seconds": loop.time() - started},
            )

        async def _poll(device: dict[str, Any]) -> tuple[ProbeResult | None, float]:
            result = await poll_target(services, config, device, deadline)
            return result, loop.time()

        while True:
            if loop.time() >= deadline:
                return _timed_out()
            attempts += 1
            pending = [index for index in range(count) if down_at[index] is None]
            try:
                polled = await for_each_target_device(
                    [target_devices[index] for index in pending],
                    _poll,
                    max_parallel=config.max_parallel_devices,
                )
            except CheckUnavailable:
                return HandlerResult(
                    success=False,
                    error=f"Check type '{check_type}' is not available on this worker",
                    summary=f"Unsupported check type: {check_type}",
                )
            except CheckMisconfigured as exc:
                return HandlerResult(
                    success=False,
                    error=f"{check_type} cannot run against {exc}",
                    summary=f"Check cannot run: {check_type}",
                )

            for index, (result, polled_at) in zip(pending, polled, strict=True):
                name = _name(target_devices[index])
                if result is not None and result.ok:
                    answered[index] = True
                    unclear[index] = None
                    if down_since[index] is not None:
                        logger.info(f"Device {name} answered again, restarting its down count")
                    down_since[index] = None
                    continue
                if result is not None and result.error_kind in INCONCLUSIVE_ERRORS:
                    # Neither up nor down: the count starts again once a
                    # poll can tell.
                    unclear[index] = result.error_detail or result.error_kind
                    down_since[index] = None
                    continue
                unclear[index] = None
                if down_since[index] is None:
                    down_since[index] = polled_at
                    logger.info(f"Device {name} stopped answering, starting its down count")
                since = down_since[index]
                if since is not None and polled_at - since >= down_seconds:
                    down_at[index] = polled_at
                    logger.info(f"Device {name} down for {polled_at - since:.1f}s")

            if all(at is not None for at in down_at):
                evidence = []
                for index, device in enumerate(target_devices):
                    at = down_at[index]
                    evidence.append(
                        {
                            "kind": "transport_meta",
                            "name": f"unreachability_check_{_name(device)}",
                            "device_id": device.get("id"),
                            "content_json": {
                                "device_id": device.get("id"),
                                "device_name": _name(device),
                                "host": device.get("mgmt_host"),
                                "check_type": check_type,
                                "port": poll_port(config, device),
                                "answered_first": answered[index],
                                "down_after_seconds": (
                                    round(at - started, 3) if at is not None else None
                                ),
                                "down_seconds": down_seconds,
                            },
                        }
                    )
                output = _output()
                return HandlerResult(
                    success=True,
                    summary=(
                        f"All {count} target(s) down for {down_seconds}s "
                        f"({len(output['went_down'])} went down, "
                        f"{len(output['already_down'])} already down)"
                    ),
                    output=output,
                    metrics={
                        "attempts": attempts,
                        "elapsed_seconds": loop.time() - started,
                        "down_seconds": down_seconds,
                        "device_count": count,
                    },
                    evidence=evidence,
                )

            remaining = deadline - loop.time()
            if remaining <= 0:
                return _timed_out()
            await asyncio.sleep(min(config.poll_interval_seconds, remaining))
