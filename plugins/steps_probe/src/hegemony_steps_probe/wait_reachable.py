# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""WaitReachableHandler: wait until devices are reachable and stable.

Each poll runs a probe from the host's ``hegemony.probes`` registry through
``ctx.services.run_probe``, like ``probe.connectivity``, so the flow egress
gate, SOCKS proxies, ICMP and IPv6 work the same way in both handlers.
"""

import asyncio
import logging
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    StepKind,
    for_each_target_device,
)

from .checks import CHECK_TYPE_LABELS, PORT_CHECKS, CheckUnavailable, default_port
from .targets import DEFAULT_MAX_PARALLEL_TARGETS, all_probe_targets

logger = logging.getLogger(__name__)


class _CheckMisconfigured(Exception):
    """The probe refused its options (a ``config_error``); no poll can pass."""


class WaitReachableConfig(BaseModel):
    """Config for ``probe.wait_reachable``."""

    model_config = ConfigDict(extra="allow")

    # Registry-driven like probe.connectivity's: the host injects the options
    # from x_options_source, and run_probe decides validity at run time.
    check_type: str = Field(
        default="tcp_connect",
        title="Check Type",
        description=(
            "Which probe each poll runs against each target; the list comes "
            "from the checks registered on the worker. Defaults to a TCP "
            "connection attempt (tcp_connect)."
        ),
        json_schema_extra={
            "x_widget": "select",
            "x_options_source": "probes",
            "x_option_labels": CHECK_TYPE_LABELS,
        },
    )
    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        title="Port",
        description=(
            "Port the port-based checks connect to. When empty, a device is "
            "polled on its management port (22 when the inventory sets none), "
            "an IP target on 22, and HTTP Health uses 80. Ignored by ICMP Ping "
            "and DNS Resolve."
        ),
        json_schema_extra={
            "x_placeholder": "management port",
            "x_hide_when": {"field": "check_type", "value": "icmp_ping"},
        },
    )
    max_wait_seconds: int = Field(
        default=300,
        ge=1,
        title="Max Wait (sec)",
        description=(
            "Overall deadline for the wait, in seconds. The step fails once "
            "this much time passes without every target completing its "
            "stability window. Defaults to 300; the step's own timeout must "
            "be larger, or it ends the wait first."
        ),
        json_schema_extra={"x_legacy_keys": ["max_wait"]},
    )
    stable_seconds: int = Field(
        default=30,
        ge=1,
        title="Stable (sec)",
        description=(
            "How long every target must remain continuously reachable before "
            "the step succeeds, in seconds. A target that goes unreachable "
            "restarts its window from zero. Defaults to 30."
        ),
        json_schema_extra={"x_legacy_keys": ["stability_checks"]},
    )
    poll_interval: int = Field(
        default=5,
        ge=1,
        title="Poll Interval (sec)",
        description="Seconds to wait between reachability polls. Defaults to 5.",
        json_schema_extra={"x_legacy_keys": ["check_interval"]},
    )
    connect_timeout_seconds: int = Field(
        default=5,
        ge=1,
        le=60,
        # Steps saved before the field was declared carry connect_timeout.
        validation_alias=AliasChoices("connect_timeout_seconds", "connect_timeout"),
        title="Connect Timeout (sec)",
        description=(
            "Time limit for each poll of a target, in seconds. A target that "
            "does not answer in time counts as unreachable for that poll. "
            "Defaults to 5."
        ),
        json_schema_extra={"x_legacy_keys": ["connect_timeout"]},
    )
    socks_proxy: str = Field(
        default="",
        title="SOCKS5 Proxy",
        description=(
            "Route TCP-based checks through an authenticated SOCKS5 proxy "
            "(socks5[h]://user:pass@host:port), e.g. the lab bastion. "
            "icmp_ping rejects it — use tcp_connect for tunneled targets."
        ),
        json_schema_extra={
            "x_placeholder": "socks5://user:{{ secret('vault://lab/bastion/password') }}@dind:1080",
            "x_col_span": 2,
        },
    )
    max_parallel_devices: int = Field(
        default=DEFAULT_MAX_PARALLEL_TARGETS,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Targets polled at the same time (1 = one after another). Defaults to 10.",
    )


class WaitReachableHandler(BaseHandler):
    """Handler for waiting until device is reachable and stable."""

    handler_id = "probe.wait_reachable"
    supported_kinds = [StepKind.WAIT]
    display_name = "Wait Reachable (Stable)"
    description = "Wait until targets stay reachable for a stability window."
    category = "Checks"
    config_model = WaitReachableConfig
    default_config = {
        "check_type": "tcp_connect",
        "max_wait_seconds": 300,
        "stable_seconds": 30,
        "poll_interval": 5,
    }

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Wait for all target devices to be reachable with stability window."""
        target_devices = all_probe_targets(ctx)
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices or IPs configured",
                summary="Missing targets",
            )

        # The validated model, not raw config gets: a value of the wrong type
        # (a string timeout) used to make every poll fail as "unreachable".
        errors = self.validate_config(ctx.config)
        if errors:
            return HandlerResult(
                success=False,
                error=f"Invalid probe.wait_reachable config: {'; '.join(errors)}",
                summary="Config validation failed",
            )
        config = WaitReachableConfig.model_validate(ctx.config)
        check_type = config.check_type
        max_wait_seconds = config.max_wait_seconds
        stable_seconds = config.stable_seconds
        poll_interval = config.poll_interval
        connect_timeout = config.connect_timeout_seconds
        socks_proxy = config.socks_proxy.strip()

        # Fail fast if any device is missing mgmt_host — waiting would always time out
        for device in target_devices:
            host = device.get("mgmt_host")
            if not host:
                device_name = device.get("name", device.get("id", "unknown"))
                return HandlerResult(
                    success=False,
                    error=f"Device '{device_name}' has no mgmt_host configured",
                    summary=f"Device '{device_name}' missing mgmt_host — cannot check reachability",
                )

        def _port(device: dict[str, Any]) -> int | None:
            """The port polled on ``device``, or None for a check without one."""
            if check_type not in PORT_CHECKS:
                return None
            if config.port is not None:
                return config.port
            return default_port(check_type, device.get("mgmt_port") or 22)

        services = ctx.require_services()
        loop = asyncio.get_running_loop()
        started = loop.time()
        deadline = started + max_wait_seconds
        # Per target, the loop time it answered from when it last became
        # reachable; None while it is not.
        stable_since: list[float | None] = [None] * len(target_devices)
        attempts = 0

        async def _poll(device: dict[str, Any]) -> float | None:
            """Poll one target; the loop time it answered, or None if it did not.

            run_probe applies the flow egress gate, so a denied target raises
            here on its first poll and fails the step with the policy's reason.
            """
            # A poll never outlasts the deadline, also when it starts late in
            # a round with more targets than run at once.
            timeout = min(connect_timeout, deadline - loop.time())
            if timeout <= 0:
                return None
            options: dict[str, Any] = {"timeout_ms": max(1, int(timeout * 1000))}
            port = _port(device)
            if port is not None:
                options["port"] = port
            if check_type == "icmp_ping":
                options["count"] = 1
            if socks_proxy:
                options["socks_proxy"] = socks_proxy
            try:
                result = await asyncio.wait_for(
                    services.run_probe(check_type, device["mgmt_host"], options),
                    timeout=timeout,
                )
            except TimeoutError:
                return None
            except KeyError:
                raise CheckUnavailable from None
            # A probe that refuses its options refuses them on every poll.
            if result.error_kind == "config_error":
                name = device.get("name", device["mgmt_host"])
                raise _CheckMisconfigured(f"{name}: {result.error_detail}")
            return loop.time() if result.ok else None

        def _timed_out() -> HandlerResult:
            not_stable = [
                d.get("name", d.get("mgmt_host"))
                for d, since in zip(target_devices, stable_since, strict=True)
                if since is None
            ]
            return HandlerResult(
                success=False,
                error=f"Timeout waiting for targets: {', '.join(not_stable)}",
                summary=f"Targets not reachable after {max_wait_seconds}s",
                metrics={"attempts": attempts, "elapsed_seconds": loop.time() - started},
            )

        while True:
            if loop.time() >= deadline:
                return _timed_out()

            attempts += 1
            # One round polls every target, up to max_parallel_devices at once.
            try:
                answered = await for_each_target_device(
                    target_devices, _poll, max_parallel=config.max_parallel_devices
                )
            except CheckUnavailable:
                return HandlerResult(
                    success=False,
                    error=f"Check type '{check_type}' is not available on this worker",
                    summary=f"Unsupported check type: {check_type}",
                )
            except _CheckMisconfigured as exc:
                return HandlerResult(
                    success=False,
                    error=f"{check_type} cannot run against {exc}",
                    summary=f"Check cannot run: {check_type}",
                )
            all_stable = True

            for index, (device, answered_at) in enumerate(
                zip(target_devices, answered, strict=True)
            ):
                device_name = device.get("name", device.get("id", device.get("mgmt_host")))
                since = stable_since[index]
                if answered_at is None:
                    if since is not None:
                        logger.info(f"Device {device_name} went unreachable, resetting stability")
                    stable_since[index] = None
                    all_stable = False
                elif since is None:
                    stable_since[index] = answered_at
                    logger.info(f"Device {device_name} became reachable, starting stability window")
                    all_stable = False  # Just became reachable, not yet stable
                # A target is stable for the span of its own answers. The
                # round's end would credit it with time spent polling the
                # other targets, when nothing was asked of it.
                elif answered_at - since < stable_seconds:
                    all_stable = False
                else:
                    logger.info(f"Device {device_name} stable for {answered_at - since:.1f}s")

            if all_stable:
                all_evidence = []
                for device in target_devices:
                    device_id = device.get("id", device.get("mgmt_host"))
                    device_name = device.get("name", device_id)
                    all_evidence.append(
                        {
                            "kind": "transport_meta",
                            "name": f"reachability_check_{device_name}",
                            "device_id": device.get("id"),
                            "content_json": {
                                "device_id": device.get("id"),
                                "device_name": device_name,
                                "host": device.get("mgmt_host"),
                                "check_type": check_type,
                                "port": _port(device),
                                "success": True,
                                "stable_seconds": stable_seconds,
                            },
                        }
                    )
                return HandlerResult(
                    success=True,
                    summary=f"All {len(target_devices)} target(s) stable for {stable_seconds}s",
                    metrics={
                        "attempts": attempts,
                        "elapsed_seconds": loop.time() - started,
                        "stable_seconds": stable_seconds,
                        "device_count": len(target_devices),
                    },
                    evidence=all_evidence,
                )

            # Checked again after the round, so a round that ran into the
            # deadline fails now rather than after one more poll interval.
            remaining = deadline - loop.time()
            if remaining <= 0:
                return _timed_out()
            await asyncio.sleep(min(poll_interval, remaining))
