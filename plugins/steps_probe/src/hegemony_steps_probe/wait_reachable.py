# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""WaitReachableHandler: wait until devices are reachable and stable."""

import asyncio
import logging
import socket
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    StepKind,
)

logger = logging.getLogger(__name__)


class WaitReachableConfig(BaseModel):
    """Config for ``probe.wait_reachable``."""

    model_config = ConfigDict(extra="allow")

    max_wait_seconds: int = Field(
        default=300,
        ge=1,
        title="Max Wait (sec)",
        json_schema_extra={"x_legacy_keys": ["max_wait"]},
    )
    stable_seconds: int = Field(
        default=30,
        ge=1,
        title="Stable (sec)",
        json_schema_extra={"x_legacy_keys": ["stability_checks"]},
    )
    poll_interval: int = Field(
        default=5,
        ge=1,
        title="Poll Interval (sec)",
        json_schema_extra={"x_legacy_keys": ["check_interval"]},
    )


class WaitReachableHandler(BaseHandler):
    """Handler for waiting until device is reachable and stable."""

    handler_id = "probe.wait_reachable"
    supported_kinds = [StepKind.WAIT]
    display_name = "Wait Reachable (Stable)"
    description = "Wait until target devices stay reachable for a stability window."
    category = "Checks"
    config_model = WaitReachableConfig
    default_config = {"max_wait_seconds": 300, "stable_seconds": 30, "poll_interval": 5}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Wait for all target devices to be reachable with stability window."""
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )

        max_wait_seconds = ctx.config.get("max_wait_seconds", 300)
        stable_seconds = ctx.config.get("stable_seconds", 30)
        poll_interval = ctx.config.get("poll_interval", 5)
        connect_timeout = ctx.config.get("connect_timeout", 5)

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

        # This handler opens its own socket rather than going through
        # services.run_probe, which is where the host applies the flow egress
        # gate — so without this the policy would never see these targets and
        # the step would happily poll a host the flow is forbidden to reach.
        # Checked once up front rather than per poll: a denial is a
        # configuration fact, not a transient condition, so it should fail the
        # step immediately with the policy's reason instead of after
        # max_wait_seconds of pointless waiting.
        enforce = getattr(ctx.require_services(), "enforce_egress", None)
        if enforce is not None:
            for device in target_devices:
                await enforce(
                    device["mgmt_host"],
                    device.get("mgmt_port", 22),
                    proto="tcp",
                    kind="reachability check",
                )

        start_time = datetime.now(UTC)
        # Track stability per device (all devices validated to have mgmt_host above)
        device_stable_start: dict[str, datetime | None] = {
            d.get("id", d.get("mgmt_host")): None for d in target_devices
        }
        attempts = 0
        all_evidence = []

        while True:
            elapsed = (datetime.now(UTC) - start_time).total_seconds()
            if elapsed > max_wait_seconds:
                not_stable = [
                    d.get("name", d.get("mgmt_host"))
                    for d in target_devices
                    if device_stable_start.get(d.get("id", d.get("mgmt_host"))) is None
                ]
                return HandlerResult(
                    success=False,
                    error=f"Timeout waiting for devices: {', '.join(not_stable)}",
                    summary=f"Devices not reachable after {max_wait_seconds}s",
                    metrics={"attempts": attempts, "elapsed_seconds": elapsed},
                    evidence=all_evidence,
                )

            attempts += 1
            all_stable = True

            for device in target_devices:
                device_id = device.get("id", device.get("mgmt_host"))
                device_name = device.get("name", device_id)
                host: str = device["mgmt_host"]  # validated non-None above
                port = device.get("mgmt_port", 22)

                reachable = await self._check_tcp(host, port, connect_timeout)

                if reachable:
                    if device_stable_start[device_id] is None:
                        device_stable_start[device_id] = datetime.now(UTC)
                        logger.info(
                            f"Device {device_name} became reachable, starting stability window"
                        )
                        all_stable = False  # Just became reachable, not yet stable
                    else:
                        stable_start = device_stable_start[device_id]
                        if stable_start is not None:
                            stable_duration = (datetime.now(UTC) - stable_start).total_seconds()
                            if stable_duration < stable_seconds:
                                all_stable = False
                            else:
                                logger.info(
                                    f"Device {device_name} stable for {stable_duration:.1f}s"
                                )
                else:
                    if device_stable_start[device_id] is not None:
                        logger.info(f"Device {device_name} went unreachable, resetting stability")
                    device_stable_start[device_id] = None
                    all_stable = False

            if all_stable and all(s is not None for s in device_stable_start.values()):
                # All devices are stable
                for device in target_devices:
                    device_id = device.get("id", device.get("mgmt_host"))
                    device_name = device.get("name", device_id)
                    all_evidence.append(
                        {
                            "kind": "transport_meta",
                            "name": f"reachability_check_{device_name}",
                            "device_id": device_id,
                            "content_json": {
                                "device_id": device_id,
                                "device_name": device_name,
                                "host": device.get("mgmt_host"),
                                "port": device.get("mgmt_port", 22),
                                "success": True,
                                "stable_seconds": stable_seconds,
                            },
                        }
                    )
                return HandlerResult(
                    success=True,
                    summary=f"All {len(target_devices)} device(s) stable for {stable_seconds}s",
                    metrics={
                        "attempts": attempts,
                        "elapsed_seconds": elapsed,
                        "stable_seconds": stable_seconds,
                        "device_count": len(target_devices),
                    },
                    evidence=all_evidence,
                )

            await asyncio.sleep(poll_interval)

    async def _check_tcp(self, host: str, port: int, timeout: float) -> bool:
        """Check TCP connectivity."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(loop.sock_connect(sock, (host, port)), timeout=timeout)
            return True
        except Exception:
            return False
        finally:
            sock.close()
