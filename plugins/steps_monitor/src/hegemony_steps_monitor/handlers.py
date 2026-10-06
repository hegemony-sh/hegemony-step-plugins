# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Connectivity monitor handler (monitor.connectivity).

A thin shell over the host monitor machinery: it assembles the monitor config
and resolves targets (pure), then hands off to ``services.start_monitor``. The
host owns ``MonitorManager`` and the engine's until-join / run-cleanup
semantics (keyed off the ``monitor.`` id prefix).
"""

from __future__ import annotations

import logging
from typing import Any

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    InvalidConfigError,
    StepKind,
)

from .config import ConnectivityMonitorConfig
from .targets import extract_ip_addresses

logger = logging.getLogger(__name__)

#: Ports a check uses when the step sets none, as in probe.connectivity: 80 for
#: HTTP Health, where SSH's 22, the default of the other checks, would be wrong.
_CHECK_DEFAULT_PORTS = {"http_health": 80}


class ConnectivityMonitorHandler(BaseHandler):
    """Unified connectivity monitoring handler (``monitor.connectivity``)."""

    handler_id = "monitor.connectivity"
    supported_kinds = [StepKind.CHECK]
    display_name = "Connectivity Monitor"
    description = "Continuously probe targets in the background during a flow run."
    category = "Checks"
    config_model = ConnectivityMonitorConfig
    default_config = {
        "check_type": "tcp_connect",
        "interval_ms": 5000,
        "schedule_mode": "count",
        "count": 10,
    }

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        try:
            config = self.parse_config(ctx.config, ConnectivityMonitorConfig)
        except InvalidConfigError as exc:
            return exc.result()
        check_type = config.check_type
        interval_ms = config.interval_ms
        schedule_mode = config.schedule_mode

        services = ctx.require_services()
        if not services.is_check_registered(check_type):
            return HandlerResult(
                success=False,
                error=f"Invalid check_type: {check_type}",
                summary=f"Unknown check type: {check_type}",
            )

        monitor_id = ctx.config.get("monitor_id", ctx.step_id)

        # Resolve targets - support both role-based and explicit IP targeting.
        resolved_targets: list[dict[str, Any]] = []
        target_selectors = list(ctx.target_selectors or ctx.config.get("targets", []))

        if target_selectors:
            for idx, selector in enumerate(target_selectors):
                selector_type = selector.get("type", "role")
                if selector_type == "ip":
                    for addr in extract_ip_addresses(selector):
                        resolved_targets.append(
                            {
                                "instance_id": f"{monitor_id}:ip:{addr}",
                                "selector_index": idx,
                                "selector_type": "ip",
                                "role": None,
                                "device_id": None,
                                "address": addr,
                            }
                        )
                elif selector_type == "role":
                    role = selector.get("role", "")
                    for device in ctx.target_devices_by_role.get(role, []):
                        address = device.get("mgmt_host")
                        if address:
                            resolved_targets.append(
                                {
                                    "instance_id": f"{monitor_id}:{role}:{device.get('id', 'unknown')}",
                                    "selector_index": idx,
                                    "selector_type": "role",
                                    "role": role,
                                    "device_id": device.get("id"),
                                    "address": address,
                                }
                            )
        else:
            target_devices = ctx.get_target_devices()
            if not target_devices:
                return HandlerResult(
                    success=False,
                    error="No target devices configured",
                    summary="Missing target devices",
                )
            target_selectors = []
            for i, device in enumerate(target_devices):
                address = device.get("mgmt_host")
                target_selectors.append(
                    {
                        "type": "role",
                        "role": device.get("role", "default"),
                        "device_id": device.get("id"),
                        "address": address,
                    }
                )
                if address:
                    resolved_targets.append(
                        {
                            "instance_id": f"{monitor_id}:{i}:{device.get('id', 'unknown')}:{address}",
                            "selector_index": i,
                            "selector_type": "role",
                            "role": device.get("role", "default"),
                            "device_id": device.get("id"),
                            "address": address,
                        }
                    )

        if not resolved_targets:
            return HandlerResult(
                success=False, error="No valid targets with addresses", summary="No targets found"
            )

        options: dict[str, Any] = {"timeout_ms": config.attempt_timeout_seconds * 1000}
        if check_type in ("tcp_connect", "http_health", "tls_handshake", "ssh_banner"):
            options["port"] = config.port or _CHECK_DEFAULT_PORTS.get(check_type, 22)
        if check_type == "http_health":
            options["url_path"] = config.url_path or "/health"
        if check_type == "icmp_ping":
            options["count"] = config.ping_count
        # Forward the authenticated SOCKS proxy so a monitor can watch targets
        # only reachable through a bastion (e.g. a lab management subnet behind
        # dind:1080). The TCP-based checks tunnel through it; the probe layer
        # rejects it for icmp_ping. Form: socks5[h]://[user:pass@]host:port
        if config.socks_proxy.strip():
            options["socks_proxy"] = config.socks_proxy.strip()

        schedule: dict[str, Any] = {"schedule_mode": schedule_mode, "interval_ms": interval_ms}
        if schedule_mode == "count":
            schedule["count"] = config.count
        elif schedule_mode == "duration":
            schedule["duration_s"] = config.duration_seconds

        monitor_config = {
            "monitor_id": monitor_id,
            "check_id": check_type,
            "schedule": schedule,
            "options": options,
            "target_selectors": target_selectors,
        }

        try:
            db_id = await services.start_monitor(
                monitor_config,
                resolved_targets,
                run_id=ctx.run_id,
                step_id=ctx.step_id,
                step_run_id=ctx.step_run_id,
                phase=ctx.tags.get("phase"),
            )
        except Exception as e:  # noqa: BLE001 - surfaced as a step failure
            logger.exception("Failed to start monitor %s", monitor_id)
            return HandlerResult(
                success=False, error=str(e), summary=f"Failed to start monitor: {e}"
            )

        logger.info("Monitor %s started in background (mode=%s)", monitor_id, schedule_mode)
        return HandlerResult(
            success=True,
            summary=(
                f"Monitor {check_type} started: {len(resolved_targets)} targets, "
                f"{schedule_mode} mode"
            ),
            metrics={
                "monitor_db_id": db_id,
                "target_count": len(resolved_targets),
                "schedule_mode": schedule_mode,
                "background_monitor": True,
            },
            evidence=[
                {
                    "kind": "transport_meta",
                    "name": f"monitor_started_{monitor_id}",
                    "content_json": {
                        "monitor_id": monitor_id,
                        "check_id": check_type,
                        "schedule_mode": schedule_mode,
                        "interval_ms": interval_ms,
                        "target_count": len(resolved_targets),
                    },
                }
            ],
        )
