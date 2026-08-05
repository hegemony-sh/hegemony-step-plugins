# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Connectivity monitor handlers (monitor.connectivity / .start / .stop).

Thin shells over the host monitor machinery: they assemble the monitor config
and resolve targets (pure), then hand off to ``services.start_monitor`` /
``services.stop_monitor``. The host owns ``MonitorManager`` and the engine's
until-join / run-cleanup semantics (keyed off the ``monitor.`` id prefix).
"""

from __future__ import annotations

import logging
from typing import Any

from hegemony_step_sdk import BaseHandler, HandlerContext, HandlerResult, HandlerTargeting, StepKind

from .config import ConnectivityMonitorConfig, MonitorLifecycleConfig
from .targets import extract_ip_addresses, resolve_targets

logger = logging.getLogger(__name__)


class ConnectivityMonitorStartHandler(BaseHandler):
    """Handler to start a connectivity monitor (internal lifecycle)."""

    handler_id = "monitor.start"
    supported_kinds = [StepKind.CHECK]
    display_name = "Connectivity Monitor: Start"
    description = "Internal: start a background connectivity monitor."
    category = "Checks"
    hidden = True
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = MonitorLifecycleConfig

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        config = ctx.config.get("monitor")
        if not config:
            return HandlerResult(
                success=False,
                error="No monitor configuration provided",
                summary="Missing monitor config",
            )

        monitor_id = config.get("monitor_id")
        if not monitor_id:
            return HandlerResult(
                success=False, error="monitor_id is required", summary="Missing monitor_id"
            )

        check_id_str = config.get("check_id")
        if not check_id_str:
            return HandlerResult(
                success=False, error="check_id is required", summary="Missing check_id"
            )

        services = ctx.require_services()
        if not services.is_check_registered(check_id_str):
            return HandlerResult(
                success=False,
                error=f"Check {check_id_str} is not registered",
                summary=f"Unknown check: {check_id_str}",
            )

        try:
            resolved = resolve_targets(config, ctx.target_devices_by_role)
        except ValueError as exc:
            return HandlerResult(
                success=False, error=str(exc), summary="Invalid monitor target config"
            )
        if not resolved:
            return HandlerResult(
                success=False,
                error="No targets resolved from selectors",
                summary="No targets found",
            )

        try:
            db_id = await services.start_monitor(
                config,
                resolved,
                run_id=ctx.run_id,
                step_id=ctx.step_id,
                step_run_id=ctx.step_run_id,
                phase=ctx.phase,
            )
        except Exception as e:  # noqa: BLE001 - surfaced as a step failure
            logger.exception("Failed to start monitor %s", monitor_id)
            return HandlerResult(
                success=False, error=str(e), summary=f"Failed to start monitor: {e}"
            )

        return HandlerResult(
            success=True,
            summary=f"Started monitor {monitor_id} with {len(resolved)} targets",
            metrics={"monitor_db_id": db_id, "target_count": len(resolved)},
            evidence=[
                {
                    "kind": "transport_meta",
                    "name": f"monitor_started_{monitor_id}",
                    "content_json": {
                        "monitor_id": monitor_id,
                        "check_id": check_id_str,
                        "target_count": len(resolved),
                        "resolved_targets": [
                            {"address": t["address"], "role": t.get("role")} for t in resolved
                        ],
                    },
                }
            ],
        )


class ConnectivityMonitorStopHandler(BaseHandler):
    """Handler to stop a connectivity monitor (internal lifecycle)."""

    handler_id = "monitor.stop"
    supported_kinds = [StepKind.CHECK]
    display_name = "Connectivity Monitor: Stop"
    description = "Internal: stop a background connectivity monitor."
    category = "Checks"
    hidden = True
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = MonitorLifecycleConfig

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        monitor_id = ctx.config.get("monitor_id")
        if not monitor_id:
            return HandlerResult(
                success=False, error="monitor_id is required", summary="Missing monitor_id"
            )

        reason = ctx.config.get("reason", "step_requested")
        services = ctx.require_services()
        stopped = await services.stop_monitor(monitor_id, reason=reason)

        if not stopped:
            return HandlerResult(
                success=False,
                error=f"Monitor {monitor_id} not found or already stopped",
                summary=f"Monitor {monitor_id} not found",
            )

        return HandlerResult(
            success=True,
            summary=f"Stopped monitor {monitor_id}",
            evidence=[
                {
                    "kind": "transport_meta",
                    "name": f"monitor_stopped_{monitor_id}",
                    "content_json": {"monitor_id": monitor_id, "reason": reason},
                }
            ],
        )


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
        "port": 22,
        "interval_ms": 5000,
        "schedule_mode": "count",
        "count": 10,
    }

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        check_type = ctx.config.get("check_type", "tcp_connect")
        port = ctx.config.get("port", 22)
        interval_ms = ctx.config.get("interval_ms", 5000)
        timeout_sec = ctx.config.get("timeout_sec", 10)
        schedule_mode = ctx.config.get("schedule_mode", "count")

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

        options: dict[str, Any] = {"timeout_ms": timeout_sec * 1000}
        if check_type in ("tcp_connect", "http_health", "tls_handshake", "ssh_banner"):
            options["port"] = port
        if check_type == "http_health":
            options["url_path"] = ctx.config.get("url_path", "/health")
        if check_type == "icmp_ping":
            options["count"] = ctx.config.get("ping_count", 3)
        # Forward the authenticated SOCKS proxy so a monitor can watch targets
        # only reachable through a bastion (e.g. a lab management subnet behind
        # dind:1080). The TCP-based checks tunnel through it; the probe layer
        # rejects it for icmp_ping. Form: socks5[h]://[user:pass@]host:port
        socks_proxy = ctx.config.get("socks_proxy")
        if isinstance(socks_proxy, str) and socks_proxy.strip():
            options["socks_proxy"] = socks_proxy.strip()

        schedule: dict[str, Any] = {"schedule_mode": schedule_mode, "interval_ms": interval_ms}
        if schedule_mode == "count":
            schedule["count"] = ctx.config.get("count", 10)
        elif schedule_mode == "duration":
            schedule["duration_s"] = ctx.config.get("duration_sec", 60)

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
                phase=ctx.phase,
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
