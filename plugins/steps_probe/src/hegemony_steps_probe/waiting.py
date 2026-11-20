# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What ``probe.wait_reachable`` and ``probe.wait_unreachable`` share.

Both poll every target through ``ctx.services.run_probe``, so the flow
egress gate, SOCKS proxies, ICMP and IPv6 work the same way in both.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from hegemony_step_sdk import HandlerResult, HandlerServices, ProbeResult

from .checks import PORT_CHECKS, CheckUnavailable, default_port

if TYPE_CHECKING:
    from .wait_reachable import WaitReachableConfig


class CheckMisconfigured(Exception):
    """The probe refused its options (a ``config_error``); no poll can pass."""


def poll_port(config: WaitReachableConfig, device: dict[str, Any]) -> int | None:
    """The port polled on ``device``, or None for a check without one."""
    if config.check_type not in PORT_CHECKS:
        return None
    if config.port is not None:
        return config.port
    return default_port(config.check_type, device.get("mgmt_port") or 22)


def missing_host(target_devices: list[dict[str, Any]]) -> HandlerResult | None:
    """The failure for the first target without a management address, if any."""
    for device in target_devices:
        if not device.get("mgmt_host"):
            device_name = device.get("name", device.get("id", "unknown"))
            return HandlerResult(
                success=False,
                error=f"Device '{device_name}' has no mgmt_host configured",
                summary=f"Device '{device_name}' missing mgmt_host — cannot check reachability",
            )
    return None


async def poll_target(
    services: HandlerServices,
    config: WaitReachableConfig,
    device: dict[str, Any],
    deadline: float,
) -> ProbeResult | None:
    """Poll one target once; its probe result, or None when it did not answer in time.

    A poll never outlasts ``deadline`` (loop time), also when it starts late
    in a round with more targets than run at once. run_probe applies the
    flow egress gate, so a denied target raises here on its first poll and
    fails the step with the policy's reason. Raises ``CheckUnavailable``
    when the worker has no such check, and ``CheckMisconfigured`` when the
    probe refuses its options, which it would do on every poll.
    """
    loop = asyncio.get_running_loop()
    timeout = min(config.connect_timeout_seconds, deadline - loop.time())
    if timeout <= 0:
        return None
    options: dict[str, Any] = {"timeout_ms": max(1, int(timeout * 1000))}
    port = poll_port(config, device)
    if port is not None:
        options["port"] = port
    if config.check_type == "http_health":
        options["url_path"] = config.url_path or "/health"
    elif config.check_type == "icmp_ping":
        options["count"] = 1
    socks_proxy = config.socks_proxy.strip()
    if socks_proxy:
        options["socks_proxy"] = socks_proxy
    try:
        result = await asyncio.wait_for(
            services.run_probe(config.check_type, device["mgmt_host"], options),
            timeout=timeout,
        )
    except TimeoutError:
        return None
    except KeyError:
        raise CheckUnavailable from None
    if result.error_kind == "config_error":
        name = device.get("name", device["mgmt_host"])
        raise CheckMisconfigured(f"{name}: {result.error_detail}")
    return result
