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


#: How much sooner a probe through a SOCKS5 proxy must finish than its poll.
_PROXY_GRACE_SECONDS = 0.25

#: Failures that mean only that no answer came in time.
NO_ANSWER_ERRORS = frozenset({"timeout", "no_response", "packet_loss"})


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
    *,
    proxy_stage: bool = False,
) -> ProbeResult | None:
    """Poll one target once; its probe result, or None when the poll was skipped.

    A poll never outlasts ``deadline`` (loop time), also when it starts late
    in a round with more targets than run at once: one that would start at
    or after it is skipped (None), since it learns nothing about the target.
    A poll the deadline cut short that got no answer at all is skipped (None)
    too: silence for less than Connect Timeout proves nothing, while a clear
    refusal does. A probe that does not answer in its full time is a failed
    ``timeout`` result. With ``proxy_stage``, a probe through a SOCKS5 proxy
    gets a little less time than the poll, so it can tell a proxy that
    stalled (a socks_error) from a target that did not answer, and a poll
    that still runs out is a socks_error too: which end stalled is unknown. run_probe applies the flow egress gate, so a
    denied target raises here on its first poll and fails the step with the
    policy's reason. Raises ``CheckUnavailable``
    when the worker has no such check, and ``CheckMisconfigured`` when the
    probe refuses its options, which it would do on every poll.
    """
    loop = asyncio.get_running_loop()
    timeout = min(config.connect_timeout_seconds, deadline - loop.time())
    if timeout <= 0:
        return None
    socks_proxy = config.socks_proxy.strip()
    probe_timeout = timeout
    if proxy_stage and socks_proxy and timeout > 2 * _PROXY_GRACE_SECONDS:
        probe_timeout = timeout - _PROXY_GRACE_SECONDS
    options: dict[str, Any] = {"timeout_ms": max(1, int(probe_timeout * 1000))}
    port = poll_port(config, device)
    if port is not None:
        options["port"] = port
    if config.check_type == "http_health":
        options["url_path"] = config.url_path or "/health"
    elif config.check_type == "icmp_ping":
        options["count"] = 1
    if socks_proxy:
        options["socks_proxy"] = socks_proxy
    try:
        result = await asyncio.wait_for(
            services.run_probe(config.check_type, device["mgmt_host"], options),
            timeout=timeout,
        )
    except TimeoutError:
        result = ProbeResult(
            ok=False,
            # Through a proxy, a poll the probe could not finish says nothing
            # about which end stalled.
            error_kind="socks_error" if proxy_stage and socks_proxy else "timeout",
            error_detail=f"no answer within {timeout:g}s",
        )
    except KeyError:
        raise CheckUnavailable from None
    if result.error_kind == "config_error":
        name = device.get("name", device["mgmt_host"])
        raise CheckMisconfigured(f"{name}: {result.error_detail}")
    if (
        not result.ok
        and result.error_kind in NO_ANSWER_ERRORS
        and timeout < config.connect_timeout_seconds
    ):
        return None
    return result
