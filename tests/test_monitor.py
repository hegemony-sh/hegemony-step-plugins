# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the monitor wheel: IP selector parsing + the connectivity handler shell."""

from __future__ import annotations

from typing import Any, cast

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_steps_monitor.handlers import ConnectivityMonitorHandler
from hegemony_steps_monitor.targets import extract_ip_addresses

# ── IP selectors ─────────────────────────────────────────────────────────────


def test_extract_ip_addresses_dedupes_and_orders():
    selector = {"type": "ip", "ip": "192.0.2.1", "addresses": ["192.0.2.1", " 192.0.2.2 ", ""]}
    assert extract_ip_addresses(selector) == ["192.0.2.1", "192.0.2.2"]


# ── handler shell ────────────────────────────────────────────────────────────


class _FakeServices:
    def __init__(self, *, registered: bool = True, started: str = "db-1"):
        self._registered = registered
        self._started = started
        self.start_calls: list[tuple[dict, list]] = []
        self.start_phases: list[str | None] = []

    def is_check_registered(self, check_id: str) -> bool:
        return self._registered

    async def start_monitor(self, config, resolved_targets, **kw) -> str:
        self.start_calls.append((config, resolved_targets))
        self.start_phases.append(kw.get("phase"))
        return self._started


def _ctx(
    config: dict[str, Any],
    services: _FakeServices,
    devices=None,
    tags: dict[str, str] | None = None,
) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        target_roles=["core"],
        target_devices_by_role=devices or {"core": [{"id": "d1", "mgmt_host": "10.0.0.9"}]},
        services=cast(HandlerServices, services),
        tags=tags or {},
    )


async def test_connectivity_starts_monitor_via_services():
    services = _FakeServices()
    result = await ConnectivityMonitorHandler().execute(
        _ctx({"check_type": "tcp_connect", "port": 22}, services)
    )
    assert result.success is True
    assert result.metrics["monitor_db_id"] == "db-1"
    assert result.metrics["background_monitor"] is True
    assert len(services.start_calls) == 1
    config, resolved = services.start_calls[0]
    assert config["check_id"] == "tcp_connect"
    assert resolved[0]["address"] == "10.0.0.9"
    # No socks_proxy configured → the option is absent.
    assert "socks_proxy" not in config["options"]


async def test_connectivity_forwards_socks_proxy_option():
    services = _FakeServices()
    proxy = "socks5://u:p@dind:1080"
    result = await ConnectivityMonitorHandler().execute(
        _ctx({"check_type": "tcp_connect", "port": 22, "socks_proxy": proxy}, services)
    )
    assert result.success is True
    config, _ = services.start_calls[0]
    # A monitor can watch targets reachable only through a bastion.
    assert config["options"]["socks_proxy"] == proxy


async def test_connectivity_hands_the_phase_tag_to_the_monitor():
    """The monitor is filed under the step's ``phase`` tag, read straight off ``ctx.tags``.

    An untagged step passes ``None``, which the platform reads as "no phase".
    """
    tagged = _FakeServices()
    result = await ConnectivityMonitorHandler().execute(
        _ctx({"check_type": "tcp_connect", "port": 22}, tagged, tags={"phase": "VERIFY"})
    )
    assert result.success is True
    assert tagged.start_phases == ["VERIFY"]

    untagged = _FakeServices()
    await ConnectivityMonitorHandler().execute(
        _ctx({"check_type": "tcp_connect", "port": 22}, untagged)
    )
    assert untagged.start_phases == [None]


async def test_connectivity_rejects_unregistered_check():
    services = _FakeServices(registered=False)
    result = await ConnectivityMonitorHandler().execute(_ctx({"check_type": "bogus"}, services))
    assert result.success is False
    assert "Unknown check type" in result.summary
    assert not services.start_calls
