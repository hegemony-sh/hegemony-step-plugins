# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the monitor wheel: target resolution + thin handler shells."""

from __future__ import annotations

from typing import Any, cast

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_steps_monitor.handlers import (
    ConnectivityMonitorHandler,
    ConnectivityMonitorStartHandler,
    ConnectivityMonitorStopHandler,
)
from hegemony_steps_monitor.targets import extract_ip_addresses, resolve_targets

# ── target resolution ────────────────────────────────────────────────────────


def test_extract_ip_addresses_dedupes_and_orders():
    selector = {"type": "ip", "ip": "192.0.2.1", "addresses": ["192.0.2.1", " 192.0.2.2 ", ""]}
    assert extract_ip_addresses(selector) == ["192.0.2.1", "192.0.2.2"]


def test_resolve_ip_targets():
    resolved = resolve_targets({"targets": [{"type": "ip", "addresses": ["10.0.0.1"]}]}, {})
    assert resolved == [
        {
            "instance_id": "ip:10.0.0.1",
            "selector_index": 0,
            "selector_type": "ip",
            "role": None,
            "device_id": None,
            "address": "10.0.0.1",
        }
    ]


def test_resolve_role_targets():
    devices = {"core": [{"id": "d1", "mgmt_host": "10.0.0.9"}]}
    resolved = resolve_targets({"targets": [{"type": "role", "role": "core"}]}, devices)
    assert len(resolved) == 1
    assert resolved[0]["selector_type"] == "role"
    assert resolved[0]["role"] == "core"
    assert resolved[0]["address"] == "10.0.0.9"


def test_resolve_missing_role_yields_nothing():
    assert resolve_targets({"targets": [{"type": "role", "role": "absent"}]}, {}) == []


def test_resolve_rejects_unknown_address_kind():
    import pytest

    with pytest.raises(ValueError, match="address_kind"):
        resolve_targets({"address_kind": "loopbck", "targets": []}, {})
    with pytest.raises(ValueError, match="address_family"):
        resolve_targets({"address_family": "ipv7", "targets": []}, {})


# ── handler shells ───────────────────────────────────────────────────────────


class _FakeServices:
    def __init__(self, *, registered: bool = True, started: str = "db-1", stopped: bool = True):
        self._registered = registered
        self._started = started
        self._stopped = stopped
        self.start_calls: list[tuple[dict, list]] = []
        self.start_phases: list[str | None] = []
        self.stop_calls: list[tuple[str, str]] = []

    def is_check_registered(self, check_id: str) -> bool:
        return self._registered

    async def start_monitor(self, config, resolved_targets, **kw) -> str:
        self.start_calls.append((config, resolved_targets))
        self.start_phases.append(kw.get("phase"))
        return self._started

    async def stop_monitor(self, monitor_id: str, *, reason: str = "step_requested") -> bool:
        self.stop_calls.append((monitor_id, reason))
        return self._stopped


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


async def test_start_handler_requires_registered_check():
    services = _FakeServices(registered=False)
    ctx = _ctx({"monitor": {"monitor_id": "m1", "check_id": "bogus", "targets": []}}, services)
    result = await ConnectivityMonitorStartHandler().execute(ctx)
    assert result.success is False
    assert "not registered" in (result.error or "")


async def test_start_handler_reports_invalid_address_kind_cleanly():
    services = _FakeServices()
    ctx = _ctx(
        {
            "monitor": {
                "monitor_id": "m1",
                "check_id": "tcp_connect",
                "address_kind": "loopbck",
                "targets": [{"type": "role", "role": "core"}],
            }
        },
        services,
    )
    result = await ConnectivityMonitorStartHandler().execute(ctx)
    assert result.success is False
    assert "address_kind" in (result.error or "")
    assert not services.start_calls


async def test_stop_handler_calls_services():
    services = _FakeServices()
    result = await ConnectivityMonitorStopHandler().execute(
        _ctx({"monitor_id": "m1", "reason": "join_fired"}, services)
    )
    assert result.success is True
    assert services.stop_calls == [("m1", "join_fired")]


def test_address_family_prefers_matching_literal():
    """ipv4/ipv6 pick the first candidate of that family for role devices."""
    devices = {
        "core": [
            {
                "id": "d1",
                "mgmt_ips": ["10.0.0.1", "2001:db8::1"],
                "mgmt_host": "r1.example",
            }
        ]
    }
    config = {"address_kind": "primary", "targets": [{"type": "role", "role": "core"}]}

    v6 = resolve_targets({**config, "address_family": "ipv6"}, devices)
    assert [t["address"] for t in v6] == ["2001:db8::1"]
    v4 = resolve_targets({**config, "address_family": "ipv4"}, devices)
    assert [t["address"] for t in v4] == ["10.0.0.1"]
    auto = resolve_targets({**config, "address_family": "auto"}, devices)
    assert [t["address"] for t in auto] == ["10.0.0.1"]


def test_address_family_falls_back_when_no_literal_matches():
    """A preference, not a filter: hostnames and lone v4 still resolve under ipv6."""
    devices = {"core": [{"id": "d1", "mgmt_host": "r1.example"}]}
    resolved = resolve_targets(
        {"address_family": "ipv6", "targets": [{"type": "role", "role": "core"}]},
        devices,
    )
    assert [t["address"] for t in resolved] == ["r1.example"]


def test_address_family_leaves_explicit_ip_targets_alone():
    """Explicit IP selectors are used exactly as written, whatever the family."""
    resolved = resolve_targets(
        {"address_family": "ipv6", "targets": [{"type": "ip", "addresses": ["10.9.9.9"]}]},
        {},
    )
    assert [t["address"] for t in resolved] == ["10.9.9.9"]
