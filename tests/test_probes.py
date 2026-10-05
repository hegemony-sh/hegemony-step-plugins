# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Registration and behavior tests for the hegemony-probe-net wheel."""

import httpx

import hegemony_probe_net
from hegemony_probe_net import http_health
from hegemony_step_sdk import BaseProbe, ProbeResult

EXPECTED_PROBE_IDS = {"tcp_connect", "icmp_ping", "http_health", "dns_resolve"}


def test_all_probes_are_base_probes_with_ids():
    ids = set()
    for cls in hegemony_probe_net.ALL_PROBES:
        assert issubclass(cls, BaseProbe), cls.__name__
        assert cls.probe_id, cls.__name__
        ids.add(cls.probe_id)
    assert ids == EXPECTED_PROBE_IDS


def test_register_populates_a_registry():
    registered: list[type] = []

    class _Registry:
        def register_probe(self, probe_class: type) -> None:
            registered.append(probe_class)

    hegemony_probe_net.register(_Registry())
    assert set(registered) == set(hegemony_probe_net.ALL_PROBES)


def test_tcp_connect_requires_port():
    from hegemony_probe_net.tcp_connect import TcpConnectProbe

    async def run() -> ProbeResult:
        return await TcpConnectProbe().execute("192.0.2.1", {})

    import asyncio

    result = asyncio.run(run())
    assert result.ok is False
    assert result.error_kind == "config_error"


async def test_tcp_connect_connection_refused():
    from hegemony_probe_net.tcp_connect import TcpConnectProbe

    # localhost:1 is almost certainly closed → fast refusal.
    result = await TcpConnectProbe().execute("127.0.0.1", {"port": 1, "timeout_ms": 2000})
    assert result.ok is False
    assert result.error_kind in {"connection_refused", "timeout", "network_error"}


async def test_dns_resolve_localhost():
    from hegemony_probe_net.dns_resolve import DnsResolveProbe

    result = await DnsResolveProbe().execute("localhost", {"timeout_ms": 2000})
    assert result.ok is True
    assert result.metrics.get("addresses", 0) >= 1


def _route_http_health_to(monkeypatch, answer) -> None:
    """Send the probe's direct requests to ``answer`` instead of the network."""
    real_client = httpx.AsyncClient

    def client_with_mock_transport(**kwargs):
        kwargs["transport"] = httpx.MockTransport(answer)
        return real_client(**kwargs)

    monkeypatch.setattr(http_health.httpx, "AsyncClient", client_with_mock_transport)


async def test_http_health_brackets_an_ipv6_target(monkeypatch):
    from hegemony_probe_net.http_health import HttpHealthProbe

    seen: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200)

    _route_http_health_to(monkeypatch, answer)
    probe = HttpHealthProbe()
    for port in (8080, None):
        result = await probe.execute("2001:db8::7", {"port": port, "timeout_ms": 1000})
        assert result.ok is True, result.error_detail
    assert seen == ["http://[2001:db8::7]:8080/health", "http://[2001:db8::7]/health"]


async def test_http_health_does_not_follow_a_redirect(monkeypatch):
    """The egress gate saw only the first target, so a redirect is the answer:
    a 3xx is below 400 and already counts as healthy."""
    from hegemony_probe_net.http_health import HttpHealthProbe

    seen: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://198.51.100.99/elsewhere"})

    _route_http_health_to(monkeypatch, answer)
    result = await HttpHealthProbe().execute("192.0.2.7", {"timeout_ms": 1000})
    assert result.ok is True, result.error_detail
    assert result.metrics["http_status"] == 302
    assert seen == ["http://192.0.2.7/health"]
