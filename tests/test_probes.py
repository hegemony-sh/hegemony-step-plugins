# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Registration and behavior tests for the hegemony-probe-net wheel."""

import asyncio
import contextlib
import os
import signal
import sys

import httpx
import pytest

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


async def test_tcp_connect_handles_an_ipv6_literal_without_raising():
    """An IPv6 target is a reachability question, not a crash, also on hosts
    whose kernel lacks IPv6 entirely."""
    from hegemony_probe_net.tcp_connect import TcpConnectProbe

    result = await TcpConnectProbe().execute("2001:db8::7", {"port": 22, "timeout_ms": 200})
    assert result.ok is False


async def test_dns_resolve_localhost():
    from hegemony_probe_net.dns_resolve import DnsResolveProbe

    result = await DnsResolveProbe().execute("localhost", {"timeout_ms": 2000})
    assert result.ok is True
    assert result.metrics.get("addresses", 0) >= 1


async def test_dns_resolve_refuses_an_ip_target_without_a_hostname():
    """The resolver hands an IP literal back unasked, which used to pass."""
    from hegemony_probe_net.dns_resolve import DnsResolveProbe

    probe = DnsResolveProbe()
    for address in ("192.0.2.7", "2001:db8::7"):
        for options in ({}, {"hostname": "  "}):
            result = await probe.execute(address, {"timeout_ms": 2000, **options})
            assert result.ok is False, (address, options)
            assert result.error_kind == "config_error"
            assert "needs a hostname" in (result.error_detail or "")
    # With a name to look up, the IP target is only where the question came from.
    result = await probe.execute("192.0.2.7", {"hostname": "localhost", "timeout_ms": 2000})
    assert result.ok is True, result.error_detail


async def test_dns_resolve_refuses_an_ip_address_as_the_hostname():
    """The hostname option is handed back unasked too when it is an IP
    address. A bracketed IPv6 address counts as one rather than failing as
    a name that does not resolve."""
    from hegemony_probe_net.dns_resolve import DnsResolveProbe

    probe = DnsResolveProbe()
    for address in ("localhost", "192.0.2.7"):
        for hostname in ("192.0.2.9", " 192.0.2.9 ", "2001:db8::9", "[2001:db8::9]"):
            options = {"hostname": hostname, "timeout_ms": 2000}
            result = await probe.execute(address, options)
            assert result.ok is False, (address, hostname)
            assert result.error_kind == "config_error", (address, hostname)
            assert result.error_detail == (
                f"dns_resolve needs a hostname to look up: the hostname "
                f"{hostname.strip()} is an IP address"
            )


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


@pytest.mark.skipif(sys.platform == "win32", reason="uses a POSIX shell script as ping")
async def test_icmp_ping_kills_and_reaps_ping_when_cancelled(tmp_path, monkeypatch):
    """A caller's deadline cancels the probe while ping still runs; the
    child must not outlive it."""
    from hegemony_probe_net.icmp_ping import IcmpPingProbe

    pid_file = tmp_path / "ping.pid"
    fake_ping = tmp_path / "ping"
    fake_ping.write_text(f'#!/bin/sh\necho $$ > "{pid_file}"\nexec sleep 30\n')
    fake_ping.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")

    task = asyncio.ensure_future(
        IcmpPingProbe().execute("192.0.2.7", {"count": 1, "timeout_ms": 1000})
    )
    for _ in range(500):
        if pid_file.exists() and pid_file.read_text().strip():
            break
        await asyncio.sleep(0.01)
    pid = int(pid_file.read_text())
    try:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # Killed and reaped: a zombie would still accept signal 0.
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
