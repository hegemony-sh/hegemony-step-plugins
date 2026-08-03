# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SOCKS5-aware probe support (design-dind-sandbox.md §11.4).

Runs the probes against a minimal in-process SOCKS5 server so the whole
handshake path (auth negotiation, CONNECT, tunneled I/O) is exercised, plus
the URL grammar and the icmp_ping rejection contract.
"""

from __future__ import annotations

import asyncio

import pytest

from hegemony_probe_net.http_health import HttpHealthProbe
from hegemony_probe_net.icmp_ping import IcmpPingProbe
from hegemony_probe_net.socks import SocksError, parse_socks_proxy
from hegemony_probe_net.tcp_connect import TcpConnectProbe


class _FakeSocks5Server:
    """A tiny SOCKS5 CONNECT server that bridges to a target, optionally authed.

    Records whether auth was performed and what destination was requested, then
    proxies bytes both ways so a real HTTP exchange can flow over the tunnel.
    """

    def __init__(self, *, require_auth: bool = False, upstream_response: bytes | None = None):
        self.require_auth = require_auth
        self.upstream_response = upstream_response
        self.authed = False
        self.requested: tuple[str, int] | None = None
        self._server: asyncio.AbstractServer | None = None

    @property
    def port(self) -> int:
        assert self._server is not None
        sockets = list(getattr(self._server, "sockets", []))
        return int(sockets[0].getsockname()[1])

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            version, nmethods = await reader.readexactly(2)
            methods = await reader.readexactly(nmethods)
            assert version == 0x05
            if self.require_auth:
                if 0x02 not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    return
                writer.write(b"\x05\x02")
                await writer.drain()
                ver = (await reader.readexactly(1))[0]
                ulen = (await reader.readexactly(1))[0]
                await reader.readexactly(ulen)
                plen = (await reader.readexactly(1))[0]
                await reader.readexactly(plen)
                assert ver == 0x01
                self.authed = True
                writer.write(b"\x01\x00")
                await writer.drain()
            else:
                writer.write(b"\x05\x00")
                await writer.drain()

            ver, cmd, _rsv, atyp = await reader.readexactly(4)
            assert ver == 0x05 and cmd == 0x01 and atyp == 0x03
            hlen = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(hlen)).decode()
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.requested = (host, port)

            # Success reply with a dummy bound address.
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            if self.upstream_response is not None:
                # Read the tunneled request (until blank line) then reply.
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b""):
                        break
                writer.write(self.upstream_response)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()


# ── URL grammar ───────────────────────────────────────────────────────────────


def test_parse_socks_proxy_reads_credentials_and_scheme():
    proxy = parse_socks_proxy("socks5://jump:s3cret@dind:1080")
    assert (proxy.host, proxy.port) == ("dind", 1080)
    assert proxy.username == "jump"
    assert proxy.password == "s3cret"
    assert proxy.remote_dns is False

    remote = parse_socks_proxy("socks5h://dind:1080")
    assert remote.remote_dns is True
    assert remote.username is None


def test_parse_socks_proxy_rejects_bad_input():
    for value in ("http://dind:1080", "socks5://dind", "socks4://dind:1080", "dind:1080"):
        with pytest.raises(SocksError):
            parse_socks_proxy(value)


# ── tcp_connect through the proxy ─────────────────────────────────────────────


async def test_tcp_connect_dials_through_authenticated_proxy():
    server = _FakeSocks5Server(require_auth=True)
    await server.start()
    try:
        result = await TcpConnectProbe().execute(
            "10.9.9.9",
            {
                "port": 22,
                "timeout_ms": 3000,
                "socks_proxy": f"socks5://jump:pw@127.0.0.1:{server.port}",
            },
        )
    finally:
        await server.stop()

    assert result.ok is True
    assert server.authed is True
    # The destination reaches the proxy as a name+port, not the local socket.
    assert server.requested == ("10.9.9.9", 22)


async def test_tcp_connect_reports_socks_error_for_unreachable_proxy():
    result = await TcpConnectProbe().execute(
        "10.9.9.9",
        {"port": 22, "timeout_ms": 1000, "socks_proxy": "socks5://127.0.0.1:1/"},
    )
    assert result.ok is False
    assert result.error_kind in {"socks_error", "timeout"}


async def test_tcp_connect_rejects_bad_proxy_url():
    result = await TcpConnectProbe().execute(
        "10.9.9.9", {"port": 22, "socks_proxy": "http://nope:8080"}
    )
    assert result.ok is False
    assert result.error_kind == "socks_error"


# ── http_health through the proxy ─────────────────────────────────────────────


async def test_http_health_tunnels_the_request():
    server = _FakeSocks5Server(
        require_auth=True, upstream_response=b"HTTP/1.1 204 No Content\r\n\r\n"
    )
    await server.start()
    try:
        result = await HttpHealthProbe().execute(
            "10.9.9.9",
            {
                "port": 8080,
                "url_path": "/healthz",
                "timeout_ms": 3000,
                "socks_proxy": f"socks5://jump:pw@127.0.0.1:{server.port}",
            },
        )
    finally:
        await server.stop()

    assert result.ok is True
    assert result.metrics["http_status"] == 204
    assert server.requested == ("10.9.9.9", 8080)


async def test_http_health_surfaces_bad_status_over_tunnel():
    server = _FakeSocks5Server(
        upstream_response=b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"
    )
    await server.start()
    try:
        result = await HttpHealthProbe().execute(
            "10.9.9.9",
            {"port": 80, "timeout_ms": 3000, "socks_proxy": f"socks5://127.0.0.1:{server.port}"},
        )
    finally:
        await server.stop()

    assert result.ok is False
    assert result.metrics["http_status"] == 503


# ── icmp_ping rejection ───────────────────────────────────────────────────────


async def test_icmp_ping_rejects_socks_proxy():
    result = await IcmpPingProbe().execute(
        "10.9.9.9", {"socks_proxy": "socks5://dind:1080", "count": 1}
    )
    assert result.ok is False
    assert result.error_kind == "config_error"
    assert "tcp_connect" in (result.error_detail or "")
