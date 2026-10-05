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
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hegemony_probe_net.http_health import HttpHealthProbe
from hegemony_probe_net.icmp_ping import IcmpPingProbe
from hegemony_probe_net.socks import SocksError, SocksProxy, parse_socks_proxy
from hegemony_probe_net.tcp_connect import TcpConnectProbe


class _FakeSocks5Server:
    """A tiny SOCKS5 CONNECT server that bridges to a target, optionally authed.

    Records whether auth was performed and what destination was requested, then
    proxies bytes both ways so a real HTTP exchange can flow over the tunnel.
    """

    def __init__(
        self,
        *,
        require_auth: bool = False,
        upstream_response: bytes | None = None,
        force_no_auth: bool = False,
        hang_after_connect: bool = False,
    ):
        self.require_auth = require_auth
        # Accept the CONNECT then withhold any response (and never close),
        # modelling a slow/withholding target so the probe's own timeout is
        # exercised rather than an EOF.
        self.hang_after_connect = hang_after_connect
        # Always answer the method-selection with no-auth (0x00), even if the
        # client offered only username/password — models an open/misconfigured
        # proxy so the client's refuse-to-connect-unauthenticated path is testable.
        self.force_no_auth = force_no_auth
        self.upstream_response = upstream_response
        self.authed = False
        # The tunneled request's lines (request line and headers), as sent.
        self.request_lines: list[str] = []
        self.requested: tuple[str, int] | None = None
        self.requested_atyp: int | None = None
        self._server: asyncio.AbstractServer | None = None
        self._handlers: set[asyncio.Task] = set()

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
        # asyncio.start_server runs each connection in its own task, and
        # closing the listener does not touch them. The withholding-target test
        # leaves a handler parked in asyncio.sleep(30), so without this the
        # loop closes with a pending task and emits "Task was destroyed but it
        # is pending" — which fails any run configured to error on warnings,
        # for a reason unrelated to what is being tested.
        for task in list(self._handlers):
            task.cancel()
        if self._handlers:
            await asyncio.gather(*self._handlers, return_exceptions=True)
        self._handlers.clear()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._handlers.add(task)
        try:
            version, nmethods = await reader.readexactly(2)
            methods = await reader.readexactly(nmethods)
            assert version == 0x05
            if self.force_no_auth:
                writer.write(b"\x05\x00")
                await writer.drain()
                # A well-behaved client that offered only 0x02 hangs up here.
            elif self.require_auth:
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
            assert ver == 0x05 and cmd == 0x01
            self.requested_atyp = atyp
            if atyp == 0x01:
                host = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 0x04:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            elif atyp == 0x03:
                hlen = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(hlen)).decode()
            else:
                raise AssertionError(f"unexpected ATYP {atyp:#x}")
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.requested = (host, port)

            # Success reply with a dummy bound address.
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            if self.hang_after_connect:
                await asyncio.sleep(30)
            elif self.upstream_response is not None:
                # Read the tunneled request (until blank line) then reply.
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b""):
                        break
                    self.request_lines.append(line.decode("latin-1").rstrip("\r\n"))
                writer.write(self.upstream_response)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass
        finally:
            if task is not None:
                self._handlers.discard(task)
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
    # An IP-literal destination is sent in its native ATYP (IPv4), not wrapped
    # as a DOMAINNAME, and reaches the proxy — not the local socket.
    assert server.requested == ("10.9.9.9", 22)
    assert server.requested_atyp == 0x01


async def test_socks5h_sends_hostname_for_proxy_resolution():
    server = _FakeSocks5Server()
    await server.start()
    try:
        result = await TcpConnectProbe().execute(
            "router.lab.internal",
            {"port": 22, "timeout_ms": 3000, "socks_proxy": f"socks5h://127.0.0.1:{server.port}"},
        )
    finally:
        await server.stop()

    assert result.ok is True
    # socks5h → the proxy resolves the name, so it travels as a DOMAINNAME.
    assert server.requested == ("router.lab.internal", 22)
    assert server.requested_atyp == 0x03


async def test_socks5_resolves_locally_and_reports_failure_clearly():
    # Plain socks5 (no 'h') resolves on the probe host; a name that does not
    # resolve locally must surface a clear error rather than silently asking
    # the proxy to resolve it. The proxy is reachable so we reach the CONNECT
    # (resolution) stage rather than failing on the proxy connection.
    server = _FakeSocks5Server()
    await server.start()
    try:
        result = await TcpConnectProbe().execute(
            "does-not-exist.invalid",
            {"port": 22, "timeout_ms": 2000, "socks_proxy": f"socks5://127.0.0.1:{server.port}"},
        )
    finally:
        await server.stop()

    assert result.ok is False
    assert result.error_kind == "socks_error"
    assert "locally" in (result.error_detail or "")
    # The proxy never received a CONNECT — resolution failed on the probe host.
    assert server.requested is None


async def test_client_refuses_unauthenticated_proxy_when_credentials_configured():
    # An open/misconfigured proxy answers no-auth even though the client, having
    # credentials, offered only username/password. The client must refuse rather
    # than connect unauthenticated.
    server = _FakeSocks5Server(force_no_auth=True)
    await server.start()
    try:
        result = await TcpConnectProbe().execute(
            "10.9.9.9",
            {
                "port": 22,
                "timeout_ms": 3000,
                "socks_proxy": f"socks5://u:p@127.0.0.1:{server.port}",
            },
        )
    finally:
        await server.stop()

    assert result.ok is False
    assert result.error_kind == "socks_error"
    assert "unauthenticated" in (result.error_detail or "")


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
    assert server.request_lines[0] == "GET /healthz HTTP/1.1"
    assert "Host: 10.9.9.9:8080" in server.request_lines


async def test_http_health_tunnels_to_an_ipv6_target_with_a_bracketed_host():
    # The CONNECT carries the bare address; the Host header needs it
    # bracketed, with the port, or the target sees a malformed header.
    server = _FakeSocks5Server(upstream_response=b"HTTP/1.1 200 OK\r\n\r\n")
    await server.start()
    try:
        result = await HttpHealthProbe().execute(
            "2001:db8::7",
            {"port": 8080, "timeout_ms": 3000, "socks_proxy": f"socks5://127.0.0.1:{server.port}"},
        )
    finally:
        await server.stop()

    assert result.ok is True, result.error_detail
    assert server.requested == ("2001:db8::7", 8080)
    assert server.requested_atyp == 0x04
    assert "Host: [2001:db8::7]:8080" in server.request_lines


async def test_http_health_times_out_when_target_withholds_response():
    # The tunnel opens (CONNECT succeeds) but the target never answers; the
    # probe must bound the exchange itself and return a timeout, not hang.
    server = _FakeSocks5Server(hang_after_connect=True)
    await server.start()
    try:
        result = await asyncio.wait_for(
            HttpHealthProbe().execute(
                "10.9.9.9",
                {"port": 80, "timeout_ms": 400, "socks_proxy": f"socks5://127.0.0.1:{server.port}"},
            ),
            timeout=10,
        )
    finally:
        await server.stop()

    assert result.ok is False
    assert result.error_kind == "timeout"


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


class TestSocksProxyParsing:
    """The value is a resolved secret, so parsing must neither mis-locate the
    host nor let a credential fragment escape into an error message."""

    def test_passwords_with_url_metacharacters_parse_correctly(self) -> None:
        # urlsplit().port raises ValueError on these — a password may legally
        # contain any of them, and mis-locating the authority would send the
        # bastion credentials to the wrong host.
        for password in ("a/b", "p@ss", "p?x", "p#x", "a/b?c#d@e"):
            proxy = parse_socks_proxy(f"socks5://user:{password}@dind:1080")
            assert (proxy.host, proxy.port) == ("dind", 1080), password
            assert proxy.username == "user"
            assert proxy.password == password

    def test_errors_never_echo_the_input(self) -> None:
        # A parse detail is a credential detail: the message names the shape
        # expected, never what was supplied.
        for value in ("socks5://user:s3cr3t@dind", "socks5://user:s3cr3t@dind:notaport"):
            with pytest.raises(SocksError) as exc_info:
                parse_socks_proxy(value)
            assert "s3cr3t" not in str(exc_info.value)
            assert "requires host and port" in str(exc_info.value)

    def test_rejects_a_non_socks_scheme_without_echoing_credentials(self) -> None:
        with pytest.raises(SocksError) as exc_info:
            parse_socks_proxy("http://user:s3cr3t@dind:1080")
        assert "s3cr3t" not in str(exc_info.value)
        assert "socks5" in str(exc_info.value)

    def test_out_of_range_port_is_rejected(self) -> None:
        with pytest.raises(SocksError):
            parse_socks_proxy("socks5://dind:99999")

    def test_an_ipv6_proxy_is_dialled_without_its_brackets(self) -> None:
        proxy = parse_socks_proxy("socks5://u:p@[fd00::1]:1080")
        assert (proxy.host, proxy.port) == ("fd00::1", 1080)
        assert (proxy.username, proxy.password) == ("u", "p")

    def test_credential_less_and_socks5h_forms(self) -> None:
        plain = parse_socks_proxy("socks5://dind:1080")
        assert (plain.username, plain.password, plain.remote_dns) == (None, None, False)
        remote = parse_socks_proxy("socks5h://dind:1080")
        assert remote.remote_dns is True


class TestSocksWireLimits:
    """Everything this module raises must be a SocksError. Both wire fields
    below are length-prefixed with a single byte, and packing an over-long one
    would raise from bytes()/the idna codec instead — exception types the
    caller does not catch, carrying messages this module never vetted."""

    async def test_oversized_credentials_raise_socks_error(self) -> None:
        from hegemony_probe_net.socks import _negotiate_auth

        writer = MagicMock()
        writer.drain = AsyncMock()
        reader = AsyncMock()
        reader.readexactly = AsyncMock(return_value=bytes([0x05, 0x02]))
        proxy = SocksProxy(
            host="dind", port=1080, username="u" * 256, password="p", remote_dns=False
        )
        with pytest.raises(SocksError) as exc_info:
            await _negotiate_auth(reader, writer, proxy)
        assert "RFC 1929" in str(exc_info.value)
        # Still a credential: the limit is named, the value is not.
        assert "uuu" not in str(exc_info.value)

    async def test_undersized_username_raises_socks_error(self) -> None:
        from hegemony_probe_net.socks import _negotiate_auth

        writer = MagicMock()
        writer.drain = AsyncMock()
        reader = AsyncMock()
        reader.readexactly = AsyncMock(return_value=bytes([0x05, 0x02]))
        proxy = SocksProxy(host="dind", port=1080, username="", password="p", remote_dns=False)
        with pytest.raises(SocksError):
            await _negotiate_auth(reader, writer, proxy)

    async def test_undialable_destination_names_raise_socks_error(self) -> None:
        from hegemony_probe_net.socks import _dest_address

        proxy = SocksProxy(host="dind", port=1080, username=None, password=None, remote_dns=True)
        # An over-long label: the idna codec raises UnicodeError, not SocksError.
        with pytest.raises(SocksError):
            await _dest_address(proxy, "a" * 64 + ".example")
        # 255 is the DOMAINNAME ceiling; an empty name has nothing to dial.
        with pytest.raises(SocksError):
            await _dest_address(proxy, ".".join(["abc"] * 70))
        with pytest.raises(SocksError):
            await _dest_address(proxy, "")

    async def test_lab_hostnames_still_encode_verbatim(self) -> None:
        from hegemony_probe_net.socks import _dest_address

        proxy = SocksProxy(host="dind", port=1080, username=None, password=None, remote_dns=True)
        # Underscores and mixed case are common in lab DNS and must survive.
        encoded = await _dest_address(proxy, "Router_1.lab.internal")
        assert encoded == b"\x03" + bytes([21]) + b"Router_1.lab.internal"
        # Non-ASCII is punycoded, not rejected.
        assert await _dest_address(proxy, "münchen.de") == b"\x03\x11xn--mnchen-3ya.de"


# ── Probes that cannot carry the tunnel reject it ────────────────────────────


async def test_dns_resolve_rejects_a_socks_proxy():
    # DNS is UDP and this client implements CONNECT only, so the option cannot
    # be honored. Accepting it would resolve on the *worker* and report a
    # success describing a network path the caller never asked for — the same
    # misleading result icmp_ping refuses.
    from hegemony_probe_net.dns_resolve import DnsResolveProbe

    result = await DnsResolveProbe().execute(
        "example.test", {"socks_proxy": "socks5://user:pw@dind:1080", "timeout_ms": 1000}
    )
    assert result.ok is False
    assert result.error_kind == "config_error"
    assert "dns_resolve cannot use socks_proxy" in (result.error_detail or "")
    # And it never echoes the credential it was handed.
    assert "pw@" not in (result.error_detail or "")


async def test_dns_resolve_still_works_without_a_proxy():
    from hegemony_probe_net.dns_resolve import DnsResolveProbe

    result = await DnsResolveProbe().execute("localhost", {"timeout_ms": 3000})
    assert result.ok is True


async def test_tunneled_http_rejects_https_instead_of_sending_cleartext():
    # The transport writes a plaintext HTTP/1.1 request on the tunneled stream.
    # Selecting port 443 for an https:// URL and proceeding would put the
    # request line and Host header in the clear on a TLS port.
    import httpx

    from hegemony_probe_net.http_health import _SocksAsyncTransport

    transport = _SocksAsyncTransport("socks5://dind:1080", 5.0)
    request = httpx.Request("GET", "https://example.test/health")
    with pytest.raises(SocksError, match="http:// only"):
        await transport.handle_async_request(request)


async def test_tunneled_http_shares_one_timeout_budget():
    # The handshake and the exchange must share timeout_ms; charging the full
    # budget to each lets a proxied probe run for twice as long as the direct
    # path, overlapping the ticks of a short-interval monitor.
    import httpx

    from hegemony_probe_net import http_health

    seen: dict[str, float] = {}

    async def _fake_open(proxy, host, port, *, timeout):
        seen["handshake"] = timeout
        reader, writer = MagicMock(), MagicMock()
        writer.drain = AsyncMock()
        reader.readline = AsyncMock(side_effect=[b"HTTP/1.1 200 OK\r\n", b"\r\n"])
        return reader, writer

    async def _fake_wait_for(coro, timeout):
        seen["exchange"] = timeout
        return await coro

    clock = iter([100.0, 103.0])  # the handshake eats 3 of the 5 seconds
    with (
        patch.object(http_health, "open_socks_connection", _fake_open),
        patch.object(http_health.asyncio, "wait_for", _fake_wait_for),
        patch.object(http_health.time, "perf_counter", lambda: next(clock)),
    ):
        transport = http_health._SocksAsyncTransport("socks5://dind:1080", 5.0)
        await transport.handle_async_request(httpx.Request("GET", "http://example.test/health"))

    assert seen["handshake"] == 5.0
    assert seen["exchange"] == 2.0
