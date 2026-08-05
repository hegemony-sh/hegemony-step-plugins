# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Minimal SOCKS5 client for tunneling TCP probes through a bastion.

Implements just enough of RFC 1928 (CONNECT) and RFC 1929
(username/password auth) to dial a target host:port through the lab
bastion's authenticated SOCKS5 listener (design-dind-sandbox.md §11.4).
Kept dependency-free — the probe wheel already speaks asyncio streams, and
adding python-socks/httpx-socks for one handshake is not worth the pin.

The ``socks_proxy`` option is a URL like
``socks5://user:password@dind:1080`` (or ``socks5h://…`` to resolve the
target name at the proxy); credentials are already resolved host-side by
the platform's template pipeline before the probe sees them.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import unquote


class SocksError(Exception):
    """The SOCKS5 handshake failed (unreachable proxy, auth, or CONNECT reply)."""


@dataclass(frozen=True, slots=True)
class SocksProxy:
    """A parsed ``socks_proxy`` option."""

    host: str
    port: int
    username: str | None
    password: str | None
    #: socks5h — resolve the destination hostname at the proxy, not locally.
    remote_dns: bool


def parse_socks_proxy(value: str) -> SocksProxy:
    """Parse a ``socks5[h]://[user:pass@]host:port`` URL; raise on anything else.

    The userinfo is split off at the *last* ``@`` rather than handed to
    ``urlsplit``, because a password may legally contain ``@``, ``/``, ``?``
    or ``#`` and those make ``urlsplit`` mis-locate the authority. It then
    raises ``ValueError`` from ``.port`` — an exception type this module does
    not own, carrying a message ("Port could not be cast to integer value as
    'a'") that embeds the leading fragment of the password. Since these
    values arrive already resolved from a secret, a parse detail is a
    credential detail: every error raised here names only the shape expected,
    never the input.
    """
    text = value.strip()
    scheme, separator, authority = text.partition("://")
    if not separator or scheme not in ("socks5", "socks5h"):
        raise SocksError(f"unsupported socks_proxy scheme {scheme!r} (use socks5:// or socks5h://)")
    userinfo, _, hostport = authority.rpartition("@")
    host, _, port_text = hostport.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        raise SocksError(
            "socks_proxy requires host and port (e.g. socks5://user:pass@dind:1080)"
        ) from None
    if not host or not 1 <= port <= 65535:
        raise SocksError("socks_proxy requires host and port (e.g. socks5://user:pass@dind:1080)")
    username, _, password = userinfo.partition(":")
    return SocksProxy(
        host=host,
        port=port,
        username=unquote(username) if username else None,
        password=unquote(password) if password else None,
        remote_dns=scheme == "socks5h",
    )


_SOCKS_REPLY_ERRORS = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
}


async def _negotiate_auth(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, proxy: SocksProxy
) -> None:
    # When credentials are configured, offer ONLY username/password (0x02) —
    # never no-auth alongside it. Otherwise a misconfigured or open proxy that
    # selects no-auth (0x00) would let us connect unauthenticated, silently
    # defeating the design's guarantee that both endpoints authenticate
    # (design-dind-sandbox.md §11.4).
    methods = b"\x02" if proxy.username is not None else b"\x00"
    writer.write(bytes([0x05, len(methods)]) + methods)
    await writer.drain()
    version, method = await reader.readexactly(2)
    if version != 0x05:
        raise SocksError("proxy is not a SOCKS5 server")
    if method == 0xFF:
        raise SocksError("proxy rejected all offered authentication methods")
    if proxy.username is not None:
        # We offered only 0x02; anything else (including an unsolicited 0x00)
        # is a protocol violation we must not accept unauthenticated.
        if method != 0x02:
            raise SocksError(
                f"proxy did not select username/password auth (returned {method:#x}); "
                "refusing to connect unauthenticated"
            )
        user = proxy.username.encode()
        password = (proxy.password or "").encode()
        # RFC 1929 length-prefixes each field with a single byte, so anything
        # past 255 cannot be represented. Check before packing: bytes([256])
        # raises ValueError, an exception this module does not own and whose
        # message would escape the "never echo the input" rule the parser
        # above follows. UNAME must also be non-empty.
        if not 1 <= len(user) <= 255 or len(password) > 255:
            raise SocksError(
                "socks_proxy credentials do not fit SOCKS5 username/password auth "
                "(RFC 1929: username 1-255 bytes, password up to 255)"
            )
        writer.write(bytes([0x01, len(user)]) + user + bytes([len(password)]) + password)
        await writer.drain()
        _auth_ver, status = await reader.readexactly(2)
        if status != 0x00:
            raise SocksError("SOCKS5 username/password authentication failed")
    elif method != 0x00:
        raise SocksError(f"proxy selected an unsupported auth method {method:#x}")


async def _dest_address(proxy: SocksProxy, dest_host: str) -> bytes:
    """Encode the CONNECT destination as ``ATYP + address`` bytes.

    An IP literal is always sent in its native form (IPv4=0x01, IPv6=0x04) —
    there is nothing to resolve. A hostname is sent as a DOMAINNAME (0x03) so
    the *proxy* resolves it when the scheme is ``socks5h``; under plain
    ``socks5`` the name is resolved *locally* first (the documented
    local-vs-proxy split), which surfaces a clear error if a lab-only name
    does not resolve on the probe host.
    """
    try:
        ip = ipaddress.ip_address(dest_host)
    except ValueError:
        ip = None
    if ip is None and proxy.remote_dns:
        if not dest_host:
            raise SocksError("destination host is empty")
        try:
            # Pure-ASCII names (including the underscores and mixed case lab
            # hostnames use) pass through unchanged; only non-ASCII is
            # punycoded. The codec is strict, though — an over-long label
            # raises UnicodeError, which is not a SocksError and so would
            # escape this module's documented contract.
            host_bytes = dest_host.encode("idna")
        except UnicodeError as exc:
            raise SocksError(f"destination host {dest_host!r} is not a valid DNS name") from exc
        if not 1 <= len(host_bytes) <= 255:
            raise SocksError(f"destination host {dest_host!r} does not fit a SOCKS5 DOMAINNAME")
        return b"\x03" + bytes([len(host_bytes)]) + host_bytes
    if ip is None:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                dest_host, None, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            raise SocksError(
                f"cannot resolve {dest_host!r} locally (use socks5h:// to resolve "
                f"at the proxy): {exc}"
            ) from exc
        if not infos:
            raise SocksError(f"cannot resolve {dest_host!r} locally")
        ip = ipaddress.ip_address(infos[0][4][0])
    return (b"\x01" if ip.version == 4 else b"\x04") + ip.packed


async def _send_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    proxy: SocksProxy,
    dest_host: str,
    dest_port: int,
) -> None:
    request = b"\x05\x01\x00" + await _dest_address(proxy, dest_host) + dest_port.to_bytes(2, "big")
    writer.write(request)
    await writer.drain()

    version, reply, _reserved, atyp = await reader.readexactly(4)
    if version != 0x05:
        raise SocksError("malformed SOCKS5 CONNECT reply")
    if reply != 0x00:
        raise SocksError(
            "SOCKS5 CONNECT failed: " + _SOCKS_REPLY_ERRORS.get(reply, f"reply {reply:#x}")
        )
    # Drain the bound address so the stream is positioned at tunneled data.
    if atyp == 0x01:
        await reader.readexactly(4)
    elif atyp == 0x04:
        await reader.readexactly(16)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length)
    else:
        raise SocksError(f"SOCKS5 CONNECT reply has unknown address type {atyp:#x}")
    await reader.readexactly(2)  # bound port


async def open_socks_connection(
    proxy: SocksProxy,
    dest_host: str,
    dest_port: int,
    *,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a TCP tunnel to ``dest_host:dest_port`` through ``proxy``.

    Returns the tunneled (reader, writer) once CONNECT succeeds. Raises
    :class:`SocksError` on any handshake failure; the caller owns closing
    the writer. The whole handshake shares one ``timeout`` budget.
    """

    async def _handshake() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            reader, writer = await asyncio.open_connection(proxy.host, proxy.port)
        except OSError as exc:
            # A failure to reach the proxy itself is a proxy error, distinct
            # from the tunneled target being unreachable.
            raise SocksError(f"cannot reach SOCKS proxy {proxy.host}:{proxy.port}: {exc}") from exc
        try:
            await _negotiate_auth(reader, writer, proxy)
            await _send_connect(reader, writer, proxy, dest_host, dest_port)
        except asyncio.IncompleteReadError as exc:
            writer.close()
            raise SocksError("SOCKS proxy closed the connection during the handshake") from exc
        except BaseException:
            writer.close()
            raise
        return reader, writer

    return await asyncio.wait_for(_handshake(), timeout=timeout)
