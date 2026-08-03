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
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


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
    """Parse a ``socks5[h]://[user:pass@]host:port`` URL; raise on anything else."""
    parts = urlsplit(value.strip())
    if parts.scheme not in ("socks5", "socks5h"):
        raise SocksError(f"unsupported socks_proxy scheme {parts.scheme!r} (use socks5 or socks5h)")
    if not parts.hostname or not parts.port:
        raise SocksError("socks_proxy requires host and port (e.g. socks5://user:pass@dind:1080)")
    return SocksProxy(
        host=parts.hostname,
        port=parts.port,
        username=unquote(parts.username) if parts.username else None,
        password=unquote(parts.password) if parts.password else None,
        remote_dns=parts.scheme == "socks5h",
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
    methods = b"\x00"  # no-auth
    if proxy.username is not None:
        methods = b"\x00\x02"  # no-auth or username/password
    writer.write(bytes([0x05, len(methods)]) + methods)
    await writer.drain()
    version, method = await reader.readexactly(2)
    if version != 0x05:
        raise SocksError("proxy is not a SOCKS5 server")
    if method == 0xFF:
        raise SocksError("proxy rejected all offered authentication methods")
    if method == 0x02:
        if proxy.username is None:
            raise SocksError("proxy requires username/password but none was configured")
        user = proxy.username.encode()
        password = (proxy.password or "").encode()
        writer.write(bytes([0x01, len(user)]) + user + bytes([len(password)]) + password)
        await writer.drain()
        _auth_ver, status = await reader.readexactly(2)
        if status != 0x00:
            raise SocksError("SOCKS5 username/password authentication failed")
    elif method != 0x00:
        raise SocksError(f"proxy selected an unsupported auth method {method:#x}")


async def _send_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    proxy: SocksProxy,
    dest_host: str,
    dest_port: int,
) -> None:
    # Always send the destination as a DOMAINNAME; the proxy resolves it
    # (socks5h) or we could resolve locally, but DOMAINNAME keeps one path.
    host_bytes = dest_host.encode("idna") if _looks_like_hostname(dest_host) else dest_host.encode()
    if len(host_bytes) > 255:
        raise SocksError("destination host name too long for SOCKS5")
    request = (
        b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + dest_port.to_bytes(2, "big")
    )
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


def _looks_like_hostname(value: str) -> bool:
    return any(ch.isalpha() for ch in value)


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
