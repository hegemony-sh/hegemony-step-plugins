# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""DNS resolution probe.

Resolves a hostname (the ``hostname`` option, falling back to the target
address) via the system resolver. An IP address target needs the option: the
resolver hands an address back without a lookup. Record types, custom
resolvers, and expected-answer assertions live in the ``probe.dns`` step
handler.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from typing import Any

from hegemony_step_sdk import BaseProbe, ProbeResult

logger = logging.getLogger(__name__)


def _is_ip_address(value: str) -> bool:
    """Is this target an address literal rather than a name to look up?"""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class DnsResolveProbe(BaseProbe):
    """DNS resolution probe using the system resolver.

    Options:
        hostname: Name to resolve (default: the target address; required
            when the target is an IP address)
        timeout_ms: Resolution timeout in milliseconds (default: 5000)

    Metrics produced:
        resolve_ms: Resolution time
        addresses: Number of resolved addresses
    """

    probe_id = "dns_resolve"

    async def execute(self, address: str, options: dict[str, Any]) -> ProbeResult:
        # This probe uses the host resolver, which no SOCKS5 CONNECT tunnel
        # can carry (DNS is UDP, and RFC 1928 UDP ASSOCIATE is not
        # implemented). Accepting the option would resolve on the *worker* and
        # report a success describing a network path the caller never asked
        # for — the same misleading result icmp_ping refuses. Fail closed
        # instead; socks5h:// on a TCP-based check resolves at the bastion.
        if (options.get("socks_proxy") or "").strip():
            return ProbeResult(
                ok=False,
                error_kind="config_error",
                error_detail=(
                    "dns_resolve cannot use socks_proxy (DNS does not traverse a "
                    "SOCKS5 CONNECT tunnel); use socks5h:// on tcp_connect or "
                    "http_health to resolve at the bastion"
                ),
            )

        hostname = (options.get("hostname") or "").strip()
        if not hostname:
            # getaddrinfo returns an IP literal as it is, so falling back to
            # an IP target would pass without asking any DNS server.
            if _is_ip_address(address):
                return ProbeResult(
                    ok=False,
                    error_kind="config_error",
                    error_detail=(
                        f"dns_resolve needs a hostname to look up: the target "
                        f"{address} is an IP address"
                    ),
                )
            hostname = address
        timeout_sec = options.get("timeout_ms", 5000) / 1000.0

        loop = asyncio.get_running_loop()
        start = time.perf_counter()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM),
                timeout=timeout_sec,
            )
        except TimeoutError:
            elapsed = (time.perf_counter() - start) * 1000
            return ProbeResult(
                ok=False,
                metrics={"resolve_ms": round(elapsed, 3)},
                error_kind="timeout",
                error_detail=f"Resolution timed out after {timeout_sec}s",
            )
        except socket.gaierror as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return ProbeResult(
                ok=False,
                metrics={"resolve_ms": round(elapsed, 3)},
                error_kind="resolution_failed",
                error_detail=str(exc),
            )

        elapsed = (time.perf_counter() - start) * 1000
        addresses = sorted({info[4][0] for info in infos})
        return ProbeResult(
            ok=bool(addresses),
            metrics={"resolve_ms": round(elapsed, 3), "addresses": len(addresses)},
            error_kind=None if addresses else "no_answers",
            error_detail=None if addresses else f"no addresses for {hostname}",
        )
