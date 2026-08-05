# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""TCP connect probe.

Tests TCP connectivity by opening a connection to a port, measuring the
connect time.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from hegemony_step_sdk import BaseProbe, ProbeResult

from .socks import SocksError, open_socks_connection, parse_socks_proxy

logger = logging.getLogger(__name__)


class TcpConnectProbe(BaseProbe):
    """TCP connection probe.

    Options:
        port: TCP port to connect to (required)
        timeout_ms: Connection timeout in milliseconds (default: 5000)
        socks_proxy: Optional ``socks5[h]://[user:pass@]host:port`` to dial
            through (design-dind-sandbox.md §11.4); the connect then measures
            the tunneled reach, not the local one.

    Metrics produced:
        connect_ms: Time to establish the TCP connection
    """

    probe_id = "tcp_connect"

    async def execute(self, address: str, options: dict[str, Any]) -> ProbeResult:
        port = options.get("port")
        if port is None:
            return ProbeResult(
                ok=False,
                error_kind="config_error",
                error_detail="port is required for tcp_connect check",
            )

        timeout_ms = options.get("timeout_ms", 5000)
        timeout_sec = timeout_ms / 1000.0
        socks_proxy = (options.get("socks_proxy") or "").strip()
        start_time = time.perf_counter()

        try:
            if socks_proxy:
                proxy = parse_socks_proxy(socks_proxy)
                _reader, writer = await open_socks_connection(
                    proxy, address, port, timeout=timeout_sec
                )
            else:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, port),
                    timeout=timeout_sec,
                )
            connect_time = (time.perf_counter() - start_time) * 1000
            writer.close()
            await writer.wait_closed()
            return ProbeResult(
                ok=True, metrics={"connect_ms": round(connect_time, 3), "port": port}
            )

        except SocksError as e:
            elapsed = (time.perf_counter() - start_time) * 1000
            return ProbeResult(
                ok=False,
                metrics={"connect_ms": round(elapsed, 3), "port": port},
                error_kind="socks_error",
                error_detail=str(e),
            )

        except TimeoutError:
            elapsed = (time.perf_counter() - start_time) * 1000
            return ProbeResult(
                ok=False,
                metrics={"connect_ms": round(elapsed, 3), "port": port},
                error_kind="timeout",
                error_detail=f"Connection timed out after {timeout_ms}ms",
            )

        except ConnectionRefusedError:
            elapsed = (time.perf_counter() - start_time) * 1000
            return ProbeResult(
                ok=False,
                metrics={"connect_ms": round(elapsed, 3), "port": port},
                error_kind="connection_refused",
                error_detail=f"Connection refused on port {port}",
            )

        except OSError as e:
            elapsed = (time.perf_counter() - start_time) * 1000
            error_kind = "network_error"
            if "Network is unreachable" in str(e):
                error_kind = "network_unreachable"
            elif "No route to host" in str(e):
                error_kind = "no_route"
            elif "Host is down" in str(e):
                error_kind = "host_down"
            return ProbeResult(
                ok=False,
                metrics={"connect_ms": round(elapsed, 3), "port": port},
                error_kind=error_kind,
                error_detail=str(e),
            )

        except Exception as e:  # noqa: BLE001 - probe never raises for a single target
            logger.exception("TCP connect check failed for %s:%s", address, port)
            elapsed = (time.perf_counter() - start_time) * 1000
            return ProbeResult(
                ok=False,
                metrics={"connect_ms": round(elapsed, 3), "port": port},
                error_kind="exception",
                error_detail=str(e),
            )
