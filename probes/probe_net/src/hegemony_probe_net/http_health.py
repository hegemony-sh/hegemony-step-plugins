# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HTTP health probe.

GETs ``http://<address>[:port]<url_path>`` and reports ok for any status below
400. The richer one-shot variant (https, methods, status specs, body matching)
lives in the ``probe.http`` step handler.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

from hegemony_step_sdk import BaseProbe, ProbeResult

from .socks import SocksError, open_socks_connection, parse_socks_proxy

logger = logging.getLogger(__name__)


class _SocksAsyncTransport(httpx.AsyncBaseTransport):
    """httpx transport that dials every request through a SOCKS5 proxy.

    Dependency-free stand-in for httpx-socks: reuses the probe's minimal
    SOCKS client to open the tunnel, then hands httpx the tunneled stream via
    an :class:`httpx.AsyncHTTPTransport` bound to that connection.
    """

    def __init__(self, proxy_url: str, timeout_sec: float) -> None:
        self._proxy = parse_socks_proxy(proxy_url)
        self._timeout = timeout_sec

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        reader, writer = await open_socks_connection(self._proxy, host, port, timeout=self._timeout)
        # Speak HTTP/1.1 over the tunneled stream ourselves: only the status
        # line matters for a health check, so read headers and stop.
        path = request.url.raw_path.decode()
        head = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: hegemony-probe/1\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n\r\n"
        )

        async def _exchange() -> int:
            writer.write(head.encode())
            await writer.drain()
            status_line = await reader.readline()
            parts = status_line.decode("latin-1").split(" ", 2)
            if len(parts) < 2 or not parts[1].isdigit():
                raise SocksError("malformed HTTP status line from tunneled target")
            status_code = int(parts[1])
            # Drain remaining headers (bounded) so the peer close is clean.
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            return status_code

        try:
            # httpx's client timeout does NOT apply to a custom transport, so
            # bound the post-CONNECT exchange ourselves — otherwise a target
            # that accepts the tunnel then withholds its response would hang
            # the probe (and its bastion connection) indefinitely.
            status_code = await asyncio.wait_for(_exchange(), timeout=self._timeout)
        except TimeoutError as exc:
            raise httpx.ReadTimeout("tunneled HTTP exchange timed out", request=request) from exc
        finally:
            writer.close()
        return httpx.Response(status_code=status_code, request=request)


class HttpHealthProbe(BaseProbe):
    """HTTP health probe.

    Options:
        port: TCP port (default: 80)
        url_path: Request path (default: /health)
        timeout_ms: Request timeout in milliseconds (default: 5000)
        socks_proxy: Optional ``socks5[h]://[user:pass@]host:port`` to route
            the request through (design-dind-sandbox.md §11.4).

    Metrics produced:
        connect_ms: Total request time
        http_status: Response status code
    """

    probe_id = "http_health"

    async def execute(self, address: str, options: dict[str, Any]) -> ProbeResult:
        port = options.get("port")
        url_path = options.get("url_path") or "/health"
        if not url_path.startswith("/"):
            url_path = "/" + url_path
        timeout_sec = options.get("timeout_ms", 5000) / 1000.0
        socks_proxy = (options.get("socks_proxy") or "").strip()

        netloc = address if port in (None, 80) else f"{address}:{port}"
        url = f"http://{netloc}{url_path}"

        start = time.perf_counter()
        try:
            transport = _SocksAsyncTransport(socks_proxy, timeout_sec) if socks_proxy else None
            async with httpx.AsyncClient(
                timeout=timeout_sec, follow_redirects=True, transport=transport
            ) as client:
                response = await client.get(url)
        except SocksError as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return ProbeResult(
                ok=False,
                metrics={"connect_ms": round(elapsed, 3)},
                error_kind="socks_error",
                error_detail=str(exc),
            )
        except httpx.TimeoutException:
            elapsed = (time.perf_counter() - start) * 1000
            return ProbeResult(
                ok=False,
                metrics={"connect_ms": round(elapsed, 3)},
                error_kind="timeout",
                error_detail=f"Request timed out after {timeout_sec}s",
            )
        except httpx.HTTPError as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return ProbeResult(
                ok=False,
                metrics={"connect_ms": round(elapsed, 3)},
                error_kind="http_error",
                error_detail=f"{type(exc).__name__}: {exc}",
            )
        except Exception as exc:  # noqa: BLE001 - a probe must fail one target, never the batch
            # The custom SOCKS transport can surface raw OSError/ValueError
            # (peer reset mid-read, oversized header line) that httpx does not
            # wrap; record this target as failed instead of aborting the whole
            # multi-device check, matching the tcp_connect contract.
            elapsed = (time.perf_counter() - start) * 1000
            return ProbeResult(
                ok=False,
                metrics={"connect_ms": round(elapsed, 3)},
                error_kind="error",
                error_detail=f"{type(exc).__name__}: {exc}",
            )

        elapsed = (time.perf_counter() - start) * 1000
        metrics = {"connect_ms": round(elapsed, 3), "http_status": response.status_code}
        if response.status_code >= 400:
            return ProbeResult(
                ok=False,
                metrics=metrics,
                error_kind="http_status",
                error_detail=f"HTTP {response.status_code}",
            )
        return ProbeResult(ok=True, metrics=metrics)
