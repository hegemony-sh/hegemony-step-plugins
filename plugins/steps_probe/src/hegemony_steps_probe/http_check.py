# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HttpProbeHandler: HTTP(S) endpoint checks against target devices."""

import asyncio
import logging
import time
from typing import Any, Literal

import httpx
from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    InvalidConfigError,
    StepKind,
    for_each_target_device,
)

from .targets import (
    DEFAULT_MAX_PARALLEL_TARGETS,
    TargetOutcome,
    all_probe_targets,
    merge_outcomes,
)

logger = logging.getLogger(__name__)

_SCHEME_DEFAULT_PORTS = {"http": 80, "https": 443}


def parse_status_spec(spec: str) -> list[tuple[int, int]]:
    """Parse an expected-status spec like ``200-299,301,404`` into ranges.

    Raises ``ValueError`` for malformed entries.
    """
    ranges: list[tuple[int, int]] = []
    for raw in spec.split(","):
        entry = raw.strip()
        if not entry:
            continue
        if "-" in entry:
            low_raw, high_raw = entry.split("-", 1)
            low, high = int(low_raw), int(high_raw)
        else:
            low = high = int(entry)
        if not (100 <= low <= 599 and 100 <= high <= 599 and low <= high):
            raise ValueError(f"invalid status entry: {entry}")
        ranges.append((low, high))
    if not ranges:
        raise ValueError("expected_status must list at least one status or range")
    return ranges


def status_matches(status: int, ranges: list[tuple[int, int]]) -> bool:
    return any(low <= status <= high for low, high in ranges)


class HttpProbeConfig(BaseModel):
    """Config for ``probe.http``."""

    # Expected Status written as a number (200) is its text.
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    scheme: Literal["http", "https"] = Field(
        default="http",
        title="Scheme",
        description=(
            "Whether the request uses plain HTTP or TLS-protected HTTPS. Also "
            "selects the default port (80 or 443) when Port is left empty."
        ),
        json_schema_extra={"x_option_labels": {"http": "HTTP", "https": "HTTPS"}},
    )
    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        title="Port",
        description="Defaults to 80/443 by scheme",
    )
    path: str = Field(
        default="/",
        title="Path",
        description=(
            "Request path on the target, such as /health. A missing leading "
            "slash is added automatically, and an empty value requests the "
            "root path /."
        ),
        json_schema_extra={"x_placeholder": "/health"},
    )
    method: Literal["GET", "HEAD", "POST"] = Field(
        default="GET",
        title="Method",
        description=(
            "HTTP request method to send. Defaults to GET; note that a HEAD "
            "response has no body for the Body Contains assertion to match."
        ),
    )
    expected_status: str = Field(
        default="200-399",
        title="Expected Status",
        description="Comma-separated status codes and ranges, e.g. 200-299,301",
    )
    body_contains: str = Field(
        default="",
        title="Body Contains (optional)",
        description="Fail unless the response body contains this text",
        json_schema_extra={"x_col_span": 2},
    )
    verify_tls: bool = Field(
        default=True,
        title="Verify TLS certificate",
        description=(
            "Validate the server's TLS certificate on HTTPS checks; turn off "
            "for devices with self-signed certificates. Enabled by default "
            "and ignored by plain HTTP checks."
        ),
        json_schema_extra={"x_show_when": {"field": "scheme", "value": "https"}},
    )
    follow_redirects: bool = Field(
        default=True,
        title="Follow redirects",
        description=(
            "Follow HTTP redirects and assert the final response. When "
            "disabled, the redirect response itself is what Expected Status "
            "and Body Contains see. Enabled by default."
        ),
    )
    attempt_timeout_seconds: int = Field(
        default=10,
        ge=1,
        # Steps saved before the rename carry timeout_sec.
        validation_alias=AliasChoices("attempt_timeout_seconds", "timeout_sec"),
        title="Timeout (sec)",
        description=(
            "Time limit for each request attempt, in seconds, covering "
            "connection setup and the response. Defaults to 10."
        ),
        json_schema_extra={"x_legacy_keys": ["timeout_sec"]},
    )
    attempts: int = Field(
        default=1, ge=1, le=10, title="Attempts", description="Number of attempts (1-10)"
    )
    max_parallel_devices: int = Field(
        default=DEFAULT_MAX_PARALLEL_TARGETS,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Targets requested at the same time (1 = one after another). Defaults to 10.",
    )


class HttpProbeHandler(BaseHandler):
    """HTTP(S) endpoint check against each target device's management address."""

    handler_id = "probe.http"
    supported_kinds = [StepKind.CHECK]
    display_name = "HTTP Check"
    description = "Request an HTTP(S) endpoint on each target and assert status/body."
    category = "Checks"
    config_model = HttpProbeConfig
    default_config = {"scheme": "http", "path": "/", "expected_status": "200-399"}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        target_devices = all_probe_targets(ctx)
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices or IPs configured",
                summary="Missing targets",
            )

        try:
            config = self.parse_config(ctx.config, HttpProbeConfig)
        except InvalidConfigError as exc:
            return exc.result()
        scheme = config.scheme
        port = config.port
        path = config.path or "/"
        if not path.startswith("/"):
            path = "/" + path
        method = config.method
        body_contains = config.body_contains
        verify_tls = config.verify_tls
        follow_redirects = config.follow_redirects
        timeout_sec = config.attempt_timeout_seconds
        attempts = config.attempts

        try:
            status_ranges = parse_status_spec(config.expected_status)
        except ValueError as exc:
            return HandlerResult(
                success=False,
                error=f"Invalid expected_status: {exc}",
                summary="HTTP check configuration error",
            )

        effective_port = port or _SCHEME_DEFAULT_PORTS[scheme]
        default_port = effective_port == _SCHEME_DEFAULT_PORTS[scheme]

        # This handler drives its own httpx client rather than going through
        # services.run_probe, which is where the host applies the flow egress
        # gate — so without this hook a restricted policy would never see
        # these targets. A *request* hook rather than a pre-dial check,
        # because with follow_redirects every hop is a new destination and a
        # redirect must not launder a denied one through an allowed first
        # hop. A denial raises out of the request rather than being recorded
        # as a failed check, so the step reports the policy's reason.
        enforce = getattr(ctx.require_services(), "enforce_egress", None)

        async def _authorize_request(request: httpx.Request) -> None:
            """Walk every outgoing request, redirect hops included, past the gate."""
            if enforce is None:
                return
            port = request.url.port or _SCHEME_DEFAULT_PORTS.get(request.url.scheme, 80)
            await enforce(request.url.host, port, proto="tcp", kind="http check")

        async with httpx.AsyncClient(
            verify=verify_tls,
            follow_redirects=follow_redirects,
            timeout=timeout_sec,
            event_hooks={"request": [_authorize_request]},
        ) as client:

            async def _check(device: dict[str, Any]) -> TargetOutcome:
                """Request one target, retrying up to ``attempts`` times."""
                # None for a direct-IP target: it has no inventory identity,
                # and the artifact column behind evidence device_id is a UUID.
                device_id = device.get("id")
                device_name = device.get("name") or device_id or "unknown"
                host = device.get("mgmt_host")
                if not host:
                    return TargetOutcome(device_name, ok=False, error="no host")

                # A colon marks an IPv6 literal (hostnames and IPv4 cannot
                # carry one), and a URL authority requires it bracketed.
                authority = f"[{host}]" if ":" in host else host
                netloc = authority if default_port else f"{authority}:{effective_port}"
                url = f"{scheme}://{netloc}{path}"

                outcome: dict[str, Any] = {}
                for attempt in range(attempts):
                    outcome = await self._request(client, method, url, status_ranges, body_contains)
                    if outcome["success"]:
                        break
                    if attempt < attempts - 1:
                        await asyncio.sleep(0.5)

                ok = bool(outcome.get("success"))
                return TargetOutcome(
                    device_name,
                    ok=ok,
                    error=None if ok else outcome.get("error", "failed"),
                    latency_ms=outcome.get("latency_ms"),
                    evidence={
                        "kind": "transport_meta",
                        "name": f"http_{device_name}",
                        "device_id": device_id,
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "url": url,
                            "method": method,
                            **outcome,
                        },
                    },
                )

            # An egress denial raised by the request hook propagates and
            # cancels the requests still running.
            outcomes = await for_each_target_device(
                target_devices,
                _check,
                max_parallel=config.max_parallel_devices,
            )

        all_evidence, all_metrics, failed_devices = merge_outcomes(outcomes)
        success_count = sum(outcome.ok for outcome in outcomes)

        total = len(target_devices)
        summary = f"http {method} {path}: {success_count}/{total} targets OK"
        if failed_devices:
            return HandlerResult(
                success=False,
                error=f"Failed: {', '.join(failed_devices)}",
                summary=summary,
                metrics=all_metrics,
                evidence=all_evidence,
            )
        return HandlerResult(
            success=True, summary=summary, metrics=all_metrics, evidence=all_evidence
        )

    @staticmethod
    async def _request(
        client: httpx.AsyncClient,
        method: str,
        url: str,
        status_ranges: list[tuple[int, int]],
        body_contains: str,
    ) -> dict[str, Any]:
        """One HTTP attempt; returns a JSON-serializable outcome dict."""
        start = time.perf_counter()
        try:
            response = await client.request(method, url)
        except httpx.HTTPError as exc:
            return {"success": False, "error": f"{type(exc).__name__}: {exc}"}
        latency_ms = round((time.perf_counter() - start) * 1000, 3)

        if not status_matches(response.status_code, status_ranges):
            return {
                "success": False,
                "status": response.status_code,
                "latency_ms": latency_ms,
                "error": f"unexpected status {response.status_code}",
            }
        if body_contains and body_contains not in response.text:
            return {
                "success": False,
                "status": response.status_code,
                "latency_ms": latency_ms,
                "error": "body does not contain expected text",
            }
        return {"success": True, "status": response.status_code, "latency_ms": latency_ms}
