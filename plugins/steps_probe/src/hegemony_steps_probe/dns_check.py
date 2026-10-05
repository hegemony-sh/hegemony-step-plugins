# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""DnsProbeHandler: DNS resolution checks."""

import asyncio
import ipaddress
import logging
import time
from typing import Any, Literal

import dns.asyncresolver
import dns.exception
from pydantic import BaseModel, ConfigDict, Field, field_validator

from hegemony_step_sdk import BaseHandler, HandlerContext, HandlerResult, StepKind

from .targets import all_probe_targets

logger = logging.getLogger(__name__)


def _looks_like_ip(value: str) -> bool:
    """Is this target an address literal rather than a resolvable name?"""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


#: Where a nameserver answers: DNS over UDP, and over TCP for answers too
#: large for UDP (the resolver falls back on its own).
DNS_PORT = 53
DNS_PROTOCOLS = ("udp", "tcp")


def resolver_error(value: str) -> str | None:
    """Why ``value`` cannot be a Resolver, or None when it is empty or an IP address."""
    if not value or _looks_like_ip(value):
        return None
    return (
        f"Resolver {value!r} must be a nameserver IP address; host names, ports "
        "and URLs are not accepted"
    )


def normalize_answer(value: str) -> str:
    """Normalize one DNS answer for comparison (lowercase, no trailing dot/quotes)."""
    return value.strip().strip('"').rstrip(".").lower()


async def resolve_records(
    query_name: str,
    record_type: str,
    *,
    resolver_ip: str = "",
    timeout_sec: float = 5.0,
) -> list[str]:
    """Resolve ``query_name``/``record_type``; returns normalized answer strings.

    Raises ``dns.exception.DNSException`` on resolution failure.
    """
    resolver = dns.asyncresolver.Resolver()
    if resolver_ip:
        resolver.nameservers = [resolver_ip]
    resolver.lifetime = timeout_sec
    answer = await resolver.resolve(query_name, record_type)
    return sorted(normalize_answer(rdata.to_text()) for rdata in answer)


class DnsProbeConfig(BaseModel):
    """Config for ``probe.dns``."""

    model_config = ConfigDict(extra="allow")

    query_name: str = Field(
        default="",
        title="Name to Resolve",
        description="Leave empty to resolve each target device's hostname",
        json_schema_extra={"x_placeholder": "device.example.com", "x_col_span": 2},
    )
    record_type: Literal["A", "AAAA", "CNAME", "MX", "NS", "TXT"] = Field(
        default="A",
        title="Record Type",
        description="Which kind of DNS record to query for. Defaults to A records.",
    )
    resolver: str = Field(
        default="",
        title="Resolver (optional)",
        description=(
            "Nameserver IP address, asked on port 53 under the flow's network "
            "policy; empty uses the system resolver"
        ),
        json_schema_extra={"x_placeholder": "192.0.2.53"},
    )
    expected_values: list[str] = Field(
        default_factory=list,
        title="Expected Values (optional)",
        description="One per line; every listed value must appear in the answers",
        json_schema_extra={
            "x_widget": "commands",
            "x_rows": 3,
            "x_col_span": 2,
            "x_placeholder": "192.0.2.10\n192.0.2.11",
        },
    )
    timeout_sec: int = Field(
        default=5,
        ge=1,
        title="Timeout (sec)",
        description=(
            "Overall time budget for each resolution attempt, in seconds. A "
            "lookup that has not answered in time counts as a failed attempt. "
            "Defaults to 5."
        ),
    )
    attempts: int = Field(
        default=1, ge=1, le=10, title="Attempts", description="Number of attempts (1-10)"
    )

    @field_validator("resolver")
    @classmethod
    def _resolver_is_an_ip(cls, value: str) -> str:
        """A host name or URL would let the query go somewhere the policy never saw."""
        error = resolver_error(value.strip())
        if error:
            raise ValueError(error)
        return value


class DnsProbeHandler(BaseHandler):
    """DNS resolution check, per target device or for an explicit name."""

    handler_id = "probe.dns"
    supported_kinds = [StepKind.CHECK]
    display_name = "DNS Check"
    description = "Resolve a DNS name (or each target's hostname) and assert the answers."
    category = "Checks"
    config_model = DnsProbeConfig
    default_config = {"record_type": "A", "timeout_sec": 5}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        target_devices = all_probe_targets(ctx)
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices or IPs configured",
                summary="Missing targets",
            )

        configured_name = str(ctx.config.get("query_name", "") or "").strip()
        record_type = ctx.config.get("record_type", "A")
        resolver_ip = str(ctx.config.get("resolver", "") or "").strip()
        bad_resolver = resolver_error(resolver_ip)
        if bad_resolver:
            return HandlerResult(
                success=False, error=bad_resolver, summary="DNS check configuration error"
            )
        timeout_sec = ctx.config.get("timeout_sec", 5)
        attempts = min(int(ctx.config.get("attempts", 1)), 10)
        expected = [
            normalize_answer(str(value))
            for value in ctx.config.get("expected_values", []) or []
            if str(value).strip()
        ]

        if resolver_ip:
            # The system resolver is the platform's own; a chosen nameserver is
            # a destination like any other the step dials, so the flow's
            # egress policy decides whether the queries may reach it. A denial
            # raises out of the step with the policy's reason.
            enforce = getattr(ctx.services, "enforce_egress", None)
            if enforce is not None:
                for proto in DNS_PROTOCOLS:
                    await enforce(resolver_ip, DNS_PORT, proto=proto, kind="dns query")

        all_evidence: list[dict[str, Any]] = []
        all_metrics: dict[str, Any] = {}
        failed_devices: list[str] = []
        success_count = 0

        for device in target_devices:
            # None for a direct-IP target: it has no inventory identity, and
            # the artifact column behind evidence device_id is a UUID.
            device_id = device.get("id")
            device_name = device.get("name") or device_id or "unknown"
            query_name = configured_name or device.get("hostname") or device.get("mgmt_host")
            if not query_name:
                failed_devices.append(f"{device_name} (no name to resolve)")
                continue
            # A bare IP literal is not a DNS question. A direct-IP target only
            # makes sense here alongside an explicit Name to Resolve; without
            # one, resolving "8.8.8.8" as an A record would fail confusingly.
            if not configured_name and _looks_like_ip(query_name):
                failed_devices.append(f"{device_name} (IP target needs a Name to Resolve)")
                continue

            answers: list[str] = []
            error: str | None = None
            latency_ms: float | None = None
            for attempt in range(attempts):
                start = time.perf_counter()
                try:
                    answers = await resolve_records(
                        query_name,
                        record_type,
                        resolver_ip=resolver_ip,
                        timeout_sec=float(timeout_sec),
                    )
                    latency_ms = round((time.perf_counter() - start) * 1000, 3)
                    error = None
                    break
                except dns.exception.DNSException as exc:
                    error = f"{type(exc).__name__}: {exc}"
                except OSError as exc:
                    error = str(exc)
                if attempt < attempts - 1:
                    await asyncio.sleep(0.5)

            missing = [value for value in expected if value not in answers]
            ok = error is None and not missing
            if ok:
                success_count += 1
                if latency_ms is not None:
                    all_metrics[f"{device_name}_ms"] = latency_ms
            elif error is not None:
                failed_devices.append(f"{device_name} ({error})")
            else:
                failed_devices.append(f"{device_name} (missing: {', '.join(missing)})")

            all_evidence.append(
                {
                    "kind": "transport_meta",
                    "name": f"dns_{record_type}_{device_name}",
                    "device_id": device_id,
                    "content_json": {
                        "device_id": device_id,
                        "device_name": device_name,
                        "query_name": query_name,
                        "record_type": record_type,
                        "resolver": resolver_ip or "system",
                        "success": ok,
                        "answers": answers,
                        "missing_expected": missing,
                        "error": error,
                    },
                }
            )

        total = len(target_devices)
        summary = f"dns {record_type}: {success_count}/{total} lookups OK"
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
