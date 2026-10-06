# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ConnectivityCheckHandler: one-shot connectivity probes against targets.

The probe implementations (tcp/icmp/http/dns) come from the host's
``hegemony.probes`` registry via ``ctx.services.run_probe`` — the *same*
probes the background monitor runs, so there is a single implementation of
each check type rather than one copy here and one in the monitor.
"""

import asyncio
import logging
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    InvalidConfigError,
    ProbeResult,
    StepKind,
    for_each_target_device,
)

from .checks import CHECK_TYPE_LABELS, PORT_CHECKS, CheckUnavailable, default_port
from .targets import (
    DEFAULT_MAX_PARALLEL_TARGETS,
    TargetOutcome,
    all_probe_targets,
    merge_outcomes,
)

logger = logging.getLogger(__name__)


class ConnectivityCheckConfig(BaseModel):
    """Config for ``probe.connectivity``."""

    model_config = ConfigDict(extra="allow")

    # Registry-driven: the selectable check types are whatever the host's
    # ``hegemony.probes`` registry provides. The wheel declares intent via
    # ``x_options_source`` and the host injects the enum at the metadata
    # endpoint; ``run_probe`` enforces validity at run time. ``x_option_labels``
    # are cosmetic — unknown ids fall back to the id string.
    check_type: str = Field(
        default="tcp_connect",
        title="Check Type",
        description=(
            "Which probe to run against each target; the list comes from the "
            "checks registered on the worker. Defaults to a TCP connection "
            "attempt (tcp_connect) on the configured port."
        ),
        json_schema_extra={
            "x_widget": "select",
            "x_options_source": "probes",
            "x_option_labels": CHECK_TYPE_LABELS,
        },
    )
    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        title="Port",
        description=(
            "Port the port-based checks connect to. When empty, HTTP Health "
            "uses 80 and the other checks 22. Ignored by ICMP Ping and DNS "
            "Resolve."
        ),
        json_schema_extra={
            "x_placeholder": "22, or 80 for HTTP Health",
            "x_hide_when": {"field": "check_type", "value": "icmp_ping"},
        },
    )
    attempt_timeout_seconds: int = Field(
        default=10,
        ge=1,
        # Steps saved before the rename carry timeout_sec.
        validation_alias=AliasChoices("attempt_timeout_seconds", "timeout_sec"),
        title="Timeout (sec)",
        description=(
            "Time limit for each probe attempt, in seconds. An attempt that "
            "does not complete in time counts as failed. Defaults to 10."
        ),
        json_schema_extra={"x_legacy_keys": ["timeout_sec"]},
    )
    attempts: int = Field(
        default=1, ge=1, le=10, title="Attempts", description="Number of attempts (1-10)"
    )
    url_path: str = Field(
        default="",
        title="URL Path",
        description=(
            "URL path requested by the HTTP Health check; when omitted the "
            "check requests /health. Ignored by every other check type."
        ),
        json_schema_extra={
            "x_placeholder": "/health",
            "x_show_when": {"field": "check_type", "value": "http_health"},
            "x_col_span": 2,
        },
    )
    hostname: str = Field(
        default="",
        title="Hostname to Resolve",
        description=(
            "DNS name the DNS Resolve check looks up with the worker's system "
            "resolver, once per target; the target is not asked. When empty, "
            "each target's own name is looked up, so an IP address target "
            "needs this field. An IP address here fails the check, as the "
            "resolver returns it without a lookup. Ignored by every other "
            "check type."
        ),
        json_schema_extra={
            "x_placeholder": "device.example.com",
            "x_show_when": {"field": "check_type", "value": "dns_resolve"},
            "x_col_span": 2,
        },
    )
    socks_proxy: str = Field(
        default="",
        title="SOCKS5 Proxy",
        description=(
            "Route TCP-based checks through an authenticated SOCKS5 proxy "
            "(socks5[h]://user:pass@host:port), e.g. the lab bastion. "
            "icmp_ping rejects it — use tcp_connect for tunneled targets."
        ),
        json_schema_extra={
            "x_placeholder": "socks5://user:{{ secret('vault://lab/bastion/password') }}@dind:1080",
            "x_col_span": 2,
        },
    )
    max_parallel_devices: int = Field(
        default=DEFAULT_MAX_PARALLEL_TARGETS,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Targets checked at the same time (1 = one after another). Defaults to 10.",
    )


class ConnectivityCheckHandler(BaseHandler):
    """Unified connectivity check handler.

    Performs single or few connectivity checks against targets and
    emits results as evidence. Settings: :class:`ConnectivityCheckConfig`.
    """

    handler_id = "probe.connectivity"
    supported_kinds = [StepKind.CHECK]
    display_name = "Connectivity Check"
    description = "One-shot connectivity probes (TCP/ICMP/HTTP/DNS) against targets."
    category = "Checks"
    config_model = ConnectivityCheckConfig
    default_config = {"check_type": "tcp_connect", "attempt_timeout_seconds": 10, "attempts": 1}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Run connectivity check against all targets (devices and direct IPs)."""
        target_devices = all_probe_targets(ctx)
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices or IPs configured",
                summary="Missing targets",
            )

        try:
            config = self.parse_config(ctx.config, ConnectivityCheckConfig)
        except InvalidConfigError as exc:
            return exc.result()
        check_type = config.check_type
        # An empty Port means the check's own default: 80 for HTTP Health,
        # 22 (the old fixed default) for the rest.
        port = config.port or default_port(check_type)
        attempts = config.attempts

        # Build check options based on type. An unregistered check type fails
        # the step below when run_probe raises KeyError — validity is the host
        # probe registry, not a hardcoded allowlist here.
        options: dict[str, Any] = {"timeout_ms": config.attempt_timeout_seconds * 1000}
        if check_type in PORT_CHECKS:
            options["port"] = port
        if check_type == "http_health":
            options["url_path"] = config.url_path or "/health"
        elif check_type == "icmp_ping":
            options["count"] = 1
        elif check_type == "dns_resolve":
            options["hostname"] = config.hostname

        # Bastion routing (design-dind-sandbox.md §11.4): forwarded for every
        # check type — the probes that cannot carry it (icmp_ping, dns_resolve)
        # reject it with a clear config_error instead of silently probing the
        # wrong path.
        socks_proxy = config.socks_proxy.strip()
        if socks_proxy:
            options["socks_proxy"] = socks_proxy

        services = ctx.require_services()

        async def _check(device: dict[str, Any]) -> TargetOutcome:
            """Probe one target, retrying up to ``attempts`` times."""
            # None for a direct-IP target: it has no inventory identity, and
            # the artifact column behind evidence device_id is a UUID.
            device_id = device.get("id")
            device_name = device.get("name") or device_id or "unknown"
            host = device.get("mgmt_host")
            if not host:
                return TargetOutcome(device_name, ok=False, error="no host")

            # Run checks with attempts, through the host's shared probe registry.
            best_result: ProbeResult | None = None
            for attempt in range(attempts):
                try:
                    result = await services.run_probe(check_type, host, options)
                except KeyError:
                    raise CheckUnavailable from None
                best_result = result
                if result.ok:
                    break
                if attempt < attempts - 1:
                    await asyncio.sleep(0.5)  # Brief pause between retries

            if best_result and best_result.ok:
                # Extract primary metric
                latency_ms = None
                if "rtt_ms" in best_result.metrics:
                    latency_ms = best_result.metrics["rtt_ms"]
                elif "connect_ms" in best_result.metrics:
                    latency_ms = best_result.metrics["connect_ms"]
                return TargetOutcome(
                    device_name,
                    ok=True,
                    latency_ms=latency_ms,
                    evidence={
                        "kind": "transport_meta",
                        "name": f"connectivity_{check_type}_{device_name}",
                        "device_id": device_id,
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "host": host,
                            "check_type": check_type,
                            "success": True,
                            "metrics": best_result.metrics,
                        },
                    },
                )
            error_msg = best_result.error_detail if best_result else "unknown error"
            return TargetOutcome(
                device_name,
                ok=False,
                error=error_msg,
                evidence={
                    "kind": "transport_meta",
                    "name": f"connectivity_{check_type}_{device_name}",
                    "device_id": device_id,
                    "content_json": {
                        "device_id": device_id,
                        "device_name": device_name,
                        "host": host,
                        "check_type": check_type,
                        "success": False,
                        "error": error_msg,
                    },
                },
            )

        # Egress denials raised by run_probe propagate and cancel the rest.
        try:
            outcomes = await for_each_target_device(
                target_devices,
                _check,
                max_parallel=config.max_parallel_devices,
            )
        except CheckUnavailable:
            return HandlerResult(
                success=False,
                error=f"Check type '{check_type}' is not available on this worker",
                summary=f"Unsupported check type: {check_type}",
            )
        all_evidence, all_metrics, failed_devices = merge_outcomes(outcomes)
        success_count = sum(outcome.ok for outcome in outcomes)

        total = len(target_devices)
        if failed_devices:
            return HandlerResult(
                success=False,
                error=f"Failed: {', '.join(failed_devices)}",
                summary=f"{check_type}: {success_count}/{total} targets OK",
                metrics=all_metrics,
                evidence=all_evidence,
            )

        return HandlerResult(
            success=True,
            summary=f"{check_type}: {success_count}/{total} targets OK",
            metrics=all_metrics,
            evidence=all_evidence,
        )
