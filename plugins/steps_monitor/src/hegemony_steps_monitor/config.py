# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Config models for the monitor handlers (editor form schemas)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ConnectivityMonitorConfig(BaseModel):
    """Config for ``monitor.connectivity``."""

    model_config = ConfigDict(extra="allow")

    # Registry-driven with a monitor twist: the host injects the options from
    # the hegemony.probes registry INTERSECTED with its monitor check-id
    # vocabulary ("monitor_checks" source) — the monitor pipeline persists
    # check ids in enum-typed API/DB columns, so a probe id outside that
    # vocabulary must not be offered here (one-shot probe.* handlers use the
    # unrestricted "probes" source). Validated against the registry at run time.
    check_type: str = Field(
        default="tcp_connect",
        title="Check Type",
        json_schema_extra={
            "x_widget": "select",
            "x_options_source": "monitor_checks",
            "x_option_labels": {
                "tcp_connect": "TCP Connect",
                "icmp_ping": "ICMP Ping",
                "http_health": "HTTP Health",
                "dns_resolve": "DNS Resolve",
            },
        },
    )
    port: int = Field(
        default=22,
        ge=1,
        le=65535,
        title="Port",
        json_schema_extra={
            "x_placeholder": "22",
            "x_hide_when": {"field": "check_type", "value": "icmp_ping"},
        },
    )
    interval_ms: int = Field(
        default=5000, ge=100, title="Interval (ms)", json_schema_extra={"x_step": 100}
    )
    schedule_mode: Literal["count", "duration", "until_join"] = Field(
        default="count",
        title="Schedule Mode",
        json_schema_extra={
            "x_option_labels": {
                "count": "Fixed Count",
                "duration": "Duration",
                "until_join": "Until Join",
            }
        },
    )
    count: int = Field(
        default=10,
        ge=1,
        title="Count",
        json_schema_extra={"x_show_when": {"field": "schedule_mode", "value": "count"}},
    )
    duration_sec: int = Field(
        default=60,
        ge=1,
        title="Duration (sec)",
        json_schema_extra={"x_show_when": {"field": "schedule_mode", "value": "duration"}},
    )
    timeout_sec: int = Field(default=10, ge=1, title="Timeout (sec)")
    url_path: str = Field(
        default="",
        title="URL Path",
        json_schema_extra={
            "x_placeholder": "/health",
            "x_show_when": {"field": "check_type", "value": "http_health"},
            "x_col_span": 2,
        },
    )
    socks_proxy: str = Field(
        default="",
        title="SOCKS Proxy",
        description=(
            "Optional authenticated SOCKS5 proxy for the TCP-based checks, so a "
            "monitor can reach targets only accessible through a bastion (e.g. a "
            "lab management subnet behind dind:1080). "
            "socks5[h]://[user:pass@]host:port; ignored by icmp_ping."
        ),
        json_schema_extra={
            "x_placeholder": "socks5://user:pass@dind:1080",
            "x_advanced": True,
            "x_col_span": 2,
        },
    )


class MonitorLifecycleConfig(BaseModel):
    """Config for the internal monitor start/stop lifecycle handlers."""

    model_config = ConfigDict(extra="allow")
