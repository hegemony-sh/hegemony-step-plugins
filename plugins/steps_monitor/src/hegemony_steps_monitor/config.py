# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Config model for the monitor handler (editor form schema)."""

from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


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
        description=(
            "The kind of probe sent to each target on every sample, such as a "
            "TCP connection attempt, an ICMP echo, an HTTP health request, or "
            "a DNS lookup. Options come from the host's monitor check registry and the "
            "value is validated when the step runs. Defaults to a plain TCP "
            "connect check."
        ),
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
    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        title="Port",
        description=(
            "TCP port probed on each target by the port-based checks such as "
            "TCP Connect and HTTP Health. When empty, HTTP Health uses 80 and "
            "the other checks 22 (SSH). Ignored by checks that do not connect "
            "to a port, such as ICMP Ping and DNS Resolve. Must be between 1 "
            "and 65535."
        ),
        json_schema_extra={
            "x_placeholder": "22, or 80 for HTTP Health",
            "x_hide_when": {"field": "check_type", "value": "icmp_ping"},
        },
    )
    interval_ms: int = Field(
        default=5000,
        ge=100,
        title="Interval (ms)",
        description=(
            "Time between successive samples, in milliseconds. Defaults to "
            "5000 (one sample every five seconds); minimum 100."
        ),
        json_schema_extra={"x_step": 100},
    )
    schedule_mode: Literal["count", "duration", "until_join"] = Field(
        default="count",
        title="Schedule Mode",
        description=(
            "How the monitor decides when to stop sampling: after a fixed "
            "number of samples, after a fixed duration, or - with Until Join "
            "- when the flow engine stops it at the branch's join point. "
            "Defaults to a fixed count."
        ),
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
        description=(
            "Number of samples to take before the monitor stops on its own. "
            "Only used when Schedule Mode is Fixed Count. Defaults to 10; "
            "minimum 1."
        ),
        json_schema_extra={"x_show_when": {"field": "schedule_mode", "value": "count"}},
    )
    duration_seconds: int = Field(
        default=60,
        ge=1,
        # Steps saved before the rename carry duration_sec.
        validation_alias=AliasChoices("duration_seconds", "duration_sec"),
        title="Duration (sec)",
        description=(
            "How long the monitor keeps sampling, in seconds, before it "
            "stops on its own. Only used when Schedule Mode is Duration. "
            "Defaults to 60; minimum 1."
        ),
        json_schema_extra={
            "x_show_when": {"field": "schedule_mode", "value": "duration"},
            "x_legacy_keys": ["duration_sec"],
        },
    )
    attempt_timeout_seconds: int = Field(
        default=10,
        ge=1,
        # Steps saved before the rename carry timeout_sec.
        validation_alias=AliasChoices("attempt_timeout_seconds", "timeout_sec"),
        title="Timeout (sec)",
        description=(
            "Per-sample time limit in seconds: how long each probe waits for "
            "an answer before giving up on that sample. Defaults to 10; "
            "minimum 1."
        ),
        json_schema_extra={"x_legacy_keys": ["timeout_sec"]},
    )
    url_path: str = Field(
        default="",
        title="URL Path",
        description=(
            "Request path for the HTTP Health check, e.g. /health. Used only "
            "when Check Type is HTTP Health; when omitted, /health is probed."
        ),
        json_schema_extra={
            "x_placeholder": "/health",
            "x_show_when": {"field": "check_type", "value": "http_health"},
            "x_col_span": 2,
        },
    )
    ping_count: int = Field(
        default=3,
        ge=1,
        le=10,
        title="Ping Count",
        description=(
            "Echo requests sent to each target on every ICMP Ping sample. "
            "Used only when Check Type is ICMP Ping. Defaults to 3; must be "
            "between 1 and 10."
        ),
        json_schema_extra={"x_show_when": {"field": "check_type", "value": "icmp_ping"}},
    )
    socks_proxy: str = Field(
        default="",
        title="SOCKS Proxy",
        description=(
            "Optional authenticated SOCKS5 proxy for the TCP-based checks "
            "(tcp_connect, http_health), so a monitor can reach targets only "
            "accessible through a bastion (e.g. a lab management subnet behind "
            "dind:1080). socks5[h]://[user:pass@]host:port. Not usable by "
            "icmp_ping or dns_resolve — neither ICMP nor DNS traverses a SOCKS5 "
            "CONNECT tunnel, so those checks reject a configured proxy rather "
            "than probe the wrong path."
        ),
        json_schema_extra={
            "x_placeholder": "socks5://user:pass@dind:1080",
            "x_advanced": True,
            "x_col_span": 2,
            # Hide it where it cannot work. The editor's condition is a single
            # equality test, so only one check_type can be named here;
            # dns_resolve is covered by the description and the probe's own
            # config_error.
            "x_hide_when": {"field": "check_type", "value": "icmp_ping"},
        },
    )
