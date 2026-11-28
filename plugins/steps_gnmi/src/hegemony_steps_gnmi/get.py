# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``gnmi.get``: read configuration or state data over gNMI."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, field_validator

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
)

from .common import (
    SECRET_FIELDS,
    DeviceOutcome,
    GnmiConnectionConfig,
    StepUnavailable,
    build_result,
    gnmi_session,
    max_parallel_field,
    no_targets,
    pick_encoding,
    prepare,
    pretty_json,
    run_per_device,
    text_evidence,
    unavailable,
)
from .paths import PathError, parse_path, path_from_proto
from .templates import has_template, path_template_errors
from .values import decode_value

HANDLER_ID = "gnmi.get"

#: Paths one step reads.
MAX_PATHS = 100

DataType = Literal["all", "config", "state", "operational"]
GetEncoding = Literal["auto", "json_ietf", "json", "proto", "ascii"]

#: What ``auto`` picks, in order, from the encodings the device lists.
AUTO_GET_ENCODINGS = ("json_ietf", "json", "proto")


def collect_values(response: Any) -> dict[str, Any]:
    """``{path: value}`` of every update a Get (or Set read-back) returned."""
    values: dict[str, Any] = {}
    for notification in response.notification:
        prefix = notification.prefix if notification.HasField("prefix") else None
        for update in notification.update:
            values[path_from_proto(update.path, prefix=prefix)] = decode_value(update.val)
    return values


class GnmiGetConfig(GnmiConnectionConfig):
    """Config for ``gnmi.get``."""

    paths: list[str] = Field(
        default_factory=list,
        title="Paths (one per line)",
        description=(
            "What to read, one gNMI path per line, such as "
            "/interfaces/interface[name=Ethernet1]/state. Write origin:/path for another "
            "origin (openconfig:/system). A key value from a template is written "
            "[name={{ inputs.interface | tojson }}]."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_rows": 4,
            "x_col_span": 2,
            "x_placeholder": "/interfaces/interface[name=Ethernet1]/state/counters",
        },
    )
    data_type: DataType = Field(
        default="all",
        title="Data",
        description=(
            "All reads configuration and state; Config only configuration (read-write) "
            "nodes; State only state (read-only) nodes; Operational only state nodes that "
            "are not derived from configuration. Defaults to all."
        ),
        json_schema_extra={
            "x_option_labels": {
                "all": "Configuration and state",
                "config": "Configuration",
                "state": "State",
                "operational": "Operational state",
            }
        },
    )
    encoding: GetEncoding = Field(
        default="auto",
        title="Encoding",
        description=(
            "How the device encodes the data. Auto takes JSON_IETF, else JSON, else PROTO, "
            "whichever the device lists first in that order."
        ),
        json_schema_extra={"x_advanced": True},
    )
    max_parallel_devices: int = max_parallel_field(10)

    @field_validator("paths")
    @classmethod
    def _paths(cls, paths: list[str]) -> list[str]:
        cleaned = [path.strip() for path in paths if isinstance(path, str) and path.strip()]
        if len(cleaned) > MAX_PATHS:
            raise ValueError(f"at most {MAX_PATHS} paths")
        for number, path in enumerate(cleaned, 1):
            if has_template(path):
                continue  # checked as written by template_errors, parsed once rendered
            try:
                parse_path(path)
            except PathError as exc:
                raise ValueError(f"path {number}: {exc}") from None
        return cleaned


class GnmiGetHandler(BaseHandler):
    """Read configuration or state data from each device over gNMI."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.CHECK, StepKind.EXECUTE]
    display_name = "gNMI Get"
    description = "Read configuration or state data from devices over gNMI."
    category = "Checks"
    targeting = HandlerTargeting(ips=False)
    raw_config_keys = frozenset(SECRET_FIELDS)
    config_model = GnmiGetConfig
    default_config = {"data_type": "all", "encoding": "auto"}
    output_fields = (
        OutputField(
            "devices",
            "Each device's result by name: ok, error, values (each path read and its value) "
            "and data (the same as JSON text, cut short when long)",
            "object",
        ),
        OutputField("truncated", "Output values and texts cut short, as device.key", "list"),
    )

    def template_errors(self, config: dict[str, Any]) -> list[str]:
        paths = config.get("paths")
        if not isinstance(paths, list):
            return []
        errors: list[str] = []
        for number, path in enumerate(paths, 1):
            if isinstance(path, str):
                errors += path_template_errors(path, f"paths line {number}")
        return errors

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, GnmiGetConfig)
        except InvalidConfigError as exc:
            return exc.result()
        if not config.paths:
            return HandlerResult(
                success=False, error="No paths configured", summary="Missing paths"
            )
        try:
            paths = [parse_path(path) for path in config.paths]
        except PathError as exc:
            return HandlerResult(
                success=False, error=f"Invalid gnmi.get path: {exc}", summary="Config error"
            )
        access = await prepare(ctx, config)
        if isinstance(access, HandlerResult):
            return access

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            outcome.text_keys = ("data",)
            outcome.value_keys = ("values",)
            async with gnmi_session(ctx, device, config, access) as session:
                encoding = pick_encoding(session, config.encoding, choices=AUTO_GET_ENCODINGS)
                response = await session.get(
                    [path.to_proto() for path in paths],
                    data_type=config.data_type.upper(),
                    encoding=encoding.upper(),
                )
            values = collect_values(response)
            data = pretty_json(values)
            outcome.output = {
                "values": values,
                "data": data,
                "data_type": config.data_type,
                "encoding": encoding,
            }
            outcome.evidence.append(
                text_evidence(
                    device,
                    f"gnmi get {config.data_type}",
                    data,
                    command="gnmi get " + " ".join(str(path) for path in paths),
                )
            )

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except StepUnavailable as exc:
            return unavailable(exc)
        passed = sum(outcome.ok for outcome in outcomes)
        return build_result(
            outcomes, summary=f"gnmi get {config.data_type}: {passed}/{len(outcomes)} devices"
        )
