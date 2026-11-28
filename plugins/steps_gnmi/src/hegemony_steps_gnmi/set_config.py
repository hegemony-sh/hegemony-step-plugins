# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``gnmi.set``: change configuration over gNMI as one transaction.

A gNMI Set applies its deletes, then its replaces, then its updates, and the
device applies all of them or none (gNMI specification 3.4.3). The step reads
the touched paths before and after, so the change is visible and comparable
(``evidence.compare``); a dry run reads them and sends nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

import grpc
from pydantic import Field, field_validator, model_validator

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
)

from . import messages
from .client import GnmiError, GnmiSession
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
from .get import collect_values
from .paths import GnmiPath, PathError, parse_path, split_assignment
from .templates import has_template, path_template_errors, value_template_errors
from .values import encode_value

HANDLER_ID = "gnmi.set"

#: Operations (deletes, replaces and updates together) one step sends.
MAX_OPERATIONS = 200
#: Characters of one value as written.
MAX_VALUE_CHARS = 256 * 1024

SetEncoding = Literal["auto", "json_ietf", "json"]
AUTO_SET_ENCODINGS = ("json_ietf", "json")


@dataclass(frozen=True)
class Assignment:
    path: GnmiPath
    value: Any


def parse_assignment(line: str) -> Assignment:
    """``PATH = JSON`` as written (rendered). Raises ``ValueError``."""
    path_text, value_text = split_assignment(line)
    if len(value_text) > MAX_VALUE_CHARS:
        raise ValueError(f"{path_text}: the value is longer than {MAX_VALUE_CHARS} characters")
    path = parse_path(path_text)
    try:
        value = json.loads(value_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{path_text}: the value is not JSON ({exc.msg}); write text in double quotes"
        ) from None
    return Assignment(path=path, value=value)


def _lines(values: list[str]) -> list[str]:
    return [
        line.strip()
        for line in values
        if isinstance(line, str) and line.strip() and not line.strip().startswith("#")
    ]


class GnmiSetConfig(GnmiConnectionConfig):
    """Config for ``gnmi.set``."""

    deletes: list[str] = Field(
        default_factory=list,
        title="Delete (one path per line)",
        description="Paths to delete, one per line. Applied first.",
        json_schema_extra={
            "x_widget": "commands",
            "x_rows": 2,
            "x_col_span": 2,
            "x_placeholder": "/interfaces/interface[name=Loopback9]",
        },
    )
    replaces: list[str] = Field(
        default_factory=list,
        title="Replace (PATH = JSON, one per line)",
        description=(
            "Paths whose whole content is replaced by the value, one PATH = JSON per line. "
            "Anything under the path the value leaves out is removed. Applied after the "
            "deletes."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_rows": 3,
            "x_col_span": 2,
            "x_placeholder": '/system/ntp/config = {"enabled": true}',
        },
    )
    updates: list[str] = Field(
        default_factory=list,
        title="Update (PATH = JSON, one per line)",
        description=(
            "Paths merged with the value, one PATH = JSON per line; what the value leaves "
            "out stays as it is. Text values are written in double quotes. A value from a "
            "template is written {{ inputs.x | tojson }}. Applied last."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_rows": 4,
            "x_col_span": 2,
            "x_placeholder": (
                '/interfaces/interface[name=Ethernet1]/config/description = "uplink"'
            ),
        },
    )
    encoding: SetEncoding = Field(
        default="auto",
        title="Encoding",
        description=(
            "How values are sent. Auto takes JSON_IETF (RFC 7951) when the device lists it, "
            "else JSON."
        ),
        json_schema_extra={"x_advanced": True},
    )
    dry_run: bool = Field(
        default=False,
        title="Dry run",
        description=(
            "Connect, read the current values of the paths and show what would be sent, then "
            "stop: nothing is changed. gNMI has no device-side check of a change, so a dry "
            "run cannot tell whether the device would accept it."
        ),
    )
    read_back: bool = Field(
        default=True,
        title="Read before and after",
        description=(
            "Read the configuration of every changed path before the change and after it, "
            "and report which paths changed. Off sends the change alone."
        ),
        json_schema_extra={"x_advanced": True},
    )
    max_parallel_devices: int = max_parallel_field(1)

    @field_validator("deletes", "replaces", "updates")
    @classmethod
    def _clean(cls, lines: list[str]) -> list[str]:
        return _lines(lines)

    @model_validator(mode="after")
    def _operations(self) -> GnmiSetConfig:
        total = len(self.deletes) + len(self.replaces) + len(self.updates)
        if total > MAX_OPERATIONS:
            raise ValueError(f"at most {MAX_OPERATIONS} deletes, replaces and updates together")
        for name in ("deletes", "replaces", "updates"):
            for number, line in enumerate(getattr(self, name), 1):
                if has_template(line):
                    continue  # checked as written by template_errors, parsed once rendered
                try:
                    if name == "deletes":
                        parse_path(line)
                    else:
                        parse_assignment(line)
                except ValueError as exc:
                    raise ValueError(f"{name} line {number}: {exc}") from None
        return self


@dataclass(frozen=True)
class SetPlan:
    deletes: tuple[GnmiPath, ...]
    replaces: tuple[Assignment, ...]
    updates: tuple[Assignment, ...]

    @property
    def touched(self) -> list[GnmiPath]:
        seen: dict[str, GnmiPath] = {}
        for path in (
            *self.deletes,
            *(item.path for item in self.replaces),
            *(item.path for item in self.updates),
        ):
            seen.setdefault(str(path), path)
        return list(seen.values())

    def describe(self) -> list[dict[str, Any]]:
        return [
            *({"op": "delete", "path": str(path)} for path in self.deletes),
            *({"op": "replace", "path": str(a.path), "value": a.value} for a in self.replaces),
            *({"op": "update", "path": str(a.path), "value": a.value} for a in self.updates),
        ]


def build_plan(config: GnmiSetConfig) -> SetPlan:
    """The parsed operations of a rendered config. Raises ``ValueError``."""
    return SetPlan(
        deletes=tuple(parse_path(line) for line in config.deletes),
        replaces=tuple(parse_assignment(line) for line in config.replaces),
        updates=tuple(parse_assignment(line) for line in config.updates),
    )


async def read_paths(
    session: GnmiSession, paths: list[GnmiPath], *, encoding: str
) -> tuple[dict[str, Any], list[str]]:
    """The configuration under each path: ``(values by path, paths the device has not)``.

    One Get per path, so a path that does not exist yet (NOT_FOUND) is
    reported as missing instead of failing the others.
    """
    values: dict[str, Any] = {}
    missing: list[str] = []
    for path in paths:
        try:
            response = await session.get(
                [path.to_proto()], data_type="CONFIG", encoding=encoding.upper()
            )
        except GnmiError as exc:
            if exc.code == grpc.StatusCode.NOT_FOUND:
                missing.append(str(path))
                continue
            raise
        found = collect_values(response)
        if not found:
            missing.append(str(path))
        values.update(found)
    return values, missing


def changed_paths(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    return sorted(path for path in {*before, *after} if before.get(path) != after.get(path))


def _operation_name(number: int) -> str:
    return messages.enum_name("gnmi.UpdateResult.Operation", number).lower()


class GnmiSetHandler(BaseHandler):
    """Change configuration on each device over gNMI, as one transaction per device."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.EXECUTE]
    display_name = "gNMI Set"
    description = (
        "Change configuration on devices over gNMI: delete, replace and update paths as one "
        "transaction, with a dry run and the values before and after."
    )
    category = "Actions"
    targeting = HandlerTargeting(ips=False)
    raw_config_keys = frozenset(SECRET_FIELDS)
    config_model = GnmiSetConfig
    default_config = {"encoding": "auto", "read_back": True}
    output_fields = (
        OutputField(
            "devices",
            "Each device's result by name: ok, error, applied, operations, before and after "
            "(each path's configuration), changed (the paths whose value changed) and missing "
            "(paths that did not exist before)",
            "object",
        ),
        OutputField("dry_run", "Whether the step only read and sent nothing", "bool"),
        OutputField("truncated", "Output values and texts cut short, as device.key", "list"),
    )

    def template_errors(self, config: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        for name in ("deletes", "replaces", "updates"):
            lines = config.get(name)
            if not isinstance(lines, list):
                continue
            for number, line in enumerate(lines, 1):
                if not isinstance(line, str) or not has_template(line):
                    continue
                where = f"{name} line {number}"
                if name == "deletes":
                    errors += path_template_errors(line.strip(), where)
                    continue
                try:
                    path_text, value_text = split_assignment(line.strip())
                except PathError as exc:
                    errors.append(f"{where}: {exc}")
                    continue
                errors += path_template_errors(path_text, where)
                errors += value_template_errors(value_text, where)
        return errors

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, GnmiSetConfig)
        except InvalidConfigError as exc:
            return exc.result()
        try:
            plan = build_plan(config)
        except ValueError as exc:
            return HandlerResult(
                success=False, error=f"Invalid gnmi.set config: {exc}", summary="Config error"
            )
        if not plan.touched:
            return HandlerResult(
                success=False,
                error="Nothing to change: set Delete, Replace or Update",
                summary="Missing operations",
            )
        access = await prepare(ctx, config)
        if isinstance(access, HandlerResult):
            return access
        touched = plan.touched
        operations = plan.describe()

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            outcome.value_keys = ("operations", "before", "after")
            outcome.output = {"applied": False, "operations": operations}
            async with gnmi_session(ctx, device, config, access) as session:
                encoding = pick_encoding(session, config.encoding, choices=AUTO_SET_ENCODINGS)
                outcome.output["encoding"] = encoding
                before: dict[str, Any] | None = None
                if config.read_back or config.dry_run:
                    before, missing = await read_paths(session, touched, encoding=encoding)
                    outcome.output.update(before=before, missing=missing)
                    outcome.evidence.append(
                        text_evidence(
                            device,
                            "gnmi set before",
                            pretty_json(before),
                            command="gnmi get config " + " ".join(map(str, touched)),
                        )
                    )
                if config.dry_run:
                    return
                response = await session.set(
                    deletes=[path.to_proto() for path in plan.deletes],
                    replaces=[
                        (item.path.to_proto(), encode_value(item.value, encoding))
                        for item in plan.replaces
                    ],
                    updates=[
                        (item.path.to_proto(), encode_value(item.value, encoding))
                        for item in plan.updates
                    ],
                )
                outcome.output["applied"] = True
                outcome.output["timestamp"] = response.timestamp or None
                outcome.output["results"] = [_operation_name(item.op) for item in response.response]
                outcome.evidence.append(
                    text_evidence(
                        device,
                        "gnmi set request",
                        pretty_json(operations),
                        command="gnmi set",
                    )
                )
                if before is None:
                    return
                try:
                    after, _ = await read_paths(session, touched, encoding=encoding)
                except GnmiError as exc:
                    raise GnmiError(
                        f"the change was applied, but reading it back failed: {exc}"
                    ) from None
            outcome.output.update(after=after, changed=changed_paths(before, after))
            outcome.evidence.append(
                text_evidence(
                    device,
                    "gnmi set after",
                    pretty_json(after),
                    command="gnmi get config " + " ".join(map(str, touched)),
                )
            )

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except StepUnavailable as exc:
            return unavailable(exc)
        passed = sum(outcome.ok for outcome in outcomes)
        verb = "dry run" if config.dry_run else "applied"
        return build_result(
            outcomes,
            summary=f"gnmi set {verb}: {passed}/{len(outcomes)} devices",
            extra_output={"dry_run": config.dry_run},
        )
