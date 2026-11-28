# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``napalm.get``: read vendor-neutral structured data with NAPALM getters."""

from __future__ import annotations

from typing import Any

from pydantic import Field, field_validator

from hegemony_step_sdk import (
    NAPALM_GETTERS,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
)

from .common import (
    MAX_OUTPUT_TEXT_CHARS,
    DeviceOutcome,
    NapalmConnectionConfig,
    SessionUnavailable,
    build_result,
    log_line,
    max_parallel_field,
    napalm_session,
    no_targets,
    run_per_device,
    text_evidence,
    to_json_text,
    unavailable,
)

HANDLER_ID = "napalm.get"

#: The most a step may read per device.
MAX_GETTERS = 20


class NapalmGetConfig(NapalmConnectionConfig):
    """Config for ``napalm.get``."""

    getters: list[str] = Field(
        default_factory=lambda: ["facts"],
        min_length=1,
        max_length=MAX_GETTERS,
        title="Getters",
        description=(
            "What to read, one getter per line, such as facts, interfaces or bgp_neighbors. "
            "Each gives the same data shape on every platform. Defaults to facts."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_rows": 3,
            "x_placeholder": "facts",
        },
    )
    max_parallel_devices: int = max_parallel_field(10)

    @field_validator("getters")
    @classmethod
    def _known_getters(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in value:
            name = raw.strip()
            if name.startswith("get_"):
                name = name[len("get_") :]
            if not name:
                continue
            if name not in NAPALM_GETTERS:
                allowed = ", ".join(sorted(NAPALM_GETTERS))
                raise ValueError(f"unknown getter {raw.strip()!r}; choose from: {allowed}")
            if name not in cleaned:
                cleaned.append(name)
        if not cleaned:
            raise ValueError("name at least one getter")
        return cleaned


class NapalmGetHandler(BaseHandler):
    """Read structured data from each device with NAPALM getters."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.CHECK, StepKind.EXECUTE]
    display_name = "NAPALM Get"
    description = "Read vendor-neutral structured data (facts, interfaces, BGP, ...) with NAPALM."
    category = "Checks"
    targeting = HandlerTargeting(ips=False)
    config_model = NapalmGetConfig
    default_config = {"getters": ["facts"]}
    output_fields = (
        OutputField(
            "devices",
            "Each device's result by name: ok, error, driver, data (each getter's result) "
            "and omitted (getters whose result was too large for the output; the evidence "
            "has it)",
            "object",
        ),
        OutputField("truncated", "Output texts cut short, as device.key", "list"),
    )

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, NapalmGetConfig)
        except InvalidConfigError as exc:
            return exc.result()

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            data: dict[str, Any] = {}
            async with napalm_session(ctx, device, config) as session:
                outcome.output["driver"] = session.driver
                for getter in config.getters:
                    await log_line(ctx, device, f"get_{getter}")
                    data[getter] = await session.get(getter)
            kept: dict[str, Any] = {}
            omitted: list[str] = []
            for getter, value in data.items():
                text = to_json_text(value)
                outcome.evidence.append(text_evidence(device, getter, text, command=getter))
                # Large results (a whole configuration, a big MAC table) stay
                # in the evidence only, so the run's output stays small.
                if len(text) <= MAX_OUTPUT_TEXT_CHARS:
                    kept[getter] = value
                else:
                    omitted.append(getter)
            outcome.output["data"] = kept
            outcome.output["omitted"] = omitted

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except SessionUnavailable as exc:
            return unavailable(exc)
        passed = sum(outcome.ok for outcome in outcomes)
        return build_result(
            outcomes,
            summary=f"napalm get {', '.join(config.getters)}: {passed}/{len(outcomes)} devices",
        )
