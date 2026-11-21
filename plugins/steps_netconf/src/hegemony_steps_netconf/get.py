# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``netconf.get``: read configuration or state data over NETCONF."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
)

from .client import CAP_CANDIDATE, CAP_STARTUP, CAP_XPATH, NetconfError, filter_xml
from .common import (
    DeviceOutcome,
    NetconfConnectionConfig,
    SessionUnavailable,
    build_result,
    max_parallel_field,
    netconf_session,
    no_targets,
    run_per_device,
    text_evidence,
    unavailable,
)

HANDLER_ID = "netconf.get"

Source = Literal["running", "candidate", "startup", "state"]


class NetconfGetConfig(NetconfConnectionConfig):
    """Config for ``netconf.get``."""

    source: Source = Field(
        default="running",
        title="Read",
        description=(
            "Running, candidate or startup reads that datastore's configuration "
            "(get-config). Configuration and state reads both, operational data included "
            "(get). Defaults to running."
        ),
        json_schema_extra={
            "x_option_labels": {
                "running": "Running configuration",
                "candidate": "Candidate configuration",
                "startup": "Startup configuration",
                "state": "Configuration and state",
            }
        },
    )
    filter_type: Literal["subtree", "xpath"] = Field(
        default="subtree",
        title="Filter Type",
        description="How Filter selects the data: a subtree of XML, or an XPath expression.",
    )
    filter: str = Field(
        default="",
        title="Filter",
        description=(
            "What to read. A subtree filter is XML naming the nodes, with their namespace; "
            "an XPath filter is one expression. Empty reads everything, which can be large."
        ),
        json_schema_extra={
            "x_widget": "textarea",
            "x_rows": 6,
            "x_col_span": 2,
            "x_placeholder": ('<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/>'),
        },
    )
    max_parallel_devices: int = max_parallel_field(10)

    @model_validator(mode="after")
    def _filter_parses(self) -> NetconfGetConfig:
        if self.filter.strip():
            try:
                filter_xml(self.filter_type, self.filter)
            except NetconfError as exc:
                raise ValueError(str(exc)) from None
        return self


class NetconfGetHandler(BaseHandler):
    """Read configuration or state data from each device over NETCONF."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.CHECK, StepKind.EXECUTE]
    display_name = "NETCONF Get"
    description = "Read configuration or state data from devices over NETCONF."
    category = "Checks"
    targeting = HandlerTargeting(ips=False)
    config_model = NetconfGetConfig
    default_config = {"source": "running", "filter_type": "subtree"}
    output_fields = (
        OutputField(
            "devices",
            "Each device's result by name: ok, error and data (the XML read, cut short when long)",
            "object",
        ),
        OutputField("truncated", "Output texts cut short, as device.key", "list"),
    )

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, NetconfGetConfig)
        except InvalidConfigError as exc:
            return exc.result()
        filter_body = filter_xml(config.filter_type, config.filter)

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            outcome.text_keys = ("data",)
            async with netconf_session(ctx, device, config) as session:
                if (
                    config.filter_type == "xpath"
                    and filter_body
                    and not session.supports(CAP_XPATH)
                ):
                    raise NetconfError("the device has no :xpath capability; use a subtree filter")
                if config.source == "state":
                    reply = await session.get(filter_body)
                else:
                    needs = {"candidate": CAP_CANDIDATE, "startup": CAP_STARTUP}.get(config.source)
                    if needs and not session.supports(needs):
                        raise NetconfError(f"the device has no {config.source} datastore")
                    reply = await session.get_config(config.source, filter_body)
            data = reply.pretty_data()
            outcome.output = {"data": data, "source": config.source}
            outcome.evidence.append(
                text_evidence(
                    device,
                    f"netconf {config.source}",
                    data,
                    command=f"netconf get {config.source} {config.filter.strip()}".strip(),
                )
            )

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except SessionUnavailable as exc:
            return unavailable(exc)
        passed = sum(outcome.ok for outcome in outcomes)
        return build_result(
            outcomes, summary=f"netconf get {config.source}: {passed}/{len(outcomes)} devices"
        )
