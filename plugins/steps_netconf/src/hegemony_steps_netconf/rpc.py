# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``netconf.rpc``: send any NETCONF operation and keep its reply."""

from __future__ import annotations

import re
from typing import Any

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

from .client import NetconfError, check_fragment, inherited_prefixes, local_name, pretty
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

HANDLER_ID = "netconf.rpc"

#: Operations with a step of their own, or that would break the session.
_REFUSED = {"hello", "close-session", "kill-session"}


class NetconfRpcConfig(NetconfConnectionConfig):
    """Config for ``netconf.rpc``."""

    rpc: str = Field(
        default="",
        validate_default=True,
        title="Operation",
        description=(
            "The XML that goes inside <rpc>: one operation element with its namespace, such "
            'as <save-config xmlns="http://cisco.com/yang/cisco-ia"/>. Templates are filled '
            "in."
        ),
        json_schema_extra={
            "x_widget": "textarea",
            "x_rows": 8,
            "x_col_span": 2,
            "x_placeholder": '<save-config xmlns="http://cisco.com/yang/cisco-ia"/>',
        },
    )
    max_parallel_devices: int = max_parallel_field(1)

    @field_validator("rpc")
    @classmethod
    def _one_operation(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("'rpc' is required")
        try:
            elements = check_fragment(value, what="'rpc'")
        except NetconfError as exc:
            raise ValueError(str(exc)) from None
        if len(elements) != 1:
            raise ValueError("'rpc' must hold exactly one operation element")
        name = local_name(elements[0].tag)
        if name in _REFUSED:
            raise ValueError(f"<{name}> cannot be sent with netconf.rpc")
        return value


class NetconfRpcHandler(BaseHandler):
    """Send one NETCONF operation to each device and keep the reply."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "NETCONF RPC"
    description = "Send any NETCONF operation (a vendor RPC, an action) and keep the reply."
    category = "Actions"
    targeting = HandlerTargeting(ips=False)
    config_model = NetconfRpcConfig
    output_fields = (
        OutputField(
            "devices",
            "Each device's result by name: ok, error, reply (the reply's content, cut short "
            "when long) and warnings",
            "object",
        ),
        OutputField("truncated", "Output texts cut short, as device.key", "list"),
    )

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, NetconfRpcConfig)
        except InvalidConfigError as exc:
            return exc.result()
        operation = local_name(check_fragment(config.rpc, what="'rpc'")[0].tag)

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            outcome.text_keys = ("reply",)
            async with netconf_session(ctx, device, config) as session:
                reply = await session.rpc(config.rpc, operation=operation)
            content = pretty(_inner(reply.text), inherited_prefixes(reply.text, "rpc-reply"))
            outcome.output = {
                "reply": content,
                "warnings": [warning.describe() for warning in reply.warnings],
            }
            outcome.evidence.append(
                text_evidence(
                    device,
                    f"netconf {operation}",
                    content or "<ok/>",
                    command=f"netconf rpc {operation}",
                )
            )

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except SessionUnavailable as exc:
            return unavailable(exc)
        done = sum(outcome.ok for outcome in outcomes)
        return build_result(
            outcomes, summary=f"netconf {operation}: {done}/{len(outcomes)} devices"
        )


def _inner(reply_text: str) -> str:
    """The content of ``<rpc-reply>`` as the device wrote it."""
    opening = re.search(r"<(?:[\w.-]+:)?rpc-reply\b[^>]*>", reply_text)
    closings = list(re.finditer(r"</(?:[\w.-]+:)?rpc-reply\s*>", reply_text))
    closing = closings[-1] if closings else None
    if opening is None or closing is None:
        return ""
    return reply_text[opening.end() : closing.start()]
