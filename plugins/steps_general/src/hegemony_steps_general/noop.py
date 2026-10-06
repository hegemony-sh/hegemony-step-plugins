# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""NoOp handler (does nothing)."""

import asyncio

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    StepKind,
)


class NoOpConfig(BaseModel):
    """Config for the internal ``noop`` handler."""

    model_config = ConfigDict(extra="allow")

    delay_seconds: float = Field(
        default=0,
        ge=0,
        title="Delay (seconds)",
        description=(
            "Artificial delay before the step reports success. The default 0 "
            "completes immediately; a positive value sleeps that many seconds "
            "first. Cannot be negative."
        ),
    )


class NoOpHandler(BaseHandler):
    """Handler that does nothing (for testing/placeholders)."""

    handler_id = "general.noop"
    supported_kinds = [StepKind.CHECK, StepKind.ACTION, StepKind.WAIT, StepKind.EXECUTE]
    display_name = "No-op"
    description = "Does nothing; placeholder/testing step."
    hidden = True
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = NoOpConfig
    run_timeout_field = "delay_seconds"

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Do nothing and succeed."""
        try:
            config = self.parse_config(ctx.config, NoOpConfig)
        except InvalidConfigError as exc:
            return exc.result()
        delay = config.delay_seconds
        if delay > 0:
            await asyncio.sleep(delay)

        return HandlerResult(
            success=True,
            summary="No-op completed",
            metrics={"delay_seconds": delay},
        )
