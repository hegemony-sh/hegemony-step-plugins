# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SleepHandler: simple delay/wait handler."""

import asyncio
import logging

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)

logger = logging.getLogger(__name__)


class SleepConfig(BaseModel):
    """Config for ``general.sleep``."""

    model_config = ConfigDict(extra="allow")

    seconds: int = Field(
        default=30,
        ge=1,
        title="Duration (seconds)",
        description=(
            "How many seconds the flow pauses at this step before moving on. "
            "Must be at least 1; defaults to 30."
        ),
    )
    message: str = Field(
        default="",
        title="Message (optional)",
        description=(
            "Note recorded as the step summary and in the sleep evidence, "
            "e.g. why the flow is waiting. When omitted, a generated "
            "'Sleeping for N seconds' text is used."
        ),
        json_schema_extra={"x_placeholder": "e.g., Waiting for BGP to converge"},
    )


class SleepHandler(BaseHandler):
    """Handler for simple delays/sleep.

    Config:
        seconds: int - Number of seconds to sleep (required)
        message: str - Optional message to log
    """

    handler_id = "general.sleep"
    supported_kinds = [StepKind.WAIT, StepKind.ACTION]
    display_name = "Sleep"
    description = "Pause the flow for a fixed duration."
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = SleepConfig
    default_config = {"seconds": 30}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Sleep for configured duration."""
        seconds = ctx.config.get("seconds", 0)
        default_message = f"Sleeping for {seconds} seconds"
        message = ctx.config.get("message", default_message)

        if seconds <= 0:
            return HandlerResult(
                success=False,
                error="Invalid sleep duration: must be > 0",
                summary="Sleep configuration error",
            )

        logger.info(f"Sleep starting: {seconds}s - {message}")
        await asyncio.sleep(seconds)
        logger.info(f"Sleep completed: {seconds}s")

        return HandlerResult(
            success=True,
            summary=message,
            metrics={"sleep_seconds": seconds},
            evidence=[
                {
                    "kind": "step_result",
                    "name": "sleep_completed",
                    "content_json": {
                        "seconds": seconds,
                        "message": message,
                    },
                }
            ],
        )
