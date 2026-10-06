# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SleepHandler: simple delay/wait handler."""

import asyncio
import logging

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    StepKind,
)

logger = logging.getLogger(__name__)


class SleepConfig(BaseModel):
    """Config for ``general.sleep``."""

    model_config = ConfigDict(extra="allow")

    duration_seconds: int = Field(
        default=30,
        ge=1,
        # Steps saved before the rename carry seconds.
        validation_alias=AliasChoices("duration_seconds", "seconds"),
        title="Duration (seconds)",
        description=(
            "How many seconds the flow pauses at this step before moving on. "
            "Must be at least 1; defaults to 30."
        ),
        json_schema_extra={"x_legacy_keys": ["seconds"]},
    )
    message: str | None = Field(
        default=None,
        title="Message (optional)",
        description=(
            "Note recorded as the step summary and in the sleep evidence, "
            "e.g. why the flow is waiting. When omitted, a generated "
            "'Sleeping for N seconds' text is used."
        ),
        json_schema_extra={"x_placeholder": "e.g., Waiting for BGP to converge"},
    )


class SleepHandler(BaseHandler):
    """Handler for simple delays/sleep (settings: :class:`SleepConfig`)."""

    handler_id = "general.sleep"
    supported_kinds = [StepKind.WAIT, StepKind.ACTION]
    display_name = "Sleep"
    description = "Pause the flow for a fixed duration."
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = SleepConfig
    default_config = {"duration_seconds": 30}
    run_timeout_field = "duration_seconds"

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Sleep for configured duration."""
        try:
            config = self.parse_config(ctx.config, SleepConfig)
        except InvalidConfigError as exc:
            return exc.result()
        seconds = config.duration_seconds
        message = config.message or f"Sleeping for {seconds} seconds"

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
