# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""PollUntilHandler: poll a command until a condition matches."""

import asyncio
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)

logger = logging.getLogger(__name__)


class PollUntilConfig(BaseModel):
    """Config for ``netcli.poll_until``."""

    model_config = ConfigDict(extra="allow")

    command: str = Field(
        default="",
        title="Command to Poll",
        json_schema_extra={"x_placeholder": "e.g., show standby brief", "x_col_span": 2},
    )
    match_regex: str = Field(
        default="",
        title="Match Regex (optional)",
        description="Regex pattern to match in command output",
        json_schema_extra={"x_placeholder": "e.g., Active.*192\\.168\\.1\\.1"},
    )
    match_string: str = Field(
        default="",
        title="Match String (optional)",
        description="Literal string to find (case-insensitive)",
        json_schema_extra={"x_placeholder": "e.g., State is Active"},
    )
    interval_seconds: int = Field(default=5, ge=1, title="Interval (sec)")
    max_attempts: int = Field(default=12, ge=1, title="Max Attempts")
    invert_match: bool = Field(
        default=False,
        title="Invert Match",
        description="Succeed when pattern does NOT match",
    )


class PollUntilHandler(BaseHandler):
    """Handler for polling a command until condition is met."""

    handler_id = "netcli.poll_until"
    supported_kinds = [StepKind.CHECK, StepKind.WAIT]
    display_name = "Poll Until"
    description = "Poll a device command until its output matches a condition."
    category = "Checks"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = PollUntilConfig
    default_config = {"interval_seconds": 5, "max_attempts": 12}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Poll command until condition matches on all target devices."""
        import re

        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )

        command = ctx.config.get("command")
        match_regex = ctx.config.get("match_regex")
        match_string = ctx.config.get("match_string")
        interval = ctx.config.get("interval_seconds", 5)
        max_attempts = ctx.config.get("max_attempts", 12)
        invert_match = ctx.config.get("invert_match", False)

        if not command:
            return HandlerResult(
                success=False,
                error="No command configured",
                summary="Poll configuration error",
            )

        if not match_regex and not match_string:
            return HandlerResult(
                success=False,
                error="No match condition configured (match_regex or match_string required)",
                summary="Poll configuration error",
            )

        # Compile regex if provided
        pattern = None
        if match_regex:
            try:
                pattern = re.compile(match_regex, re.MULTILINE | re.IGNORECASE)
            except re.error as e:
                return HandlerResult(
                    success=False,
                    error=f"Invalid regex pattern: {e}",
                    summary="Poll configuration error",
                )

        all_evidence = []
        all_success = True
        device_errors = []

        services = ctx.require_services()
        for device in target_devices:
            device_id = device.get("id", device.get("mgmt_host"))
            device_name = device.get("name", device_id)
            host = device.get("mgmt_host")
            if not host:
                all_success = False
                device_errors.append(f"{device_name}: no mgmt_host configured")
                continue

            attempt = 0
            last_output = ""
            all_outputs: list[dict[str, Any]] = []
            device_success = False

            try:
                transport = services.connect(device, platform=device.get("platform"))

                while attempt < max_attempts:
                    attempt += 1
                    logger.info(
                        f"Poll attempt {attempt}/{max_attempts} on {device_name}: {command}"
                    )

                    result = await transport.execute_command(command)
                    output = result.output
                    last_output = output
                    all_outputs.append({"attempt": attempt, "output_preview": output[:500]})
                    if output:
                        # Live view: each poll attempt's output into the Logs tab
                        await ctx.emit_output(output, device=device, command=command)

                    # Check match condition
                    matched = False
                    if pattern:
                        matched = bool(pattern.search(output))
                    elif match_string:
                        matched = match_string.lower() in output.lower()

                    # Handle invert_match
                    if invert_match:
                        matched = not matched

                    if matched:
                        device_success = True
                        all_evidence.append(
                            {
                                "kind": "poll_result",
                                "name": (
                                    f"poll_{command.split()[0]}_{device_name}"
                                    if len(target_devices) > 1
                                    else f"poll_{command.split()[0]}"
                                ),
                                "device_id": device_id,
                                "content_json": {
                                    "device_id": device_id,
                                    "device_name": device_name,
                                    "command": command,
                                    "attempts": attempt,
                                    "matched": True,
                                    "match_condition": match_regex or match_string,
                                    "final_output": last_output,
                                },
                            }
                        )
                        break

                    # Wait before next attempt
                    if attempt < max_attempts:
                        await asyncio.sleep(interval)

                if not device_success:
                    all_success = False
                    device_errors.append(
                        f"{device_name}: condition not matched after {max_attempts} attempts"
                    )
                    all_evidence.append(
                        {
                            "kind": "poll_result",
                            "name": (
                                f"poll_{command.split()[0]}_{device_name}"
                                if len(target_devices) > 1
                                else f"poll_{command.split()[0]}"
                            ),
                            "device_id": device_id,
                            "content_json": {
                                "device_id": device_id,
                                "device_name": device_name,
                                "command": command,
                                "attempts": max_attempts,
                                "matched": False,
                                "match_condition": match_regex or match_string,
                                "final_output": last_output,
                                "all_attempts": all_outputs,
                            },
                        }
                    )

            except Exception as e:
                logger.error(f"Poll error on {device_name}: {e}")
                all_success = False
                device_errors.append(f"{device_name}: {str(e)}")
                all_evidence.append(
                    {
                        "kind": "poll_result",
                        "name": f"poll_error_{device_name}",
                        "device_id": device_id,
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": str(e),
                        },
                    }
                )

        if all_success:
            summary = f"Condition matched on all {len(target_devices)} device(s)"
        else:
            summary = f"Poll failed: {'; '.join(device_errors)}"

        return HandlerResult(
            success=all_success,
            error="; ".join(device_errors) if device_errors else None,
            summary=summary,
            metrics={
                "device_count": len(target_devices),
                "max_attempts": max_attempts,
                "interval_seconds": interval,
            },
            evidence=all_evidence,
        )
