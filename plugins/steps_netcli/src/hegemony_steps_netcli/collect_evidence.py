# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""CollectEvidenceHandler: collect CLI command outputs as evidence."""

import logging

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    StepKind,
    command_label,
    for_each_target_device,
    max_parallel_from_config,
)

logger = logging.getLogger(__name__)


class CollectEvidenceConfig(BaseModel):
    """Config for ``netcli.collect_evidence``."""

    model_config = ConfigDict(extra="allow")

    commands: list[str] = Field(
        default_factory=list,
        title="Commands (one per line)",
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "show version\nshow interfaces",
            "x_rows": 3,
            "x_col_span": 2,
        },
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Devices processed concurrently (1 = sequential)",
    )


class CollectEvidenceHandler(BaseHandler):
    """Handler for collecting CLI evidence from devices."""

    handler_id = "netcli.collect_evidence"
    supported_kinds = [StepKind.CHECK]
    display_name = "Collect Evidence"
    description = "Capture CLI command outputs from devices as evidence."
    category = "Checks"
    config_model = CollectEvidenceConfig

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Collect CLI command outputs as evidence from all target devices."""
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )

        # Commands are already resolved by resolve_step_templates() before
        # handler execution — no second Jinja pass needed.
        commands = ctx.config.get("commands", [])
        if not isinstance(commands, list):
            return HandlerResult(
                success=False,
                error="'commands' must be a list of strings",
                summary="Invalid commands configuration",
            )
        if any(not isinstance(command, str) or not command.strip() for command in commands):
            return HandlerResult(
                success=False,
                error="'commands' must contain only non-empty strings",
                summary="Invalid commands configuration",
            )
        if not commands:
            return HandlerResult(
                success=True,
                summary="No commands configured",
                evidence=[],
            )

        all_evidence = []
        total_success = 0
        total_failure = 0
        failed_devices = []

        services = ctx.require_services()

        async def _process_device(device: dict) -> None:
            nonlocal total_success, total_failure
            device_id = device.get("id", "unknown")
            device_name = device.get("name", device_id)
            host = device.get("mgmt_host")
            if not host:
                total_failure += 1
                failed_devices.append(device_name)
                all_evidence.append(
                    {
                        "kind": "error",
                        "name": f"error_{device_name}",
                        "device_id": device_id,
                        "content_text": f"Device {device_name} has no mgmt_host configured",
                    }
                )
                return

            try:
                ssh = services.connect(device, platform=device.get("platform"))
                # Execute all commands together for efficiency
                results = await ssh.execute_commands(commands)
                for result in results:
                    if result.output:
                        # Live view: per-command output into the Logs tab
                        await ctx.emit_output(result.output, device=device, command=result.command)
                    all_evidence.append(
                        {
                            "kind": "cli_output",
                            "name": f"{device_name}:{command_label(result.command)}",
                            "device_id": device_id,
                            "content_text": result.output,
                            "content_json": {
                                "device_id": device_id,
                                "device_name": device_name,
                                "command": result.command,
                                "success": result.exit_code == 0,
                                "exit_code": result.exit_code,
                                "error": result.error,
                            },
                        }
                    )
                    if result.exit_code == 0:
                        total_success += 1
                    else:
                        total_failure += 1
                        if device_name not in failed_devices:
                            failed_devices.append(device_name)

            except Exception as e:
                if not any(
                    entry == device_name or entry.startswith(f"{device_name} (")
                    for entry in failed_devices
                ):
                    failed_devices.append(f"{device_name} ({e})")
                # Add error evidence for this device
                all_evidence.append(
                    {
                        "kind": "error",
                        "name": f"{device_name}:connection_error",
                        "device_id": device_id,
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": str(e),
                        },
                    }
                )

        await for_each_target_device(
            target_devices,
            _process_device,
            max_parallel=max_parallel_from_config(ctx.config),
        )

        metrics = {
            "device_count": len(target_devices),
            "command_count": len(commands),
            "total_success": total_success,
            "total_failure": total_failure,
            "failed_devices": len(failed_devices),
        }

        if failed_devices:
            return HandlerResult(
                success=False,
                error=f"Failed on: {', '.join(failed_devices)}",
                summary=f"Evidence collected from {len(target_devices) - len(failed_devices)}/{len(target_devices)} devices",
                metrics=metrics,
                evidence=all_evidence,
            )

        return HandlerResult(
            success=True,
            summary=f"Collected evidence from {len(target_devices)} device(s), {total_success} commands OK",
            metrics=metrics,
            evidence=all_evidence,
        )
