# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ExecuteCLIActionHandler: execute CLI commands on devices as actions."""

import logging

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_CHAIN_OUTPUT_CHARS,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
    command_label,
)

logger = logging.getLogger(__name__)


class ExecuteCliConfig(BaseModel):
    """Config for ``netcli.execute``."""

    model_config = ConfigDict(extra="allow")

    commands: list[str] = Field(
        default_factory=list,
        title="Commands (one per line)",
        description="Use {{ variable }} syntax for flow inputs",
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "configure terminal\ninterface {{ interface_name }}\nshutdown",
            "x_rows": 3,
            "x_col_span": 2,
        },
    )


def _top_level_cli_failure_detail(*, error: str | None, exit_code: int) -> str:
    """Return a sanitized CLI failure detail for summary/error surfaces."""
    if error:
        return error
    return f"CLI command failed with exit code {exit_code}"


class ExecuteCLIActionHandler(BaseHandler):
    """Handler for executing CLI commands as an action."""

    handler_id = "netcli.execute"
    supported_kinds = [StepKind.ACTION]
    display_name = "Execute CLI"
    description = "Run CLI commands on target devices."
    category = "Actions"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = ExecuteCliConfig

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Execute CLI commands on all target devices."""
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
        if not commands:
            return HandlerResult(
                success=False,
                error="No commands configured",
                summary="Missing command configuration",
            )

        all_evidence = []
        all_success = True
        device_errors = []
        total_commands = 0
        combined_output_parts: list[str] = []

        services = ctx.require_services()
        for device in target_devices:
            device_id = device.get("id", device.get("mgmt_host"))
            device_name = device.get("name", device_id)
            host = device.get("mgmt_host")
            if not host:
                all_success = False
                device_errors.append(f"{device_name}: no mgmt_host configured")
                continue

            try:
                ssh = services.connect(device, platform=device.get("platform"))
                # Execute all commands together so config mode detection works
                results = await ssh.execute_commands(commands)

                # For config command sets, create a single consolidated artifact
                if self._is_config_command_set(commands):
                    config_cmds = []
                    for cmd in commands:
                        cmd_lower = cmd.strip().lower()
                        if (
                            cmd_lower
                            not in (
                                "configure terminal",
                                "conf t",
                                "config t",
                                "end",
                                "exit",
                            )
                            and not cmd_lower.startswith("write")
                            and not cmd_lower.startswith("copy run")
                        ):
                            config_cmds.append(cmd)

                    full_output = ""
                    has_error = False
                    error_msg = None
                    for result in results:
                        if result.output:
                            full_output += result.output + "\n"
                        if result.exit_code != 0:
                            has_error = True
                            if error_msg is None:
                                error_msg = _top_level_cli_failure_detail(
                                    error=result.error,
                                    exit_code=result.exit_code,
                                )

                    if full_output:
                        combined_output_parts.append(full_output)
                        # Deliberately NOT streamed to the Logs tab: config-mode
                        # sessions echo credential lines (username/password,
                        # RADIUS keys, …). The transcript stays artifact-only;
                        # see docs/development/ssh-output-streaming.md (host
                        # repo) — "Secrets in output".

                    if has_error:
                        all_success = False
                        device_errors.append(f"{device_name}: {error_msg}")

                    artifact_name = (
                        f"Configuration ({device_name})"
                        if len(target_devices) > 1
                        else "Configuration"
                    )
                    all_evidence.append(
                        {
                            "kind": "cli_output",
                            "name": artifact_name,
                            "device_id": device_id,
                            "content_text": (
                                full_output.strip()
                                if full_output
                                else "Configuration applied successfully"
                            ),
                            "content_json": {
                                "device_id": device_id,
                                "device_name": device_name,
                                "commands": config_cmds,
                                "success": not has_error,
                                "exit_code": 1 if has_error else 0,
                                "error": error_msg,
                            },
                        }
                    )
                else:
                    # For show/exec commands, create individual artifacts per command
                    for result in results:
                        command_display = command_label(result.command)
                        cmd_name = (
                            f"{command_display} ({device_name})"
                            if len(target_devices) > 1
                            else command_display
                        )
                        if result.output:
                            combined_output_parts.append(result.output)
                            # Live view: per-command output into the Logs tab
                            await ctx.emit_output(
                                result.output, device=device, command=result.command
                            )
                        all_evidence.append(
                            {
                                "kind": "cli_output",
                                "name": cmd_name,
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
                        if result.exit_code != 0:
                            all_success = False
                            failure_detail = _top_level_cli_failure_detail(
                                error=result.error,
                                exit_code=result.exit_code,
                            )
                            device_errors.append(f"{device_name}: {failure_detail}")

                total_commands += len(commands)

            except Exception as e:
                all_success = False
                device_errors.append(f"{device_name}: {str(e)}")
                all_evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Error ({device_name})",
                        "device_id": device_id,
                        "content_text": str(e),
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": str(e),
                            "success": False,
                        },
                    }
                )

        if all_success:
            summary = f"Executed {len(commands)} commands on {len(target_devices)} device(s)"
        else:
            summary = f"Command execution failed on some devices: {'; '.join(device_errors)}"

        combined_output = "\n".join(combined_output_parts)

        return HandlerResult(
            success=all_success,
            error="; ".join(device_errors) if device_errors else None,
            summary=summary,
            metrics={
                "command_count": len(commands),
                "device_count": len(target_devices),
                "total_executions": total_commands,
            },
            evidence=all_evidence,
            output={
                "stdout": combined_output[:MAX_CHAIN_OUTPUT_CHARS],
            },
        )

    def _is_config_command_set(self, commands: list[str]) -> bool:
        """Check if commands are a configuration command set."""
        if not commands:
            return False
        first_cmd = commands[0].strip().lower()
        return first_cmd in ("configure terminal", "conf t", "config t")
