# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ExecuteCLIActionHandler: execute CLI commands on devices as actions."""

import logging
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_CHAIN_OUTPUT_CHARS,
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
    command_label,
    for_each_target_device,
    max_parallel_from_config,
)

logger = logging.getLogger(__name__)

_DEFAULT_COMMAND_TIMEOUT_SECONDS = 30


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
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Devices processed concurrently (1 = sequential)",
    )
    command_timeout_seconds: int = Field(
        _DEFAULT_COMMAND_TIMEOUT_SECONDS,
        ge=1,
        le=3600,
        title="Command timeout (seconds)",
        description=(
            "How long one command may run on a device before it fails. With the "
            "netmiko transport a configuration block is sent as one command, so "
            "the limit covers the whole block. The step timeout must still cover "
            "every command on every device. Defaults to 30 seconds."
        ),
    )


def _top_level_cli_failure_detail(*, error: str | None, exit_code: int) -> str:
    """Return a sanitized CLI failure detail for summary/error surfaces."""
    if error:
        return error
    return f"CLI command failed with exit code {exit_code}"


@dataclass
class _DeviceOutcome:
    """One device's results, merged in device order after the fan-out.

    Workers collect into these locals instead of shared lists so aggregation
    stays deterministic when devices run in parallel (completion order varies;
    device order does not).
    """

    evidence: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    output_parts: list[str] = field(default_factory=list)
    success: bool = True
    commands_run: int = 0


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

        services = ctx.require_services()
        command_timeout = float(
            ctx.config.get("command_timeout_seconds") or _DEFAULT_COMMAND_TIMEOUT_SECONDS
        )

        async def _process_device(device: dict) -> _DeviceOutcome:
            outcome = _DeviceOutcome()
            device_id = device.get("id", device.get("mgmt_host"))
            device_name = device.get("name", device_id)
            host = device.get("mgmt_host")
            if not host:
                outcome.success = False
                outcome.errors.append(f"{device_name}: no mgmt_host configured")
                return outcome

            try:
                # step_run_id registers the session, so cancelling the run
                # closes it.
                ssh = services.connect(
                    device,
                    platform=device.get("platform"),
                    command_timeout=command_timeout,
                    step_run_id=ctx.step_run_id,
                )
                # Execute all commands together so config mode detection works
                results = await ssh.execute_commands(commands)

                # For config command sets, create a single consolidated artifact
                if self._is_config_command_set(commands):
                    # `exit` is a config line sent to the device (it leaves
                    # a sub-mode), so only the block wrappers are left out.
                    config_cmds = []
                    for cmd in commands:
                        cmd_lower = cmd.strip().lower()
                        if (
                            cmd_lower not in ("configure terminal", "conf t", "config t", "end")
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
                        outcome.output_parts.append(full_output)
                        # Live view: the config-session transcript streams too.
                        # The host redacts every platform-resolved secret
                        # (device/enable/bastion credentials, secret()/file()
                        # template values) from progress events and artifacts
                        # alike, so a credential echoed by the device reaches
                        # neither surface in clear. Operator-typed literals are
                        # out of scope — we redact used secrets, no more; see
                        # docs/development/ssh-output-streaming.md (host repo).
                        await ctx.emit_output(full_output, device=device, command="configure")

                    if has_error:
                        outcome.success = False
                        outcome.errors.append(f"{device_name}: {error_msg}")

                    artifact_name = (
                        f"Configuration ({device_name})"
                        if len(target_devices) > 1
                        else "Configuration"
                    )
                    outcome.evidence.append(
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
                            outcome.output_parts.append(result.output)
                            # Live view: per-command output into the Logs tab
                            await ctx.emit_output(
                                result.output, device=device, command=result.command
                            )
                        outcome.evidence.append(
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
                            outcome.success = False
                            failure_detail = _top_level_cli_failure_detail(
                                error=result.error,
                                exit_code=result.exit_code,
                            )
                            outcome.errors.append(f"{device_name}: {failure_detail}")

                outcome.commands_run = len(commands)

            except Exception as e:
                outcome.success = False
                outcome.errors.append(f"{device_name}: {str(e)}")
                outcome.evidence.append(
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

            return outcome

        outcomes = await for_each_target_device(
            target_devices,
            _process_device,
            max_parallel=max_parallel_from_config(ctx.config),
        )

        all_evidence = [item for outcome in outcomes for item in outcome.evidence]
        device_errors = [error for outcome in outcomes for error in outcome.errors]
        combined_output_parts = [part for outcome in outcomes for part in outcome.output_parts]
        all_success = all(outcome.success for outcome in outcomes)
        total_commands = sum(outcome.commands_run for outcome in outcomes)

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
