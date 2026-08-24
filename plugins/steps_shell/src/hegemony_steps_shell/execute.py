# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ShellExecuteHandler: run shell commands on remote hosts.

The remote-shell paradigm (see CONVENTIONS.md): exec-channel semantics with
meaningful exit codes and separate stdout/stderr — distinct from netcli's
interactive prompt-scraping. The transport (SSH today, WinRM when the host
implements it) is resolved from ``device.access_config`` via
``services.open_shell``; the interpreter is config, never part of the id.
"""

import logging
import shlex
from dataclasses import dataclass, field
from typing import Any, Literal

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

#: Interpreters that accept the sh-style ``env``/``-c`` wrapping.
_SH_FAMILY = frozenset({"sh", "bash"})


def build_command(
    command: str,
    *,
    shell: str = "default",
    env: dict[str, str] | None = None,
) -> str:
    """Compose the remote command line for the chosen interpreter.

    - ``default``: the command runs as-is in the account's login shell; env
      vars are prefixed via ``env KEY=VALUE`` (POSIX remotes).
    - ``sh``/``bash``: the command is quoted into ``<shell> -c '...'``.
    - ``pwsh``: the command is quoted into ``pwsh -NoProfile -Command '...'``;
      env vars are not supported (no portable prefix syntax).

    Raises ``ValueError`` for unsupported combinations.
    """
    env = env or {}
    if shell == "pwsh":
        if env:
            raise ValueError("env variables are not supported with the pwsh interpreter")
        return f"pwsh -NoProfile -Command {shlex.quote(command)}"

    prefix = ""
    if env:
        pairs = " ".join(f"{key}={shlex.quote(value)}" for key, value in sorted(env.items()))
        prefix = f"env {pairs} "

    if shell in _SH_FAMILY:
        return f"{prefix}{shell} -c {shlex.quote(command)}"
    if shell == "default":
        return f"{prefix}{command}"
    raise ValueError(f"unsupported shell interpreter: {shell}")


class ShellExecuteConfig(BaseModel):
    """Config for ``shell.execute``."""

    model_config = ConfigDict(extra="allow")

    commands: list[str] = Field(
        default_factory=list,
        title="Commands (one per line)",
        description="Each line runs as its own exec-channel command with its own exit code",
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "uname -a\ndf -h /var\nsystemctl is-active nginx",
            "x_rows": 3,
            "x_col_span": 2,
        },
    )
    shell: Literal["default", "sh", "bash", "pwsh"] = Field(
        default="default",
        title="Interpreter",
        description="How commands are wrapped on the remote host",
        json_schema_extra={
            "x_option_labels": {
                "default": "Login shell (as-is)",
                "sh": "sh -c",
                "bash": "bash -c",
                "pwsh": "pwsh -NoProfile -Command",
            }
        },
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        title="Environment Variables",
        description="KEY=VALUE per line; prefixed via env(1). Not supported with pwsh.",
        json_schema_extra={
            "x_widget": "env-vars",
            "x_rows": 3,
            "x_col_span": 2,
            "x_placeholder": "APP_ENV=prod\nRETRIES=3",
        },
    )
    fail_fast: bool = Field(
        default=True,
        title="Stop on first failure",
        description="Skip remaining commands on a device after a non-zero exit code",
    )
    command_timeout_sec: int = Field(
        default=60,
        ge=1,
        title="Per-command timeout (sec)",
        description=(
            "Maximum time in seconds each command may run. The limit applies to "
            "every command individually, not to the step as a whole; a command "
            "that exceeds it fails the device and its remaining commands are "
            "skipped. Defaults to 60 seconds."
        ),
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Hosts processed concurrently (1 = sequential)",
    )


@dataclass
class _DeviceOutcome:
    """One host's results, merged in device order after the fan-out.

    Workers collect into these locals instead of shared lists so aggregation
    stays deterministic when hosts run in parallel.
    """

    evidence: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    output_parts: list[str] = field(default_factory=list)
    executed: int = 0
    success: bool = True


class ShellExecuteHandler(BaseHandler):
    """Run shell commands on each target host over the device's shell transport."""

    handler_id = "shell.execute"
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "Execute Shell"
    description = "Run shell commands on Linux/Unix hosts (exit codes, stdout/stderr)."
    category = "Actions"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = ShellExecuteConfig
    default_config = {"shell": "default", "fail_fast": True, "command_timeout_sec": 60}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )

        commands = ctx.config.get("commands", [])
        if not commands:
            return HandlerResult(
                success=False,
                error="No commands configured",
                summary="Missing command configuration",
            )

        shell = ctx.config.get("shell", "default")
        env = ctx.config.get("env") or {}
        fail_fast = bool(ctx.config.get("fail_fast", True))
        command_timeout = ctx.config.get("command_timeout_sec", 60)

        try:
            composed = [build_command(cmd, shell=shell, env=env) for cmd in commands]
        except ValueError as exc:
            return HandlerResult(
                success=False,
                error=str(exc),
                summary="Shell configuration error",
            )

        services = ctx.require_services()

        async def _process_device(device: dict[str, Any]) -> _DeviceOutcome:
            outcome = _DeviceOutcome()
            device_id = device.get("id", device.get("mgmt_host"))
            device_name = device.get("name", device_id)
            if not device.get("mgmt_host"):
                outcome.success = False
                outcome.errors.append(f"{device_name}: no mgmt_host configured")
                return outcome

            try:
                transport = await services.open_shell(device)
            except Exception as exc:
                outcome.success = False
                outcome.errors.append(f"{device_name}: {exc}")
                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Error ({device_name})",
                        "device_id": device_id,
                        "content_text": str(exc),
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": str(exc),
                            "success": False,
                        },
                    }
                )
                return outcome

            try:
                for original, remote_command in zip(commands, composed, strict=True):
                    result = await transport.run(remote_command, timeout=command_timeout)
                    outcome.executed += 1
                    ok = result.exit_code == 0
                    if result.stdout:
                        outcome.output_parts.append(result.stdout)

                    # Live view: surface each command's output in the Logs tab —
                    # unless the transport already streamed it live (Phase B
                    # sinks set streams_exec_output; emitting again would
                    # duplicate every command's output).
                    if not getattr(transport, "streams_exec_output", False):
                        if result.stdout:
                            await ctx.emit_output(
                                result.stdout, stream="stdout", device=device, command=original
                            )
                        if result.stderr:
                            await ctx.emit_output(
                                result.stderr, stream="stderr", device=device, command=original
                            )

                    command_display = command_label(original)
                    display_name_suffix = (
                        f"{command_display} ({device_name})"
                        if len(target_devices) > 1
                        else command_display
                    )
                    outcome.evidence.append(
                        {
                            "kind": "cli_output",
                            "name": display_name_suffix,
                            "device_id": device_id,
                            "content_text": result.stdout
                            if ok
                            else (result.stderr or result.stdout),
                            "content_json": {
                                "device_id": device_id,
                                "device_name": device_name,
                                "command": original,
                                "exit_code": result.exit_code,
                                "success": ok,
                                "stderr": result.stderr[:MAX_CHAIN_OUTPUT_CHARS],
                            },
                        }
                    )
                    if not ok:
                        outcome.success = False
                        detail = (result.stderr or result.stdout or "").strip().splitlines()
                        first_line = detail[0] if detail else ""
                        outcome.errors.append(
                            f"{device_name}: exit {result.exit_code}"
                            + (f" ({first_line})" if first_line else "")
                        )
                        if fail_fast:
                            break
            except Exception as exc:
                outcome.success = False
                outcome.errors.append(f"{device_name}: {exc}")
            finally:
                try:
                    await transport.close()
                except Exception:  # noqa: BLE001 - closing is best-effort
                    logger.debug("shell transport close failed", exc_info=True)
            return outcome

        outcomes = await for_each_target_device(
            target_devices,
            _process_device,
            max_parallel=max_parallel_from_config(ctx.config),
        )

        all_evidence = [item for outcome in outcomes for item in outcome.evidence]
        device_errors = [error for outcome in outcomes for error in outcome.errors]
        combined_output_parts = [part for outcome in outcomes for part in outcome.output_parts]
        executed = sum(outcome.executed for outcome in outcomes)
        all_success = all(outcome.success for outcome in outcomes)

        if all_success:
            summary = f"Executed {len(commands)} command(s) on {len(target_devices)} host(s)"
        else:
            summary = f"Shell execution failed on some hosts: {'; '.join(device_errors)}"

        combined_output = "\n".join(combined_output_parts)
        return HandlerResult(
            success=all_success,
            error="; ".join(device_errors) if device_errors else None,
            summary=summary,
            metrics={
                "command_count": len(commands),
                "device_count": len(target_devices),
                "total_executions": executed,
            },
            evidence=all_evidence,
            output={"stdout": combined_output[:MAX_CHAIN_OUTPUT_CHARS]},
        )
