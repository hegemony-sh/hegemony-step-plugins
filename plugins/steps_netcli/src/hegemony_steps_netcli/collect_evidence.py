# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""CollectEvidenceHandler: collect CLI command outputs as evidence."""

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
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

#: Characters of one command's output kept in the step's chainable output.
#: The full text always stays in the command's evidence artifact.
MAX_OUTPUT_TEXT_CHARS = 16_384

#: Characters of command output the whole step hands to later steps. Step
#: outputs share one response budget per run (the host trims the largest
#: when they exceed it), so a step keeps well inside it.
MAX_OUTPUT_TOTAL_CHARS = 49_152


class CollectEvidenceConfig(BaseModel):
    """Config for ``netcli.collect_evidence``."""

    model_config = ConfigDict(extra="allow")

    commands: list[str] = Field(
        default_factory=list,
        title="Commands (one per line)",
        description=(
            "Device CLI commands whose outputs are captured as evidence, one "
            "artifact per command per device. Use {{ variable }} syntax for "
            "flow inputs. Leave empty to collect nothing (the step still "
            "succeeds)."
        ),
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
    command_timeout_seconds: int = Field(
        _DEFAULT_COMMAND_TIMEOUT_SECONDS,
        ge=1,
        le=3600,
        title="Command timeout (seconds)",
        description=(
            "How long one command may run on a device before it fails. Raise it "
            "for slow commands such as show tech-support. The step timeout must "
            "still cover every command on every device. Defaults to 30 seconds."
        ),
    )


def _cli_failure_detail(*, error: str | None, exit_code: int) -> str:
    """Why a command failed, as the step's error says it (as ``netcli.execute`` does)."""
    if error:
        return error
    return f"CLI command failed with exit code {exit_code}"


def _failed_on(failures: list[tuple[str, str]]) -> str:
    """The step's error: the failed devices, those that failed alike listed together.

    ``failures`` holds ``(device, reason)`` in device order. Devices behind one
    broken jump host all fail with the same message, which is then said once:
    ``Failed on: r1, r2 (reason A); r3 (reason B)``.
    """
    by_reason: dict[str, list[str]] = {}
    for device, reason in failures:
        by_reason.setdefault(reason, []).append(device)
    return "Failed on: " + "; ".join(
        f"{', '.join(devices)} ({reason})" for reason, devices in by_reason.items()
    )


@dataclass
class _DeviceOutcome:
    """One device's results, merged in device order after the fan-out.

    Workers collect into these locals instead of shared lists so aggregation
    stays deterministic when devices run in parallel.
    """

    device_name: str = ""
    device_id: str = ""
    evidence: list[dict] = field(default_factory=list)
    #: Each command's output, keyed by the command as configured.
    texts: dict[str, str] = field(default_factory=dict)
    succeeded: int = 0
    failed: int = 0
    #: Why the device failed: its first failure.
    failure: str | None = None


class CollectEvidenceHandler(BaseHandler):
    """Handler for collecting CLI evidence from devices."""

    handler_id = "netcli.collect_evidence"
    supported_kinds = [StepKind.CHECK]
    display_name = "Collect Evidence"
    description = "Capture CLI command outputs from devices as evidence."
    category = "Checks"
    # Devices come from roles only: an additional IP has no login details.
    targeting = HandlerTargeting(roles=True, ips=False)
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
                output={"devices": {}, "truncated": [], "omitted": []},
            )

        services = ctx.require_services()
        command_timeout = float(
            ctx.config.get("command_timeout_seconds") or _DEFAULT_COMMAND_TIMEOUT_SECONDS
        )

        async def _process_device(device: dict) -> _DeviceOutcome:
            device_id = device.get("id", "unknown")
            device_name = device.get("name", device_id)
            outcome = _DeviceOutcome(device_name=device_name, device_id=str(device_id))
            host = device.get("mgmt_host")
            if not host:
                outcome.failed += 1
                outcome.failure = "no mgmt_host configured"
                outcome.evidence.append(
                    {
                        "kind": "error",
                        "name": f"error_{device_name}",
                        "device_id": device_id,
                        "content_text": f"Device {device_name} has no mgmt_host configured",
                    }
                )
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
                # Execute all commands together for efficiency
                results = await ssh.execute_commands(commands)
                for result in results:
                    outcome.texts[result.command] = result.output or ""
                    if result.output:
                        # Live view: per-command output into the Logs tab
                        await ctx.emit_output(result.output, device=device, command=result.command)
                    outcome.evidence.append(
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
                        outcome.succeeded += 1
                    else:
                        outcome.failed += 1
                        if outcome.failure is None:
                            outcome.failure = _cli_failure_detail(
                                error=result.error, exit_code=result.exit_code
                            )

            except Exception as e:
                if outcome.failure is None:
                    outcome.failure = str(e)
                # Add error evidence for this device
                outcome.evidence.append(
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

            return outcome

        outcomes = await for_each_target_device(
            target_devices,
            _process_device,
            max_parallel=max_parallel_from_config(ctx.config),
        )

        all_evidence = [item for outcome in outcomes for item in outcome.evidence]
        total_success = sum(outcome.succeeded for outcome in outcomes)
        total_failure = sum(outcome.failed for outcome in outcomes)
        failed_devices = [
            (outcome.device_name, outcome.failure)
            for outcome in outcomes
            if outcome.failure is not None
        ]

        output = _chain_output(outcomes)
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
                error=_failed_on(failed_devices),
                summary=f"Evidence collected from {len(target_devices) - len(failed_devices)}/{len(target_devices)} devices",
                metrics=metrics,
                evidence=all_evidence,
                output=output,
            )

        return HandlerResult(
            success=True,
            summary=f"Collected evidence from {len(target_devices)} device(s), {total_success} commands OK",
            metrics=metrics,
            evidence=all_evidence,
            output=output,
        )


def _whole_lines(text: str, limit: int) -> str:
    """``text`` cut to at most ``limit`` characters at the end of a line.

    The host masks registered secrets by their whole value after the step
    returns; a cut inside a line could keep the start of one, which no longer
    matches. Text with no line end within the limit is left out entirely.
    """
    if len(text) <= limit:
        return text
    end = text.rfind("\n", 0, limit)
    return text[: end + 1] if end >= 0 else ""


def _device_keys(outcomes: list[_DeviceOutcome]) -> list[str]:
    """One key per device: its name, or ``name (id)`` for a name used twice.

    Inventory names are unique per site only, so two targets can share one;
    a key still taken (a device named like that) gets a counter.
    """
    names = Counter(outcome.device_name for outcome in outcomes)
    keys: list[str] = []
    taken: set[str] = set()
    for outcome in outcomes:
        name = outcome.device_name
        key = base = name if names[name] == 1 else f"{name} ({outcome.device_id})"
        number = 2
        while key in taken:
            key, number = f"{base} #{number}", number + 1
        taken.add(key)
        keys.append(key)
    return keys


def _chain_output(outcomes: list[_DeviceOutcome]) -> dict[str, Any]:
    """The step's chainable output: every device's command outputs, bounded.

    ``devices`` maps each device (see :func:`_device_keys`) to whether it
    succeeded, why it failed, and its outputs by command, so a later step
    reads ``{{ steps.ID.output.devices['r1'].commands['show version'] }}``.
    One command's text keeps at most :data:`MAX_OUTPUT_TEXT_CHARS` and the
    whole output about :data:`MAX_OUTPUT_TOTAL_CHARS`, names included, cut at
    line ends. A shortened text is named in ``truncated`` as
    ``device:command``; once the budget is spent, later devices keep their
    status but no commands and are named in ``omitted``. The artifacts keep
    the whole text either way.
    """
    budget = MAX_OUTPUT_TOTAL_CHARS
    truncated: list[str] = []
    omitted: list[str] = []
    devices: dict[str, Any] = {}
    for key, outcome in zip(_device_keys(outcomes), outcomes, strict=True):
        budget -= len(key) + len(outcome.failure or "")
        commands: dict[str, str] = {}
        if budget <= 0:
            if outcome.texts:
                omitted.append(key)
        else:
            for command, text in outcome.texts.items():
                budget -= len(command)
                kept = _whole_lines(text, max(0, min(MAX_OUTPUT_TEXT_CHARS, budget)))
                if len(kept) < len(text):
                    truncated.append(f"{key}:{command}")
                budget -= len(kept)
                commands[command] = kept
        devices[key] = {
            "success": outcome.failure is None,
            "error": outcome.failure,
            "commands": commands,
        }
    return {"devices": devices, "truncated": truncated, "omitted": omitted}
