# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""WatchCliHandler: follow what network devices print for a while.

Logs in to every target device at the same time, sends the setup commands
(``terminal monitor`` by default), and then reads what the devices print on
that session for a set duration, such as the log messages a change causes.
The reading is the transport's (``CliWatchTransport.watch_output``); this
module checks the output against optional patterns and reports it.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from hegemony_step_sdk import (
    DEFAULT_RUN_TIMEOUT_MARGIN_SECONDS,
    MAX_CHAIN_OUTPUT_CHARS,
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    CliWatchTransport,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
    for_each_target_device,
)
from hegemony_step_sdk.ssh import SshSecurityConfig, configure_ssh_security

from .transcript import command_transcript

logger = logging.getLogger(__name__)

#: Limits on the login and on each setup command; the run-timeout margin covers them.
MAX_CONNECT_TIMEOUT_SECONDS = 120
MAX_COMMAND_TIMEOUT_SECONDS = 120
MAX_SETUP_COMMANDS = 10
#: Time the handler gives the transport past all of its own limits.
CALL_GRACE_SECONDS = 30

#: Lines that matched Fail Pattern, kept per device in the output and evidence.
MAX_REPORTED_MATCHES = 20
#: Each reported line is cut to this many characters.
MAX_REPORTED_LINE_CHARS = 500
#: A watch may print a lot: its evidence keeps the last this many characters.
MAX_EVIDENCE_CHARS = 1_000_000


def _compile(pattern: str, name: str) -> re.Pattern[str] | None:
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except (re.error, OverflowError) as exc:
        raise ValueError(f"{name} is not a valid regular expression: {exc}") from exc


class WatchCliConfig(SshSecurityConfig):
    """Config for ``netcli.watch``."""

    model_config = ConfigDict(extra="allow")

    commands: list[str] = Field(
        default_factory=lambda: ["terminal monitor"],
        title="Setup Commands (one per line)",
        description=(
            "Exec-mode commands sent before the watch starts, on the same session, "
            "such as 'terminal monitor', which makes a Cisco device send its log "
            "messages to the session. At most 10. Defaults to terminal monitor."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "terminal monitor",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    duration_seconds: int = Field(
        default=300,
        ge=1,
        le=86_400,
        title="Duration (sec)",
        description=(
            "How long to watch after the setup commands, in seconds. Defaults to "
            "300. The step's timeout is raised to cover it."
        ),
    )
    fail_pattern: str = Field(
        default="",
        title="Fail Pattern (regex)",
        description=(
            "Optional regular expression (Python syntax). A device fails when any "
            "line it printed matches, such as '%LINK-3-UPDOWN|%OSPF-5-ADJCHG.*Down'. "
            "Start it with (?i) to ignore case."
        ),
        json_schema_extra={"x_placeholder": r"%LINK-3-UPDOWN", "x_col_span": 2},
    )
    expect_pattern: str = Field(
        default="",
        title="Expect Pattern (regex)",
        description=(
            "Optional regular expression (Python syntax). A device fails unless at "
            "least one line it printed matches, such as '%BGP-5-ADJCHANGE.*Up'."
        ),
        json_schema_extra={"x_placeholder": r"%BGP-5-ADJCHANGE.*Up", "x_col_span": 2},
    )
    keepalive_seconds: int = Field(
        default=300,
        ge=0,
        le=3600,
        title="Keepalive (sec)",
        description=(
            "Send an empty line this often, so the device's line exec-timeout "
            "does not end a long watch; each makes the device print its prompt. "
            "0 = off. Defaults to 300."
        ),
    )
    connect_timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=MAX_CONNECT_TIMEOUT_SECONDS,
        title="Connect Timeout (sec)",
        description="Time limit for the login to each device, in seconds. Defaults to 10.",
    )
    command_timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=MAX_COMMAND_TIMEOUT_SECONDS,
        title="Command Timeout (sec)",
        description="Time limit for each setup command, in seconds. Defaults to 30.",
    )

    @field_validator("commands")
    @classmethod
    def _few_setup_commands(cls, commands: list[str]) -> list[str]:
        lines = [command for command in commands if command.strip()]
        if len(lines) > MAX_SETUP_COMMANDS:
            raise ValueError(f"at most {MAX_SETUP_COMMANDS} setup commands are allowed")
        return lines

    @model_validator(mode="after")
    def _patterns_compile(self) -> Self:
        _compile(self.fail_pattern, "fail_pattern")
        _compile(self.expect_pattern, "expect_pattern")
        return self


#: What the step puts in its output, for the flow editor's variable picker.
_OUTPUT_FIELDS = (
    OutputField(
        "passed", "Whether every device was watched to the end and passed the patterns", "bool"
    ),
    OutputField(
        "devices",
        "Each device's result by name: ended, elapsed_seconds, lines, fail_matches, "
        "expect_matched and error",
        "object",
    ),
    OutputField("stdout", "The end of the combined output of every device", "string"),
)


@dataclass
class _DeviceWatch:
    """One device's result, merged in device order after the fan-out."""

    name: str
    ended: str | None = None
    elapsed_seconds: int = 0
    lines: int = 0
    fail_matches: list[str] = field(default_factory=list)
    expect_matched: bool | None = None
    error: str | None = None
    output: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def report(self) -> dict[str, Any]:
        return {
            "ended": self.ended,
            "elapsed_seconds": self.elapsed_seconds,
            "lines": self.lines,
            "fail_matches": self.fail_matches,
            "expect_matched": self.expect_matched,
            "error": self.error,
        }


def _check_lines(
    text: str,
    fail: re.Pattern[str] | None,
    expect: re.Pattern[str] | None,
) -> tuple[int, list[str], bool | None]:
    """Count lines, collect those that match ``fail``, and whether any matches ``expect``."""
    lines = [line for line in text.replace("\r", "").splitlines() if line.strip()]
    fail_matches: list[str] = []
    expect_matched = None if expect is None else False
    for line in lines:
        if fail is not None and len(fail_matches) < MAX_REPORTED_MATCHES and fail.search(line):
            fail_matches.append(line[:MAX_REPORTED_LINE_CHARS])
        if expect is not None and not expect_matched and expect.search(line):
            expect_matched = True
    return len(lines), fail_matches, expect_matched


class WatchCliHandler(BaseHandler):
    """Follow what each device prints for a set time, checking it against patterns."""

    handler_id = "netcli.watch"
    supported_kinds = [StepKind.CHECK]
    display_name = "Watch CLI Output"
    description = "Follow what devices print (terminal monitor) for a set time."
    category = "Checks"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = WatchCliConfig
    output_fields = _OUTPUT_FIELDS
    default_config = {"commands": ["terminal monitor"], "duration_seconds": 300}
    run_timeout_field = "duration_seconds"
    run_timeout_margin_seconds = (
        DEFAULT_RUN_TIMEOUT_MARGIN_SECONDS
        + MAX_CONNECT_TIMEOUT_SECONDS
        + MAX_SETUP_COMMANDS * MAX_COMMAND_TIMEOUT_SECONDS
        + CALL_GRACE_SECONDS
    )

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        started = time.monotonic()
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )
        if len(target_devices) > MAX_PARALLEL_DEVICES_LIMIT:
            # Every device is watched at the same time: one that waited for
            # a free slot would run past the step's timeout.
            return HandlerResult(
                success=False,
                error=(
                    f"netcli.watch follows at most {MAX_PARALLEL_DEVICES_LIMIT} devices at "
                    f"once; {len(target_devices)} are selected"
                ),
                summary="Too many target devices",
            )
        try:
            config = self.parse_config(ctx.config, WatchCliConfig)
        except InvalidConfigError as exc:
            return exc.result()
        fail = _compile(config.fail_pattern, "fail_pattern")
        expect = _compile(config.expect_pattern, "expect_pattern")
        commands = [command.strip() for command in config.commands]

        # A platform that does not raise the step's timeout to the duration
        # gets a shorter watch, so the step still reports before it is cut off.
        room = int(ctx.timeout_seconds) - self.run_timeout_margin_seconds
        duration = min(config.duration_seconds, room)
        if duration < 1:
            return HandlerResult(
                success=False,
                error=(
                    f"the step's timeout ({ctx.timeout_seconds} s) leaves no time to "
                    "watch; raise it or upgrade the platform"
                ),
                summary="Step timeout too short",
            )
        call_limit = (
            duration
            + config.connect_timeout_seconds
            + len(commands) * config.command_timeout_seconds
            + CALL_GRACE_SECONDS
        )
        label = "watch" + (f" after {commands[-1]}" if commands else "")
        services = ctx.require_services()

        async def _watch(device: dict[str, Any]) -> _DeviceWatch:
            device_id = device.get("id", device.get("mgmt_host"))
            name = str(device.get("name") or device_id)
            outcome = _DeviceWatch(name=name)
            if not device.get("mgmt_host"):
                outcome.error = "no mgmt_host configured"
                return outcome
            try:
                # step_run_id registers the session, so cancelling the run closes it.
                transport = services.connect(
                    device,
                    platform=device.get("platform"),
                    connect_timeout=float(config.connect_timeout_seconds),
                    command_timeout=float(config.command_timeout_seconds),
                    step_run_id=ctx.step_run_id,
                )
                configure_ssh_security(transport, config.allow_legacy_ssh)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reported as the device's error
                outcome.error = str(exc) or type(exc).__name__
                return outcome
            if getattr(transport, "supports_cli_watch", False) is not True:
                outcome.error = (
                    "this device's transport cannot follow output; netcli.watch needs "
                    "the netmiko or scrapli transport"
                )
                return outcome

            await ctx.emit_output(f"watching for {duration} s\n", device=device, command=label)
            try:
                result = await asyncio.wait_for(
                    cast(CliWatchTransport, transport).watch_output(
                        commands,
                        duration_seconds=float(duration),
                        keepalive_seconds=float(config.keepalive_seconds),
                    ),
                    timeout=call_limit,
                )
            except TimeoutError:
                outcome.error = "the watch did not end in time"
                return outcome
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - reported as the device's error
                outcome.error = f"the watch failed ({type(exc).__name__})"
                detail = str(exc)
                if detail:
                    await ctx.emit_output(
                        detail + "\n", stream="stderr", device=device, command=label
                    )
                return outcome

            setup = list(result.setup)
            for item in setup:
                await ctx.emit_output(
                    command_transcript(item.command, item.output),
                    device=device,
                    command=item.command,
                )
            output = result.output or ""
            if output and not getattr(transport, "streams_watch_output", False):
                await ctx.emit_output(output, device=device, command=label)

            outcome.output = output
            outcome.elapsed_seconds = round(result.elapsed_seconds)
            failed_setup = next((item for item in setup if item.exit_code != 0), None)
            if result.error:
                outcome.ended = "failed"
                outcome.error = result.error
            elif failed_setup is not None:
                outcome.ended = "failed"
                outcome.error = f"setup command {failed_setup.command!r} failed" + (
                    f": {failed_setup.error}" if failed_setup.error else ""
                )
            elif result.cancelled:
                outcome.ended = "cancelled"
                outcome.error = "the run was cancelled"
            elif result.disconnected:
                outcome.ended = "disconnected"
                outcome.error = f"the device closed the session after {outcome.elapsed_seconds} s"
            else:
                outcome.ended = "duration"
            outcome.lines, outcome.fail_matches, outcome.expect_matched = _check_lines(
                output, fail, expect
            )
            if outcome.error is None and outcome.fail_matches:
                outcome.error = (
                    f"{len(outcome.fail_matches)} line(s) matched fail_pattern"
                    if len(outcome.fail_matches) < MAX_REPORTED_MATCHES
                    else f"at least {MAX_REPORTED_MATCHES} lines matched fail_pattern"
                )
            if outcome.error is None and outcome.expect_matched is False:
                outcome.error = "no line matched expect_pattern"

            kept = output[-MAX_EVIDENCE_CHARS:]
            transcript = "".join(command_transcript(i.command, i.output) for i in setup)
            outcome.evidence.append(
                {
                    "kind": "cli_output",
                    "name": f"Watch ({name})" if len(target_devices) > 1 else "Watch",
                    "device_id": device_id,
                    "content_text": transcript + kept,
                    "content_json": {
                        "device_id": device_id,
                        "device_name": name,
                        "commands": commands,
                        "duration_seconds": duration,
                        "elapsed_seconds": outcome.elapsed_seconds,
                        "ended": outcome.ended,
                        "success": outcome.error is None,
                        "lines": outcome.lines,
                        "fail_matches": outcome.fail_matches,
                        "expect_matched": outcome.expect_matched,
                        "truncated": len(kept) < len(output),
                    },
                }
            )
            return outcome

        watches = await for_each_target_device(
            target_devices, _watch, max_parallel=MAX_PARALLEL_DEVICES_LIMIT
        )

        errors = [f"{watch.name}: {watch.error}" for watch in watches if watch.error]
        passed = not errors
        combined = "\n".join(watch.output for watch in watches if watch.output)
        count = len(target_devices)
        if passed:
            summary = f"Watched {count} device(s) for {duration} s"
        else:
            summary = f"Watch failed on {len(errors)} of {count} device(s): {'; '.join(errors)}"
        return HandlerResult(
            success=passed,
            error="; ".join(errors) if errors else None,
            summary=summary,
            metrics={
                "device_count": count,
                "duration_seconds": duration,
                "elapsed_seconds": round(time.monotonic() - started),
            },
            evidence=[item for watch in watches for item in watch.evidence],
            output={
                "passed": passed,
                "devices": {watch.name: watch.report() for watch in watches},
                "stdout": combined[-MAX_CHAIN_OUTPUT_CHARS:],
            },
        )
