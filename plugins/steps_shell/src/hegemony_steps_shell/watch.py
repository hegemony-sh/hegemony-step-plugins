# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ShellWatchHandler: follow a host's output for a while, such as ``tail -F``.

Runs one long command (``tail -F /var/log/syslog``, ``journalctl -f``) on
every target host at the same time, for a set duration, and checks what it
printed against optional patterns. The command is wrapped in the host's
``timeout`` tool, so it ends on the host when the duration is up and the
transport returns everything it printed: stopping it from the worker side
would lose the captured output.
"""

from __future__ import annotations

import logging
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from hegemony_step_sdk import (
    DEFAULT_RUN_TIMEOUT_MARGIN_SECONDS,
    MAX_CHAIN_OUTPUT_CHARS,
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
    command_label,
    for_each_target_device,
)
from hegemony_step_sdk.ssh import SshSecurityConfig

from .execute import _open_shell, command_template_errors

logger = logging.getLogger(__name__)

#: Seconds ``timeout`` waits after its TERM signal before it sends KILL.
KILL_AFTER_SECONDS = 5

#: Extra time the worker gives the command past its duration (login, the
#: KILL grace, the last output reaching the worker) before it gives up.
RUN_GRACE_SECONDS = 30

#: Longest login the step allows.
MAX_CONNECT_TIMEOUT_SECONDS = 120

#: Exit codes that mean ``timeout`` ended the command at the duration:
#: GNU coreutils returns 124, BusyBox the signal status (TERM 143, KILL 137).
_DURATION_EXIT_CODES = frozenset({124, 137, 143})

#: Lines that matched Fail Pattern, kept per host in the output and evidence.
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


class ShellWatchConfig(SshSecurityConfig):
    """Config for ``shell.watch``."""

    model_config = ConfigDict(extra="allow")

    command: str = Field(
        default="",
        min_length=1,
        validate_default=True,
        title="Command",
        description=(
            "The command to follow, such as 'tail -F /var/log/syslog' or "
            "'journalctl -f -u nginx'. It runs until Duration is up. In a "
            "pipeline, give grep --line-buffered so lines arrive as they come. "
            "A {{ }} value must end with | quote and stand outside quotes, as "
            "in shell.execute."
        ),
        json_schema_extra={"x_placeholder": "tail -F /var/log/syslog", "x_col_span": 2},
    )
    shell: Literal["sh", "bash"] = Field(
        default="sh",
        title="Interpreter",
        description="The shell that runs the command (sh -c or bash -c). Defaults to sh.",
        json_schema_extra={"x_option_labels": {"sh": "sh -c", "bash": "bash -c"}},
    )
    duration_seconds: int = Field(
        default=300,
        ge=1,
        le=86_400,
        title="Duration (sec)",
        description=(
            "How long to watch, in seconds. The command is stopped on the host "
            "when it is up. Defaults to 300. The step's timeout is raised to "
            "cover it."
        ),
    )
    fail_pattern: str = Field(
        default="",
        title="Fail Pattern (regex)",
        description=(
            "Optional regular expression (Python syntax). A host fails when any "
            "line it printed matches, such as 'ERROR|Out of memory'. Start it "
            "with (?i) to ignore case."
        ),
        json_schema_extra={"x_placeholder": "(?i)error|panic", "x_col_span": 2},
    )
    expect_pattern: str = Field(
        default="",
        title="Expect Pattern (regex)",
        description=(
            "Optional regular expression (Python syntax). A host fails unless at "
            "least one line it printed matches, such as 'Started nginx'."
        ),
        json_schema_extra={"x_placeholder": "Started nginx", "x_col_span": 2},
    )
    connect_timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=MAX_CONNECT_TIMEOUT_SECONDS,
        title="Connect Timeout (sec)",
        description="Time limit for the login to each host, in seconds. Defaults to 10.",
    )

    @field_validator("command")
    @classmethod
    def _command_is_not_blank(cls, command: str) -> str:
        if not command.strip():
            raise ValueError("command must not be blank")
        return command

    @model_validator(mode="after")
    def _patterns_compile(self) -> Self:
        _compile(self.fail_pattern, "fail_pattern")
        _compile(self.expect_pattern, "expect_pattern")
        return self


def build_watch_command(command: str, *, shell: str, duration_seconds: int) -> str:
    """The remote command line: ``command`` under the host's ``timeout`` tool."""
    return f"timeout -k {KILL_AFTER_SECONDS} {duration_seconds} {shell} -c {shlex.quote(command)}"


#: What the step puts in its output, for the flow editor's variable picker.
_OUTPUT_FIELDS = (
    OutputField("passed", "Whether every host watched to the end and passed the patterns", "bool"),
    OutputField(
        "devices",
        "Each host's result by name: ended, exit_code, lines, fail_matches, "
        "expect_matched and error",
        "object",
    ),
    OutputField("stdout", "The end of the combined output of every host", "string"),
)


@dataclass
class _HostWatch:
    """One host's result, merged in device order after the fan-out."""

    name: str
    ended: str | None = None
    exit_code: int | None = None
    lines: int = 0
    fail_matches: list[str] = field(default_factory=list)
    expect_matched: bool | None = None
    error: str | None = None
    stdout: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def report(self) -> dict[str, Any]:
        return {
            "ended": self.ended,
            "exit_code": self.exit_code,
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
    lines = text.splitlines()
    fail_matches: list[str] = []
    expect_matched = None if expect is None else False
    for line in lines:
        if fail is not None and len(fail_matches) < MAX_REPORTED_MATCHES and fail.search(line):
            fail_matches.append(line[:MAX_REPORTED_LINE_CHARS])
        if expect is not None and not expect_matched and expect.search(line):
            expect_matched = True
    return len(lines), fail_matches, expect_matched


class ShellWatchHandler(BaseHandler):
    """Follow a command's output on each host for a set time, checking it against patterns."""

    handler_id = "shell.watch"
    supported_kinds = [StepKind.CHECK]
    display_name = "Watch Shell Output"
    description = "Follow a command such as tail -F on Linux/Unix hosts for a set time."
    category = "Checks"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = ShellWatchConfig
    output_fields = _OUTPUT_FIELDS
    default_config = {"shell": "sh", "duration_seconds": 300}
    run_timeout_field = "duration_seconds"
    run_timeout_margin_seconds = (
        DEFAULT_RUN_TIMEOUT_MARGIN_SECONDS + MAX_CONNECT_TIMEOUT_SECONDS + RUN_GRACE_SECONDS
    )

    def template_errors(self, config: dict[str, Any]) -> list[str]:
        """Refuse a command whose ``{{ }}`` values would not be single literal words."""
        command = config.get("command")
        if not isinstance(command, str):
            return []
        return command_template_errors([command], config.get("shell", "sh"))

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
            # Every host is watched at the same time: a host that waited for
            # a free slot would run past the step's timeout.
            return HandlerResult(
                success=False,
                error=(
                    f"shell.watch follows at most {MAX_PARALLEL_DEVICES_LIMIT} hosts at "
                    f"once; {len(target_devices)} are selected"
                ),
                summary="Too many target hosts",
            )
        try:
            config = self.parse_config(ctx.config, ShellWatchConfig)
        except InvalidConfigError as exc:
            return exc.result()
        fail = _compile(config.fail_pattern, "fail_pattern")
        expect = _compile(config.expect_pattern, "expect_pattern")

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
        remote_command = build_watch_command(
            config.command, shell=config.shell, duration_seconds=duration
        )
        label = command_label(config.command)
        services = ctx.require_services()

        async def _watch(device: dict[str, Any]) -> _HostWatch:
            device_id = device.get("id", device.get("mgmt_host"))
            name = str(device.get("name") or device_id)
            outcome = _HostWatch(name=name)
            if not device.get("mgmt_host"):
                outcome.error = "no mgmt_host configured"
                return outcome
            try:
                transport = await _open_shell(
                    services,
                    device,
                    config.allow_legacy_ssh,
                    connect_timeout=float(config.connect_timeout_seconds),
                )
            except Exception as exc:  # noqa: BLE001 - reported per host
                outcome.error = str(exc) or type(exc).__name__
                return outcome
            try:
                await ctx.emit_output(
                    f"watching for {duration} s: {config.command}\n",
                    device=device,
                    command=config.command,
                )
                try:
                    result = await transport.run(
                        remote_command, timeout=duration + KILL_AFTER_SECONDS + RUN_GRACE_SECONDS
                    )
                except TimeoutError:
                    outcome.error = "the command did not stop when Duration was up"
                    return outcome
                except Exception as exc:  # noqa: BLE001 - a lost connection, reported per host
                    outcome.error = f"the connection was lost ({type(exc).__name__})"
                    detail = str(exc)
                    if detail:
                        await ctx.emit_output(
                            detail + "\n", stream="stderr", device=device, command=config.command
                        )
                    return outcome

                if not getattr(transport, "streams_exec_output", False):
                    if result.stdout:
                        await ctx.emit_output(
                            result.stdout, stream="stdout", device=device, command=config.command
                        )
                    if result.stderr:
                        await ctx.emit_output(
                            result.stderr, stream="stderr", device=device, command=config.command
                        )

                stdout = result.stdout or ""
                stderr = result.stderr or ""
                outcome.exit_code = result.exit_code
                outcome.stdout = stdout
                outcome.lines, outcome.fail_matches, outcome.expect_matched = _check_lines(
                    stdout + ("\n" if stdout and stderr else "") + stderr, fail, expect
                )
                if result.exit_code in _DURATION_EXIT_CODES:
                    outcome.ended = "duration"
                elif result.exit_code == 0:
                    outcome.ended = "exited"
                else:
                    outcome.ended = "failed"
                    detail = (stderr or stdout).strip().splitlines()
                    first_line = detail[0][:MAX_REPORTED_LINE_CHARS] if detail else ""
                    outcome.error = f"exit {result.exit_code}" + (
                        f" ({first_line})" if first_line else ""
                    )
                if outcome.error is None and outcome.fail_matches:
                    outcome.error = (
                        f"{len(outcome.fail_matches)} line(s) matched fail_pattern"
                        if len(outcome.fail_matches) < MAX_REPORTED_MATCHES
                        else f"at least {MAX_REPORTED_MATCHES} lines matched fail_pattern"
                    )
                if outcome.error is None and outcome.expect_matched is False:
                    outcome.error = "no line matched expect_pattern"

                kept = stdout[-MAX_EVIDENCE_CHARS:]
                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"{label} ({name})" if len(target_devices) > 1 else label,
                        "device_id": device_id,
                        "content_text": kept,
                        "content_json": {
                            "device_id": device_id,
                            "device_name": name,
                            "command": config.command,
                            "duration_seconds": duration,
                            "exit_code": result.exit_code,
                            "ended": outcome.ended,
                            "success": outcome.error is None,
                            "lines": outcome.lines,
                            "fail_matches": outcome.fail_matches,
                            "expect_matched": outcome.expect_matched,
                            "truncated": len(kept) < len(stdout),
                            "stderr": stderr[-MAX_CHAIN_OUTPUT_CHARS:],
                        },
                    }
                )
                return outcome
            finally:
                try:
                    await transport.close()
                except Exception:  # noqa: BLE001 - closing is best-effort
                    logger.debug("shell transport close failed", exc_info=True)

        watches = await for_each_target_device(
            target_devices, _watch, max_parallel=MAX_PARALLEL_DEVICES_LIMIT
        )

        errors = [f"{watch.name}: {watch.error}" for watch in watches if watch.error]
        passed = not errors
        combined = "\n".join(watch.stdout for watch in watches if watch.stdout)
        hosts = len(target_devices)
        if passed:
            summary = f"Watched {label!r} on {hosts} host(s) for {duration} s"
        else:
            summary = f"Watch failed on {len(errors)} of {hosts} host(s): {'; '.join(errors)}"
        return HandlerResult(
            success=passed,
            error="; ".join(errors) if errors else None,
            summary=summary,
            metrics={
                "device_count": hosts,
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
