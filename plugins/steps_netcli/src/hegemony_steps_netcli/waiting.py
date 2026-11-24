# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The polling loop of the ``wait_for`` steps: run a command until its output matches.

``netcli.wait_for`` and ``shell.wait_for`` share this module. A step plugin
may not import another one (``tests/test_package_architecture.py``), and the
SDK holds the contract only, so each wheel carries its own copy:
``hegemony_steps_netcli.waiting`` and ``hegemony_steps_shell.waiting``. The
two files are identical, and a test keeps them so; change both together.
Move it to the SDK if a third wheel needs it.

The step plugin supplies a :class:`DeviceSession` for each device: how to
log in, run the command once, and close. This module decides when to poll,
when to reconnect, whether the output satisfies the condition, and what to
write to the live log.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, Self

from pydantic import BaseModel, Field, model_validator

from hegemony_step_sdk import (
    DEFAULT_RUN_TIMEOUT_MARGIN_SECONDS,
    MAX_CHAIN_OUTPUT_CHARS,
    MAX_PARALLEL_DEVICES_LIMIT,
    HandlerResult,
    HostKeyRejectedError,
    OutputField,
)

#: ReDoS guardrail, as in ``evidence.assert``: the pattern never runs against
#: more than this much text, so a catastrophic pattern cannot stall the worker.
MAX_REGEX_INPUT_CHARS = 1_000_000

#: The longest login and command a poll may take. A poll that starts just
#: before Max Wait ends may still take both, so the steps' run-timeout margin
#: covers them (:data:`RUN_TIMEOUT_MARGIN_SECONDS`).
MAX_CONNECT_TIMEOUT_SECONDS = 120
MAX_COMMAND_TIMEOUT_SECONDS = 600
RUN_TIMEOUT_MARGIN_SECONDS = (
    DEFAULT_RUN_TIMEOUT_MARGIN_SECONDS + MAX_CONNECT_TIMEOUT_SECONDS + MAX_COMMAND_TIMEOUT_SECONDS
)

#: A poll starts only when at least this much time is left before the deadline.
MIN_POLL_SECONDS = 1.0


class WaitForFields(BaseModel):
    """The settings both ``wait_for`` steps share, apart from the command itself."""

    pattern: str = Field(
        default="",
        min_length=1,
        title="Pattern (regex)",
        description=(
            "Regular expression (Python syntax) searched for in the command's "
            "output. It may match anywhere; anchor it with ^ and $ for a whole "
            "line with Scope 'Any line'. Start it with (?i) to ignore case."
        ),
        json_schema_extra={"x_placeholder": r"Install state:\s+COMMITTED", "x_col_span": 2},
    )
    until: Literal["matches", "not_matches"] = Field(
        default="matches",
        title="Wait Until",
        description=(
            "Wait until the output matches the pattern, or until it no longer "
            "does (a process gone from a list, an alarm cleared). A command "
            "that fails never counts, in either mode. Defaults to Matches."
        ),
        json_schema_extra={
            "x_option_labels": {"matches": "Matches", "not_matches": "Does not match"}
        },
    )
    match_scope: Literal["output", "lines"] = Field(
        default="output",
        title="Match Scope",
        description=(
            "'Whole output' searches the whole output at once, so a pattern can "
            "span lines. 'Any line' searches each line on its own and counts a "
            "match in any of them. Defaults to Whole output."
        ),
        json_schema_extra={"x_option_labels": {"output": "Whole output", "lines": "Any line"}},
    )
    poll_interval_seconds: int = Field(
        default=10,
        ge=1,
        le=3600,
        title="Poll Interval (sec)",
        description=(
            "Seconds from the start of one poll to the start of the next. A "
            "device that cannot be reached is tried again at the same pace. "
            "Defaults to 10."
        ),
    )
    max_wait_seconds: int = Field(
        default=600,
        ge=1,
        le=86_400,
        title="Max Wait (sec)",
        description=(
            "Time limit for the whole step, in seconds. A device whose output "
            "does not meet the condition in time fails. Time a device cannot "
            "be reached counts against it. Defaults to 600. The step's "
            "timeout is raised to cover it."
        ),
    )
    stable_polls: int = Field(
        default=1,
        ge=1,
        le=1000,
        title="Stable For (polls)",
        description=(
            "How many polls in a row must meet the condition, so a value that "
            "flaps is not taken as settled. A poll that does not meet it, "
            "fails, or cannot reach the device starts the count again. "
            "Defaults to 1."
        ),
    )
    connect_timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=MAX_CONNECT_TIMEOUT_SECONDS,
        title="Connect Timeout (sec)",
        description=(
            "Time limit for each login to a device, in seconds. A login that "
            "runs out is tried again at the next poll. Defaults to 10."
        ),
    )
    command_timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=MAX_COMMAND_TIMEOUT_SECONDS,
        title="Command Timeout (sec)",
        description=(
            "How long the command may run on each poll. A command that runs "
            "out counts as a lost session: the step logs in again at the "
            "next poll. Defaults to 30."
        ),
    )
    max_parallel_devices: int = Field(
        default=10,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description=(
            "Devices waited on at the same time (1 = one after another). Max "
            "Wait covers the whole step, so a device that waits for others "
            "to finish has less time left. Defaults to 10."
        ),
    )

    @model_validator(mode="after")
    def _pattern_compiles(self) -> Self:
        try:
            re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"pattern is not a valid regular expression: {exc}") from exc
        return self


#: What a ``wait_for`` step puts in its output, for the flow editor's variable picker.
OUTPUT_FIELDS = (
    OutputField("matched", "Whether every device met the condition in time", "bool"),
    OutputField(
        "devices",
        "Each device's result by name: matched, attempts, elapsed_seconds, reconnects, "
        "matched_at, last_output and error",
        "object",
    ),
    OutputField("truncated", "Devices whose last_output was cut short", "list"),
)


def condition_met(compiled: re.Pattern[str], text: str, *, until: str, scope: str) -> bool:
    """Whether ``text`` meets the condition: the pattern found (or not found) in it."""
    text = text[:MAX_REGEX_INPUT_CHARS]
    if scope == "lines":
        found = any(compiled.search(line) for line in text.splitlines())
    else:
        found = compiled.search(text) is not None
    return found if until == "matches" else not found


class WaitAborted(Exception):
    """A problem no later poll can fix (a refused host key, bad credentials)."""


def is_permanent(exc: BaseException) -> bool:
    """Whether a login error would come back on every try, so waiting is pointless.

    A host key the platform refuses, a destination the egress policy denies
    and a device without usable credentials stay that way. A login the
    device refuses is permanent too: trying a wrong password again at every
    poll can lock the account. The transports raise their SSH library's own
    authentication error, which a step plugin cannot import, so it is known
    by name. Anything else (refused, reset, timed out) may be the device
    still booting, and is tried again.
    """
    if isinstance(exc, (HostKeyRejectedError, PermissionError, ValueError, WaitAborted)):
        return True
    names = {cls.__name__ for cls in type(exc).__mro__}
    return any("Authentication" in name or name == "PermissionDenied" for name in names)


@dataclass
class Poll:
    """One run of the command on a device."""

    #: The text the condition is checked against.
    output: str = ""
    #: The command ran and succeeded (exit code 0, no CLI error).
    ok: bool = False
    #: The session is gone or did not answer: log in again before the next poll.
    lost: bool = False
    #: Why the poll failed, for the live log and the step's error.
    error: str | None = None
    #: With ``lost``: a session existed and was lost. False when the login
    #: itself failed (a transport that logs in for every command).
    had_session: bool = True


class DeviceSession(Protocol):
    """How a step plugin reaches one device; see the module docstring."""

    async def connect(self) -> None:
        """Log in and keep the session. Raise when the login fails."""

    async def run(self) -> Poll:
        """Run the command once on the session.

        Never raises for a device problem, except :class:`WaitAborted` for one
        no later poll can fix.
        """

    async def close(self) -> None:
        """Close the session, if any (idempotent; never raises)."""


@dataclass
class DeviceWait:
    """One device's wait: its counters and what it reports."""

    name: str
    matched: bool = False
    attempts: int = 0
    reconnects: int = 0
    elapsed_seconds: float = 0.0
    matched_at: str | None = None
    last_output: str = ""
    error: str | None = None
    #: Polls in a row that met the condition.
    streak: int = 0
    #: A session was lost and no command has run on a new one yet.
    _session_lost: bool = field(default=False, repr=False)

    def output(self) -> tuple[dict[str, Any], bool]:
        """This device's entry in the step output, and whether last_output was cut."""
        cut = len(self.last_output) > MAX_CHAIN_OUTPUT_CHARS
        return (
            {
                "matched": self.matched,
                "attempts": self.attempts,
                "elapsed_seconds": round(self.elapsed_seconds, 1),
                "reconnects": self.reconnects,
                "matched_at": self.matched_at,
                "last_output": self.last_output[:MAX_CHAIN_OUTPUT_CHARS],
                "error": self.error,
            },
            cut,
        )


#: Writes one status line to the device's live log.
Emit = Callable[[str], Awaitable[Any]]


def monotonic() -> float:
    """The loop's clock; tests replace it with a fake one."""
    return time.monotonic()


async def sleep(seconds: float) -> None:
    """The loop's pause between polls; tests replace it with a fake one."""
    await asyncio.sleep(seconds)


def _seconds(value: float) -> str:
    return f"{value:.0f} s"


async def wait_on_device(
    session: DeviceSession,
    config: WaitForFields,
    *,
    name: str,
    started: float,
    deadline: float,
    emit: Emit,
) -> DeviceWait:
    """Poll one device until its output meets the condition or ``deadline`` passes.

    ``started`` and ``deadline`` are :func:`monotonic` values shared by every
    device of the step. The session stays open between polls. A poll that
    cannot log in, or whose session is lost (the device reloads), counts as
    not met, and the next poll logs in again. ``emit`` gets a short status
    line for each poll; the session writes the command's output itself.
    """
    wait = DeviceWait(name=name)
    compiled = re.compile(config.pattern)
    connected = False
    given_up = False
    want = "match" if config.until == "matches" else "no match"
    try:
        while True:
            poll_started = monotonic()
            if deadline - poll_started < MIN_POLL_SECONDS:
                break
            wait.attempts += 1
            elapsed = poll_started - started
            if not connected:
                try:
                    await session.connect()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - the error is reported, not lost
                    detail = str(exc) or type(exc).__name__
                    if is_permanent(exc):
                        wait.error = f"cannot log in: {detail}"
                        given_up = True
                        break
                    wait.error = f"not reachable: {detail}"
                    wait.streak = 0
                    await emit(
                        f"[attempt {wait.attempts}, {_seconds(elapsed)} elapsed] not reachable "
                        f"({detail}); trying again in {config.poll_interval_seconds} s"
                    )
                    await _pause(poll_started, config.poll_interval_seconds, deadline)
                    continue
                connected = True
            try:
                poll = await session.run()
            except WaitAborted as exc:
                # A transport that logs in for every command reports a
                # refused login here.
                wait.error = f"cannot log in: {exc}"
                given_up = True
                break
            elapsed = monotonic() - started
            if poll.lost:
                connected = False
                await session.close()
                wait.streak = 0
                wait._session_lost = wait._session_lost or poll.had_session
                wait.error = f"session lost: {poll.error}" if poll.error else "session lost"
                await emit(
                    f"[attempt {wait.attempts}, {_seconds(elapsed)} elapsed] session lost"
                    + (f" ({poll.error})" if poll.error else "")
                    + f"; reconnecting in {config.poll_interval_seconds} s"
                )
                await _pause(poll_started, config.poll_interval_seconds, deadline)
                continue
            if wait._session_lost:
                wait.reconnects += 1
                wait._session_lost = False
            wait.last_output = poll.output
            if not poll.ok:
                wait.streak = 0
                wait.error = f"command failed: {poll.error}" if poll.error else "command failed"
                status = wait.error
            elif condition_met(compiled, poll.output, until=config.until, scope=config.match_scope):
                wait.streak += 1
                wait.error = None
                if wait.streak >= config.stable_polls:
                    wait.matched = True
                    wait.matched_at = datetime.now(UTC).isoformat(timespec="seconds")
                    wait.elapsed_seconds = elapsed
                    await emit(
                        f"[attempt {wait.attempts}, {_seconds(elapsed)} elapsed] matched"
                        + (f" ({wait.streak} polls in a row)" if config.stable_polls > 1 else "")
                    )
                    return wait
                status = f"{want} {wait.streak} of {config.stable_polls} in a row"
            else:
                wait.streak = 0
                wait.error = None
                status = f"{want} not yet"
            await emit(
                f"[attempt {wait.attempts}, {_seconds(elapsed)} elapsed] {status}; "
                f"next poll in {config.poll_interval_seconds} s"
            )
            await _pause(poll_started, config.poll_interval_seconds, deadline)
    finally:
        await session.close()
    wait.elapsed_seconds = monotonic() - started
    if not given_up:
        reason = f"; last poll: {wait.error}" if wait.error else ""
        wait.error = (
            f"condition not met within {config.max_wait_seconds} s "
            f"({wait.attempts} attempts){reason}"
        )
    await emit(f"gave up after {wait.attempts} attempts: {wait.error}")
    return wait


async def _pause(poll_started: float, interval: float, deadline: float) -> None:
    """Sleep until the next poll is due, but not past the deadline."""
    due = min(poll_started + interval, deadline)
    left = due - monotonic()
    if left > 0:
        await sleep(left)


def step_result(
    waits: list[DeviceWait],
    devices: list[dict[str, Any]],
    config: WaitForFields,
    label: str,
    command: str,
) -> HandlerResult:
    """The step's result: one ``cli_output`` evidence per device, and its output.

    The evidence holds each device's last output in full, as
    ``netcli.execute``'s does; the output holds it cut to
    ``MAX_CHAIN_OUTPUT_CHARS`` and names the devices whose text was cut.
    """
    entries: dict[str, Any] = {}
    truncated: list[str] = []
    evidence: list[dict[str, Any]] = []
    errors: list[str] = []
    for device, wait in zip(devices, waits, strict=True):
        device_id = device.get("id", device.get("mgmt_host"))
        entry, cut = wait.output()
        entries[wait.name] = entry
        if cut:
            truncated.append(wait.name)
        if not wait.matched:
            errors.append(f"{wait.name}: {wait.error}")
        evidence.append(
            {
                "kind": "cli_output",
                "name": f"{label} ({wait.name})" if len(devices) > 1 else label,
                "device_id": device_id,
                "content_text": wait.last_output,
                "content_json": {
                    "device_id": device_id,
                    "device_name": wait.name,
                    "command": command,
                    "pattern": config.pattern,
                    "until": config.until,
                    "success": wait.matched,
                    **{key: value for key, value in entry.items() if key != "last_output"},
                },
            }
        )
    matched = not errors
    count = len(devices)
    if matched:
        slowest = max((wait.elapsed_seconds for wait in waits), default=0.0)
        summary = f"Condition met on {count} device(s) within {slowest:.0f} s"
    else:
        summary = f"Condition not met on {len(errors)} of {count} device(s): {'; '.join(errors)}"
    return HandlerResult(
        success=matched,
        error="; ".join(errors) if errors else None,
        summary=summary,
        metrics={
            "device_count": count,
            "matched_count": sum(wait.matched for wait in waits),
            "attempts": sum(wait.attempts for wait in waits),
            "reconnects": sum(wait.reconnects for wait in waits),
        },
        evidence=evidence,
        output={"matched": matched, "devices": entries, "truncated": truncated},
    )
