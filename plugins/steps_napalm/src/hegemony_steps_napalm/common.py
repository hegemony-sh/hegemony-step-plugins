# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What the ``napalm.*`` steps share: settings, sessions, fan-out and output."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_PARALLEL_DEVICES_LIMIT,
    HandlerContext,
    HandlerResult,
    NapalmSession,
    for_each_target_device,
)

logger = logging.getLogger(__name__)

#: Characters of one device's text (data, a diff) kept in the step output;
#: the evidence keeps all of it.
MAX_OUTPUT_TEXT_CHARS = 16 * 1024
#: Characters of text the whole step puts in its output.
MAX_OUTPUT_TOTAL_CHARS = 64 * 1024
TRUNCATED_NOTE = "\n… [cut short: the full text is in the step's evidence]"


class NapalmConnectionConfig(BaseModel):
    """Connection settings every ``napalm.*`` step has."""

    model_config = ConfigDict(extra="allow")

    connect_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=300,
        title="Connect Timeout (sec)",
        description="How long logging in to the device may take. Defaults to 15.",
        json_schema_extra={"x_advanced": True},
    )
    command_timeout_seconds: int = Field(
        default=120,
        ge=1,
        le=3600,
        title="Command Timeout (sec)",
        description=(
            "How long the device may take to answer one NAPALM operation (a large "
            "configuration, a commit). Defaults to 120."
        ),
        json_schema_extra={"x_advanced": True},
    )
    allow_legacy_ssh: bool = Field(
        default=False,
        title="Allow legacy SSH",
        description=(
            "Accept weak SSH algorithms and small keys for this step, for old devices. "
            "Off: the platform's SSH policy applies."
        ),
        json_schema_extra={"x_advanced": True},
    )


def max_parallel_field(default: int) -> Any:
    """The Max Parallel Devices field with the step's own default."""
    return Field(
        default=default,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description=(
            f"Devices worked on at the same time (1 = one after another). Defaults to {default}."
        ),
    )


class SessionUnavailable(Exception):
    """The platform cannot open NAPALM sessions (it predates ``open_napalm``)."""


def opener(ctx: HandlerContext) -> Callable[..., Awaitable[NapalmSession]]:
    """The host's ``open_napalm``, or raise when the platform has none."""
    services = ctx.require_services()
    open_napalm = getattr(services, "open_napalm", None)
    if open_napalm is None:
        raise SessionUnavailable(
            "this platform cannot open NAPALM sessions; upgrade Hegemony to a release "
            "that supports the napalm steps"
        )
    return open_napalm


async def log_line(ctx: HandlerContext, device: dict[str, Any], line: str) -> None:
    """One line on the run's Logs tab: operations only, never configuration."""
    await ctx.emit_output(line + "\n", device=device, command="napalm")


@contextlib.asynccontextmanager
async def napalm_session(
    ctx: HandlerContext, device: dict[str, Any], config: NapalmConnectionConfig
) -> AsyncIterator[NapalmSession]:
    """An open NAPALM session to ``device``; closed on exit."""
    open_napalm = opener(ctx)
    kwargs: dict[str, Any] = {
        "connect_timeout": float(config.connect_timeout_seconds),
        "command_timeout": float(config.command_timeout_seconds),
    }
    if config.allow_legacy_ssh:
        kwargs["allow_legacy_ssh"] = True
    loop = asyncio.get_running_loop()
    started = loop.time()
    await log_line(ctx, device, "opening a NAPALM session")
    try:
        session = await open_napalm(device, **kwargs)
    except NotImplementedError as exc:
        # The device's platform has no supported driver, or the platform
        # lacks the NAPALM transport: this device's failure, with the reason.
        await log_line(ctx, device, f"no NAPALM session: {exc}")
        raise NapalmStepError(str(exc) or "this platform cannot open NAPALM sessions") from None
    except Exception as exc:
        await log_line(ctx, device, f"opening the NAPALM session failed: {type(exc).__name__}")
        raise
    try:
        await log_line(
            ctx,
            device,
            f"NAPALM session open ({session.driver} driver) after {loop.time() - started:.1f} s",
        )
        yield session
    finally:
        await session.close()
        await log_line(ctx, device, "NAPALM session closed")


class NapalmStepError(Exception):
    """A device-level failure the step reports with this text."""


def device_label(device: dict[str, Any]) -> str:
    return str(device.get("name") or device.get("mgmt_host") or device.get("id") or "unknown")


@dataclass
class DeviceOutcome:
    """One device's part of a step: its output, evidence and error."""

    device: dict[str, Any]
    ok: bool = True
    error: str | None = None
    output: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    #: Output keys that hold long text, cut to the output budget.
    text_keys: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return device_label(self.device)


def describe_error(exc: BaseException) -> str:
    """The step's wording for a failure on one device."""
    if isinstance(exc, (NapalmStepError, SessionUnavailable, ValueError, PermissionError)):
        return str(exc)
    if isinstance(exc, NotImplementedError):
        return f"not supported on this device: {exc}" if str(exc) else "not supported"
    if isinstance(exc, TimeoutError):
        return str(exc) or "timed out"
    if isinstance(exc, OSError):
        return f"connection failed: {exc}"
    # NAPALM's own exceptions (MergeConfigException, CommitError, ...) carry
    # the device's message; their class name says which operation failed.
    return f"{type(exc).__name__}: {exc}"


async def run_per_device(
    ctx: HandlerContext,
    devices: list[dict[str, Any]],
    work: Callable[[dict[str, Any], DeviceOutcome], Awaitable[None]],
    *,
    max_parallel: int,
) -> list[DeviceOutcome]:
    """Run ``work`` for every device; a failure is recorded on its outcome.

    Only a platform without NAPALM (``SessionUnavailable``) propagates and
    fails the whole step.
    """

    async def _one(device: dict[str, Any]) -> DeviceOutcome:
        outcome = DeviceOutcome(device)
        try:
            await work(device, outcome)
        except SessionUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - one device's failure is its own
            outcome.ok = False
            outcome.error = describe_error(exc)
            # The device's own error text can echo configuration, secrets
            # included, so the log names only the kind of failure.
            logger.info(
                "napalm step failed on a device",
                extra={
                    "run_id": ctx.run_id,
                    "device": outcome.name,
                    "error_type": type(exc).__name__,
                },
            )
        return outcome

    return await for_each_target_device(devices, _one, max_parallel=max_parallel)


def _cap(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + TRUNCATED_NOTE, True


def build_result(outcomes: list[DeviceOutcome], *, summary: str) -> HandlerResult:
    """The step result: devices keyed by name, text cut to the output budget."""
    names = Counter(outcome.name for outcome in outcomes)
    devices: dict[str, Any] = {}
    truncated: list[str] = []
    used = 0
    for outcome in outcomes:
        key = outcome.name
        if names[key] > 1 and outcome.device.get("id"):
            key = f"{key} ({outcome.device['id']})"
        number = 2
        base = key
        while key in devices:
            key, number = f"{base} #{number}", number + 1
        entry = {
            **outcome.output,
            "device_id": outcome.device.get("id"),
            "ok": outcome.ok,
            "error": outcome.error,
        }
        for text_key in outcome.text_keys:
            text = entry.get(text_key)
            if not isinstance(text, str):
                continue
            room = max(0, min(MAX_OUTPUT_TEXT_CHARS, MAX_OUTPUT_TOTAL_CHARS - used))
            entry[text_key], cut = _cap(text, room)
            used += min(len(text), room)
            if cut:
                truncated.append(f"{key}.{text_key}")
        devices[key] = entry
    evidence = [item for outcome in outcomes for item in outcome.evidence]
    failures = [f"{outcome.name} ({outcome.error})" for outcome in outcomes if not outcome.ok]
    output = {"devices": devices, "truncated": truncated}
    if failures:
        return HandlerResult(
            success=False,
            summary=summary,
            error="Failed: " + "; ".join(failures),
            evidence=evidence,
            output=output,
        )
    return HandlerResult(success=True, summary=summary, evidence=evidence, output=output)


def to_json_text(data: Any) -> str:
    """Stable, readable JSON: sorted keys, so text checks and diffs are repeatable."""
    return json.dumps(data, indent=2, sort_keys=True, default=str)


def text_evidence(
    device: dict[str, Any],
    name: str,
    text: str,
    *,
    command: str,
    success: bool = True,
) -> dict[str, Any]:
    """An artifact other steps read like a CLI capture (evidence.*, git.commit)."""
    return {
        "kind": "cli_output",
        "name": f"{device_label(device)}:{name}",
        "device_id": device.get("id"),
        "content_text": text,
        "content_json": {
            "device_id": device.get("id"),
            "device_name": device_label(device),
            "command": command,
            "success": success,
        },
    }


def no_targets() -> HandlerResult:
    return HandlerResult(
        success=False, error="No target devices configured", summary="Missing targets"
    )


def unavailable(exc: SessionUnavailable) -> HandlerResult:
    return HandlerResult(success=False, error=str(exc), summary="NAPALM unavailable")
