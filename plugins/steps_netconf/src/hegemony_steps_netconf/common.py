# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What the ``netconf.*`` steps share: settings, sessions, fan-out and output."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    DEFAULT_NETCONF_PORT,
    MAX_PARALLEL_DEVICES_LIMIT,
    HandlerContext,
    HandlerResult,
    for_each_target_device,
)

from .client import NetconfError, NetconfSession, RpcFailed

logger = logging.getLogger(__name__)

#: Characters of one device's text (data, a diff, a reply) kept in the step
#: output; the evidence keeps all of it.
MAX_OUTPUT_TEXT_CHARS = 16 * 1024
#: Characters of text the whole step puts in its output.
MAX_OUTPUT_TOTAL_CHARS = 64 * 1024
TRUNCATED_NOTE = "\n… [cut short: the full text is in the step's evidence]"


class NetconfConnectionConfig(BaseModel):
    """Connection settings every ``netconf.*`` step has."""

    model_config = ConfigDict(extra="allow")

    port: int = Field(
        default=DEFAULT_NETCONF_PORT,
        ge=1,
        le=65535,
        title="Port",
        description="The device's NETCONF over SSH port. Defaults to 830.",
        json_schema_extra={"x_advanced": True},
    )
    connect_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=300,
        title="Connect Timeout (sec)",
        description="How long connecting and the hello exchange may take. Defaults to 15.",
        json_schema_extra={"x_advanced": True},
    )
    rpc_timeout_seconds: int = Field(
        default=120,
        ge=1,
        le=3600,
        title="Request Timeout (sec)",
        description=(
            "How long the device may take to answer one request (a large get-config, a "
            "commit). Defaults to 120."
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
    """The platform cannot open NETCONF sessions (it predates ``open_netconf``)."""


def opener(ctx: HandlerContext) -> Callable[..., Awaitable[Any]]:
    """The host's ``open_netconf``, or raise when the platform has none."""
    services = ctx.require_services()
    open_netconf = getattr(services, "open_netconf", None)
    if open_netconf is None:
        raise SessionUnavailable(
            "this platform cannot open NETCONF sessions; upgrade Hegemony to a release "
            "that supports the netconf steps"
        )
    return open_netconf


@contextlib.asynccontextmanager
async def netconf_session(
    ctx: HandlerContext, device: dict[str, Any], config: NetconfConnectionConfig
) -> AsyncIterator[NetconfSession]:
    """An open NETCONF session to ``device``, hello done; closed on exit."""
    open_netconf = opener(ctx)
    kwargs: dict[str, Any] = {
        "port": config.port,
        "connect_timeout": float(config.connect_timeout_seconds),
    }
    if config.allow_legacy_ssh:
        kwargs["allow_legacy_ssh"] = True
    try:
        channel = await open_netconf(device, **kwargs)
    except NotImplementedError:
        raise SessionUnavailable("this platform cannot open NETCONF sessions") from None
    session = NetconfSession(channel, timeout=float(config.rpc_timeout_seconds))
    try:
        try:
            await asyncio.wait_for(session.hello(), timeout=config.connect_timeout_seconds)
        except TimeoutError:
            raise NetconfError(
                f"no NETCONF hello within {config.connect_timeout_seconds} s"
            ) from None
        yield session
    finally:
        await session.close()


def persist_id_for(ctx: HandlerContext, device: dict[str, Any]) -> str:
    """The persist id of this step's confirmed commit on ``device``.

    Derived from the run, the step run and the device, so it is the same on
    every attempt of the step: the platform creates the step run once and an
    activity retry (a crashed worker, a lost connection) reuses it. A retried
    step can then find, extend and report the commit an earlier attempt left
    pending, instead of leaving one nobody can confirm.
    """
    parts = (
        ctx.run_id or "",
        ctx.step_run_id or "",
        str(device.get("id") or ""),
        device_label(device),
        str(device.get("mgmt_host") or ""),
    )
    if not (ctx.run_id or ctx.step_run_id):
        return ""  # no stable identity: the transaction makes a random one
    return "hegemony-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:32]


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
    if isinstance(exc, (RpcFailed, NetconfError, SessionUnavailable, ValueError, PermissionError)):
        return str(exc)
    if isinstance(exc, TimeoutError):
        return str(exc) or "timed out"
    if isinstance(exc, OSError):
        return f"connection failed: {exc}"
    return f"{type(exc).__name__}: {exc}"


async def run_per_device(
    ctx: HandlerContext,
    devices: list[dict[str, Any]],
    work: Callable[[dict[str, Any], DeviceOutcome], Awaitable[None]],
    *,
    max_parallel: int,
) -> list[DeviceOutcome]:
    """Run ``work`` for every device; a failure is recorded on its outcome.

    A refusal by the flow's egress policy is recorded on that device's
    outcome too, so the devices done before it keep their results (a pending
    commit's persist id among them). Only a platform without NETCONF
    (``SessionUnavailable``) propagates and fails the whole step.
    """

    async def _one(device: dict[str, Any]) -> DeviceOutcome:
        outcome = DeviceOutcome(device)
        try:
            await work(device, outcome)
        except SessionUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - one device's failure is its own
            # A policy refusal too: the devices done before it keep their
            # results (a pending commit's persist id among them).
            outcome.ok = False
            outcome.error = describe_error(exc)
            # The device's own error text can echo configuration, secrets
            # included, so the log names only the kind of failure.
            logger.info(
                "netconf step failed on a device",
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


def build_result(
    outcomes: list[DeviceOutcome], *, summary: str, extra_output: dict[str, Any] | None = None
) -> HandlerResult:
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
        entry = {**outcome.output, "ok": outcome.ok, "error": outcome.error}
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
    output = {"devices": devices, "truncated": truncated, **(extra_output or {})}
    if failures:
        return HandlerResult(
            success=False,
            summary=summary,
            error="Failed: " + "; ".join(failures),
            evidence=evidence,
            output=output,
        )
    return HandlerResult(success=True, summary=summary, evidence=evidence, output=output)


def text_evidence(
    device: dict[str, Any], name: str, text: str, *, command: str, success: bool = True
) -> dict[str, Any]:
    """A text artifact other steps read like a CLI capture (evidence.*, git.commit)."""
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
    return HandlerResult(success=False, error=str(exc), summary="NETCONF unavailable")
