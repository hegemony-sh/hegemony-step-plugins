# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""InventorySyncHandler: sync one of the run organization's inventory providers now.

The handler runs on the worker and never talks to a source of truth itself: it
asks the host's ``sync_inventory`` service, which finds the provider in the
run's organization, refuses one an administrator has not opened to flows, runs
the sync under the provider's lease and audits it. A flow uses the step to see
what its source holds right now, for example a device a previous step created
in NetBox, before a later step targets it.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    StepKind,
)

#: How often to ask again while another sync of the provider is running.
BUSY_POLL_SECONDS = 10.0


class _Wait:
    """The time spent waiting for another sync, not the step's own sync.

    It starts at the first ``busy`` answer and ends when the step asks again
    after it; while the step sleeps between asks it is still running.
    """

    def __init__(self) -> None:
        self.started: float | None = None
        self.ended: float | None = None

    @property
    def seconds(self) -> float:
        if self.started is None:
            return 0.0
        end = self.ended if self.ended is not None else time.monotonic()
        return end - self.started


#: The host's documented error types, each with the summary the step reports for it.
#: Their messages name the provider and the rule, so ``_describe`` passes them on.
_HOST_SUMMARIES: dict[type[BaseException], str] = {
    PermissionError: "Refused by the platform",
    LookupError: "Provider not found",
    ValueError: "Rejected by the platform",
    RuntimeError: "Sync could not be requested",
}
_HOST_ERRORS = tuple(_HOST_SUMMARIES)

#: The counts a sync that ran reports, in the order the summary names them.
COUNT_KEYS = (
    "items_added",
    "items_updated",
    "items_unchanged",
    "items_stale",
    "items_restored",
    "sites_added",
    "sites_updated",
    "sites_stale",
    "sites_restored",
)


class InventorySyncConfig(BaseModel):
    """Config for ``inventory.sync``."""

    model_config = ConfigDict(extra="allow")

    provider: str = Field(
        min_length=1,
        max_length=255,
        title="Provider",
        description=(
            "The inventory provider to sync, by its id (netbox:primary) or its name (primary). "
            "Only providers of the run's organization are found, and only one an administrator "
            "has opened to flows ('Flows may sync this provider') may be synced."
        ),
        json_schema_extra={"x_placeholder": "netbox:primary", "x_col_span": 2},
    )

    @field_validator("provider")
    @classmethod
    def _provider_is_named(cls, value: str) -> str:
        """Strip the name; one of only spaces names no provider."""
        value = value.strip()
        if not value:
            raise ValueError("name an inventory provider by its id or name")
        return value

    max_age_seconds: int = Field(
        default=0,
        ge=0,
        le=86400 * 7,
        title="Skip if synced within (seconds)",
        description=(
            "When the provider's last sync succeeded no longer ago than this, no sync runs and "
            "the step succeeds with status 'fresh'. 0 (the default) always syncs."
        ),
    )
    wait_seconds: int = Field(
        default=300,
        ge=0,
        le=3600,
        title="Wait for a running sync (seconds)",
        description=(
            "When another sync of the provider is running, ask again every 10 seconds for up "
            "to this long, then start this step's own sync. 0 fails at once with status 'busy'."
        ),
        json_schema_extra={"x_advanced": True},
    )
    fail_on_partial: bool = Field(
        default=False,
        title="Fail on a partial sync",
        description=(
            "A partial sync brought devices and sites up to date but failed for some other "
            "object type (VLANs, say). Off (the default): the step succeeds. On: it fails."
        ),
        json_schema_extra={"x_advanced": True},
    )
    timeout_seconds: int = Field(
        default=1800,
        ge=60,
        le=86400,
        title="Timeout (seconds)",
        description=(
            "The longest the whole step may take, waiting for a running sync included. Leave "
            "room for the platform's sync deadline (15 minutes unless an administrator "
            "changed it)."
        ),
        json_schema_extra={"x_advanced": True},
    )


def _describe(exc: BaseException) -> str:
    """A host error as text: the message of a documented error type, else only its type."""
    if type(exc) in _HOST_ERRORS:
        return str(exc).strip() or type(exc).__name__
    return f"unexpected {type(exc).__name__} from the platform"


def _host_summary(exc: BaseException) -> str:
    """The summary for a host error, by the same exact-type rule as :func:`_describe`."""
    return _HOST_SUMMARIES.get(type(exc), "Unexpected error")


def _output(provider: str, answer: Mapping[str, Any] | None, *, waited: float) -> dict[str, Any]:
    """The step's chainable output; every key is present whatever happened."""
    answer = answer or {}
    counts = answer.get("counts")
    return {
        "provider": provider,
        "provider_id": answer.get("provider_id"),
        "provider_name": answer.get("provider_name"),
        "provider_type": answer.get("provider_type"),
        "status": answer.get("status"),
        "synced": answer.get("status") in ("ok", "partial", "error"),
        "history_id": answer.get("history_id"),
        "started_at": answer.get("started_at"),
        "finished_at": answer.get("finished_at"),
        "duration_ms": answer.get("duration_ms"),
        "counts": (
            {key: int(counts.get(key) or 0) for key in COUNT_KEYS}
            if isinstance(counts, Mapping)
            else None
        ),
        "error_message": answer.get("error_message"),
        "last_sync_at": answer.get("last_sync_at"),
        "waited_seconds": round(waited, 1),
    }


def _counted(counts: Mapping[str, int] | None) -> str:
    if not counts:
        return ""
    parts = [
        f"{counts['items_added']} added",
        f"{counts['items_updated']} updated",
        f"{counts['items_stale']} stale",
    ]
    if counts["items_restored"]:
        parts.append(f"{counts['items_restored']} restored")
    sites = sum(counts[key] for key in COUNT_KEYS if key.startswith("sites_"))
    if sites:
        parts.append(f"{sites} site changes")
    return ", ".join(parts)


def _result(
    ctx: HandlerContext,
    output: dict[str, Any],
    *,
    success: bool,
    summary: str,
    error: str | None = None,
) -> HandlerResult:
    lines = [summary]
    if output.get("error_message"):
        lines.append(f"error: {output['error_message']}")
    if output.get("last_sync_at"):
        lines.append(f"last sync ended: {output['last_sync_at']}")
    metrics: dict[str, Any] = {"waited_seconds": output["waited_seconds"]}
    if output.get("duration_ms") is not None:
        metrics["duration_ms"] = output["duration_ms"]
    for key, value in (output.get("counts") or {}).items():
        metrics[key] = value
    return HandlerResult(
        success=success,
        summary=summary,
        error=error,
        output=output,
        metrics=metrics,
        evidence=[
            {
                "kind": "step_result",
                "name": f"inventory_sync_{ctx.step_id}",
                "content_text": "\n".join(lines) + "\n",
                "content_json": output,
            }
        ],
    )


class InventorySyncHandler(BaseHandler):
    """Sync one of the run organization's inventory providers now."""

    handler_id = "inventory.sync"
    supported_kinds = [StepKind.ACTION]
    display_name = "Sync Inventory"
    description = (
        "Sync an inventory provider of the run's organization now, so later steps see what "
        "the source of truth holds, such as a device a previous step created there."
    )
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    syncs_inventory = True
    run_timeout_field = "timeout_seconds"
    config_model = InventorySyncConfig
    default_config = {"max_age_seconds": 0}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Ask the host for a sync; wait while another sync of the provider runs."""
        raw_provider = ctx.config.get("provider")
        requested = raw_provider.strip() if isinstance(raw_provider, str) else ""
        try:
            config = self.parse_config(ctx.config, InventorySyncConfig)
        except InvalidConfigError as exc:
            return _result(
                ctx,
                _output(requested, None, waited=0.0),
                success=False,
                summary=exc.result().summary,
                error=str(exc),
            )
        provider = config.provider
        services = ctx.require_services()
        sync = getattr(services, "sync_inventory", None)
        if not callable(sync):
            return self._unavailable(ctx, provider, "its worker lacks sync_inventory")

        wait = _Wait()
        deadline = asyncio.timeout(config.timeout_seconds)
        try:
            async with deadline:
                answer = await self._ask(sync, provider, config, wait)
        except TimeoutError as exc:
            if not deadline.expired():
                # The host raised it; the step's own time limit did not run out.
                return self._host_failed(ctx, provider, exc, wait)
            return _result(
                ctx,
                _output(provider, None, waited=wait.seconds),
                success=False,
                summary="Timed out",
                error=(
                    f"the sync of {provider} did not end within {config.timeout_seconds} seconds; "
                    "it may still be running on the platform"
                ),
            )
        except NotImplementedError:
            return self._unavailable(ctx, provider, "its worker does not support inventory syncs")
        except Exception as exc:
            return self._host_failed(ctx, provider, exc, wait)
        return self._report(ctx, provider, config, answer, waited=wait.seconds)

    @staticmethod
    def _host_failed(
        ctx: HandlerContext, provider: str, exc: BaseException, wait: _Wait
    ) -> HandlerResult:
        """The result for a host error: its message for a documented type, else its type."""
        return _result(
            ctx,
            _output(provider, None, waited=wait.seconds),
            success=False,
            summary=_host_summary(exc),
            error=f"Could not sync {provider}: {_describe(exc)}",
        )

    async def _ask(
        self, sync: Any, provider: str, config: InventorySyncConfig, wait: _Wait
    ) -> Mapping[str, Any]:
        """Ask for the sync; while another one runs, ask again until the wait runs out."""
        max_age = config.max_age_seconds or None
        while True:
            if wait.started is not None:
                wait.ended = time.monotonic()
            answer = await sync(provider, max_age_seconds=max_age)
            if not isinstance(answer, Mapping):
                raise RuntimeError("the platform answered the sync with something unexpected")
            if answer.get("status") != "busy":
                return answer
            now = time.monotonic()
            if wait.started is None:
                wait.started = now
            wait.ended = None
            remaining = config.wait_seconds - (now - wait.started)
            if remaining <= 0:
                wait.ended = now
                return answer
            await asyncio.sleep(min(BUSY_POLL_SECONDS, remaining))

    def _report(
        self,
        ctx: HandlerContext,
        provider: str,
        config: InventorySyncConfig,
        answer: Mapping[str, Any],
        *,
        waited: float,
    ) -> HandlerResult:
        output = _output(provider, answer, waited=waited)
        name = output["provider_id"] or provider
        status = output["status"]
        counted = _counted(output["counts"])
        if status == "ok":
            return _result(
                ctx,
                output,
                success=True,
                summary=f"Synced {name}" + (f": {counted}" if counted else ""),
            )
        if status == "fresh":
            return _result(
                ctx,
                output,
                success=True,
                summary=f"{name} is fresh: synced within {config.max_age_seconds} s, no sync ran",
            )
        if status == "partial":
            summary = f"Synced {name} in part" + (f": {counted}" if counted else "")
            if config.fail_on_partial:
                return _result(
                    ctx,
                    output,
                    success=False,
                    summary=summary,
                    error=f"the sync of {name} was partial: "
                    + (output["error_message"] or "an object type failed"),
                )
            return _result(ctx, output, success=True, summary=summary)
        if status == "busy":
            return _result(
                ctx,
                output,
                success=False,
                summary="Another sync is running",
                error=(
                    f"another sync of {name} was still running after {config.wait_seconds} "
                    "seconds of waiting"
                ),
            )
        if status == "error":
            return _result(
                ctx,
                output,
                success=False,
                summary=f"Sync of {name} failed",
                error=f"the sync of {name} failed: "
                + (output["error_message"] or "no reason given"),
            )
        return _result(
            ctx,
            output,
            success=False,
            summary="Unexpected answer",
            error=f"the platform answered the sync of {name} with status {status!r}",
        )

    def _unavailable(self, ctx: HandlerContext, provider: str, reason: str) -> HandlerResult:
        return _result(
            ctx,
            _output(provider, None, waited=0.0),
            success=False,
            summary="Inventory syncs unavailable",
            error=(
                f"this platform does not let steps sync inventory: {reason}. Upgrade the "
                "platform to use this step"
            ),
        )
