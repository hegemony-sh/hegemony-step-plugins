# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""inventory.sync: sync an inventory provider of the run's organization from a flow.

The host's ``sync_inventory`` service is faked: it answers from a script of
replies and records every call, so the handler's part is what is checked:
what it asks for, how it waits for a running sync, and how each answer and
refusal becomes the step's result.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerResult, HandlerServices
from hegemony_step_sdk.docs import check_page, load_docs_bundle
from hegemony_steps_inventory import sync as sync_module
from hegemony_steps_inventory.sync import InventorySyncConfig, InventorySyncHandler

COUNTS = {
    "items_added": 1,
    "items_updated": 2,
    "items_unchanged": 40,
    "items_stale": 0,
    "items_restored": 0,
    "sites_added": 0,
    "sites_updated": 0,
    "sites_stale": 0,
    "sites_restored": 0,
}


def _answer(status: str, **extra: Any) -> dict[str, Any]:
    ran = status in ("ok", "partial", "error")
    return {
        "provider_id": "netbox:primary",
        "provider_name": "primary",
        "provider_type": "netbox",
        "status": status,
        "history_id": "3f1c" if ran else None,
        "started_at": "2026-10-12T22:00:00Z" if ran else None,
        "finished_at": "2026-10-12T22:00:03Z" if ran else None,
        "duration_ms": 3000 if ran else None,
        "counts": dict(COUNTS) if ran else None,
        "error_message": None,
        "last_sync_at": "2026-10-12T22:00:03Z",
        **extra,
    }


class FakeServices:
    """A host whose ``sync_inventory`` answers from ``replies`` in order."""

    def __init__(self, *replies: Mapping[str, Any] | BaseException) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[str, int | None]] = []

    async def sync_inventory(
        self, provider: str, *, max_age_seconds: int | None = None
    ) -> Mapping[str, Any]:
        self.calls.append((provider, max_age_seconds))
        reply = self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]
        if isinstance(reply, BaseException):
            raise reply
        return reply


class OldHost:
    """A host from before the service: no ``sync_inventory`` at all."""


def _ctx(config: dict[str, Any], services: Any) -> HandlerContext:
    return HandlerContext(
        run_id="run-1",
        flow_id="flow-1",
        step_run_id="step-run-1",
        step_id="refresh",
        config=config,
        services=cast(HandlerServices, services),
    )


async def _run(config: dict[str, Any], services: Any) -> HandlerResult:
    return await InventorySyncHandler().execute(_ctx(config, services))


@pytest.fixture
def no_sleep(monkeypatch) -> list[float]:
    """Waits return at once; the clock moves by what was slept."""
    slept: list[float] = []
    clock = [1000.0]

    async def _sleep(seconds: float) -> None:
        slept.append(seconds)
        clock[0] += seconds

    monkeypatch.setattr(sync_module.asyncio, "sleep", _sleep)
    monkeypatch.setattr(sync_module.time, "monotonic", lambda: clock[0])
    return slept


# --- the handler as registered -------------------------------------------------------


def test_the_handler_declares_it_syncs_inventory_and_its_own_time_limit():
    assert InventorySyncHandler.syncs_inventory is True
    assert InventorySyncHandler.run_timeout_field == "timeout_seconds"
    assert "timeout_seconds" in InventorySyncConfig.model_fields


def test_docs_page_satisfies_the_contract():
    bundle = load_docs_bundle("hegemony_steps_inventory")
    assert set(bundle) == {"inventory.sync"}
    assert check_page("inventory.sync", bundle["inventory.sync"]) == []


def test_a_step_without_a_provider_is_refused_when_saved():
    assert InventorySyncHandler().validate_config({"provider": ""})
    assert InventorySyncHandler().validate_config({"provider": "netbox:primary"}) == []


# --- a sync that ran ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_sync_reports_what_it_changed():
    services = FakeServices(_answer("ok"))

    result = await _run({"provider": " netbox:primary "}, services)

    assert result.success is True
    assert services.calls == [("netbox:primary", None)]
    assert result.summary == "Synced netbox:primary: 1 added, 2 updated, 0 stale"
    assert result.output["status"] == "ok"
    assert result.output["synced"] is True
    assert result.output["counts"] == COUNTS
    assert result.output["history_id"] == "3f1c"
    assert result.metrics["items_added"] == 1 and result.metrics["duration_ms"] == 3000
    [evidence] = result.evidence
    assert evidence["name"] == "inventory_sync_refresh"
    assert evidence["content_json"] == result.output


@pytest.mark.asyncio
async def test_max_age_is_passed_and_a_fresh_provider_succeeds_without_a_sync():
    services = FakeServices(_answer("fresh"))

    result = await _run({"provider": "primary", "max_age_seconds": 120}, services)

    assert services.calls == [("primary", 120)]
    assert result.success is True
    assert result.output["status"] == "fresh"
    assert result.output["synced"] is False
    assert result.output["counts"] is None
    assert "no sync ran" in result.summary


@pytest.mark.asyncio
async def test_a_partial_sync_succeeds_unless_told_otherwise():
    partial = _answer("partial", error_message="vlan: timed out")

    lenient = await _run({"provider": "primary"}, FakeServices(partial))
    strict = await _run({"provider": "primary", "fail_on_partial": True}, FakeServices(partial))

    assert lenient.success is True and lenient.summary.startswith("Synced netbox:primary in part")
    assert strict.success is False
    assert strict.error is not None and "vlan: timed out" in strict.error


@pytest.mark.asyncio
async def test_a_failed_sync_fails_the_step_with_its_reason():
    services = FakeServices(_answer("error", error_message="unavailable: 503 from NetBox"))

    result = await _run({"provider": "primary"}, services)

    assert result.success is False
    assert result.summary == "Sync of netbox:primary failed"
    assert result.error is not None and "503 from NetBox" in result.error
    assert result.output["synced"] is True


# --- another sync running -------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_running_sync_is_waited_for_then_the_steps_own_runs(no_sleep):
    services = FakeServices(_answer("busy"), _answer("busy"), _answer("ok"))

    result = await _run({"provider": "primary", "wait_seconds": 60}, services)

    assert result.success is True
    assert len(services.calls) == 3
    assert no_sleep == [10.0, 10.0]
    assert result.output["waited_seconds"] == 20.0


@pytest.mark.asyncio
async def test_a_sync_still_running_after_the_wait_fails_the_step(no_sleep):
    services = FakeServices(_answer("busy"))

    result = await _run({"provider": "primary", "wait_seconds": 25}, services)

    assert result.success is False
    assert result.summary == "Another sync is running"
    assert result.output["status"] == "busy"
    # Asked at 0, 10 and 20 s; a fourth ask at 30 s would be past the wait.
    assert len(services.calls) == 3


@pytest.mark.asyncio
async def test_with_no_wait_a_running_sync_fails_at_once(no_sleep):
    services = FakeServices(_answer("busy"))

    result = await _run({"provider": "primary", "wait_seconds": 0}, services)

    assert result.success is False
    assert no_sleep == [] and len(services.calls) == 1


@pytest.mark.asyncio
async def test_a_step_past_its_timeout_fails_and_says_the_sync_may_still_run(monkeypatch):
    class SlowHost:
        async def sync_inventory(self, provider: str, *, max_age_seconds: int | None = None):
            await asyncio.sleep(10)
            return _answer("ok")

    real_timeout = asyncio.timeout
    monkeypatch.setattr(sync_module.asyncio, "timeout", lambda _seconds: real_timeout(0.01))

    result = await _run({"provider": "primary", "timeout_seconds": 60}, SlowHost())

    assert result.success is False
    assert result.summary == "Timed out"
    assert result.error is not None and "may still be running" in result.error


# --- refusals --------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "summary"),
    [
        (PermissionError("Flows may not sync inventory provider netbox:primary"), "Refused"),
        (LookupError("No inventory provider 'x' in the run's organization"), "Provider not found"),
        (ValueError("Several providers are named 'primary'"), "Rejected"),
        (RuntimeError("the inventory sync was refused: The step is not running"), "Sync could"),
    ],
)
async def test_the_platforms_refusals_fail_the_step_with_its_message(error, summary):
    result = await _run({"provider": "primary"}, FakeServices(error))

    assert result.success is False
    assert result.summary.startswith(summary)
    assert result.error is not None and str(error) in result.error
    assert set(result.output) >= {"provider", "status", "synced", "counts", "waited_seconds"}
    assert result.output["provider"] == "primary" and result.output["synced"] is False


@pytest.mark.asyncio
async def test_an_unexpected_error_reports_only_its_type():
    class LeakyError(Exception):
        pass

    result = await _run({"provider": "primary"}, FakeServices(LeakyError("token=abc123")))

    assert result.success is False
    assert result.error is not None and "LeakyError" in result.error
    assert "abc123" not in result.error


@pytest.mark.asyncio
async def test_a_platform_without_the_service_says_to_upgrade():
    result = await _run({"provider": "primary"}, OldHost())

    assert result.success is False
    assert result.summary == "Inventory syncs unavailable"
    assert result.error is not None and "lacks sync_inventory" in result.error


@pytest.mark.asyncio
async def test_a_host_that_has_the_method_but_no_support_says_so_too():
    result = await _run({"provider": "primary"}, FakeServices(NotImplementedError()))

    assert result.success is False
    assert result.summary == "Inventory syncs unavailable"


@pytest.mark.asyncio
async def test_an_invalid_config_fails_with_every_output_key():
    result = await _run({"provider": "primary", "max_age_seconds": -1}, FakeServices(_answer("ok")))

    assert result.success is False
    assert result.output["provider"] == "primary"
    assert result.output["status"] is None and result.output["counts"] is None
