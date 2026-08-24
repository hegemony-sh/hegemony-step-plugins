# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""flow.git_sync: the sync API payload carries exactly what was configured.

The flow_ids scope was historically declared in the config model and its
docstring but never forwarded, so a sync scoped to specific flows silently
synced everything. These tests pin the payload contract.
"""

from __future__ import annotations

from typing import Any, cast

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_steps_flow.git_sync import GitSyncRepoHandler


class _FakeResponse:
    status_code = 200

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return {"total": 2, "succeeded": 2, "failed": 0, "conflicts": 0, "skipped": 0}


class _FakeClient:
    def __init__(self, calls: list[tuple[str, dict[str, Any]]]) -> None:
        self._calls = calls

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def post(self, url: str, json: dict[str, Any]) -> _FakeResponse:
        self._calls.append((url, json))
        return _FakeResponse()


class _FakeServices:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def open_api_client(self, timeout: int) -> _FakeClient:
        return _FakeClient(self.calls)


def _ctx(config: dict[str, Any], services: _FakeServices) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        phase="IMPLEMENTATION",
        kind="EXECUTE",
        config=config,
        target_roles=[],
        target_devices_by_role={},
        services=cast(HandlerServices, services),
    )


async def test_flow_ids_scope_is_forwarded() -> None:
    services = _FakeServices()
    ids = ["11111111-1111-1111-1111-111111111111"]
    result = await GitSyncRepoHandler().execute(
        _ctx({"git_repo_id": "repo-1", "flow_ids": ids}, services)
    )
    assert result.success is True
    (url, payload) = services.calls[0]
    assert url.endswith("/git-repositories/repo-1/sync")
    assert payload["flow_ids"] == ids


async def test_unscoped_sync_omits_flow_ids() -> None:
    """No scope configured means the key is absent, not an empty list."""
    services = _FakeServices()
    result = await GitSyncRepoHandler().execute(_ctx({"git_repo_id": "repo-1"}, services))
    assert result.success is True
    (_, payload) = services.calls[0]
    assert "flow_ids" not in payload
    assert payload["trigger_source"] == "scheduled"
