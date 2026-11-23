# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What a step reaches on the platform: run_access, central_only, no raw internal paths."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, cast

import pytest

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerServices,
    PlatformRequestError,
    run_access,
)

REPO = Path(__file__).resolve().parents[1]


def _ctx(services: object) -> HandlerContext:
    return HandlerContext(
        run_id="run-1",
        flow_id="f",
        step_run_id="sr-1",
        step_id="notify",
        config={},
        tags={"phase": "post"},
        services=cast(HandlerServices, services),
    )


class _NamedMethods:
    """A host with the named methods."""

    def __init__(self, destination: dict[str, Any] | None = None) -> None:
        self.destination = destination
        self.events: list[dict[str, Any]] = []

    async def fetch_notification_destination(self, destination_id: str) -> dict[str, Any] | None:
        return self.destination

    async def emit_run_event(
        self, message: str, *, kind: str = "log", attrs: dict | None = None, phase: str = ""
    ) -> None:
        self.events.append({"message": message, "kind": kind, "attrs": attrs, "phase": phase})


class _Response:
    def __init__(self, status_code: int, payload: Any = None) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _OlderHost:
    """A host from before the named methods: only the internal-API client."""

    def __init__(self, response: _Response) -> None:
        self.response = response
        self.requests: list[tuple[str, str, Any]] = []

    def open_api_client(self, *, timeout: float = 30.0) -> _OlderHost:
        return self

    async def __aenter__(self) -> _OlderHost:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get(self, url: str) -> _Response:
        self.requests.append(("GET", url, None))
        return self.response

    async def post(self, url: str, *, json: Any) -> _Response:
        self.requests.append(("POST", url, json))
        return self.response


DESTINATION = {"id": "d1", "name": "Ops", "type": "webhook", "config_json": {}}


class TestNamedMethods:
    async def test_destination(self) -> None:
        host = _NamedMethods(DESTINATION)
        assert await run_access.fetch_notification_destination(_ctx(host), "d1") == DESTINATION

    async def test_no_destination(self) -> None:
        assert await run_access.fetch_notification_destination(_ctx(_NamedMethods()), "d1") is None

    async def test_event_carries_the_steps_phase(self) -> None:
        host = _NamedMethods()
        await run_access.emit_run_event(_ctx(host), "sent", kind="notification", attrs={"a": 1})
        assert host.events == [
            {"message": "sent", "kind": "notification", "attrs": {"a": 1}, "phase": "post"}
        ]


class TestOlderHost:
    async def test_destination(self) -> None:
        host = _OlderHost(_Response(200, DESTINATION))
        assert await run_access.fetch_notification_destination(_ctx(host), "d1") == DESTINATION
        assert host.requests == [("GET", "/internal/notification-destinations/d1", None)]

    async def test_unknown_destination(self) -> None:
        host = _OlderHost(_Response(404))
        assert await run_access.fetch_notification_destination(_ctx(host), "d1") is None

    async def test_destination_error(self) -> None:
        with pytest.raises(PlatformRequestError) as exc:
            await run_access.fetch_notification_destination(_ctx(_OlderHost(_Response(500))), "d1")
        assert exc.value.status_code == 500

    async def test_event(self) -> None:
        host = _OlderHost(_Response(201))
        await run_access.emit_run_event(_ctx(host), "sent", kind="notification", attrs={"a": 1})
        assert host.requests == [
            (
                "POST",
                "/internal/runs/run-1/events",
                {
                    "step_run_id": "sr-1",
                    "step_id": "notify",
                    "phase": "post",
                    "kind": "notification",
                    "message": "sent",
                    "attrs": {"a": 1},
                },
            )
        ]

    async def test_event_refused(self) -> None:
        with pytest.raises(PlatformRequestError):
            await run_access.emit_run_event(_ctx(_OlderHost(_Response(403))), "sent")


class TestNotifyUsesRunAccess:
    async def test_an_unknown_destination_fails_the_step(self) -> None:
        from hegemony_steps_flow.notify import SendNotificationHandler

        ctx = _ctx(_NamedMethods(None))
        ctx.config = {"destination_id": "d1"}
        result = await SendNotificationHandler().execute(ctx)
        assert result.success is False
        assert result.error == "Notification destination not found or disabled"


class TestCentralOnly:
    def test_off_by_default(self) -> None:
        assert BaseHandler.central_only is False

    @pytest.mark.parametrize(
        ("module", "name"),
        [
            ("hegemony_steps_flow.run", "RunFlowHandler"),
            ("hegemony_steps_flow.notify", "SendNotificationHandler"),
            ("hegemony_steps_secret.write", "WriteSecretHandler"),
            ("hegemony_steps_inventory.sync", "InventorySyncHandler"),
        ],
    )
    def test_handlers_that_drive_the_platform(self, module: str, name: str) -> None:
        import importlib

        assert getattr(importlib.import_module(module), name).central_only is True


def _plugin_sources() -> list[Path]:
    return sorted((REPO / "plugins").glob("*/src/**/*.py"))


def test_no_plugin_calls_the_internal_api_itself() -> None:
    """Plugins reach the platform through named methods and run_access, never raw paths.

    Internal paths are not part of the plugin contract: an edge worker will
    refuse most of them, and the platform may change them.
    """
    assert _plugin_sources()
    offenders = []
    for path in _plugin_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "open_api_client":
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno} open_api_client")
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value.startswith("/internal/")
            ):
                offenders.append(f"{path.relative_to(REPO)}:{node.lineno} {node.value}")
            elif isinstance(node, ast.JoinedStr):
                first = node.values[0] if node.values else None
                if (
                    isinstance(first, ast.Constant)
                    and isinstance(first.value, str)
                    and first.value.startswith("/internal/")
                ):
                    offenders.append(f"{path.relative_to(REPO)}:{node.lineno} f'{first.value}…'")
    assert offenders == [], "use the services' named methods or hegemony_step_sdk.run_access"
