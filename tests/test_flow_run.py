# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for flow.run config validation (id vs. name child references)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_steps_flow import run as run_module
from hegemony_steps_flow.run import RunFlowHandler

_BASE = {"field_mappings": {}, "target_mappings": {}}


def _errors(config: dict) -> list[str]:
    return RunFlowHandler().validate_config({**_BASE, **config})


def test_flow_id_alone_is_valid() -> None:
    assert _errors({"flow_id": str(uuid4())}) == []


def test_flow_name_alone_is_valid() -> None:
    assert _errors({"flow_name": "Net: Wait for OSPF convergence"}) == []


def test_both_references_rejected() -> None:
    errors = _errors({"flow_id": str(uuid4()), "flow_name": "X"})
    assert any("not both" in e for e in errors)


def test_neither_reference_rejected() -> None:
    errors = _errors({})
    assert any("flow_id or flow_name is required" in e for e in errors)


def test_flow_id_must_be_uuid_when_given() -> None:
    errors = _errors({"flow_id": "not-a-uuid"})
    assert any("must be a UUID" in e for e in errors)


def test_non_string_selectors_rejected() -> None:
    # flow_id=123 + flow_name="X" must not silently launch by str(123).
    errors = _errors({"flow_id": 123, "flow_name": "X"})
    assert any("flow_id must be a string" in e for e in errors)
    errors = _errors({"flow_name": 123})
    assert any("flow_name must be a string" in e for e in errors)


@pytest.mark.parametrize(
    ("config", "field"),
    [
        ({"version": 0}, "version"),
        ({"version": "x"}, "version"),
        ({"wait_for_completion": "maybe"}, "wait_for_completion"),
        ({"poll_interval_seconds": 0.5}, "poll_interval_seconds"),
        ({"poll_interval_seconds": 61}, "poll_interval_seconds"),
    ],
)
def test_settings_are_checked_against_the_model(config, field) -> None:
    errors = _errors({"flow_name": "X", **config})
    assert any(error.startswith(f"{field}:") for error in errors), errors


def test_rendered_settings_are_valid() -> None:
    # The platform renders a template as text before the step runs.
    rendered = {"version": "3", "wait_for_completion": "false", "poll_interval_seconds": "10"}
    assert _errors({"flow_name": "X", **rendered}) == []


def test_a_template_mapping_needs_a_value() -> None:
    errors = _errors({"flow_name": "X", "field_mappings": {"force": {"mode": "template"}}})
    assert errors == ["field_mappings.force.value is required for template mode"]


async def test_rendered_template_mappings_pass_whatever_they_rendered_to() -> None:
    # The platform renders field_mappings keeping each value's type: a run input
    # that is false, empty, a number or missing reaches the step as such.
    services = _FakeServices()
    rendered = {
        "force": {"mode": "template", "value": False},
        "csr_b64": {"mode": "template", "value": ""},
        "validity_days": {"mode": "template", "value": None},
        "count": {"mode": "template", "value": 0},
        "name": {"mode": "template", "value": "web-01"},
    }
    config = {**_BASE, "flow_name": "X", "wait_for_completion": False, "field_mappings": rendered}
    assert RunFlowHandler().validate_config(config) == []
    result = await RunFlowHandler().execute(_ctx(config, services))
    assert result.success is True, result.error
    assert services.child_run_payloads[0]["params"] == {
        "force": False,
        "csr_b64": "",
        "validity_days": None,
        "count": 0,
        "name": "web-01",
    }


class _FakeServices:
    def __init__(self, statuses: list[str] | None = None) -> None:
        self.child_run_payloads: list[dict[str, Any]] = []
        self.statuses = list(statuses or [])
        self.fetches = 0

    async def create_child_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.child_run_payloads.append(payload)
        return {"run_id": "child-1", "workflow_id": "wf-1"}

    async def fetch_run(self, run_id: str) -> dict[str, Any]:
        self.fetches += 1
        return {"status": self.statuses.pop(0)}

    async def fetch_run_outputs(self, run_id: str) -> dict[str, Any]:
        return {"outputs": {"answer": 42}}


def _ctx(config: dict[str, Any], services: _FakeServices) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        target_roles=[],
        target_devices_by_role={},
        services=cast(HandlerServices, services),
    )


async def test_execute_sends_flow_name_not_flow_id() -> None:
    # The launch payload must carry exactly the configured selector: a
    # flow_name reference may not leak an (empty) flow_id and vice versa.
    services = _FakeServices()
    result = await RunFlowHandler().execute(
        _ctx(
            {
                **_BASE,
                "flow_name": "Net: Wait for OSPF convergence",
                "wait_for_completion": False,
            },
            services,
        )
    )
    assert result.success is True
    assert len(services.child_run_payloads) == 1
    payload = services.child_run_payloads[0]
    assert payload["flow_name"] == "Net: Wait for OSPF convergence"
    assert "flow_id" not in payload


async def test_execute_sends_flow_id_not_flow_name() -> None:
    services = _FakeServices()
    flow_id = str(uuid4())
    result = await RunFlowHandler().execute(
        _ctx({**_BASE, "flow_id": flow_id, "wait_for_completion": False}, services)
    )
    assert result.success is True
    payload = services.child_run_payloads[0]
    assert payload["flow_id"] == flow_id
    assert "flow_name" not in payload


@pytest.mark.parametrize("rendered", ["false", "False"])
async def test_a_rendered_false_does_not_wait(rendered: str) -> None:
    services = _FakeServices()
    config = {**_BASE, "flow_name": "X", "version": "3", "wait_for_completion": rendered}
    result = await RunFlowHandler().execute(_ctx(config, services))

    assert result.success is True, result.error
    assert result.output["waited"] is False
    assert services.fetches == 0
    # A rendered version is the number it names.
    assert services.child_run_payloads[0]["version"] == 3


async def test_a_rendered_poll_interval_is_used(monkeypatch) -> None:
    slept: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        slept.append(seconds)

    fake = SimpleNamespace(sleep=fake_sleep, CancelledError=asyncio.CancelledError)
    monkeypatch.setattr(run_module, "asyncio", fake)
    services = _FakeServices(["RUNNING", "SUCCESS"])
    config = {**_BASE, "flow_name": "X", "poll_interval_seconds": "12"}
    result = await RunFlowHandler().execute(_ctx(config, services))

    assert result.success is True, result.error
    assert result.output["outputs"] == {"answer": 42}
    assert slept == [12.0]


async def test_an_invalid_setting_starts_no_child_run() -> None:
    services = _FakeServices()
    config = {**_BASE, "flow_name": "X", "poll_interval_seconds": 600}
    result = await RunFlowHandler().execute(_ctx(config, services))

    assert result.success is False
    assert result.summary == "Nested flow configuration error"
    assert "poll_interval_seconds" in (result.error or "")
    assert services.child_run_payloads == []
