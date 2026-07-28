# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for flow.run config validation (id vs. name child references)."""

from __future__ import annotations

from typing import Any, cast
from uuid import uuid4

from hegemony_step_sdk import HandlerContext, HandlerServices
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


class _FakeServices:
    def __init__(self) -> None:
        self.child_run_payloads: list[dict[str, Any]] = []

    async def create_child_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.child_run_payloads.append(payload)
        return {"run_id": "child-1", "workflow_id": "wf-1"}


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
