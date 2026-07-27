# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for flow.run config validation (id vs. name child references)."""

from __future__ import annotations

from uuid import uuid4

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
