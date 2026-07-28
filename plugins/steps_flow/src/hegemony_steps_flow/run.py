# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Nested flow launcher handler."""

from __future__ import annotations

import asyncio
import secrets
import time
from contextlib import suppress
from typing import Any
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)

_TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCELLED"}
_DEFAULT_RUN_NAME_HASH_BYTES = 3
_FIELD_MAPPING_MODES = {"default", "literal", "template"}
_TARGET_MAPPING_MODES = {"child_default", "parent_role", "none"}


def _http_error_detail(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        try:
            payload = exc.response.json()
            detail = payload.get("detail") if isinstance(payload, dict) else None
            if detail:
                return str(detail)
        except Exception:
            pass
        return f"API returned HTTP {exc.response.status_code}"
    return str(exc)


def _device_ids_for_parent_role(
    target_devices_by_role: dict[str, list[dict[str, Any]]],
    role: str,
) -> list[str]:
    device_ids: list[str] = []
    for device in target_devices_by_role.get(role, []):
        raw_device_id = device.get("id")
        if isinstance(raw_device_id, str) and raw_device_id.strip():
            device_ids.append(raw_device_id.strip())
    return device_ids


def _validate_field_mappings(value: Any) -> list[str]:
    if value is None:
        return ["field_mappings is required"]
    if not isinstance(value, dict) or isinstance(value, list):
        return ["field_mappings must be an object"]

    errors: list[str] = []
    for field_id, mapping in value.items():
        if not isinstance(field_id, str) or not field_id.strip():
            errors.append("field_mappings keys must be non-empty field ids")
            break
        if not isinstance(mapping, dict) or isinstance(mapping, list):
            errors.append(f"field_mappings.{field_id} must be an object")
            continue

        mode = mapping.get("mode")
        if mode not in _FIELD_MAPPING_MODES:
            errors.append(
                f"field_mappings.{field_id}.mode must be one of "
                f"{', '.join(sorted(_FIELD_MAPPING_MODES))}"
            )
            continue
        if mode in {"literal", "template"} and "value" not in mapping:
            errors.append(f"field_mappings.{field_id}.value is required for {mode} mode")
        if mode == "template" and (
            not isinstance(mapping.get("value"), str) or not mapping.get("value").strip()
        ):
            errors.append(f"field_mappings.{field_id}.value must be a non-empty string")
    return errors


def _validate_target_mappings(value: Any) -> list[str]:
    if value is None:
        return ["target_mappings is required"]
    if not isinstance(value, dict) or isinstance(value, list):
        return ["target_mappings must be an object"]

    errors: list[str] = []
    for child_role, mapping in value.items():
        if not isinstance(child_role, str) or not child_role.strip():
            errors.append("target_mappings keys must be non-empty child target roles")
            break
        if not isinstance(mapping, dict) or isinstance(mapping, list):
            errors.append(f"target_mappings.{child_role} must be an object")
            continue

        mode = mapping.get("mode")
        if mode not in _TARGET_MAPPING_MODES:
            errors.append(
                f"target_mappings.{child_role}.mode must be one of "
                f"{', '.join(sorted(_TARGET_MAPPING_MODES))}"
            )
            continue
        parent_role = mapping.get("parent_role_id")
        if mode == "parent_role" and (not isinstance(parent_role, str) or not parent_role.strip()):
            errors.append(
                f"target_mappings.{child_role}.parent_role_id is required for parent_role mode"
            )
    return errors


def _params_from_field_mappings(field_mappings: dict[str, Any]) -> dict[str, Any]:
    params: dict[str, Any] = {}
    for field_id, mapping in field_mappings.items():
        if not isinstance(mapping, dict):
            continue
        if mapping.get("mode") in {"literal", "template"}:
            params[str(field_id)] = mapping.get("value")
    return params


def _related_targets_from_mappings(
    target_mappings: dict[str, Any],
    target_devices_by_role: dict[str, list[dict[str, Any]]],
) -> dict[str, list[str]]:
    related_targets: dict[str, list[str]] = {}
    for child_role, mapping in target_mappings.items():
        if not isinstance(mapping, dict) or mapping.get("mode") != "parent_role":
            continue
        parent_role = str(mapping.get("parent_role_id") or "").strip()
        related_targets[str(child_role)] = _device_ids_for_parent_role(
            target_devices_by_role,
            parent_role,
        )
    return related_targets


class RunFlowConfig(BaseModel):
    """Config for ``flow.run``.

    The editor renders the entire config with the dedicated run-flow widget
    (flow picker + field/target mappings); semantic validation lives in
    :meth:`RunFlowHandler.validate_config`.
    """

    model_config = ConfigDict(extra="allow", json_schema_extra={"x_widget": "run-flow"})

    flow_id: str = Field(default="", title="Flow")
    flow_name: str = Field(
        default="",
        title="Flow name",
        description=(
            "Child flow name, resolved to the newest flow at launch time — the "
            "portable alternative to flow_id for imported bundles. Provide "
            "exactly one of flow_id / flow_name."
        ),
    )
    version: int | None = Field(default=None, ge=1, title="Version")
    wait_for_completion: bool = Field(default=True, title="Wait for completion")
    run_name: str | None = Field(default=None, title="Child run name")
    field_mappings: dict[str, Any] = Field(default_factory=dict, title="Field mappings")
    target_mappings: dict[str, Any] = Field(default_factory=dict, title="Target mappings")
    poll_interval_seconds: float = Field(default=5, ge=1, le=60, title="Poll interval (sec)")


class RunFlowHandler(BaseHandler):
    """Launch another committed flow from the current flow."""

    handler_id = "flow.run"
    default_timeout_seconds = 7200
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "Run Flow"
    description = "Launch another committed flow as a child run."
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = RunFlowConfig

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        errors: list[str] = []
        raw_flow_id = config.get("flow_id")
        raw_flow_name = config.get("flow_name")
        if raw_flow_id is not None and not isinstance(raw_flow_id, str):
            errors.append("flow_id must be a string")
        if raw_flow_name is not None and not isinstance(raw_flow_name, str):
            errors.append("flow_name must be a string")
        flow_id = raw_flow_id.strip() if isinstance(raw_flow_id, str) else ""
        flow_name = raw_flow_name.strip() if isinstance(raw_flow_name, str) else ""
        if flow_id and flow_name:
            errors.append("provide either flow_id or flow_name, not both")
        elif not flow_id and not flow_name and not errors:
            errors.append("flow_id or flow_name is required")
        elif flow_id:
            try:
                UUID(flow_id)
            except ValueError:
                errors.append("flow_id must be a UUID")

        version = config.get("version")
        if version is not None and (
            isinstance(version, bool) or not isinstance(version, int) or version < 1
        ):
            errors.append("version must be a positive integer")

        if "input_mappings" in config:
            errors.append("input_mappings is no longer supported; configure field_mappings")

        errors.extend(_validate_field_mappings(config.get("field_mappings")))
        errors.extend(_validate_target_mappings(config.get("target_mappings")))
        return errors

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Start a child flow run and optionally wait for its terminal result."""
        validation_errors = self.validate_config(ctx.config)
        if validation_errors:
            return HandlerResult(
                success=False,
                summary="Nested flow configuration error",
                error="; ".join(validation_errors),
            )

        services = ctx.require_services()

        raw_flow_id = ctx.config.get("flow_id")
        raw_flow_name = ctx.config.get("flow_name")
        flow_id = raw_flow_id.strip() if isinstance(raw_flow_id, str) else ""
        flow_name = raw_flow_name.strip() if isinstance(raw_flow_name, str) else ""
        raw_version = ctx.config.get("version")
        version = int(raw_version) if raw_version is not None else None
        wait_for_completion = bool(ctx.config.get("wait_for_completion", True))
        run_name = ctx.config.get("run_name")
        if run_name is not None:
            run_name = str(run_name).strip() or None
        if run_name is None:
            parent_run_name = ctx.run_name.strip() if ctx.run_name else ctx.run_id[:8]
            run_name = f"{parent_run_name}_{secrets.token_hex(_DEFAULT_RUN_NAME_HASH_BYTES)}"

        field_mappings = ctx.config.get("field_mappings")
        target_mappings = ctx.config.get("target_mappings")
        assert isinstance(field_mappings, dict)
        assert isinstance(target_mappings, dict)

        params = _params_from_field_mappings(field_mappings)
        related_targets = _related_targets_from_mappings(
            target_mappings,
            ctx.target_devices_by_role,
        )

        payload = {
            "name": run_name,
            "related_targets": related_targets,
            "params": params,
            "parent_run_id": ctx.run_id,
            "parent_step_run_id": ctx.step_run_id,
        }
        if flow_id:
            payload["flow_id"] = flow_id
        else:
            payload["flow_name"] = flow_name
        if version is not None:
            payload["version"] = version

        try:
            created = await services.create_child_run(payload)
        except Exception as exc:
            return HandlerResult(
                success=False,
                summary="Failed to start child flow",
                error=_http_error_detail(exc),
            )

        raw_child_run_id = created.get("run_id")
        if not isinstance(raw_child_run_id, str) or not raw_child_run_id.strip():
            return HandlerResult(
                success=False,
                summary="Failed to start child flow",
                error="Child run creation response missing run_id",
            )
        child_run_id = raw_child_run_id.strip()
        raw_child_workflow_id = created.get("workflow_id")
        child_workflow_id = (
            raw_child_workflow_id.strip()
            if isinstance(raw_child_workflow_id, str) and raw_child_workflow_id.strip()
            else child_run_id
        )
        await ctx.emit_progress(
            "Started child flow run",
            attrs={
                "child_run_id": child_run_id,
                "child_workflow_id": child_workflow_id,
                "child_flow_id": flow_id or None,
                "child_flow_name": flow_name or None,
                "child_version": version if version is not None else "latest",
            },
        )

        if not wait_for_completion:
            return HandlerResult(
                success=True,
                summary="Started child flow",
                metrics={"child_run_count": 1},
                output={
                    "child_run_id": child_run_id,
                    "child_workflow_id": child_workflow_id,
                    "child_status": "PENDING",
                    "waited": False,
                },
            )

        poll_interval = ctx.config.get("poll_interval_seconds", 5)
        if isinstance(poll_interval, bool) or not isinstance(poll_interval, (int, float)):
            poll_interval = 5
        poll_interval = max(1.0, min(float(poll_interval), 60.0))
        started = time.monotonic()

        try:
            while True:
                child = await services.fetch_run(child_run_id)
                status = str(child.get("status") or "UNKNOWN")
                if status in _TERMINAL_STATUSES:
                    error_message = child.get("error_message")
                    break
                await ctx.emit_progress(
                    "Waiting for child flow",
                    attrs={"child_run_id": child_run_id, "child_status": status},
                )
                await asyncio.sleep(poll_interval)
        except asyncio.CancelledError:
            with suppress(Exception):
                await services.cancel_run(child_run_id)
            raise
        except Exception as exc:
            return HandlerResult(
                success=False,
                summary="Failed while waiting for child flow",
                error=_http_error_detail(exc),
                output={
                    "child_run_id": child_run_id,
                    "child_workflow_id": child_workflow_id,
                    "child_status": "UNKNOWN",
                    "waited": True,
                },
            )

        elapsed_seconds = round(time.monotonic() - started, 3)
        base_output: dict[str, Any] = {
            "child_run_id": child_run_id,
            "child_workflow_id": child_workflow_id,
            "child_status": status,
            "waited": True,
        }

        if status != "SUCCESS":
            return HandlerResult(
                success=False,
                summary=f"Child flow ended with {status}",
                error=str(error_message or f"Child flow status: {status}"),
                metrics={"child_run_count": 1, "wait_seconds": elapsed_seconds},
                output=base_output,
            )

        try:
            outputs_payload = await services.fetch_run_outputs(child_run_id)
            outputs = outputs_payload.get("outputs", {})
            if not isinstance(outputs, dict):
                outputs = {}
        except Exception as exc:
            return HandlerResult(
                success=False,
                summary="Child flow succeeded but output evaluation failed",
                error=_http_error_detail(exc),
                metrics={"child_run_count": 1, "wait_seconds": elapsed_seconds},
                output=base_output,
            )

        return HandlerResult(
            success=True,
            summary="Child flow completed",
            metrics={"child_run_count": 1, "wait_seconds": elapsed_seconds},
            output={**base_output, "outputs": outputs},
        )
