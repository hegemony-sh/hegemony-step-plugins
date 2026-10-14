# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""RenderConfigHandler: have NetBox render the intended configuration of devices.

NetBox renders a device's (or virtual machine's) config template with its
config context (``POST …/render-config/``). The step does that for each
target device, or for the NetBox IDs it is given, and keeps every rendered
configuration as run evidence and, when small enough, in its output, so a
later step can compare it with the running configuration or push it.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import Any, Literal

import httpx
from pydantic import Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    StepKind,
    resolve_target_devices_for_roles,
)
from hegemony_steps_http.security import is_templated

from .client import (
    MAX_OUTPUT_DATA_BYTES,
    NetBoxClient,
    NetBoxConnection,
    connection_errors,
    json_size,
    json_value,
    object_id_error,
)

HANDLER_ID = "netbox.render_config"

#: Each object type's REST endpoint.
ENDPOINTS = {"device": "dcim/devices", "virtual_machine": "virtualization/virtual-machines"}
MAX_OBJECTS = 500
#: A Hegemony inventory provider id for NetBox: ``netbox:<name>`` (plus ``:<org id>``).
_PROVIDER_RE = re.compile(r"^netbox:[a-z0-9][a-z0-9_-]*(:[0-9a-f-]{36})?$")


def _ids(value: Any) -> list[str]:
    """Object IDs written as a list, or as text separated by commas, spaces or lines."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part for part in re.split(r"[\s,]+", str(value)) if part]


class RenderConfigConfig(NetBoxConnection):
    """Config for ``netbox.render_config``."""

    object_type: Literal["device", "virtual_machine"] = Field(
        default="device",
        title="Object Type",
        description=(
            "Render for devices (the step's target devices, or Object IDs) or for virtual "
            "machines (Object IDs only)."
        ),
        json_schema_extra={
            "x_option_labels": {"device": "Devices", "virtual_machine": "Virtual machines"}
        },
    )
    object_ids: Any = Field(
        default=None,
        title="Object IDs",
        description=(
            "NetBox IDs to render for, separated by commas or lines, or a list. Empty "
            "renders for the step's target devices, which must come from a NetBox "
            "inventory provider."
        ),
        json_schema_extra={"x_placeholder": "33, 34", "x_col_span": 2},
    )
    inventory_provider: str = Field(
        default="",
        title="Inventory Provider",
        description=(
            "Hegemony inventory provider of the target devices, such as netbox:main, when "
            "the run's devices come from more than one NetBox. Empty: the target devices "
            "must all come from one NetBox provider, the one this step's URL points at."
        ),
        json_schema_extra={"x_placeholder": "netbox:main", "x_advanced": True},
    )
    context: Any = Field(
        default=None,
        title="Extra Context",
        description=(
            "Extra template context as a JSON object, added to the object's config "
            "context for this rendering only, such as "
            '{"change": "{{ inputs.change_id }}"}. Text is parsed as JSON.'
        ),
        json_schema_extra={"x_rows": 4, "x_col_span": 2, "x_advanced": True},
    )


def config_errors(config: RenderConfigConfig, *, allow_templates: bool) -> list[str]:
    """Semantic errors a schema cannot express (empty when valid)."""
    errors = connection_errors(config, allow_templates=allow_templates)
    if not (allow_templates and is_templated(config.object_ids)):
        ids = _ids(config.object_ids)
        for value in ids:
            error = object_id_error("object_ids", value)
            if error:
                errors.append(error)
                break
        if len(ids) > MAX_OBJECTS:
            errors.append(f"'object_ids' lists more than {MAX_OBJECTS} objects")
    provider = config.inventory_provider.strip()
    if (
        provider
        and not (allow_templates and is_templated(provider))
        and not _PROVIDER_RE.match(provider)
    ):
        errors.append("'inventory_provider' must be a NetBox provider id such as netbox:main")
    if not (allow_templates and is_templated(config.context)):
        try:
            has_context, context = json_value("context", config.context)
        except ValueError as exc:
            errors.append(str(exc))
        else:
            if has_context and not isinstance(context, dict):
                errors.append("'context' must be one JSON object")
    return errors


class RenderConfigHandler(BaseHandler):
    """Have NetBox render the configuration of devices or virtual machines."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.ACTION]
    display_name = "NetBox Render Config"
    description = (
        "Have NetBox render the intended configuration of the target devices from their "
        "config templates, and keep it for later steps."
    )
    category = "NetBox"
    targeting = HandlerTargeting(roles=True, ips=False, multi_role=True)
    raw_config_keys = frozenset({"token", "ca_bundle"})
    config_model = RenderConfigConfig
    default_config = {"object_type": "device"}

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        """Use ``transport`` instead of the network (tests only)."""
        self._transport = transport

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate the step's fields; templated values are checked again once rendered."""
        errors = super().validate_config(config)
        if errors:
            return errors
        return config_errors(RenderConfigConfig.model_validate(config), allow_templates=True)

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Render for every object, keep each configuration as evidence and output."""
        try:
            config = self.parse_config(ctx.config, RenderConfigConfig)
        except InvalidConfigError as exc:
            return exc.result()
        errors = config_errors(config, allow_templates=False)
        if errors:
            return InvalidConfigError(HANDLER_ID, errors).result()
        try:
            objects = _objects(ctx, config)
            _, context = json_value("context", config.context)
        except ValueError as exc:
            return HandlerResult(
                success=False, error=f"Invalid {HANDLER_ID} config: {exc}", summary="Config error"
            )
        client = NetBoxClient(HANDLER_ID, config, ctx.require_services(), transport=self._transport)
        try:
            await client.prepare()
        except ValueError as exc:
            return HandlerResult(
                success=False, error=f"Invalid {HANDLER_ID} config: {exc}", summary="Config error"
            )
        endpoint = ENDPOINTS[config.object_type]
        rendered: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        texts: dict[str, str] = {}
        evidence: list[dict[str, Any]] = []
        # NetBox device names are unique per site and tenant only: a repeated
        # name is told apart by its NetBox ID in configs and the evidence, and
        # a key still taken (a device named like that) by a counter.
        names = Counter(name for _, name, _ in objects)
        keys: set[str] = set()
        for done, (object_id, name, device_id) in enumerate(objects, 1):
            key = base = name if names[name] == 1 else f"{name} ({object_id})"
            number = 2
            while key in keys:
                key, number = f"{base} #{number}", number + 1
            keys.add(key)
            reply = await client.call(
                "POST",
                f"{endpoint}/{object_id}/render-config/",
                body=(True, context or {}),
                expected_status="200",
                # Rendering changes nothing in NetBox, so it may be retried.
                retry=True,
            )
            data = reply.data if isinstance(reply.data, dict) else {}
            content = data.get("content")
            if not reply.ok or not isinstance(content, str):
                failed.append(
                    {
                        "id": int(object_id),
                        "name": name,
                        "error": reply.error or "NetBox returned no rendered content",
                    }
                )
                await _progress(ctx, f"{key}: not rendered ({done} of {len(objects)})", device_id)
                continue
            template = data.get("configtemplate")
            template_name = template.get("name") if isinstance(template, dict) else None
            entry = {
                "id": int(object_id),
                "name": name,
                "template": template_name,
                "size": len(content.encode("utf-8")),
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            }
            rendered.append(entry)
            texts[key] = content
            evidence.append(
                {
                    "kind": "cli_output",
                    "name": f"Rendered configuration ({key})",
                    "device_id": device_id,
                    "content_text": content,
                    "content_json": {**entry, "object_type": config.object_type},
                }
            )
            await _progress(ctx, f"{key}: rendered ({done} of {len(objects)})", device_id)
        client.totals.evidence.extend(evidence)

        configs_fit = json_size(texts) <= MAX_OUTPUT_DATA_BYTES
        output: dict[str, Any] = {
            "ok": not failed,
            "object_type": config.object_type,
            "rendered": rendered,
            "failed": failed,
            "configs": texts if configs_fit else None,
            "configs_truncated": not configs_fit,
        }
        summary = f"rendered {len(rendered)} of {len(objects)} configuration(s)"
        error = None
        if failed:
            first = failed[0]
            error = (
                f"{len(failed)} of {len(objects)} configuration(s) could not be rendered; "
                f"{first['name']}: {first['error']}"
            )
        return client.result(
            success=not failed,
            summary=summary,
            output=output,
            error=error,
            metrics={"ok": not failed, "rendered": len(rendered), "failed": len(failed)},
            record={"object_type": config.object_type, "rendered": rendered, "failed": failed},
        )


async def _progress(ctx: HandlerContext, message: str, device_id: Any) -> None:
    """Tell the run's live view how far the step got."""
    await ctx.emit_progress(message, str(device_id) if device_id is not None else None)


def _objects(ctx: HandlerContext, config: RenderConfigConfig) -> list[tuple[str, str, Any]]:
    """``(NetBox id, name, Hegemony device id)`` of every object to render. Raises ``ValueError``."""
    ids = _ids(config.object_ids)
    if ids:
        return [(value, value, None) for value in dict.fromkeys(ids)]
    if config.object_type != "device":
        raise ValueError("virtual machines are rendered by Object IDs: set Object IDs")
    devices = resolve_target_devices_for_roles(ctx.target_devices_by_role, ctx.target_roles)
    if not devices:
        raise ValueError("no target devices and no Object IDs: nothing to render")
    if len(devices) > MAX_OBJECTS:
        raise ValueError(f"more than {MAX_OBJECTS} target devices; render them in batches")
    wanted = config.inventory_provider.strip()
    providers = {str(device.get("provider_id") or "") for device in devices}
    objects: list[tuple[str, str, Any]] = []
    for device in devices:
        name = str(device.get("name") or device.get("hostname") or device.get("id") or "?")
        provider = str(device.get("provider_id") or "")
        external_id = str(device.get("external_id") or "").strip()
        if wanted and provider != wanted:
            raise ValueError(
                f"device {name} comes from inventory provider {provider or 'none'}, not {wanted}"
            )
        if not provider.startswith("netbox:") or not external_id.isdigit():
            raise ValueError(
                f"device {name} does not come from a NetBox inventory provider, so its NetBox "
                "ID is unknown: use target devices synced from NetBox, or set Object IDs"
            )
        objects.append((external_id, name, device.get("id")))
    if not wanted and len(providers) > 1:
        raise ValueError(
            "the target devices come from more than one inventory provider "
            f"({', '.join(sorted(providers))}); set Inventory Provider to the one this "
            "step's NetBox URL serves"
        )
    return objects


__all__ = ["HANDLER_ID", "RenderConfigConfig", "RenderConfigHandler", "config_errors"]
