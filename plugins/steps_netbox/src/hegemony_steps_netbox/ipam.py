# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Take the next free IP address, prefix, VLAN or ASN from NetBox, and give it back.

``netbox.ipam.allocate`` posts to the pool's ``available-*`` route, which
NetBox serves under a lock, so two runs never get the same address. Before
allocating, it can look for what an earlier attempt of the same work already
took (Existing Filters), so a re-run returns that instead of taking more.
``netbox.ipam.release`` deletes what was allocated, by ID or by filters,
refusing to delete more objects than it is allowed to, and succeeds when
they are already gone.
"""

from __future__ import annotations

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
)
from hegemony_steps_http.security import is_templated

from .client import (
    NetBoxClient,
    NetBoxConnection,
    Reply,
    connection_errors,
    fits_output,
    json_value,
    object_id_error,
)
from .request import filter_values

ALLOCATE_ID = "netbox.ipam.allocate"
RELEASE_ID = "netbox.ipam.release"

Allocate = Literal[
    "ip_from_prefix", "ip_from_range", "prefix_from_prefix", "vlan_from_group", "asn_from_range"
]
Resource = Literal["ip_address", "prefix", "vlan", "asn"]

#: What each kind of allocation takes from: (pool endpoint, route, resource).
POOLS: dict[str, tuple[str, str, str]] = {
    "ip_from_prefix": ("ipam/prefixes", "available-ips", "ip_address"),
    "ip_from_range": ("ipam/ip-ranges", "available-ips", "ip_address"),
    "prefix_from_prefix": ("ipam/prefixes", "available-prefixes", "prefix"),
    "vlan_from_group": ("ipam/vlan-groups", "available-vlans", "vlan"),
    "asn_from_range": ("ipam/asn-ranges", "available-asns", "asn"),
}
#: Each resource's endpoint and the field that holds its value.
RESOURCES: dict[str, tuple[str, str]] = {
    "ip_address": ("ipam/ip-addresses", "address"),
    "prefix": ("ipam/prefixes", "prefix"),
    "vlan": ("ipam/vlans", "vid"),
    "asn": ("ipam/asns", "asn"),
}
MAX_COUNT = 256


def _filters_errors(field_name: str, filters: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for name, value in filters.items():
        if not name.strip():
            errors.append(f"'{field_name}' names must not be empty")
        elif name.strip().lower() in {"limit", "offset"}:
            errors.append(f"'{field_name}' must not set {name}: the step sets it")
        elif filter_values(value) is None:
            errors.append(
                f"'{field_name}.{name}' must be text, a number, true or false, or a list of them"
            )
    return errors


def _query(filters: dict[str, Any]) -> dict[str, Any]:
    return {name.strip(): filter_values(value) for name, value in filters.items()}


def _values(objects: list[Any], key: str) -> list[Any]:
    return [item.get(key) for item in objects if isinstance(item, dict)]


async def _find(
    client: NetBoxClient, endpoint: str, filters: dict[str, Any], *, at_most: int
) -> tuple[Reply, list[Any], int]:
    """The objects of ``endpoint`` that ``filters`` match, up to ``at_most`` plus one.

    Also returns how many match in all. NetBox caps a page at its MAX_PAGE_SIZE, which
    an administrator may set below ``at_most`` plus one, so the page can hold fewer
    objects than match; its ``count`` still says how many do, and every limit is
    checked against that.
    """
    reply = await client.call(
        "GET", endpoint + "/", query={**filters, "limit": at_most + 1}, expected_status="200"
    )
    if not reply.ok:
        return reply, [], 0
    data = reply.data
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        failure = Reply(status=reply.status, error=f"NetBox did not answer {endpoint} with a list")
        return failure, [], 0
    results = data["results"]
    count = data.get("count")
    total = count if isinstance(count, int) and not isinstance(count, bool) else 0
    return reply, results, max(total, len(results))


class AllocateConfig(NetBoxConnection):
    """Config for ``netbox.ipam.allocate``."""

    allocate: Allocate = Field(
        default="ip_from_prefix",
        title="Allocate",
        description=(
            "What to take, and from where: an IP address from a prefix or an IP range, a "
            "child prefix from a prefix, a VLAN from a VLAN group, or an ASN from an ASN "
            "range."
        ),
        json_schema_extra={
            "x_option_labels": {
                "ip_from_prefix": "IP address from a prefix",
                "ip_from_range": "IP address from an IP range",
                "prefix_from_prefix": "Prefix from a prefix",
                "vlan_from_group": "VLAN from a VLAN group",
                "asn_from_range": "ASN from an ASN range",
            }
        },
    )
    pool_id: str = Field(
        default="",
        title="Pool ID",
        description=(
            "NetBox ID of the prefix, IP range, VLAN group or ASN range to take from. "
            "Either this or Pool Filters. May use templates."
        ),
    )
    pool_filters: dict[str, Any] = Field(
        default_factory=dict,
        title="Pool Filters",
        description=(
            "Filters that find the pool when Pool ID is empty, NAME=value one per line, "
            "such as prefix=10.20.0.0/24 and vrf_id=3, or name=servers for a VLAN group. "
            "They must match exactly one."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "prefix=10.20.0.0/24",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    prefix_length: int | None = Field(
        default=None,
        ge=1,
        le=128,
        title="Prefix Length",
        description="Length of the child prefix to take, such as 28. Required for a prefix.",
        json_schema_extra={"x_show_when": {"field": "allocate", "value": "prefix_from_prefix"}},
    )
    count: int = Field(
        default=1,
        ge=1,
        le=MAX_COUNT,
        title="Count",
        description="How many to take in one go. Defaults to 1; at most 256.",
        json_schema_extra={"x_advanced": True},
    )
    data: Any = Field(
        default=None,
        title="Data",
        description=(
            "Fields of the new object, as JSON, such as "
            '{"status": "active", "dns_name": "web-01.example.com", "description": "web-01"}. '
            "A VLAN needs a name. Text is parsed as JSON."
        ),
        json_schema_extra={
            "x_placeholder": '{"status": "active", "description": "web-01"}',
            "x_rows": 4,
            "x_col_span": 2,
        },
    )
    existing_filters: dict[str, Any] = Field(
        default_factory=dict,
        title="Existing Filters",
        description=(
            "Filters that find what an earlier attempt of the same work already took, "
            "such as dns_name=web-01.example.com. When they match Count objects the step "
            "returns those and takes nothing new, so a re-run does not allocate twice; "
            "when they match none it allocates. Searched within the pool for prefixes and "
            "VLAN groups, and across NetBox otherwise, so make them specific. Empty always "
            "allocates."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "dns_name=web-01.example.com",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    changelog_message: str = Field(
        default="",
        title="Change Log Message",
        description="Message recorded with the change in NetBox's change log (NetBox 4.4+).",
        json_schema_extra={"x_placeholder": "Hegemony run {{ run_id }}", "x_col_span": 2},
    )


def allocate_errors(config: AllocateConfig, *, allow_templates: bool) -> list[str]:
    """Semantic errors a schema cannot express (empty when valid)."""
    errors = connection_errors(config, allow_templates=allow_templates)
    pool_id = config.pool_id.strip()
    if pool_id and not (allow_templates and is_templated(pool_id)):
        error = object_id_error("pool_id", pool_id)
        if error:
            errors.append(error)
    if bool(pool_id) == bool(config.pool_filters):
        errors.append("give either Pool ID or Pool Filters to find the pool")
    errors.extend(_filters_errors("pool_filters", config.pool_filters))
    errors.extend(_filters_errors("existing_filters", config.existing_filters))
    if config.allocate == "prefix_from_prefix" and config.prefix_length is None:
        errors.append("a prefix needs Prefix Length")
    if config.allocate != "prefix_from_prefix" and config.prefix_length is not None:
        errors.append("Prefix Length applies to a prefix only: clear it")
    if not (allow_templates and is_templated(config.data)):
        try:
            has_data, data = json_value("data", config.data)
        except ValueError as exc:
            errors.append(str(exc))
        else:
            if has_data and not isinstance(data, dict):
                errors.append("'data' must be one JSON object: the fields of the new object")
    return errors


class AllocateHandler(BaseHandler):
    """Take the next free IP address, prefix, VLAN or ASN from a NetBox pool."""

    handler_id = ALLOCATE_ID
    supported_kinds = [StepKind.ACTION]
    display_name = "NetBox Allocate"
    description = (
        "Take the next free IP address, prefix, VLAN or ASN from a NetBox pool, or return "
        "what an earlier attempt already took."
    )
    category = "NetBox"
    targeting = HandlerTargeting(roles=False, ips=False)
    raw_config_keys = frozenset({"token", "ca_bundle"})
    config_model = AllocateConfig
    default_config = {"allocate": "ip_from_prefix", "count": 1}

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        """Use ``transport`` instead of the network (tests only)."""
        self._transport = transport

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate the step's fields; templated values are checked again once rendered."""
        errors = super().validate_config(config)
        if errors:
            return errors
        return allocate_errors(AllocateConfig.model_validate(config), allow_templates=True)

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Find the pool, reuse an earlier allocation or take new ones."""
        try:
            config = self.parse_config(ctx.config, AllocateConfig)
        except InvalidConfigError as exc:
            return exc.result()
        errors = allocate_errors(config, allow_templates=False)
        if errors:
            return InvalidConfigError(ALLOCATE_ID, errors).result()
        client = NetBoxClient(
            ALLOCATE_ID, config, ctx.require_services(), transport=self._transport
        )
        try:
            await client.prepare()
            _, fields = json_value("data", config.data)
        except ValueError as exc:
            return HandlerResult(
                success=False, error=f"Invalid {ALLOCATE_ID} config: {exc}", summary="Config error"
            )
        pool_endpoint, route, resource = POOLS[config.allocate]
        resource_endpoint, value_key = RESOURCES[resource]

        pool, failure = await self._pool(client, config, pool_endpoint)
        if failure is not None:
            return self._failed(client, config, failure)
        pool_id = pool["id"]

        allocated = False
        objects: list[Any] = []
        if config.existing_filters:
            scope = _pool_scope(config.allocate, pool)
            reply, objects, matched = await _find(
                client,
                resource_endpoint,
                {**_query(config.existing_filters), **scope},
                at_most=config.count,
            )
            if not reply.ok:
                return self._failed(client, config, reply)
            if matched and matched != config.count:
                return self._failed(
                    client,
                    config,
                    Reply(
                        status=reply.status,
                        error=(
                            f"Existing Filters match {matched} objects, expected "
                            f"none or {config.count}: make them match only what this work "
                            "allocated"
                        ),
                    ),
                )
        if not objects:
            item: dict[str, Any] = dict(fields or {})
            if config.prefix_length is not None:
                item["prefix_length"] = config.prefix_length
            if config.changelog_message:
                item["changelog_message"] = config.changelog_message
            body: Any = item if config.count == 1 else [dict(item) for _ in range(config.count)]
            reply = await client.call(
                "POST",
                f"{pool_endpoint}/{pool_id}/{route}/",
                body=(True, body),
                expected_status="201",
            )
            if not reply.ok:
                if reply.status == 409 or (reply.error and "insufficient" in reply.error.lower()):
                    reply = Reply(
                        status=reply.status,
                        error=f"the pool has not enough free space: {reply.error}",
                    )
                return self._failed(client, config, reply)
            created = reply.data
            objects = created if isinstance(created, list) else [created]
            allocated = True

        values = _values(objects, value_key)
        ids = _values(objects, "id")
        first = objects[0] if objects and isinstance(objects[0], dict) else None
        output: dict[str, Any] = {
            "ok": True,
            "allocated": allocated,
            "resource": resource,
            "pool_id": pool_id,
            "id": ids[0] if ids else None,
            "ids": ids,
            "value": values[0] if values else None,
            "values": values,
            "object": first if first is not None and fits_output(first) else None,
            "objects": objects if fits_output(objects) else None,
        }
        verb = "allocated" if allocated else "reused"
        shown = ", ".join(str(value) for value in values[:5]) + (" …" if len(values) > 5 else "")
        summary = f"{verb} {resource.replace('_', ' ')} {shown} from {pool_endpoint} {pool_id}"
        return client.result(
            success=True,
            summary=summary,
            output=output,
            metrics={"ok": True, "allocated": len(objects) if allocated else 0},
            record={
                "allocate": config.allocate,
                "pool_id": pool_id,
                "allocated": allocated,
                "ids": ids,
                "values": values,
            },
        )

    @staticmethod
    async def _pool(
        client: NetBoxClient, config: AllocateConfig, endpoint: str
    ) -> tuple[dict[str, Any], Reply | None]:
        """The pool object: by its ID, or the one Pool Filters match."""
        pool_id = config.pool_id.strip()
        if pool_id:
            reply = await client.call("GET", f"{endpoint}/{pool_id}/", expected_status="200")
            if not reply.ok:
                return {}, reply
            if not isinstance(reply.data, dict) or "id" not in reply.data:
                return {}, Reply(
                    status=reply.status, error=f"NetBox returned no pool from {endpoint}"
                )
            return reply.data, None
        reply, pools, matched = await _find(
            client, endpoint, _query(config.pool_filters), at_most=1
        )
        if not reply.ok:
            return {}, reply
        if matched != 1 or len(pools) != 1:
            found = "no" if not matched else "more than one"
            return {}, Reply(
                status=reply.status,
                error=f"Pool Filters match {found} {endpoint} object; narrow them to one",
            )
        return pools[0], None

    @staticmethod
    def _failed(client: NetBoxClient, config: AllocateConfig, reply: Reply) -> HandlerResult:
        return client.result(
            success=False,
            summary=f"allocate {config.allocate.replace('_', ' ')} failed",
            output={"ok": False, "allocated": False, "status": reply.status},
            error=reply.error,
            metrics={"ok": False},
            record={"allocate": config.allocate, "status": reply.status},
        )


def _pool_scope(allocate: str, pool: dict[str, Any]) -> dict[str, Any]:
    """Filters that keep the search for an earlier allocation inside the pool."""
    vrf = pool.get("vrf")
    vrf_id = vrf.get("id") if isinstance(vrf, dict) else None
    vrf_filter = str(vrf_id) if vrf_id is not None else "null"
    if allocate == "ip_from_prefix" and pool.get("prefix"):
        return {"parent": str(pool["prefix"]), "vrf_id": vrf_filter}
    if allocate == "prefix_from_prefix" and pool.get("prefix"):
        return {"within": str(pool["prefix"]), "vrf_id": vrf_filter}
    if allocate == "vlan_from_group":
        return {"group_id": str(pool["id"])}
    return {}


class ReleaseConfig(NetBoxConnection):
    """Config for ``netbox.ipam.release``."""

    resource: Resource = Field(
        default="ip_address",
        title="Resource",
        description="What to give back: an IP address, a prefix, a VLAN or an ASN.",
        json_schema_extra={
            "x_option_labels": {
                "ip_address": "IP address",
                "prefix": "Prefix",
                "vlan": "VLAN",
                "asn": "ASN",
            }
        },
    )
    object_id: str = Field(
        default="",
        title="Object ID",
        description=(
            "NetBox ID of the object to release, such as "
            "{{ steps.allocate.output.id }}. Either this or Filters."
        ),
        json_schema_extra={"x_placeholder": "{{ steps.allocate.output.id }}"},
    )
    filters: dict[str, Any] = Field(
        default_factory=dict,
        title="Filters",
        description=(
            "Filters that find the objects to release when Object ID is empty, NAME=value "
            "one per line, such as address=10.20.0.5/24 or dns_name=web-01.example.com."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "dns_name=web-01.example.com",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    max_objects: int = Field(
        default=1,
        ge=1,
        le=MAX_COUNT,
        title="Max Objects",
        description=(
            "Most objects Filters may match. More fails the step and releases nothing, so "
            "a filter that is too broad cannot delete a whole pool. Defaults to 1."
        ),
    )
    missing_ok: bool = Field(
        default=True,
        title="Missing is OK",
        description=(
            "Succeed when nothing matches or the object is already gone, so a re-run of a "
            "clean-up passes. On by default."
        ),
    )
    changelog_message: str = Field(
        default="",
        title="Change Log Message",
        description="Message recorded with the change in NetBox's change log (NetBox 4.4+).",
        json_schema_extra={"x_placeholder": "Hegemony run {{ run_id }}", "x_col_span": 2},
    )


def release_errors(config: ReleaseConfig, *, allow_templates: bool) -> list[str]:
    """Semantic errors a schema cannot express (empty when valid)."""
    errors = connection_errors(config, allow_templates=allow_templates)
    object_id = config.object_id.strip()
    if object_id and not (allow_templates and is_templated(object_id)):
        error = object_id_error("object_id", object_id)
        if error:
            errors.append(error)
    if bool(object_id) == bool(config.filters):
        errors.append("give either Object ID or Filters to find what to release")
    errors.extend(_filters_errors("filters", config.filters))
    return errors


class ReleaseHandler(BaseHandler):
    """Give back IP addresses, prefixes, VLANs or ASNs by deleting them from NetBox."""

    handler_id = RELEASE_ID
    supported_kinds = [StepKind.ACTION]
    display_name = "NetBox Release"
    description = (
        "Give back an IP address, prefix, VLAN or ASN by deleting it from NetBox; succeeds "
        "when it is already gone."
    )
    category = "NetBox"
    targeting = HandlerTargeting(roles=False, ips=False)
    raw_config_keys = frozenset({"token", "ca_bundle"})
    config_model = ReleaseConfig
    default_config = {"resource": "ip_address", "max_objects": 1, "missing_ok": True}

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        """Use ``transport`` instead of the network (tests only)."""
        self._transport = transport

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate the step's fields; templated values are checked again once rendered."""
        errors = super().validate_config(config)
        if errors:
            return errors
        return release_errors(ReleaseConfig.model_validate(config), allow_templates=True)

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Find what to release, then delete it."""
        try:
            config = self.parse_config(ctx.config, ReleaseConfig)
        except InvalidConfigError as exc:
            return exc.result()
        errors = release_errors(config, allow_templates=False)
        if errors:
            return InvalidConfigError(RELEASE_ID, errors).result()
        client = NetBoxClient(RELEASE_ID, config, ctx.require_services(), transport=self._transport)
        try:
            await client.prepare()
        except ValueError as exc:
            return HandlerResult(
                success=False, error=f"Invalid {RELEASE_ID} config: {exc}", summary="Config error"
            )
        endpoint, value_key = RESOURCES[config.resource]
        object_id = config.object_id.strip()
        message = config.changelog_message

        if object_id:
            body: tuple[bool, Any] = (
                (True, {"changelog_message": message}) if message else (False, None)
            )
            reply = await client.call(
                "DELETE",
                f"{endpoint}/{object_id}/",
                body=body,
                expected_status="204,404" if config.missing_ok else "204",
            )
            gone = reply.ok and reply.status == 404
            ids = [] if gone or not reply.ok else [int(object_id)]
            values: list[Any] = []
        else:
            reply, objects, matched = await _find(
                client, endpoint, _query(config.filters), at_most=config.max_objects
            )
            if reply.ok and matched > config.max_objects:
                reply = Reply(
                    status=reply.status,
                    error=(
                        f"Filters match {matched} "
                        f"{config.resource.replace('_', ' ')} objects, more than Max Objects "
                        f"({config.max_objects}); nothing was released "
                        "(narrow the filters or raise Max Objects)"
                    ),
                )
            elif reply.ok and not objects and not config.missing_ok:
                reply = Reply(status=reply.status, error="no NetBox object matches the filters")
            ids = _values(objects, "id") if reply.ok else []
            values = _values(objects, value_key) if reply.ok else []
            if reply.ok and ids:
                items = [
                    {"id": object_id_value, **({"changelog_message": message} if message else {})}
                    for object_id_value in ids
                ]
                reply = await client.call(
                    "DELETE", f"{endpoint}/", body=(True, items), expected_status="204"
                )
                if not reply.ok:
                    ids, values = [], []
        output = {
            "ok": reply.ok,
            "status": reply.status,
            "resource": config.resource,
            "released": len(ids),
            "ids": ids,
            "values": values,
        }
        if not reply.ok:
            summary = f"release {config.resource.replace('_', ' ')} failed"
        elif ids:
            summary = f"released {len(ids)} {config.resource.replace('_', ' ')} object(s)"
        else:
            summary = f"nothing to release ({config.resource.replace('_', ' ')} already gone)"
        return client.result(
            success=reply.ok,
            summary=summary,
            output=output,
            error=reply.error,
            metrics={"ok": reply.ok, "released": len(ids)},
            record={"resource": config.resource, "released": ids, "status": reply.status},
        )


__all__ = [
    "ALLOCATE_ID",
    "RELEASE_ID",
    "AllocateConfig",
    "AllocateHandler",
    "ReleaseConfig",
    "ReleaseHandler",
]
