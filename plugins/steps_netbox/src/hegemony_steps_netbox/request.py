# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""NetBoxRequestHandler: read, create, update or delete NetBox objects, or call an endpoint.

One step is one action on one REST endpoint: get an object (by ID, or as the
single object some filters match), list objects across pages, create, update
or delete one object or many, or POST to a route such as ``render-config``.
The object, or the list of objects, comes back as output for later steps.
"""

from __future__ import annotations

import re
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
from hegemony_steps_http.jsonpath import PathError, get_path, parse_path
from hegemony_steps_http.request import parse_status_spec
from hegemony_steps_http.security import is_templated

from .client import (
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_RESPONSE_BYTES_LIMIT,
    MAX_RESULTS_LIMIT,
    MAX_RETRIES,
    Method,
    NetBoxClient,
    NetBoxConnection,
    Reply,
    connection_errors,
    endpoint_error,
    fits_output,
    json_value,
    normalize_endpoint,
    object_id_error,
)

HANDLER_ID = "netbox.request"

Action = Literal["get", "list", "create", "update", "delete", "post"]

#: The HTTP method and the statuses that count as success, per action.
ACTION_METHODS: dict[str, tuple[Method, str]] = {
    "get": ("GET", "200"),
    "list": ("GET", "200"),
    "create": ("POST", "201"),
    "update": ("PATCH", "200"),
    "delete": ("DELETE", "204"),
    "post": ("POST", "200-299"),
}
#: Query parameters the step sets itself.
_RESERVED_FILTERS = frozenset({"limit", "offset"})
#: Names of extracted values (``steps.<id>.output.extracted.<name>``).
_EXTRACT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


class NetBoxRequestConfig(NetBoxConnection):
    """Config for ``netbox.request``."""

    action: Action = Field(
        default="get",
        title="Action",
        description=(
            "What to do: get one object, list objects, create, update or delete objects, "
            "or post to an endpoint (a route such as render-config or available-ips). "
            "Defaults to get."
        ),
        json_schema_extra={
            "x_option_labels": {
                "get": "Get one object",
                "list": "List objects",
                "create": "Create",
                "update": "Update",
                "delete": "Delete",
                "post": "Post to an endpoint",
            }
        },
    )
    endpoint: str = Field(
        min_length=1,
        title="Endpoint",
        description=(
            "REST path of the objects, after /api/, such as dcim/devices, "
            "ipam/ip-addresses or plugins/<plugin>/<objects>. May use templates."
        ),
        json_schema_extra={"x_placeholder": "dcim/devices", "x_col_span": 2},
    )
    object_id: str = Field(
        default="",
        title="Object ID",
        description=(
            "NetBox ID of the object: required to update, delete or post to one object; "
            "for get, either this or Filters. Empty with a list in Data updates or deletes "
            "those objects in bulk. May use templates such as "
            "{{ steps.lookup.output.id }}."
        ),
        json_schema_extra={"x_placeholder": "{{ steps.lookup.output.id }}"},
    )
    route: str = Field(
        default="",
        title="Route",
        description=(
            "Path after the object (or after the endpoint), such as render-config, "
            "available-ips or trace. Required to post."
        ),
        json_schema_extra={"x_placeholder": "render-config", "x_advanced": True},
    )
    filters: dict[str, Any] = Field(
        default_factory=dict,
        title="Filters",
        description=(
            "Query filters, NAME=value one per line, such as name=web-01 or tag=managed; "
            "a list repeats the filter (tag: [a, b]). For get without an Object ID they "
            "must match exactly one object. Values may use templates. limit and offset are "
            "set by the step."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "name=web-01\nsite=paris",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    data: Any = Field(
        default=None,
        title="Data",
        description=(
            "The object to create, the fields to change, or what to post, as JSON: an "
            "object, or a list for many objects at once (each with its id to update or "
            "delete). Text is parsed as JSON, so a template that renders JSON works, such "
            'as {"status": "active", "description": {{ inputs.note | tojson }}}.'
        ),
        json_schema_extra={
            "x_placeholder": '{"status": "active"}',
            "x_rows": 6,
            "x_col_span": 2,
        },
    )
    changelog_message: str = Field(
        default="",
        title="Change Log Message",
        description=(
            "Message recorded with the change in NetBox's change log (NetBox 4.4 and "
            "later), such as the run's URL. Sent with create, update and delete."
        ),
        json_schema_extra={"x_placeholder": "Hegemony run {{ run_id }}", "x_col_span": 2},
    )
    missing_ok: bool = Field(
        default=False,
        title="Missing is OK",
        description=(
            "For get and delete: succeed when the object does not exist (output found is "
            "false) instead of failing. Off by default."
        ),
    )
    max_results: int = Field(
        default=1000,
        ge=1,
        le=MAX_RESULTS_LIMIT,
        title="Max Results",
        description=(
            "Most objects list returns, fetched in pages of up to 1000. Defaults to 1000; "
            "at most 100000."
        ),
        json_schema_extra={"x_show_when": {"field": "action", "value": "list"}},
    )
    expected_status: str | None = Field(
        default=None,
        title="Expected Status",
        description=(
            "Status codes and ranges that count as success, such as 200-299. Empty uses "
            "the action's own: 200 for get, list and update, 201 for create, 204 for "
            "delete, 200-299 for post."
        ),
        json_schema_extra={"x_placeholder": "200-299", "x_advanced": True},
    )
    extract: dict[str, str] = Field(
        default_factory=dict,
        title="Extract",
        description=(
            "Values to pick from the result, NAME=path one per line, such as "
            "primary_ip=primary_ip4.address. Paths start at the object (get, create, "
            "update, post) or at the list of objects (list, and many objects at once: "
            "[0].id). A missing value is null. Later steps read "
            "steps.<id>.output.extracted.NAME."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "site=site.slug",
            "x_rows": 2,
            "x_col_span": 2,
            "x_advanced": True,
        },
    )
    max_response_bytes: int = Field(
        default=DEFAULT_MAX_RESPONSE_BYTES,
        ge=1,
        le=MAX_RESPONSE_BYTES_LIMIT,
        title="Max Response Size (bytes)",
        description=(
            "Largest response the step reads, in bytes, summed over pages and retries. "
            "Defaults to 4194304 (4 MiB); at most 16777216 (16 MiB)."
        ),
        json_schema_extra={"x_advanced": True},
    )
    retries: int = Field(
        default=2,
        ge=0,
        le=MAX_RETRIES,
        title="Retries",
        description=(
            "How often a read (get, list) is tried again while NetBox is busy or "
            "unreachable (HTTP 429, 502, 503, 504, a timeout or a dropped connection). "
            "Writes are never repeated: NetBox may already have made the change. "
            "Defaults to 2; at most 5."
        ),
        json_schema_extra={"x_advanced": True},
    )


def _bulk(config: NetBoxRequestConfig, data: Any) -> bool:
    """Whether the step acts on many objects at once (a list in Data, no Object ID)."""
    return not config.object_id.strip() and isinstance(data, list)


def config_errors(config: NetBoxRequestConfig, *, allow_templates: bool) -> list[str]:
    """Semantic errors a schema cannot express (empty when valid)."""
    errors = connection_errors(config, allow_templates=allow_templates)

    def unchecked(value: Any) -> bool:
        return allow_templates and is_templated(value)

    if not unchecked(config.endpoint):
        error = endpoint_error("endpoint", config.endpoint, required=True)
        if error:
            errors.append(error)
    if not unchecked(config.route):
        error = endpoint_error("route", config.route, required=False)
        if error:
            errors.append(error)
    object_id = config.object_id.strip()
    if not unchecked(object_id):
        error = object_id_error("object_id", object_id)
        if error:
            errors.append(error)
    for name in config.filters:
        if not name.strip():
            errors.append("'filters' names must not be empty")
        elif name.strip().lower() in _RESERVED_FILTERS:
            errors.append(f"'filters' must not set {name}: the step pages through results itself")

    data: Any = None
    has_data = False
    if not unchecked(config.data):
        try:
            has_data, data = json_value("data", config.data)
        except ValueError as exc:
            errors.append(str(exc))
    elif config.data is not None:
        has_data = True
    action = config.action
    if action in {"get", "list"} and has_data:
        errors.append(f"{action} sends no data: clear Data")
    if action == "list" and object_id:
        errors.append("list takes no Object ID: use get for one object")
    if action == "create" and not has_data:
        errors.append("create needs Data: the object to create, or a list of them")
    if action == "create" and object_id:
        errors.append("create takes no Object ID: NetBox assigns it")
    if action == "update":
        if not has_data:
            errors.append("update needs Data: the fields to change")
        elif not object_id and data is not None and not isinstance(data, list):
            errors.append("update needs an Object ID, or a list in Data of objects with their id")
    if object_id and isinstance(data, list) and action in {"update", "delete"}:
        errors.append(
            f"a list in Data {action}s many objects at once: clear Object ID (each object "
            "carries its id)"
        )
    if action == "delete" and not object_id and not has_data:
        errors.append("delete needs an Object ID, or a list in Data of the objects to delete")
    if action == "post" and not config.route.strip():
        errors.append("post needs a Route, such as render-config or available-ips")
    if config.missing_ok and action not in {"get", "delete"}:
        errors.append("'missing_ok' applies to get and delete only")
    if action in {"get", "delete"} and config.missing_ok and _bulk(config, data):
        errors.append("'missing_ok' applies to one object, not a list in Data")
    if config.changelog_message and action in {"get", "list", "post"}:
        errors.append(f"{action} records no change: clear Change Log Message")
    expected = (config.expected_status or "").strip()
    if expected and not unchecked(expected):
        try:
            parse_status_spec(expected)
        except ValueError as exc:
            errors.append(f"'expected_status': {exc}")
    for name, value in config.filters.items():
        if filter_values(value) is None:
            errors.append(
                f"'filters.{name}' must be text, a number, true or false, or a list of them"
            )
    for name, path in config.extract.items():
        if not _EXTRACT_NAME_RE.match(name):
            errors.append(
                f"'extract' name {name!r} must start with a letter or underscore and use only "
                "letters, digits and underscores (max 64)"
            )
        try:
            parse_path(path)
        except PathError as exc:
            errors.append(f"'extract.{name}': {exc}")
    return errors


def filter_values(value: Any) -> str | list[str] | None:
    """A filter's value as query text (a list repeats the filter); None when invalid."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    if isinstance(value, list) and value:
        items = [filter_values(item) for item in value]
        if all(isinstance(item, str) for item in items):
            return [item for item in items if isinstance(item, str)]
    return None


def _with_message(data: Any, message: str) -> Any:
    """``data`` with the change-log message added to the object, or to each object."""
    if not message:
        return data
    if isinstance(data, dict):
        return {**data, "changelog_message": message}
    if isinstance(data, list):
        return [
            {**item, "changelog_message": message} if isinstance(item, dict) else item
            for item in data
        ]
    return data


def _delete_items(data: list[Any]) -> list[Any]:
    """A bulk delete's list as NetBox expects it: ``[{"id": n}, …]``."""
    items: list[Any] = []
    for item in data:
        if isinstance(item, dict):
            items.append(item)
        elif isinstance(item, (int, str)) and str(item).strip().isdigit():
            items.append({"id": int(str(item).strip())})
        else:
            raise ValueError("a bulk delete lists object IDs, or objects with their id")
    return items


def _is_page(value: Any) -> bool:
    """A NetBox list page: ``count`` and a ``results`` list."""
    return isinstance(value, dict) and "count" in value and isinstance(value.get("results"), list)


def _ids(objects: list[Any]) -> list[Any]:
    return [item.get("id") for item in objects if isinstance(item, dict)]


class NetBoxRequestHandler(BaseHandler):
    """Read, create, update or delete NetBox objects, or post to a NetBox endpoint."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.ACTION]
    display_name = "NetBox Request"
    description = (
        "Get, list, create, update or delete NetBox objects, or post to a NetBox endpoint, "
        "and return the objects for later steps."
    )
    category = "NetBox"
    targeting = HandlerTargeting(roles=False, ips=False)
    raw_config_keys = frozenset({"token", "ca_bundle"})
    config_model = NetBoxRequestConfig
    default_config = {"action": "get"}

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        """Use ``transport`` instead of the network (tests only)."""
        self._transport = transport

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate the step's fields; templated values are checked again once rendered."""
        errors = super().validate_config(config)
        if errors:
            return errors
        return config_errors(NetBoxRequestConfig.model_validate(config), allow_templates=True)

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Check the rendered config, then carry out the action."""
        try:
            config = self.parse_config(ctx.config, NetBoxRequestConfig)
        except InvalidConfigError as exc:
            return exc.result()
        errors = config_errors(config, allow_templates=False)
        if errors:
            return InvalidConfigError(HANDLER_ID, errors).result()
        client = NetBoxClient(
            HANDLER_ID,
            config,
            ctx.require_services(),
            max_response_bytes=config.max_response_bytes,
            retries=config.retries,
            transport=self._transport,
        )
        try:
            await client.prepare()
            _, data = json_value("data", config.data)
            if config.action == "delete" and _bulk(config, data):
                data = _delete_items(data)
        except ValueError as exc:
            return HandlerResult(
                success=False, error=f"Invalid {HANDLER_ID} config: {exc}", summary="Config error"
            )
        return await self._run(client, config, data)

    async def _run(
        self, client: NetBoxClient, config: NetBoxRequestConfig, data: Any
    ) -> HandlerResult:
        """Send the action's requests and build the result."""
        action = config.action
        method, default_status = ACTION_METHODS[action]
        expected = (config.expected_status or "").strip() or default_status
        endpoint = normalize_endpoint(config.endpoint)
        object_id = config.object_id.strip()
        route = normalize_endpoint(config.route)
        path = endpoint + "/"
        if object_id:
            path += object_id + "/"
        if route:
            path += route + "/"
        filters = {name.strip(): filter_values(value) for name, value in config.filters.items()}

        found: bool | None = None
        count: int | None = None
        more = False
        if action == "list":
            reply = await client.list_all(path, filters, max_results=config.max_results)
            result_value: Any = reply.data
            count = reply.count
            more = reply.more
        elif action == "get" and not object_id and filters:
            reply, result_value, found = await self._get_one(client, path, filters, config)
        else:
            body: tuple[bool, Any] = (False, None)
            if action in {"create", "update", "post"}:
                body = (True, _with_message(data, config.changelog_message))
            elif action == "delete":
                if data is not None:
                    body = (True, _with_message(data, config.changelog_message))
                elif config.changelog_message:
                    body = (True, {"changelog_message": config.changelog_message})
            missing = expected + ",404" if config.missing_ok else expected
            reply = await client.call(
                method, path, query=filters or None, body=body, expected_status=missing
            )
            result_value = reply.data
            if config.missing_ok:
                found = reply.status != 404
                if not found:
                    reply = Reply(status=reply.status)
                    result_value = None
            if action == "get" and not object_id and not route and _is_page(result_value):
                # An endpoint such as status/ answers get with one object; a collection
                # answers with a page of them, which is not the object get promises.
                reply = Reply(
                    status=reply.status,
                    error=(
                        f"get reads one object, and {endpoint} answered with a list of them: "
                        "give an Object ID or Filters that match one object, or use list"
                    ),
                )
                result_value = None

        output: dict[str, Any] = {
            "status": reply.status,
            "ok": reply.ok,
            "action": action,
            "endpoint": endpoint,
            "method": method,
        }
        if found is not None:
            output["found"] = found
        objects: list[Any] | None = None
        obj: Any = None
        if reply.ok:
            if isinstance(result_value, list):
                objects = result_value
            elif isinstance(result_value, dict):
                obj = result_value
        output["id"] = obj.get("id") if isinstance(obj, dict) else None
        data_truncated = False
        if objects is not None:
            output["count"] = count if count is not None else len(objects)
            output["returned"] = len(objects)
            output["more"] = more
            ids = _ids(objects)
            output["ids"] = ids if fits_output(ids) else None
            data_truncated = not fits_output(objects)
            output["objects"] = None if data_truncated else objects
            output["object"] = None
        else:
            data_truncated = obj is not None and not fits_output(obj)
            output["object"] = None if data_truncated else obj
            if action == "post" and reply.ok and obj is None and result_value is not None:
                # A route that answers with a scalar or text keeps it as data.
                output["data"] = result_value if fits_output(result_value) else None
        output["data_truncated"] = data_truncated
        start = objects if objects is not None else obj
        output["extracted"] = {
            name: get_path(start, parse_path(path_text))
            for name, path_text in config.extract.items()
        }

        target = endpoint + (f"/{object_id}" if object_id else "") + (f"/{route}" if route else "")
        if not reply.ok:
            summary = f"{action} {target} failed"
        elif objects is not None:
            noun = "object" if len(objects) == 1 else "objects"
            summary = f"{action} {target}: {len(objects)} {noun}"
            if more:
                summary += f" of {count}"
        elif found is False:
            summary = f"{action} {target}: not found"
        elif output["id"] is not None:
            summary = f"{action} {target}: object {output['id']}"
        else:
            summary = f"{action} {target}: done"
        record = {
            "action": action,
            "endpoint": endpoint,
            "object_id": object_id or None,
            "route": route or None,
            "filters": sorted(filters),
            "status": reply.status,
            "ok": reply.ok,
        }
        metrics: dict[str, Any] = {"ok": reply.ok}
        if reply.status is not None:
            metrics["status"] = reply.status
        if objects is not None:
            metrics["objects"] = len(objects)
        return client.result(
            success=reply.ok,
            summary=summary,
            output=output,
            error=reply.error,
            metrics=metrics,
            record=record,
        )

    @staticmethod
    async def _get_one(
        client: NetBoxClient, path: str, filters: dict[str, Any], config: NetBoxRequestConfig
    ) -> tuple[Reply, Any, bool | None]:
        """The single object ``filters`` match: ``(reply, object, found)``."""
        reply = await client.call("GET", path, query={**filters, "limit": 2}, expected_status="200")
        if not reply.ok:
            return reply, None, None
        data = reply.data
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            return (
                Reply(status=reply.status, error=f"NetBox did not answer {path} with a list"),
                None,
                None,
            )
        count = data.get("count") if isinstance(data.get("count"), int) else len(data["results"])
        if count == 0:
            if config.missing_ok:
                return Reply(status=reply.status), None, False
            return (
                Reply(status=reply.status, error="no NetBox object matches the filters"),
                None,
                False,
            )
        if count > 1:
            return (
                Reply(
                    status=reply.status,
                    error=f"{count} NetBox objects match the filters; narrow them to one",
                ),
                None,
                True,
            )
        return reply, data["results"][0], True


__all__ = [
    "HANDLER_ID",
    "NetBoxRequestConfig",
    "NetBoxRequestHandler",
    "config_errors",
    "filter_values",
]
