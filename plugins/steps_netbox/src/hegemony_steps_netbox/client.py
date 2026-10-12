# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What every NetBox step shares: the connection settings and one REST call.

A call is sent by ``http.request``'s own client (:meth:`HttpRequestHandler.send`),
so every safeguard of that step applies to NetBox too: the flow's egress
policy on every request, the refused destinations (loopback, link-local,
metadata), no credentials over plain HTTP unless allowed, response size caps,
and credentials scrubbed from everything the step reports. This module adds
what is NetBox's own: the API path, the token's header (``Token`` for a v1
token, ``Bearer`` for a v2 ``nbt_`` token), offset pagination, retries of
reads while NetBox is busy, and error messages taken from NetBox's answer.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import HandlerResult, HandlerServices
from hegemony_steps_http.request import (
    HttpRequestConfig,
    HttpRequestHandler,
    parse_status_spec,
    status_matches,
)
from hegemony_steps_http.security import (
    MIN_SCRUB_LENGTH,
    Scrubber,
    is_bare_secret_ref,
    is_templated,
    resolve_secret_text,
)

MIB = 1024 * 1024
#: The HTTP methods the NetBox steps send.
Method = Literal["GET", "POST", "PATCH", "DELETE"]
#: Most objects NetBox returns per page (its default MAX_PAGE_SIZE).
PAGE_SIZE = 1000
MAX_RESULTS_LIMIT = 100_000
DEFAULT_MAX_RESPONSE_BYTES = 4 * MIB
MAX_RESPONSE_BYTES_LIMIT = 16 * MIB
MAX_TIMEOUT_SECONDS = 600
MAX_RETRIES = 5
#: Longest wait before a retry, whatever Retry-After asks for.
MAX_RETRY_WAIT_SECONDS = 30
#: Largest object or list a step puts in its output, in bytes of compact JSON.
#: Outputs are chained into later steps' templates, so they stay small.
MAX_OUTPUT_DATA_BYTES = 64 * 1024
#: Characters of a NetBox error message kept in the step's error.
MAX_ERROR_CHARS = 600

#: A v2 token (NetBox 4.5+) starts with this and is sent as a bearer token.
V2_TOKEN_PREFIX = "nbt_"
#: Statuses a read is retried on: NetBox (or its proxy) is busy or restarting.
RETRY_STATUSES = frozenset({429, 502, 503, 504})
#: Transport failures a read is retried on (the request may not have arrived).
_TRANSIENT_ERROR_RE = re.compile(
    r"timed out|ConnectError|ConnectTimeout|ReadError|ReadTimeout|WriteError|"
    r"RemoteProtocolError|PoolTimeout"
)
#: One path segment of a REST endpoint or route (``dcim``, ``ip-addresses``).
_SEGMENT = r"[a-z0-9][a-z0-9_-]*"
ENDPOINT_RE = re.compile(rf"^{_SEGMENT}(/{_SEGMENT})*$")
OBJECT_ID_RE = re.compile(r"^[1-9][0-9]{0,18}$")
#: A NetBox Branching branch's schema id.
BRANCH_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_PEM_CERTIFICATE = "-----BEGIN CERTIFICATE-----"


class NetBoxConnection(BaseModel):
    """The connection settings every NetBox step has."""

    # A number written for a text setting (an object id) is its text.
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    url: str = Field(
        min_length=1,
        title="NetBox URL",
        description=(
            "Address of NetBox, without /api, such as https://netbox.example.com. May use "
            "templates such as {{ vars.NETBOX.url }}."
        ),
        json_schema_extra={"x_placeholder": "https://netbox.example.com", "x_col_span": 2},
    )
    token: str = Field(
        min_length=1,
        title="API Token",
        description=(
            "NetBox API token: a secret reference such as "
            "vault://orgs/acme/secrets/netbox/token, a {{ secret('...') }} template, or "
            "literal text. A value resolved from a reference is redacted from the run's "
            "logs; literal text is not, so prefer a reference. Give the token only the "
            "permissions the flow needs."
        ),
        json_schema_extra={
            "x_placeholder": "vault://orgs/acme/secrets/netbox/token",
            "x_col_span": 2,
        },
    )
    token_type: Literal["auto", "v1", "v2"] = Field(
        default="auto",
        title="Token Type",
        description=(
            "How the token is sent. Auto, the default, sends a token starting with nbt_ "
            "as a v2 token (Authorization: Bearer, NetBox 4.5 and later) and any other as "
            "a v1 token (Authorization: Token)."
        ),
        json_schema_extra={
            "x_option_labels": {"auto": "Auto", "v1": "v1 (Token)", "v2": "v2 (Bearer)"},
            "x_advanced": True,
        },
    )
    allow_insecure_auth: bool = Field(
        default=False,
        title="Allow token over HTTP",
        description=(
            "Send the token to a plain http:// NetBox URL. Off by default, because over "
            "HTTP the token travels unencrypted and anyone on the network path can read "
            "it; turn on only for an internal NetBox that offers no HTTPS."
        ),
        json_schema_extra={"x_advanced": True},
    )
    verify_tls: bool = Field(
        default=True,
        title="Verify TLS certificate",
        description=(
            "Validate NetBox's certificate on HTTPS. Turn off only for a test NetBox with "
            "a self-signed certificate, and prefer CA Bundle. On by default."
        ),
        json_schema_extra={"x_advanced": True},
    )
    ca_bundle: str = Field(
        default="",
        title="CA Bundle",
        description=(
            "PEM certificates to trust for NetBox instead of the public certificate "
            "authorities, such as an internal CA: the PEM text, a secret reference, or a "
            "{{ secret('...') }} template. Ignored when Verify TLS certificate is off."
        ),
        json_schema_extra={
            "x_placeholder": "-----BEGIN CERTIFICATE-----",
            "x_show_when": {"field": "verify_tls", "value": True},
            "x_rows": 4,
            "x_col_span": 2,
            "x_advanced": True,
        },
    )
    branch: str = Field(
        default="",
        title="Branch",
        description=(
            "Schema ID of a NetBox Branching branch to work in (sent as the "
            "X-NetBox-Branch header), so changes stay in the branch until it is merged. "
            "Empty works on main. Needs the netbox-branching plugin."
        ),
        json_schema_extra={"x_placeholder": "td5smq0f", "x_advanced": True},
    )
    request_timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=MAX_TIMEOUT_SECONDS,
        title="Timeout (sec)",
        description=(
            "Time limit for each request to NetBox, in seconds: connecting, sending and "
            "reading the whole response. Each page and each retry gets its own. Defaults "
            "to 30; 1 to 600."
        ),
        json_schema_extra={"x_advanced": True},
    )


def connection_errors(config: NetBoxConnection, *, allow_templates: bool) -> list[str]:
    """Errors in the connection settings a schema cannot express (empty when valid).

    With ``allow_templates`` (saving a flow) a value still holding template
    syntax passes; the step checks it again once rendered.
    """
    errors: list[str] = []

    def unchecked(value: str) -> bool:
        return allow_templates and is_templated(value)

    url = config.url.strip()
    if not unchecked(url):
        error = _base_url_error(url)
        if error:
            errors.append(error)
        elif url.lower().startswith("http://") and not config.allow_insecure_auth:
            errors.append(
                "the token needs an https:// NetBox URL: over http:// it travels unencrypted "
                "(turn on 'allow_insecure_auth' for an internal NetBox without HTTPS)"
            )
    if not config.token.strip():
        errors.append("'token' is required")
    branch = config.branch.strip()
    if branch and not unchecked(branch) and not BRANCH_RE.match(branch):
        errors.append("'branch' must be a branch's schema ID (letters, digits, - and _)")
    ca_bundle = config.ca_bundle.strip()
    if (
        config.verify_tls
        and ca_bundle
        and not is_templated(ca_bundle)
        and not is_bare_secret_ref(ca_bundle)
        and _PEM_CERTIFICATE not in ca_bundle
    ):
        errors.append(
            "'ca_bundle' must hold PEM certificates (-----BEGIN CERTIFICATE-----), a secret "
            "reference, or a {{ secret('...') }} template"
        )
    return errors


def _base_url_error(url: str) -> str | None:
    """Why ``url`` is not a NetBox base URL, or None."""
    if not url:
        return "'url' is required"
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError) as exc:
        return f"'url' is not a valid URL: {exc}"
    if parsed.scheme not in {"http", "https"}:
        return "'url' must start with http:// or https://"
    if not parsed.host:
        return "'url' has no host"
    if parsed.userinfo:
        return "'url' must not carry credentials (user:password@); use API Token"
    if parsed.query or parsed.fragment:
        return "'url' is NetBox's address alone, without a query or fragment"
    if parsed.path.rstrip("/").endswith("/api"):
        return "'url' is NetBox's address without /api, such as https://netbox.example.com"
    return None


def normalize_endpoint(value: str) -> str:
    """``value`` without the slashes and the ``/api/`` prefix authors often copy along."""
    text = value.strip().strip("/")
    if text.startswith("api/"):
        text = text[len("api/") :]
    return text


def endpoint_error(field_name: str, value: str, *, required: bool) -> str | None:
    """Why ``value`` is not a REST endpoint path such as ``dcim/devices``, or None."""
    text = normalize_endpoint(value)
    if not text:
        return f"'{field_name}' is required" if required else None
    if not ENDPOINT_RE.match(text):
        return (
            f"'{field_name}' must be a NetBox REST path such as dcim/devices or "
            "plugins/<plugin>/<objects>: lowercase letters, digits, - and _ separated by /"
        )
    return None


def object_id_error(field_name: str, value: str) -> str | None:
    """Why ``value`` is not a NetBox object id (a positive whole number), or None."""
    if value.strip() and not OBJECT_ID_RE.match(value.strip()):
        return f"'{field_name}' must be a NetBox object ID, a positive whole number"
    return None


def json_value(field_name: str, value: Any) -> tuple[bool, Any]:
    """``(present, value)`` of a JSON setting; text is parsed. Raises ``ValueError``."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return False, None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"'{field_name}' is not valid JSON: {exc}") from None
    try:
        json.dumps(value, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"'{field_name}' cannot be sent as JSON: {exc}") from None
    return True, value


def json_size(value: Any) -> int:
    """Bytes of ``value`` as compact UTF-8 JSON."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return len(text.encode("utf-8", errors="surrogatepass"))


def fits_output(value: Any) -> bool:
    """Whether ``value`` is small enough for a step's output."""
    return json_size(value) <= MAX_OUTPUT_DATA_BYTES


@dataclass
class Reply:
    """What NetBox answered one call (a list call: all its pages)."""

    #: HTTP status of the last response; None when no response came.
    status: int | None
    #: The parsed JSON of the response (a list call: the objects of every page).
    data: Any = None
    #: Why the call failed (transport, refusal, unexpected status), or None.
    error: str | None = None
    #: NetBox's total for a list call (its ``count``).
    count: int | None = None
    #: A list call stopped at its limit while NetBox had more.
    more: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class _Totals:
    """What every call of a step adds up to, for the result."""

    requests: int = 0
    elapsed_ms: int = 0
    size_bytes: int = 0
    evidence: list[dict[str, Any]] = field(default_factory=list)


class NetBoxClient:
    """Calls NetBox for one step, with the step's connection settings."""

    def __init__(
        self,
        handler_id: str,
        connection: NetBoxConnection,
        services: HandlerServices,
        *,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        retries: int = 2,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.handler_id = handler_id
        self.connection = connection
        self.services = services
        self.max_response_bytes = max_response_bytes
        self.retries = retries
        self._http = HttpRequestHandler(transport=transport)
        self._token = ""
        self._prefix = ""
        self.scrub = Scrubber()
        self.totals = _Totals()

    @property
    def base(self) -> str:
        """The NetBox API root, ending in ``/api/``."""
        return self.connection.url.strip().rstrip("/") + "/api/"

    async def prepare(self) -> None:
        """Resolve the token and pick its header. Raises ``ValueError``."""
        token = await resolve_secret_text(
            self.services,
            self.connection.token,
            field="token",
            source=f"{self.handler_id}.token",
        )
        token = token.strip()
        if len(token) < MIN_SCRUB_LENGTH:
            raise ValueError("token resolved to a value too short to be a NetBox token")
        if is_bare_secret_ref(token) or is_templated(token):
            # http.request would read it as a reference again; a NetBox token never looks so.
            raise ValueError("token resolved to text that is not a NetBox token")
        kind = self.connection.token_type
        if kind == "auto":
            kind = "v2" if token.startswith(V2_TOKEN_PREFIX) else "v1"
        self._token = token
        self._prefix = "Bearer " if kind == "v2" else "Token "
        self.scrub = Scrubber((token, f"{self._prefix}{token}"))

    def url(self, path: str, query: dict[str, Any] | None = None) -> str:
        """The URL of ``path`` (relative to ``/api/``, ending in ``/``) with ``query``."""
        url = self.base + path
        if query:
            url += "?" + urlencode(query, doseq=True)
        return url

    async def call(
        self,
        method: Method,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        body: tuple[bool, Any] = (False, None),
        expected_status: str = "200-299",
        retry: bool | None = None,
        budget: int | None = None,
    ) -> Reply:
        """One request to NetBox; a read is retried while NetBox is busy.

        ``retry`` defaults to retrying GET only: a write that may have reached
        NetBox is never sent twice.
        """
        retry = method == "GET" if retry is None else retry
        attempts = 1 + (self.retries if retry else 0)
        reply = Reply(status=None)
        for attempt in range(1, attempts + 1):
            reply, wait = await self._once(method, path, query, body, expected_status, budget)
            if attempt == attempts or wait is None:
                break
            await asyncio.sleep(wait if wait > 0 else min(2 ** (attempt - 1), 8))
        return reply

    async def _once(
        self,
        method: Method,
        path: str,
        query: dict[str, Any] | None,
        body: tuple[bool, Any],
        expected_status: str,
        budget: int | None,
    ) -> tuple[Reply, float | None]:
        """Send one request. Also returns how long to wait before a retry (None: do not)."""
        headers = {"Accept": "application/json"}
        branch = self.connection.branch.strip()
        if branch:
            headers["X-NetBox-Branch"] = branch
        has_body, value = body
        remaining = self.max_response_bytes - self.totals.size_bytes
        if budget is not None:
            remaining = min(remaining, budget)
        config = HttpRequestConfig(
            url=self.url(path, query),
            method=method,
            headers=headers,
            json_body=value if has_body else None,
            auth_type="header",
            auth_header_name="Authorization",
            auth_prefix=self._prefix,
            auth_secret=self._token,
            allow_insecure_auth=self.connection.allow_insecure_auth,
            # The status is judged here, from NetBox's answer.
            expected_status="100-599",
            request_timeout_seconds=self.connection.request_timeout_seconds,
            verify_tls=self.connection.verify_tls,
            ca_bundle=self.connection.ca_bundle,
            max_response_bytes=max(1, remaining),
        )
        started = time.perf_counter()
        response = await self._http.send(self.services, config)
        self.totals.requests += 1
        self.totals.elapsed_ms += round((time.perf_counter() - started) * 1000)
        result = response.result
        self.totals.evidence.extend(result.evidence)
        output = result.output or {}
        self.totals.size_bytes += int(output.get("size_bytes") or 0)
        status = output.get("status")
        if not result.success:
            error = self.scrub.text(result.error or "the request failed")
            transient = status is None and bool(_TRANSIENT_ERROR_RE.search(error))
            return Reply(status=status, error=error), (0.0 if transient else None)
        data = self.scrub.tree(response.data)
        if status is not None and status_matches(status, parse_status_spec(expected_status)):
            return Reply(status=status, data=data), None
        reply = Reply(
            status=status,
            data=data,
            error=netbox_error(status, data, str(output.get("body") or "")),
        )
        if status in RETRY_STATUSES:
            return reply, _retry_after(output.get("headers") or {})
        return reply, None

    async def list_all(self, path: str, query: dict[str, Any], *, max_results: int) -> Reply:
        """Every object of a list endpoint, page by page, up to ``max_results``.

        Pages are fetched by offset rather than by NetBox's ``next`` links:
        behind a proxy those may name another scheme or host than the one
        the step was given.
        """
        objects: list[Any] = []
        count: int | None = None
        while True:
            limit = min(PAGE_SIZE, max_results - len(objects))
            page = await self.call(
                "GET",
                path,
                query={**query, "limit": limit, "offset": len(objects)},
                expected_status="200",
            )
            if not page.ok:
                return Reply(status=page.status, data=page.data, error=page.error, count=count)
            data = page.data
            if not isinstance(data, dict) or not isinstance(data.get("results"), list):
                return Reply(
                    status=page.status,
                    error=f"NetBox did not answer {path} with a list of objects",
                )
            if count is None and isinstance(data.get("count"), int):
                count = data["count"]
            results = data["results"]
            objects.extend(results[: max_results - len(objects)])
            total = count if count is not None else len(objects)
            if not results or len(objects) >= total:
                return Reply(status=page.status, data=objects, count=count, more=False)
            if len(objects) >= max_results:
                return Reply(status=page.status, data=objects, count=count, more=True)

    def result(
        self,
        *,
        success: bool,
        summary: str,
        output: dict[str, Any],
        error: str | None = None,
        metrics: dict[str, Any] | None = None,
        record: dict[str, Any] | None = None,
    ) -> HandlerResult:
        """The step's result, with the requests' evidence and every credential scrubbed."""
        evidence = list(self.totals.evidence)
        if record is not None:
            evidence.append({"kind": "transport_meta", "name": "netbox", "content_json": record})
        all_metrics = {
            "requests": self.totals.requests,
            "elapsed_ms": self.totals.elapsed_ms,
            "size_bytes": self.totals.size_bytes,
            **(metrics or {}),
        }
        return HandlerResult(
            success=success,
            summary=self.scrub.text(summary),
            metrics=self.scrub.tree(all_metrics),
            evidence=self.scrub.tree(evidence),
            error=self.scrub.text(error) if error else None,
            output=self.scrub.tree(output),
        )


def _retry_after(headers: dict[str, str]) -> float:
    """Seconds a Retry-After header asks to wait (0: none given), capped."""
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), "")
    try:
        return min(max(float(value.strip()), 0.0), MAX_RETRY_WAIT_SECONDS)
    except ValueError:
        return 0.0


def _messages(value: Any) -> str:
    """NetBox's field errors (a string, a list of strings, nested) as one line."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(_messages(item) for item in value if item not in (None, "", {}, []))
    if isinstance(value, dict):
        return "; ".join(f"{key}: {_messages(item)}" for key, item in value.items())
    return json.dumps(value)


def netbox_error(status: int | None, data: Any, body: str) -> str:
    """A step error from NetBox's answer to a request it did not carry out."""
    if isinstance(data, dict) and isinstance(data.get("detail"), str):
        detail = data["detail"]
    elif isinstance(data, list) and any(data):
        detail = "; ".join(
            f"item {index}: {_messages(item)}" for index, item in enumerate(data, 1) if item
        )
    elif data not in (None, "", {}, []):
        detail = _messages(data)
    else:
        detail = " ".join(body.split())[:300] or "no details"
    if len(detail) > MAX_ERROR_CHARS:
        detail = detail[: MAX_ERROR_CHARS - 1] + "…"
    if status == 401:
        return (
            f"NetBox did not accept the token (HTTP 401): {detail}. Check API Token and Token Type"
        )
    if status == 403:
        return f"the token may not do this in NetBox (HTTP 403): {detail}"
    if status == 404:
        return f"NetBox has no such object or endpoint (HTTP 404): {detail}"
    return f"NetBox refused the request (HTTP {status}): {detail}"


__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "MAX_OUTPUT_DATA_BYTES",
    "MAX_RESPONSE_BYTES_LIMIT",
    "MAX_RESULTS_LIMIT",
    "MAX_RETRIES",
    "NetBoxClient",
    "NetBoxConnection",
    "Reply",
    "connection_errors",
    "endpoint_error",
    "fits_output",
    "json_size",
    "json_value",
    "netbox_error",
    "normalize_endpoint",
    "object_id_error",
]
