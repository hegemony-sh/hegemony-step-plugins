# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HttpRequestHandler: send one HTTP(S) request and return the response as step output.

The worker sends the request itself, through its own httpx client, so every
outgoing request (redirect hops and next pages included) walks the flow's
egress gate (``services.enforce_egress``) and the step's own destination
check before a connection is opened. Redirects are followed here rather
than by httpx, so a redirect body is never read and the credentials and
author-set headers stay with the origin the author wrote.
"""

from __future__ import annotations

import asyncio
import base64
import codecs
import hashlib
import json
import re
import ssl
import time
import zlib
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any, Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_CHAIN_OUTPUT_CHARS,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerServices,
    HandlerTargeting,
    InvalidConfigError,
    StepKind,
)

from .jsonpath import PathError, get_path, parse_path, replace_at
from .security import (
    MIN_SCRUB_LENGTH,
    SCHEME_PORTS,
    RequestRefused,
    Scrubber,
    check_destination,
    filtered_response_headers,
    is_bare_secret_ref,
    is_templated,
    resolve_secret_text,
    same_origin,
    url_host,
    url_port,
)

HANDLER_ID = "http.request"

#: Methods that never carry a request body here.
BODYLESS_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

MIB = 1024 * 1024
#: Content encodings the step decodes itself, within the size budget; it asks
#: servers for nothing else.
ACCEPT_ENCODING = "gzip, deflate"
_GZIP_ENCODINGS = frozenset({"gzip", "x-gzip"})
_IDENTITY_ENCODINGS = frozenset({"", "identity"})
#: Raw bytes a compressed body may take beyond the decoded budget (headers,
#: trailers and incompressible blocks), so a stream that expands to nothing
#: cannot be read forever.
_RAW_SLACK_BYTES = MIB
DEFAULT_MAX_RESPONSE_BYTES = MIB
MAX_RESPONSE_BYTES_LIMIT = 16 * MIB
MAX_PAGES_LIMIT = 100
MAX_TIMEOUT_SECONDS = 600
#: Redirect hops followed per request before the step gives up.
MAX_REDIRECTS = 10
#: Characters of the last response body kept in ``output.body``.
MAX_BODY_OUTPUT_CHARS = 64 * 1024
#: Largest ``output.data``, in bytes of compact JSON. Step outputs are chained
#: into later steps' templates and snapshots, so they stay small: larger data
#: is left out (``data_truncated``), while Extract still reads all of it.
MAX_DATA_OUTPUT_BYTES = 64 * 1024
#: Characters of the last response body kept in the evidence record.
EVIDENCE_PREVIEW_CHARS = MAX_CHAIN_OUTPUT_CHARS

#: A header name (an RFC 9110 token).
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
#: Control characters a header value may not hold (tab is allowed).
_HEADER_VALUE_BAD_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
#: Headers the step sets itself (framing, routing): never from config.
_RESERVED_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection"})
#: Author-set headers a redirect to another origin keeps. Every other header
#: the author set, and the credentials, stay with the original origin.
_CROSS_ORIGIN_SAFE_HEADERS = frozenset({"accept", "accept-language", "content-type", "user-agent"})
#: Names of extracted values (``steps.<id>.output.extracted.<name>``).
_EXTRACT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_PEM_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
_LITERAL_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")


def parse_status_spec(spec: str) -> list[tuple[int, int]]:
    """Parse an expected-status spec like ``200-299,304`` into ranges.

    Raises ``ValueError`` for malformed entries.
    """
    ranges: list[tuple[int, int]] = []
    for raw in spec.split(","):
        entry = raw.strip()
        if not entry:
            continue
        try:
            if "-" in entry:
                low_raw, high_raw = entry.split("-", 1)
                low, high = int(low_raw), int(high_raw)
            else:
                low = high = int(entry)
        except ValueError:
            raise ValueError(f"invalid status entry: {entry}") from None
        if not (100 <= low <= 599 and 100 <= high <= 599 and low <= high):
            raise ValueError(f"invalid status entry: {entry}")
        ranges.append((low, high))
    if not ranges:
        raise ValueError("expected_status must list at least one status or range")
    return ranges


def status_matches(status: int, ranges: list[tuple[int, int]]) -> bool:
    """Whether ``status`` falls in one of ``ranges``."""
    return any(low <= status <= high for low, high in ranges)


class HttpRequestConfig(BaseModel):
    """Config for ``http.request``."""

    # A number written for a text setting (expected_status: 201, a query or
    # header value) is its text.
    model_config = ConfigDict(extra="allow", coerce_numbers_to_str=True)

    url: str = Field(
        min_length=1,
        title="URL",
        description=(
            "Address the request goes to, starting with https:// or http://, such as "
            "https://api.example.com/v1/items. May use templates such as "
            "{{ inputs.base_url }}/items. Credentials never go in the URL: use "
            "Authentication."
        ),
        json_schema_extra={"x_placeholder": "https://api.example.com/v1/items", "x_col_span": 2},
    )
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] = Field(
        default="GET",
        title="Method",
        description=(
            "HTTP method of the request. GET, HEAD and OPTIONS send no body. Defaults to GET."
        ),
    )
    query: dict[str, str] = Field(
        default_factory=dict,
        title="Query Parameters",
        description=(
            "Query parameters added to the URL, NAME=value, one per line. A parameter "
            "the URL already carries is replaced. Values may use templates."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "limit=100\nstatus=active",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        title="Headers",
        description=(
            "Request headers, Name=value, one per line, such as Accept=application/json. "
            "Values may use templates. Put credentials in Authentication instead: a "
            "redirect to another origin drops the credentials and every header set here "
            "except Accept, Accept-Language, Content-Type and User-Agent. Host, "
            "Content-Length, Transfer-Encoding and Connection are set by the step."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "Accept=application/json",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    json_body: Any = Field(
        default=None,
        title="JSON Body",
        description=(
            "Request body sent as JSON, with Content-Type application/json unless "
            "Headers set another. Text is parsed as JSON, so a template that renders "
            'JSON works, such as {"name": "{{ inputs.name }}"}. Not allowed with '
            "GET, HEAD or OPTIONS, or together with Text Body."
        ),
        json_schema_extra={
            "x_placeholder": '{"name": "{{ inputs.name }}"}',
            "x_rows": 6,
            "x_col_span": 2,
        },
    )
    text_body: str = Field(
        default="",
        title="Text Body",
        description=(
            "Request body sent as written, with Content-Type text/plain; charset=utf-8 "
            "unless Headers set another. Not allowed with GET, HEAD or OPTIONS, or "
            "together with JSON Body."
        ),
        json_schema_extra={"x_rows": 4, "x_col_span": 2, "x_advanced": True},
    )
    auth_type: Literal["none", "bearer", "basic", "header"] = Field(
        default="none",
        title="Authentication",
        description=(
            "How the request authenticates: none; a bearer token (Authorization: Bearer "
            "and the secret); basic, with a username and the secret as password; or a "
            "custom header carrying the secret. Credentials go only to the URL's own "
            "scheme, host and port: a redirect elsewhere drops them. They need an "
            "https:// URL unless Allow credentials over HTTP is on."
        ),
        json_schema_extra={
            "x_option_labels": {
                "none": "None",
                "bearer": "Bearer token",
                "basic": "Basic (username and password)",
                "header": "Custom header",
            }
        },
    )
    auth_secret: str = Field(
        default="",
        title="Secret",
        description=(
            "The token or password: a secret reference such as "
            "vault://orgs/acme/secrets/api/token, a {{ secret('...') }} template, or "
            "literal text. A value resolved from a reference is redacted from the run's "
            "logs; literal text is not, so prefer a reference."
        ),
        json_schema_extra={
            "x_placeholder": "vault://orgs/acme/secrets/api/token",
            "x_hide_when": {"field": "auth_type", "value": "none"},
            "x_col_span": 2,
        },
    )
    auth_username: str = Field(
        default="",
        title="Username",
        description=(
            "Username for basic authentication; it may not contain a colon. May use templates."
        ),
        json_schema_extra={"x_show_when": {"field": "auth_type", "value": "basic"}},
    )
    auth_header_name: str = Field(
        default="Authorization",
        title="Header Name",
        description=(
            "Header that carries the secret when Authentication is Custom header, such "
            "as X-API-Key. Defaults to Authorization."
        ),
        json_schema_extra={
            "x_placeholder": "X-API-Key",
            "x_show_when": {"field": "auth_type", "value": "header"},
        },
    )
    auth_prefix: str = Field(
        default="",
        title="Value Prefix",
        description=(
            "Text sent before the secret in the custom header, such as 'Token ' with its "
            "trailing space. Empty sends the secret alone."
        ),
        json_schema_extra={
            "x_placeholder": "Token ",
            "x_show_when": {"field": "auth_type", "value": "header"},
        },
    )
    allow_insecure_auth: bool = Field(
        default=False,
        title="Allow credentials over HTTP",
        description=(
            "Send the Authentication credential to a plain http:// URL. Off by default, "
            "because over HTTP the token or password travels unencrypted and anyone on "
            "the network path can read it; turn on only for an internal endpoint that "
            "offers no HTTPS."
        ),
        json_schema_extra={"x_advanced": True},
    )
    expected_status: str = Field(
        default="200-299",
        title="Expected Status",
        description=(
            "Comma-separated status codes and ranges that count as success, such as "
            "200-299,304. Defaults to 200-299. With pagination every page must match."
        ),
        json_schema_extra={"x_placeholder": "200-299"},
    )
    request_timeout_seconds: int = Field(
        default=30,
        ge=1,
        le=MAX_TIMEOUT_SECONDS,
        title="Timeout (sec)",
        description=(
            "Time limit for each request, in seconds: connecting, sending and reading the "
            "whole response. Redirect hops and pages each get their own. Defaults to 30; "
            "1 to 600."
        ),
    )
    follow_redirects: bool = Field(
        default=False,
        title="Follow redirects",
        description=(
            "Follow 3xx redirects, at most 10, and report the final response. Off by "
            "default, when the redirect response itself is the result. Every hop is "
            "checked against the egress policy, and a redirect to a scheme other than "
            "http or https, or one that would send the request body to another origin, "
            "is refused."
        ),
    )
    verify_tls: bool = Field(
        default=True,
        title="Verify TLS certificate",
        description=(
            "Validate the server's certificate on HTTPS requests. Turn off only for test "
            "endpoints with self-signed certificates, and prefer CA Bundle. On by default."
        ),
        json_schema_extra={"x_advanced": True},
    )
    ca_bundle: str = Field(
        default="",
        title="CA Bundle",
        description=(
            "PEM certificates to trust for this request instead of the public certificate "
            "authorities, such as an internal CA: the PEM text, a secret reference, or a "
            "{{ secret('...') }} template. Empty trusts the public authorities. Ignored "
            "when Verify TLS certificate is off."
        ),
        json_schema_extra={
            "x_placeholder": "-----BEGIN CERTIFICATE-----",
            "x_show_when": {"field": "verify_tls", "value": True},
            "x_rows": 4,
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
            "Largest response body the step reads, in bytes, summed over all pages. A "
            "larger response fails the step instead of being cut short. Defaults to "
            "1048576 (1 MiB); at most 16777216 (16 MiB)."
        ),
        json_schema_extra={"x_advanced": True},
    )
    extract: dict[str, str] = Field(
        default_factory=dict,
        title="Extract",
        description=(
            "Values to pick from the JSON response, NAME=path one per line, such as "
            "id=results[0].id. A path is keys separated by dots, [n] for list items "
            "(negative counts from the end), and an optional leading $. A missing value "
            "is null. Later steps read them as steps.<id>.output.extracted.NAME."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "id=results[0].id",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    sensitive: bool = Field(
        default=False,
        title="Sensitive response",
        description=(
            "Treat the response as secret: its body, data and extracted values stay out "
            "of the output and evidence, which keep the status, headers, size and SHA-256 "
            "of the body. Off by default."
        ),
        json_schema_extra={"x_advanced": True},
    )
    paginate_next: str = Field(
        default="",
        title="Next Page Path",
        description=(
            "Path of the next page's URL in each JSON response, such as next. A missing, "
            "null or empty value ends pagination. Next pages are fetched with GET, the "
            "same headers and credentials, and must stay on the first request's scheme, "
            "host and port. Needs GET, Items Path, and Max Pages above 1."
        ),
        json_schema_extra={"x_placeholder": "next", "x_advanced": True},
    )
    paginate_items: str = Field(
        default="",
        title="Items Path",
        description=(
            "Path of the item list in each JSON response, such as results. The output's "
            "data is the first page with this list replaced by the items of every page."
        ),
        json_schema_extra={"x_placeholder": "results", "x_advanced": True},
    )
    max_pages: int = Field(
        default=1,
        ge=1,
        le=MAX_PAGES_LIMIT,
        title="Max Pages",
        description=(
            "Most pages fetched, the first included. 1, the default, fetches a single "
            "response; at most 100."
        ),
        json_schema_extra={"x_advanced": True},
    )


def _url_error(url: str, *, allow_templates: bool) -> str | None:
    """Why ``url`` cannot be requested, or None."""
    text = url.strip()
    if not text:
        return "'url' is required"
    if allow_templates and is_templated(text):
        literal = _LITERAL_SCHEME_RE.match(text)
        if literal and literal.group(1).lower() not in SCHEME_PORTS:
            return "'url' must start with http:// or https://"
        return None
    try:
        parsed = httpx.URL(text)
    except (httpx.InvalidURL, TypeError, ValueError) as exc:
        return f"'url' is not a valid URL: {exc}"
    if parsed.scheme not in SCHEME_PORTS:
        return "'url' must start with http:// or https://"
    if not parsed.host:
        return "'url' has no host"
    if parsed.userinfo:
        return "'url' must not carry credentials (user:password@); use Authentication instead"
    return None


def _header_value_error(field_name: str, value: str) -> str | None:
    """Why ``value`` cannot be sent as a header value, or None. Never echoes the value."""
    if _HEADER_VALUE_BAD_RE.search(value):
        return f"{field_name} contains line breaks or control characters"
    if not value.isascii():
        return f"{field_name} contains non-ASCII characters"
    return None


def _has_json_body(config: HttpRequestConfig) -> bool:
    """Whether JSON Body is set (blank text counts as unset)."""
    body = config.json_body
    return body is not None and not (isinstance(body, str) and not body.strip())


def _json_body(config: HttpRequestConfig) -> tuple[bool, Any]:
    """``(present, value)`` of the JSON body; text is parsed. Raises ``ValueError``."""
    if not _has_json_body(config):
        return False, None
    body = config.json_body
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (ValueError, RecursionError) as exc:
            raise ValueError(f"'json_body' is not valid JSON: {exc}") from None
    try:
        json.dumps(body, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"'json_body' cannot be sent as JSON: {exc}") from None
    return True, body


def _paths_errors(config: HttpRequestConfig) -> list[str]:
    """Errors in the Extract paths and the pagination paths (empty when valid)."""
    errors: list[str] = []
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
    for field_name in ("paginate_next", "paginate_items"):
        value = getattr(config, field_name).strip()
        if value:
            try:
                parse_path(value)
            except PathError as exc:
                errors.append(f"'{field_name}': {exc}")
    return errors


def config_errors(config: HttpRequestConfig, *, allow_templates: bool) -> list[str]:
    """Semantic errors a schema cannot express (empty when valid).

    With ``allow_templates`` (saving a flow), values still holding template
    syntax pass; the step checks them again once the host has rendered them.
    Messages name fields, never the values of headers or secrets.
    """
    errors: list[str] = []

    def unchecked(value: Any) -> bool:
        """Whether ``value`` is left for the check after rendering."""
        return allow_templates and is_templated(value)

    error = _url_error(config.url, allow_templates=allow_templates)
    if error:
        errors.append(error)

    if any(not name.strip() for name in config.query):
        errors.append("'query' names must not be empty")

    credential_header = _credential_header_name(config)
    for name, value in config.headers.items():
        if not _HEADER_NAME_RE.match(name):
            errors.append(f"'headers' name {name!r} is not a valid header name")
            continue
        lowered = name.lower()
        if lowered in _RESERVED_HEADERS:
            errors.append(f"'headers' must not set {name}: the step sets it")
        elif credential_header and lowered == credential_header.lower():
            errors.append(
                f"'headers' must not set {name}: Authentication sets it; remove it from Headers"
            )
        if not unchecked(value):
            error = _header_value_error(f"'headers.{name}'", value)
            if error:
                errors.append(error)

    has_json = _has_json_body(config)
    if has_json and not unchecked(config.json_body):
        try:
            _json_body(config)
        except ValueError as exc:
            errors.append(str(exc))
    has_text = bool(config.text_body)
    if has_json and has_text:
        errors.append("'json_body' and 'text_body' cannot both be set")
    if (has_json or has_text) and config.method in BODYLESS_METHODS:
        errors.append(f"a {config.method} request sends no body: clear JSON Body and Text Body")

    if config.auth_type != "none" and not config.auth_secret.strip():
        errors.append(f"'auth_secret' is required for {config.auth_type} authentication")
    if (
        config.auth_type != "none"
        and not config.allow_insecure_auth
        and not unchecked(config.url)
        and config.url.strip().lower().startswith("http://")
    ):
        errors.append(
            "Authentication needs an https:// URL: over http:// the credential travels "
            "unencrypted (turn on 'allow_insecure_auth' for an internal endpoint without HTTPS)"
        )
    if config.auth_type == "basic":
        username = config.auth_username
        if not username.strip():
            errors.append("'auth_username' is required for basic authentication")
        elif not unchecked(username):
            # Base64-encoded into the header, so any text but a colon or a
            # control character will do.
            if ":" in username:
                errors.append("'auth_username' must not contain a colon")
            if _HEADER_VALUE_BAD_RE.search(username):
                errors.append("'auth_username' contains line breaks or control characters")
    if config.auth_type == "header":
        name = config.auth_header_name.strip()
        if not _HEADER_NAME_RE.match(name):
            errors.append("'auth_header_name' is not a valid header name")
        elif name.lower() in _RESERVED_HEADERS:
            errors.append(f"'auth_header_name' must not be {name}: the step sets it")
        if not unchecked(config.auth_prefix):
            error = _header_value_error("'auth_prefix'", config.auth_prefix)
            if error:
                errors.append(error)

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

    if not unchecked(config.expected_status):
        try:
            parse_status_spec(config.expected_status)
        except ValueError as exc:
            errors.append(f"'expected_status': {exc}")

    errors.extend(_paths_errors(config))
    if config.sensitive and config.extract:
        errors.append(
            "'extract' has no effect on a sensitive response, whose values stay out of the "
            "output: clear Extract or turn off Sensitive response"
        )

    paginate_next = config.paginate_next.strip()
    paginate_items = config.paginate_items.strip()
    if paginate_next or paginate_items or config.max_pages > 1:
        if not paginate_next:
            errors.append("pagination needs 'paginate_next', the path of the next page's URL")
        if not paginate_items:
            errors.append("pagination needs 'paginate_items', the path of each page's items")
        if config.max_pages < 2:
            errors.append("pagination needs 'max_pages' above 1 (1 fetches only the first page)")
        if config.method != "GET":
            errors.append("pagination needs the GET method")
    return errors


def _credential_header_name(config: HttpRequestConfig) -> str | None:
    """The request header Authentication sets, or None."""
    if config.auth_type in {"bearer", "basic"}:
        return "Authorization"
    if config.auth_type == "header":
        return config.auth_header_name.strip() or "Authorization"
    return None


@dataclass(frozen=True)
class _Credentials:
    """The request header Authentication sets, and the values to scrub from reports."""

    header: str | None = None
    value: str = field(default="", repr=False)
    secrets: tuple[str, ...] = field(default=(), repr=False)


@dataclass
class _Exchange:
    """One request the step sent (a redirect hop or a page) and the status it got."""

    method: str
    url: str
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    elapsed_ms: int = 0

    def record(self) -> dict[str, Any]:
        """The exchange as recorded in the evidence."""
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class _Page:
    """The final response of one page, its body read."""

    exchange: _Exchange
    url: httpx.URL
    body: bytes
    charset: str | None

    @cached_property
    def text(self) -> str:
        """The body decoded by its charset (UTF-8 by default), bad bytes replaced.

        A UTF-8 body drops a leading byte order mark, which JSON parsing refuses.
        """
        charset = self.charset or "utf-8"
        try:
            if codecs.lookup(charset).name == "utf-8":
                charset = "utf-8-sig"
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8-sig", errors="replace")

    @cached_property
    def json(self) -> tuple[bool, Any]:
        """``(parsed, value)``: the body as JSON, when it is JSON."""
        if not self.body.strip():
            return False, None
        try:
            return True, json.loads(self.text)
        except (ValueError, RecursionError):
            return False, None


class _BodyError(Exception):
    """The response body cannot be used: too large, or not decodable."""


class _ResponseTooLarge(_BodyError):
    """The response body exceeds the step's byte budget."""


def _elapsed_ms(started: float) -> int:
    """Milliseconds since ``started`` (a ``time.perf_counter()`` value), rounded."""
    return round((time.perf_counter() - started) * 1000)


class _BoundedDecoder:
    """Decompress a gzip or deflate body without ever producing more than the budget.

    The step reads the raw body and decodes it here rather than letting httpx
    decode it, because httpx inflates each chunk in full before the size
    check could see it: a small compressed body could expand to gigabytes.
    """

    def __init__(self, encoding: str, too_large: str) -> None:
        """Start decoding ``encoding``; ``too_large`` is the error once the budget is passed."""
        self._encoding = encoding
        self._too_large = too_large
        self._gzip = encoding in _GZIP_ENCODINGS
        self._raw_deflate = False
        self._started = False
        self._decompressor = zlib.decompressobj(
            zlib.MAX_WBITS | 16 if self._gzip else zlib.MAX_WBITS
        )

    def decode(self, data: bytes, room: int) -> bytes:
        """The decompressed form of ``data``; raises once more than ``room`` bytes come out.

        A gzip body may hold several members, one after another: each is
        decoded within the same budget, and zero bytes padding them are skipped.
        """
        out = bytearray()
        pending = data
        while pending:
            if self._decompressor.eof:
                if not self._gzip:
                    # Deflate data is a single stream; nothing after its end is read.
                    break
                pending = pending.lstrip(b"\0")
                if not pending:
                    break
                self._decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
            try:
                chunk = self._decompressor.decompress(pending, room - len(out) + 1)
            except zlib.error:
                if self._encoding == "deflate" and not self._started and not self._raw_deflate:
                    # Some servers send raw deflate without the zlib wrapper.
                    self._raw_deflate = True
                    self._decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                    continue
                raise _BodyError(f"the response body is not valid {self._encoding} data") from None
            self._started = True
            out.extend(chunk)
            if len(out) > room:
                raise _ResponseTooLarge(self._too_large)
            if self._decompressor.eof:
                pending = self._decompressor.unused_data
                continue
            tail = self._decompressor.unconsumed_tail
            if not chunk and tail == pending:
                break
            pending = tail
        return bytes(out)

    def finish(self) -> None:
        """Refuse a body that ended inside its compressed data, cut short on the way."""
        if self._started and not self._decompressor.eof:
            raise _BodyError(
                f"the response body ended before its {self._encoding} data was complete"
            )


async def _read_body(response: httpx.Response, remaining: int, limit_text: str) -> bytes:
    """The response body, decoded, and refused once it passes ``remaining`` bytes.

    The raw body is read in chunks and decoded here (identity, gzip or
    deflate), so neither the raw nor the decoded body can outgrow the budget.
    A declared Content-Length over the budget is refused before reading,
    unless the response has no body by definition (HEAD, 204, 304) or is
    compressed (the declared length is not the decoded one). A compressed
    body that ends before its compressed data does is refused too.
    """
    too_large = (
        f"the response body is larger than {limit_text}; raise Max Response Size or request less"
    )
    declared = response.headers.get("content-length", "")
    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    has_body = response.request.method != "HEAD" and response.status_code not in {204, 304}
    identity = encoding in _IDENTITY_ENCODINGS
    if has_body and identity and declared.isdigit() and int(declared) > remaining:
        raise _ResponseTooLarge(
            f"the response body ({declared} bytes) is larger than {limit_text}; raise "
            "Max Response Size or request less"
        )
    if response.is_stream_consumed:
        # Only an in-process transport hands back a body already read (and
        # decoded by httpx); a network response is always still a stream.
        content = response.content
        if len(content) > remaining:
            raise _ResponseTooLarge(too_large)
        return content
    decoder: _BoundedDecoder | None = None
    if not identity and (encoding in _GZIP_ENCODINGS or encoding == "deflate"):
        decoder = _BoundedDecoder(encoding, too_large)
    body = bytearray()
    raw_total = 0
    async for raw in response.aiter_raw():
        if not raw:
            continue
        if not identity and decoder is None:
            raise _BodyError(
                f"the response uses content encoding {encoding!r}, which this step does not "
                f"decode (it asks for {ACCEPT_ENCODING} or none); remove any Accept-Encoding "
                "header that asks for it"
            )
        raw_total += len(raw)
        if decoder is None:
            body.extend(raw)
        else:
            if raw_total > remaining + _RAW_SLACK_BYTES:
                raise _ResponseTooLarge(too_large)
            body.extend(decoder.decode(raw, remaining - len(body)))
        if len(body) > remaining:
            raise _ResponseTooLarge(too_large)
    if decoder is not None:
        decoder.finish()
    return bytes(body)


def _strip_for_new_origin(
    headers: httpx.Headers, author_headers: dict[str, str], credential_header: str | None
) -> None:
    """Drop credentials and author-set headers before a request leaves the origin."""
    drop = {"authorization", "proxy-authorization"}
    if credential_header:
        drop.add(credential_header.lower())
    drop.update(
        name.lower() for name in author_headers if name.lower() not in _CROSS_ORIGIN_SAFE_HEADERS
    )
    for name in drop:
        headers.pop(name, None)


class HttpRequestHandler(BaseHandler):
    """Send one HTTP(S) request (optionally following next-page links) from the worker."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.ACTION]
    display_name = "HTTP Request"
    description = (
        "Send an HTTP(S) request with any method, headers, body and authentication, and "
        "return the response for later steps."
    )
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    # Secret references reach the handler as written (see resolve_secret_text).
    raw_config_keys = frozenset({"auth_secret", "ca_bundle"})
    config_model = HttpRequestConfig
    default_config = {"method": "GET", "expected_status": "200-299"}

    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        """Use ``transport`` instead of the network (tests only)."""
        # Tests route the client through a mock transport; the host passes nothing.
        self._transport = transport

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate the step's fields; templated values are checked again once rendered."""
        errors = super().validate_config(config)
        if errors:
            return errors
        return config_errors(HttpRequestConfig.model_validate(config), allow_templates=True)

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Validate the rendered config, resolve credentials and TLS trust, then send."""
        try:
            config = self.parse_config(ctx.config, HttpRequestConfig)
        except InvalidConfigError as exc:
            return exc.result()
        # Rendered now: a templated value must hold up as well.
        errors = config_errors(config, allow_templates=False)
        if errors:
            return InvalidConfigError(HANDLER_ID, errors).result()

        services = ctx.require_services()
        if getattr(services, "enforce_egress", None) is None:
            # Fail closed: the step dials the URL itself, so without the gate
            # nothing would apply the flow's network policy.
            return HandlerResult(
                success=False,
                error=(
                    "this platform cannot apply the flow's network policy to the request, "
                    "so it was not sent"
                ),
                summary="Config error",
            )
        try:
            credentials = await self._credentials(services, config)
            verify = await self._tls_verify(services, config)
            body = _json_body(config)
        except ValueError as exc:
            return HandlerResult(
                success=False, error=f"Invalid {HANDLER_ID} config: {exc}", summary="Config error"
            )
        return await self._run(services, config, credentials, verify, body)

    @staticmethod
    async def _credentials(services: HandlerServices, config: HttpRequestConfig) -> _Credentials:
        """Resolve Authentication into the header it sets. Raises ``ValueError``."""
        header = _credential_header_name(config)
        if header is None:
            return _Credentials()
        secret = await resolve_secret_text(
            services,
            config.auth_secret,
            field="auth_secret",
            source=f"{HANDLER_ID}.auth_secret",
        )
        if len(secret) < MIN_SCRUB_LENGTH:
            raise ValueError(
                f"auth_secret resolved to a value shorter than {MIN_SCRUB_LENGTH} characters, "
                "too short to keep reliably out of the step's output; use a longer secret"
            )
        # A basic-auth password is base64-encoded; any other secret is sent as is.
        if config.auth_type != "basic" and _header_value_error("auth_secret", secret):
            raise ValueError(
                "auth_secret resolved to a value with line breaks, control characters or "
                "non-ASCII characters, which cannot be sent in a header"
            )
        if config.auth_type == "bearer":
            value = f"Bearer {secret}"
            extra: tuple[str, ...] = ()
        elif config.auth_type == "basic":
            token = base64.b64encode(f"{config.auth_username}:{secret}".encode()).decode()
            value = f"Basic {token}"
            extra = (token,)
        else:
            value = f"{config.auth_prefix}{secret}"
            extra = ()
        return _Credentials(header=header, value=value, secrets=(secret, value, *extra))

    @staticmethod
    async def _tls_verify(services: HandlerServices, config: HttpRequestConfig) -> Any:
        """``verify`` for the client: False, True, or a context trusting the CA bundle."""
        if not config.verify_tls:
            return False
        if not config.ca_bundle.strip():
            return True
        pem = await resolve_secret_text(
            services, config.ca_bundle, field="ca_bundle", source=f"{HANDLER_ID}.ca_bundle"
        )
        if _PEM_CERTIFICATE not in pem:
            raise ValueError("ca_bundle holds no PEM certificate (-----BEGIN CERTIFICATE-----)")
        try:
            return ssl.create_default_context(cadata=pem)
        except (ssl.SSLError, ValueError) as exc:
            raise ValueError(f"ca_bundle could not be loaded: {exc}") from None

    async def _run(
        self,
        services: HandlerServices,
        config: HttpRequestConfig,
        credentials: _Credentials,
        verify: Any,
        json_body: tuple[bool, Any],
    ) -> HandlerResult:
        """Send the request (and next pages), then build the output, evidence and result."""
        scrub = Scrubber(credentials.secrets)
        ranges = parse_status_spec(config.expected_status)
        paginating = config.max_pages > 1
        next_path = parse_path(config.paginate_next) if paginating else ()
        items_path = parse_path(config.paginate_items) if paginating else ()
        limit_text = f"Max Response Size ({config.max_response_bytes} bytes)"
        if paginating:
            limit_text += " summed over the pages"

        headers: dict[str, str] = dict(config.headers)
        lowered = {name.lower() for name in headers}
        content: bytes | None = None
        has_json, json_value = json_body
        if has_json:
            content = json.dumps(
                json_value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
            if "content-type" not in lowered:
                headers["Content-Type"] = "application/json"
        elif config.text_body:
            content = config.text_body.encode("utf-8")
            if "content-type" not in lowered:
                headers["Content-Type"] = "text/plain; charset=utf-8"
        if credentials.header:
            headers[credentials.header] = credentials.value

        url = httpx.URL(config.url.strip())
        if config.query:
            url = url.copy_merge_params(config.query)
        display_url = str(url.copy_with(query=None, fragment=None))

        enforce = getattr(services, "enforce_egress", None)
        exchanges: list[_Exchange] = []
        pages: list[_Page] = []

        async def gate(request: httpx.Request) -> None:
            """Every outgoing request, redirect hops and pages included, before it dials.

            The host is checked in the ASCII form the connection dials (see
            ``url_host``). The egress policy's denial propagates as raised (the
            step reports the policy's reason); the step's own refusals are
            RequestRefused.
            """
            target = request.url
            if target.scheme not in SCHEME_PORTS:
                raise RequestRefused(
                    f"refused to send a request to a {target.scheme!r} URL: only http and "
                    "https are supported"
                )
            host = url_host(target)
            port = url_port(target)
            if enforce is not None:
                await enforce(host, port, proto="tcp", kind="http request")
            await check_destination(host, port)

        async def observe(response: httpx.Response) -> None:
            """Every response, before httpx reads its Location header.

            The status and headers are recorded first, so a redirect that
            cannot be followed still reports them. Without Follow redirects the
            response is the result: its Location is kept from httpx, which
            would otherwise build a next request from it, and fail the step on
            one that is not a valid URL.
            """
            exchange = exchanges[-1]
            exchange.status = response.status_code
            exchange.headers = filtered_response_headers(response.headers)
            if not response.has_redirect_location:
                return
            if not config.follow_redirects:
                del response.headers["location"]
                return
            try:
                httpx.URL(response.headers["location"])
            except httpx.InvalidURL as exc:
                raise RequestRefused(
                    f"cannot follow the HTTP {response.status_code} redirect: its Location "
                    f"header is not a valid URL ({exc})"
                ) from None

        client_options: dict[str, Any] = {
            "verify": verify,
            "trust_env": False,
            "follow_redirects": False,
            "timeout": httpx.Timeout(config.request_timeout_seconds),
            "event_hooks": {"request": [gate], "response": [observe]},
            # Only what _read_body can decode within the size budget.
            "headers": {"Accept-Encoding": ACCEPT_ENCODING},
        }
        if self._transport is not None:
            client_options["transport"] = self._transport

        sent_header_names: list[str] = []
        combined: Any = None
        items: list[Any] = []
        more_pages = False
        failure: str | None = None
        started = time.perf_counter()

        async with httpx.AsyncClient(**client_options) as client:
            request = client.build_request(config.method, url, headers=headers, content=content)
            origin = request.url
            sent_header_names = sorted({name.lower() for name in request.headers})
            fetched = {str(origin)}
            try:
                while True:
                    used = sum(len(page.body) for page in pages)
                    page = await self._fetch(
                        client,
                        request,
                        config=config,
                        exchanges=exchanges,
                        remaining=config.max_response_bytes - used,
                        limit_text=limit_text,
                        credential_header=credentials.header,
                        has_body=content is not None,
                        stay_at=origin if paginating else None,
                    )
                    pages.append(page)
                    status = page.exchange.status or 0
                    if not status_matches(status, ranges):
                        where = f"page {len(pages)} answered " if len(pages) > 1 else ""
                        failure = (
                            f"{where}HTTP {status} is not in expected_status "
                            f"{config.expected_status}"
                        )
                        break
                    if not paginating:
                        break
                    parsed, data = page.json
                    if not parsed:
                        failure = f"page {len(pages)} is not JSON, so it cannot be paginated"
                        break
                    page_items = get_path(data, items_path)
                    if not isinstance(page_items, list):
                        failure = (
                            f"page {len(pages)} has no list at paginate_items "
                            f"{config.paginate_items!r}"
                        )
                        break
                    items.extend(page_items)
                    if len(pages) == 1:
                        combined = data
                    next_link = get_path(data, next_path)
                    if isinstance(next_link, str):
                        next_link = next_link.strip()
                    if next_link is None or next_link == "":
                        break
                    if not isinstance(next_link, str):
                        failure = (
                            f"page {len(pages)} has a {type(next_link).__name__} at "
                            f"paginate_next {config.paginate_next!r}, not a URL"
                        )
                        break
                    if len(pages) >= config.max_pages:
                        more_pages = True
                        break
                    try:
                        next_url = page.url.join(next_link)
                    except (httpx.InvalidURL, ValueError) as exc:
                        failure = f"page {len(pages)} has an invalid next-page URL: {exc}"
                        break
                    if not same_origin(next_url, origin):
                        failure = (
                            f"refused the next-page URL of page {len(pages)}: it leaves "
                            f"{origin.scheme}://{origin.netloc.decode('ascii')} (next pages must "
                            "keep the first request's scheme, host and port)"
                        )
                        break
                    if str(next_url) in fetched:
                        failure = (
                            f"page {len(pages)} links back to a page already fetched, so "
                            "pagination stopped"
                        )
                        break
                    fetched.add(str(next_url))
                    request = client.build_request("GET", next_url, headers=headers)
            except (
                RequestRefused,
                _BodyError,
                httpx.HTTPError,
                httpx.InvalidURL,
                TimeoutError,
            ) as exc:
                failure = _describe_error(exc, config.request_timeout_seconds)

        elapsed_ms = _elapsed_ms(started)
        last = exchanges[-1] if exchanges else None
        last_page = pages[-1] if pages and last is not None and pages[-1].exchange is last else None
        status = last.status if last is not None else None
        # A response with the expected status is not ok when the step still
        # failed on it (its body, a redirect, a page).
        ok = failure is None and status is not None and status_matches(status, ranges)
        size_bytes = sum(len(page.body) for page in pages)

        if last_page is not None:
            # Redacted whole, before any preview is cut from it: a credential
            # crossing the cut would otherwise survive in part.
            text = scrub.text(last_page.text)
            parsed, data = last_page.json
            if not parsed:
                data = None
            body_sha256: str | None = hashlib.sha256(last_page.body).hexdigest()
        else:
            text, data, body_sha256 = "", None, None
        if paginating and failure is None and combined is not None:
            data = replace_at(combined, items_path, items)

        output: dict[str, Any] = {
            "status": status,
            "ok": ok,
            "url": last.url if last is not None else str(url),
            "method": config.method,
            "headers": dict(last.headers) if last is not None else {},
            "elapsed_ms": elapsed_ms,
            "size_bytes": size_bytes,
            "body_sha256": body_sha256,
            "pages": len(pages),
            "more_pages": more_pages,
        }
        meta: dict[str, Any] = {
            "method": config.method,
            "url": exchanges[0].url if exchanges else str(url),
            "status": status,
            "elapsed_ms": elapsed_ms,
            "request_headers": sent_header_names,
            "response_headers": dict(output["headers"]),
            "requests": [exchange.record() for exchange in exchanges],
            "pages": len(pages),
            "size_bytes": size_bytes,
            "body_sha256": body_sha256,
        }
        if not config.sensitive:
            data_truncated = data is not None and _json_size(data) > MAX_DATA_OUTPUT_BYTES
            output["body"] = text[:MAX_BODY_OUTPUT_CHARS]
            output["body_truncated"] = len(text) > MAX_BODY_OUTPUT_CHARS
            output["data"] = None if data_truncated else data
            output["data_truncated"] = data_truncated
            # Extract reads the whole response, however large its data.
            output["extracted"] = {
                name: get_path(data, parse_path(path)) for name, path in config.extract.items()
            }
            meta["body_preview"] = text[:EVIDENCE_PREVIEW_CHARS]
            meta["body_truncated"] = len(text) > EVIDENCE_PREVIEW_CHARS
        if failure:
            meta["error"] = failure

        timing = f"{len(pages)} pages, {elapsed_ms} ms" if len(pages) > 1 else f"{elapsed_ms} ms"
        if status is None:
            summary = f"{config.method} {display_url} failed ({timing})"
        elif failure:
            summary = f"{config.method} {display_url} -> {status}, failed ({timing})"
        else:
            summary = f"{config.method} {display_url} -> {status} ({timing})"

        metrics: dict[str, Any] = {"elapsed_ms": elapsed_ms, "size_bytes": size_bytes, "ok": ok}
        if status is not None:
            metrics["status"] = status
        evidence = [
            {"kind": "transport_meta", "name": "http_request", "content_json": scrub.tree(meta)}
        ]
        return HandlerResult(
            success=failure is None,
            summary=scrub.text(summary),
            metrics=metrics,
            evidence=evidence,
            error=scrub.text(failure) if failure else None,
            output=scrub.tree(output),
        )

    @staticmethod
    async def _fetch(
        client: httpx.AsyncClient,
        request: httpx.Request,
        *,
        config: HttpRequestConfig,
        exchanges: list[_Exchange],
        remaining: int,
        limit_text: str,
        credential_header: str | None,
        has_body: bool = False,
        stay_at: httpx.URL | None = None,
    ) -> _Page:
        """Send ``request``, following redirects when configured; the final response, read.

        A redirect that would repeat the request body (``has_body``) to another
        scheme, host or port is refused. With ``stay_at`` (while paginating), a
        redirect away from that URL's scheme, host and port is refused, as a
        next-page link would be.
        """
        hops = 0
        while True:
            exchange = _Exchange(method=request.method, url=str(request.url))
            exchanges.append(exchange)
            started = time.perf_counter()
            next_request: httpx.Request | None = None
            try:
                async with asyncio.timeout(config.request_timeout_seconds):
                    # The client's response hook records the status and headers.
                    response = await client.send(request, stream=True)
                    try:
                        if config.follow_redirects and response.next_request is not None:
                            # The redirect's own body is never read.
                            next_request = response.next_request
                        else:
                            body = await _read_body(response, remaining, limit_text)
                            return _Page(
                                exchange=exchange,
                                url=response.url,
                                body=body,
                                charset=response.charset_encoding,
                            )
                    finally:
                        await response.aclose()
            finally:
                exchange.elapsed_ms = _elapsed_ms(started)
            if next_request is None:  # pragma: no cover - every path above returns or sets it
                raise RequestRefused("the redirect could not be followed")
            hops += 1
            if hops > MAX_REDIRECTS:
                raise RequestRefused(f"stopped after {MAX_REDIRECTS} redirects")
            if next_request.url.scheme not in SCHEME_PORTS:
                raise RequestRefused(
                    f"refused to follow a redirect to a {next_request.url.scheme!r} URL: only "
                    "http and https are supported"
                )
            if stay_at is not None and not same_origin(next_request.url, stay_at):
                raise RequestRefused(
                    f"refused a redirect to {next_request.url.scheme}://"
                    f"{next_request.url.netloc.decode('ascii')} while paginating (every page "
                    "must keep the first request's scheme, host and port)"
                )
            # httpx keeps the method and body except where the redirect turns it into a GET.
            has_body = has_body and next_request.method == request.method
            if not same_origin(next_request.url, request.url):
                if has_body:
                    raise RequestRefused(
                        f"refused to follow the HTTP {exchange.status} redirect to "
                        f"{next_request.url.scheme}://{next_request.url.netloc.decode('ascii')}: "
                        "it would send the request body to another scheme, host or port; "
                        "send the request to that URL instead"
                    )
                _strip_for_new_origin(next_request.headers, config.headers, credential_header)
            request = next_request


def _json_size(value: Any) -> int:
    """Bytes of ``value`` as compact UTF-8 JSON."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return len(text.encode("utf-8", errors="surrogatepass"))


def _describe_error(exc: BaseException, timeout_seconds: int) -> str:
    """A step error for a request that failed before a usable response."""
    if isinstance(exc, (RequestRefused, _BodyError)):
        return str(exc)
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)):
        return f"the request timed out after {timeout_seconds} s"
    detail = str(exc).strip()
    name = type(exc).__name__
    return f"request failed: {name}: {detail}" if detail else f"request failed: {name}"


__all__ = [
    "HANDLER_ID",
    "HttpRequestConfig",
    "HttpRequestHandler",
    "config_errors",
    "parse_status_spec",
    "status_matches",
]
