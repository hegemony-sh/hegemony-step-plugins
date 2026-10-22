# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Behaviour of the ``http.request`` handler (hegemony-steps-http).

Most tests route the handler's own httpx client through a mock transport,
with host names resolved by a fake resolver, so the destination check runs
for real without touching the network. A few use a real HTTP server on
127.0.0.1, with the loopback refusal switched off for that test only.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import http.server
import json
import ssl
import threading
import zlib
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import Any, cast

import httpcore
import httpx
import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices, StepKind
from hegemony_step_sdk.docs import check_page, load_docs_bundle
from hegemony_steps_http import register, request as request_module, security
from hegemony_steps_http.jsonpath import PathError, get_path, parse_path, replace_at
from hegemony_steps_http.request import (
    HttpRequestConfig,
    HttpRequestHandler,
    parse_status_spec,
    status_matches,
)

SECRET_REF = "vault://orgs/acme/secrets/api/token"
SECRET_VALUE = "tok-3f9c1a7e-test-value"

#: The resolver the step uses on a worker, kept before the fake_dns fixture replaces it.
REAL_RESOLVE_HOST = security.resolve_host

#: Fake DNS for the mock-transport tests (TEST-NET documentation addresses).
FAKE_DNS = {
    "api.example.test": ["192.0.2.10"],
    "other.example.test": ["198.51.100.20"],
    "loopback.example.test": ["127.0.0.1"],
    "mixed.example.test": ["192.0.2.30", "127.0.0.1"],
    "metadata.example.test": ["169.254.169.254"],
}


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    """Resolve host names from FAKE_DNS; anything else does not resolve."""
    looked_up: list[str] = []

    async def resolve(host: str, port: int) -> list[str]:
        looked_up.append(host)
        if host in FAKE_DNS:
            return FAKE_DNS[host]
        raise OSError(f"[Errno -2] Name or service not known: {host}")

    monkeypatch.setattr(security, "resolve_host", resolve)
    return looked_up


def resolve_like_getaddrinfo(monkeypatch, names: dict[str, list[str]]) -> list[str]:
    """Resolve as a worker does: Python's socket encodes a name with its IDNA codec first.

    Returns the names looked up, as encoded.
    """
    looked_up: list[str] = []

    async def resolve(host: str, port: int) -> list[str]:
        name = host.encode("idna").decode("ascii")
        looked_up.append(name)
        if name in names:
            return names[name]
        raise OSError(f"[Errno -2] Name or service not known: {name}")

    monkeypatch.setattr(security, "resolve_host", resolve)
    return looked_up


class FakeServices:
    """The handler's slice of HandlerServices: secret resolution and the egress gate."""

    def __init__(self, secrets: dict[str, str] | None = None, deny: set[str] | None = None) -> None:
        self.secrets = {SECRET_REF: SECRET_VALUE} if secrets is None else secrets
        self.deny = deny or set()
        self.resolved: list[tuple[str, str]] = []
        self.gated: list[tuple[str, int, str | None, str]] = []

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        assert ref is not None
        self.resolved.append((ref, source))
        for key, value in self.secrets.items():
            if ref == "{{ secret('" + key + "') }}":
                return value
        return ""

    async def enforce_egress(
        self, host: str, port: int | None = None, *, proto: str | None = None, kind: str = ""
    ) -> None:
        self.gated.append((host, port or 0, proto, kind))
        if host in self.deny:
            raise EgressDenied(f"{kind} to {host}:{port} refused by the flow egress policy")


class EgressDenied(Exception):
    """Stands in for the host's egress-denial error."""


class ServicesWithoutEgress:
    """A host that predates the egress gate: no enforce_egress at all."""

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        return ""


class Recorder:
    """A mock transport that records every request it receives."""

    def __init__(self, respond: Callable[[httpx.Request], Any]) -> None:
        self.requests: list[httpx.Request] = []
        self.bodies: list[bytes] = []
        self._respond = respond

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.bodies.append(await request.aread())
        response = self._respond(request)
        if asyncio.iscoroutine(response):
            response = await response
        return response

    @property
    def urls(self) -> list[str]:
        return [str(r.url) for r in self.requests]


def _handler(recorder: Recorder) -> HttpRequestHandler:
    return HttpRequestHandler(transport=httpx.MockTransport(recorder))


def _ctx(config: dict[str, Any], services: Any = None) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        services=cast(HandlerServices, services if services is not None else FakeServices()),
    )


def _json_response(payload: Any, status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers)


def _everything(result) -> str:
    """Everything a result exposes, as one string, for leak checks."""
    return json.dumps(
        {
            "summary": result.summary,
            "error": result.error,
            "output": result.output,
            "evidence": result.evidence,
            "metrics": result.metrics,
        },
        default=str,
    )


# --- Registration and metadata ----------------------------------------------


def test_the_wheel_registers_one_handler_with_its_metadata():
    registered: list[type] = []

    class _Registry:
        api_version = 1

        def register_handler_type(self, handler_class: type) -> None:
            registered.append(handler_class)

    register(_Registry())
    assert registered == [HttpRequestHandler]
    cls = HttpRequestHandler
    assert cls.handler_id == "http.request"
    assert cls.supported_kinds == [StepKind.ACTION]
    assert cls.category == "Actions"
    assert cls.targeting.roles is False and cls.targeting.ips is False
    assert cls.raw_config_keys == frozenset({"auth_secret", "ca_bundle"})
    assert cls.default_config == {"method": "GET", "expected_status": "200-299"}
    assert cls.container_backed is False


def test_every_config_field_is_documented_and_the_page_satisfies_the_contract():
    model = HttpRequestHandler.config_model
    assert model is not None
    for name, field in model.model_fields.items():
        assert (field.title or "").strip(), name
        assert (field.description or "").strip(), name
    bundle = load_docs_bundle("hegemony_steps_http")
    assert set(bundle) == {"http.request"}
    assert check_page("http.request", bundle["http.request"]) == []
    readme = Path(__file__).resolve().parents[1] / "plugins" / "steps_http" / "README.md"
    assert "`http.request`" in readme.read_text(encoding="utf-8")


# --- The request -------------------------------------------------------------


async def test_get_returns_json_data_extracted_values_and_filtered_headers():
    payload = {"results": [{"id": 7, "name": "a"}], "meta": {"total": 1}}
    recorder = Recorder(
        lambda request: httpx.Response(
            200,
            json=payload,
            headers=[
                ("X-Request-Id", "abc"),
                ("Set-Cookie", "session=s1"),
                ("Set-Cookie", "other=s2"),
                ("Vary", "Accept"),
                ("Vary", "Origin"),
            ],
        )
    )
    services = FakeServices()
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/v1/items",
                "headers": {"Accept": "application/json", "X-Trace": "trace-value-1"},
                "extract": {"first_id": "results[0].id", "total": "$.meta.total", "gone": "a.b"},
            },
            services,
        )
    )

    assert result.success is True, result.error
    out = result.output
    assert out["status"] == 200 and out["ok"] is True
    assert out["url"] == "https://api.example.test/v1/items"
    assert out["method"] == "GET"
    assert out["data"] == payload
    assert out["extracted"] == {"first_id": 7, "total": 1, "gone": None}
    assert json.loads(out["body"]) == payload
    assert out["body_truncated"] is False
    assert out["data_truncated"] is False
    assert out["size_bytes"] == len(out["body"].encode())
    assert out["body_sha256"] == hashlib.sha256(out["body"].encode()).hexdigest()
    assert out["pages"] == 1 and out["more_pages"] is False
    assert out["headers"]["x-request-id"] == "abc"
    assert out["headers"]["vary"] == "Accept, Origin"
    assert "set-cookie" not in out["headers"]
    assert result.summary.startswith("GET https://api.example.test/v1/items -> 200 (")
    assert set(result.metrics) == {"elapsed_ms", "size_bytes", "ok", "status"}
    assert result.metrics["status"] == 200 and result.metrics["ok"] is True

    (evidence,) = result.evidence
    assert evidence["kind"] == "transport_meta"
    meta = evidence["content_json"]
    assert meta["method"] == "GET" and meta["status"] == 200
    assert "x-trace" in meta["request_headers"] and "accept" in meta["request_headers"]
    # Request header values are never recorded.
    assert "trace-value-1" not in _everything(result)
    assert "set-cookie" not in meta["response_headers"]
    assert json.loads(meta["body_preview"]) == payload
    assert meta["requests"] == [
        {
            "method": "GET",
            "url": "https://api.example.test/v1/items",
            "status": 200,
            "elapsed_ms": meta["requests"][0]["elapsed_ms"],
        }
    ]
    # The request walked the egress gate first.
    assert services.gated == [("api.example.test", 443, "tcp", "http request")]


async def test_a_long_body_is_truncated_in_output_and_evidence():
    text = "x" * (request_module.MAX_BODY_OUTPUT_CHARS + 10)
    recorder = Recorder(lambda request: httpx.Response(200, text=text))
    result = await _handler(recorder).execute(_ctx({"url": "https://api.example.test/big"}))
    assert result.success is True
    assert len(result.output["body"]) == request_module.MAX_BODY_OUTPUT_CHARS
    assert result.output["body_truncated"] is True
    assert result.output["data"] is None
    assert result.output["size_bytes"] == len(text)
    meta = result.evidence[0]["content_json"]
    assert len(meta["body_preview"]) == request_module.EVIDENCE_PREVIEW_CHARS


@pytest.mark.parametrize(
    "json_body",
    [{"name": "n1", "tags": ["a"], "count": 2}, '{"name": "n1", "tags": ["a"], "count": 2}'],
    ids=["object", "json-text"],
)
async def test_post_sends_the_json_body(json_body):
    recorder = Recorder(lambda request: _json_response({"id": 1}, 201))
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/v1/items",
                "method": "POST",
                "json_body": json_body,
                "expected_status": "201",
            }
        )
    )
    assert result.success is True, result.error
    (request,) = recorder.requests
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert json.loads(recorder.bodies[0]) == {"name": "n1", "tags": ["a"], "count": 2}
    assert result.output["data"] == {"id": 1}


async def test_a_content_type_header_replaces_the_json_default():
    recorder = Recorder(lambda request: httpx.Response(204))
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/v1/items/1",
                "method": "PATCH",
                "headers": {"Content-Type": "application/merge-patch+json"},
                "json_body": {"name": None},
                "expected_status": "204",
            }
        )
    )
    assert result.success is True, result.error
    assert recorder.requests[0].headers["content-type"] == "application/merge-patch+json"
    assert recorder.bodies[0] == b'{"name":null}'


async def test_text_body_is_sent_as_written():
    recorder = Recorder(lambda request: httpx.Response(200, text="ok"))
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/upload", "method": "PUT", "text_body": "a=1\nb=2"})
    )
    assert result.success is True, result.error
    assert recorder.bodies[0] == b"a=1\nb=2"
    assert recorder.requests[0].headers["content-type"] == "text/plain; charset=utf-8"


async def test_delete_may_carry_a_body():
    recorder = Recorder(lambda request: httpx.Response(204))
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/v1/items",
                "method": "DELETE",
                "json_body": {"ids": [1, 2]},
                "expected_status": "204",
            }
        )
    )
    assert result.success is True, result.error
    assert json.loads(recorder.bodies[0]) == {"ids": [1, 2]}


async def test_query_parameters_merge_into_the_url():
    recorder = Recorder(lambda request: _json_response([]))
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/v1/items?status=old&keep=1",
                "query": {"status": "active", "limit": "50"},
            }
        )
    )
    assert result.success is True, result.error
    params = recorder.requests[0].url.params
    assert params["status"] == "active"
    assert params["keep"] == "1"
    assert params["limit"] == "50"
    # The summary leaves the query string out.
    assert "?" not in result.summary


# --- Authentication ----------------------------------------------------------


@pytest.mark.parametrize(
    ("auth", "header", "expected"),
    [
        ({"auth_type": "bearer"}, "authorization", f"Bearer {SECRET_VALUE}"),
        (
            {"auth_type": "basic", "auth_username": "svc"},
            "authorization",
            "Basic " + base64.b64encode(f"svc:{SECRET_VALUE}".encode()).decode(),
        ),
        (
            {"auth_type": "header", "auth_header_name": "X-API-Key"},
            "x-api-key",
            SECRET_VALUE,
        ),
        (
            {"auth_type": "header", "auth_prefix": "Token "},
            "authorization",
            f"Token {SECRET_VALUE}",
        ),
    ],
    ids=["bearer", "basic", "custom-header", "custom-prefix"],
)
async def test_each_auth_type_resolves_a_bare_reference_and_never_reports_the_secret(
    auth, header, expected
):
    recorder = Recorder(lambda request: httpx.Response(500, json={"detail": "boom"}))
    services = FakeServices()
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/v1/me", "auth_secret": SECRET_REF, **auth}, services)
    )
    assert recorder.requests[0].headers[header] == expected
    assert services.resolved == [("{{ secret('" + SECRET_REF + "') }}", "http.request.auth_secret")]
    # A failed step too: nothing it reports carries the credential.
    assert result.success is False
    everything = _everything(result)
    assert SECRET_VALUE not in everything
    assert expected not in everything
    assert header in result.evidence[0]["content_json"]["request_headers"]


async def test_a_template_secret_is_rendered_and_a_literal_is_used_as_written():
    recorder = Recorder(lambda request: httpx.Response(200))
    services = FakeServices()
    template = "{{ secret('" + SECRET_REF + "') }}"
    await _handler(recorder).execute(
        _ctx(
            {"url": "https://api.example.test/", "auth_type": "bearer", "auth_secret": template},
            services,
        )
    )
    assert services.resolved == [(template, "http.request.auth_secret")]
    assert recorder.requests[0].headers["authorization"] == f"Bearer {SECRET_VALUE}"

    services = FakeServices()
    await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/",
                "auth_type": "bearer",
                "auth_secret": "literal-token-1",
            },
            services,
        )
    )
    assert services.resolved == []
    assert recorder.requests[1].headers["authorization"] == "Bearer literal-token-1"


async def test_a_reference_that_resolves_to_nothing_fails_before_any_request():
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/",
                "auth_type": "bearer",
                "auth_secret": "vault://orgs/acme/secrets/missing",
            }
        )
    )
    assert result.success is False
    assert "auth_secret resolved to an empty value" in (result.error or "")
    assert recorder.requests == []


async def test_a_secret_the_response_repeats_is_redacted():
    """An echo endpoint must not carry the credential into the output."""

    def echo(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"headers": {"Authorization": request.headers["authorization"]}},
            headers={"X-Echo": request.headers["authorization"]},
        )

    recorder = Recorder(echo)
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/echo",
                "auth_type": "bearer",
                "auth_secret": SECRET_REF,
                "extract": {"auth": "headers.Authorization"},
            }
        )
    )
    assert result.success is True, result.error
    assert SECRET_VALUE not in _everything(result)
    assert result.output["extracted"]["auth"] == security.REDACTED
    assert result.output["headers"]["x-echo"] == security.REDACTED


async def test_a_secret_with_a_line_break_is_refused_without_echoing_it():
    services = FakeServices(secrets={SECRET_REF: "abc\r\nX-Injected: 1"})
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(
        _ctx(
            {"url": "https://api.example.test/", "auth_type": "bearer", "auth_secret": SECRET_REF},
            services,
        )
    )
    assert result.success is False
    assert "line breaks" in (result.error or "")
    assert "X-Injected" not in (result.error or "")
    assert recorder.requests == []


async def test_basic_auth_encodes_any_password_text():
    services = FakeServices(secrets={SECRET_REF: "pässwörd\twith tab"})
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/",
                "auth_type": "basic",
                "auth_username": "jörg",
                "auth_secret": SECRET_REF,
            },
            services,
        )
    )
    assert result.success is True, result.error
    token = base64.b64encode("jörg:pässwörd\twith tab".encode()).decode()
    assert recorder.requests[0].headers["authorization"] == f"Basic {token}"
    assert token not in _everything(result)


# --- Status ------------------------------------------------------------------


async def test_an_unexpected_status_fails_the_step_but_fills_the_output():
    recorder = Recorder(lambda request: _json_response({"error": "not found", "code": 44}, 404))
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/v1/items/9",
                "extract": {"code": "code"},
            }
        )
    )
    assert result.success is False
    assert result.error == "HTTP 404 is not in expected_status 200-299"
    assert result.output["status"] == 404
    assert result.output["ok"] is False
    assert result.output["data"] == {"error": "not found", "code": 44}
    assert result.output["data_truncated"] is False
    assert result.output["extracted"] == {"code": 44}
    assert result.summary.endswith(")") and "-> 404, failed (" in result.summary
    assert result.evidence[0]["content_json"]["error"] == result.error


def test_parse_status_spec_ranges_and_codes():
    ranges = parse_status_spec("200-299, 304")
    assert status_matches(204, ranges)
    assert status_matches(304, ranges)
    assert not status_matches(301, ranges)


@pytest.mark.parametrize("bad", ["", "abc", "700", "300-200", "2xx", "200-"])
def test_parse_status_spec_rejects_bad_entries(bad):
    with pytest.raises(ValueError):
        parse_status_spec(bad)


# --- Redirects ---------------------------------------------------------------


async def test_without_follow_redirects_the_redirect_is_the_response():
    recorder = Recorder(
        lambda request: httpx.Response(302, headers={"Location": "https://other.example.test/"})
    )
    result = await _handler(recorder).execute(_ctx({"url": "https://api.example.test/old"}))
    assert result.success is False
    assert result.output["status"] == 302
    assert result.output["headers"]["location"] == "https://other.example.test/"
    assert recorder.urls == ["https://api.example.test/old"]

    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/old", "expected_status": "200-399"})
    )
    assert result.success is True, result.error


async def test_followed_redirects_gate_every_hop_and_keep_credentials_at_the_origin():
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(307, headers={"Location": "/moved"})
        if request.url.path == "/moved":
            return httpx.Response(302, headers={"Location": "http://other.example.test:8080/x"})
        return _json_response({"ok": True})

    recorder = Recorder(respond)
    services = FakeServices()
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/start",
                "follow_redirects": True,
                "auth_type": "bearer",
                "auth_secret": SECRET_REF,
                "headers": {"Accept": "application/json", "X-Tenant": "t1"},
            },
            services,
        )
    )
    assert result.success is True, result.error
    assert recorder.urls == [
        "https://api.example.test/start",
        "https://api.example.test/moved",
        "http://other.example.test:8080/x",
    ]
    first, same_origin_hop, cross_origin_hop = recorder.requests
    assert first.headers["authorization"] == f"Bearer {SECRET_VALUE}"
    # Same origin: credentials and author headers kept.
    assert same_origin_hop.headers["authorization"] == f"Bearer {SECRET_VALUE}"
    assert same_origin_hop.headers["x-tenant"] == "t1"
    # Another origin: credentials and author headers dropped, Accept kept.
    assert "authorization" not in cross_origin_hop.headers
    assert "x-tenant" not in cross_origin_hop.headers
    assert cross_origin_hop.headers["accept"] == "application/json"
    # Every hop walked the egress gate, with its own port.
    assert services.gated == [
        ("api.example.test", 443, "tcp", "http request"),
        ("api.example.test", 443, "tcp", "http request"),
        ("other.example.test", 8080, "tcp", "http request"),
    ]
    assert result.output["url"] == "http://other.example.test:8080/x"
    assert [r["status"] for r in result.evidence[0]["content_json"]["requests"]] == [307, 302, 200]


async def test_a_cross_origin_redirect_drops_a_custom_credential_header():
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.example.test":
            return httpx.Response(302, headers={"Location": "https://other.example.test/"})
        return httpx.Response(200)

    recorder = Recorder(respond)
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/",
                "follow_redirects": True,
                "auth_type": "header",
                "auth_header_name": "X-API-Key",
                "auth_secret": SECRET_REF,
            }
        )
    )
    assert result.success is True, result.error
    assert recorder.requests[0].headers["x-api-key"] == SECRET_VALUE
    assert "x-api-key" not in recorder.requests[1].headers


async def test_httpx_itself_drops_authorization_on_a_cross_origin_redirect():
    """The step builds each hop with httpx's redirect logic: verify that logic."""

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://other.example.test/"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        response = await client.get(
            "https://api.example.test/", headers={"Authorization": "Bearer x"}
        )
        assert response.next_request is not None
        assert "authorization" not in response.next_request.headers


async def test_a_redirect_to_another_scheme_is_refused_before_sending():
    recorder = Recorder(
        lambda request: httpx.Response(301, headers={"Location": "ftp://api.example.test/file"})
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "follow_redirects": True})
    )
    assert result.success is False
    assert "'ftp' URL" in (result.error or "")
    assert recorder.urls == ["https://api.example.test/"]
    assert result.output["status"] == 301


async def test_redirect_loops_stop():
    recorder = Recorder(lambda request: httpx.Response(302, headers={"Location": "/again"}))
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "follow_redirects": True})
    )
    assert result.success is False
    assert "stopped after 10 redirects" in (result.error or "")
    assert len(recorder.requests) == 11


# --- Egress and destinations -------------------------------------------------


async def test_an_egress_denial_propagates_as_the_step_error():
    recorder = Recorder(lambda request: httpx.Response(200))
    services = FakeServices(deny={"api.example.test"})
    with pytest.raises(EgressDenied, match="refused by the flow egress policy"):
        await _handler(recorder).execute(_ctx({"url": "https://api.example.test/"}, services))
    assert recorder.requests == []


async def test_a_redirect_cannot_launder_a_denied_destination():
    recorder = Recorder(
        lambda request: httpx.Response(302, headers={"Location": "https://other.example.test/"})
    )
    services = FakeServices(deny={"other.example.test"})
    with pytest.raises(EgressDenied):
        await _handler(recorder).execute(
            _ctx({"url": "https://api.example.test/", "follow_redirects": True}, services)
        )
    assert recorder.urls == ["https://api.example.test/"]


async def test_a_host_without_the_egress_gate_sends_nothing():
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/"}, ServicesWithoutEgress())
    )
    assert result.success is False
    assert "cannot apply the flow's network policy" in (result.error or "")
    assert recorder.urls == []


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://127.0.0.1:8080/", "loopback"),
        ("http://[::1]/", "loopback"),
        ("http://169.254.169.254/latest/meta-data/", "metadata"),
        ("http://[fd00:ec2::254]/", "metadata"),
        ("http://100.100.100.200/latest/meta-data/", "metadata"),
        ("http://169.254.10.1/", "link-local"),
        ("http://[fe80::1]/", "link-local"),
        ("http://0.0.0.0/", "unspecified"),
        ("http://[::]/", "unspecified"),
        ("http://224.0.0.1/", "multicast"),
        ("http://[::ffff:127.0.0.1]/", "loopback"),
        ("https://loopback.example.test/", "resolves to 127.0.0.1"),
        ("https://metadata.example.test/", "metadata"),
        ("https://mixed.example.test/", "resolves to 127.0.0.1"),
    ],
)
async def test_internal_destinations_are_refused_before_any_connection(url, reason):
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(_ctx({"url": url}))
    assert result.success is False
    assert "refused to send a request" in (result.error or "")
    assert reason in (result.error or "")
    assert recorder.requests == []
    assert result.output["status"] is None
    assert result.output["ok"] is False
    assert result.output["data"] is None and result.output["data_truncated"] is False
    assert "failed" in result.summary


@pytest.mark.parametrize(
    ("address", "blocked"),
    [
        ("10.0.0.1", False),
        ("192.168.1.1", False),
        ("fd12::1", False),
        ("8.8.8.8", False),
        ("127.5.5.5", True),
        ("0.1.2.3", True),
        ("255.255.255.255", True),
        ("ff02::1", True),
        ("fe80::1%eth0", True),
        ("100.100.100.200", True),
        ("100.64.0.1", False),
    ],
)
def test_blocked_address_reason(address, blocked):
    assert (security.blocked_address_reason(address) is not None) is blocked


async def test_a_name_that_does_not_resolve_fails_cleanly():
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(_ctx({"url": "https://nowhere.example.test/"}))
    assert result.success is False
    assert "cannot resolve host nowhere.example.test" in (result.error or "")


# --- Size, time and sensitivity ----------------------------------------------


async def test_a_declared_length_over_the_limit_fails_without_reading():
    served: list[int] = []

    async def chunks() -> AsyncIterator[bytes]:
        served.append(1)
        yield b"x" * 2048

    recorder = Recorder(
        lambda request: httpx.Response(200, content=chunks(), headers={"Content-Length": "2048"})
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "max_response_bytes": 1024})
    )
    assert result.success is False
    # The declared length is refused: the message names it, and nothing was read.
    assert result.error == (
        "the response body (2048 bytes) is larger than Max Response Size (1024 bytes); "
        "raise Max Response Size or request less"
    )
    assert served == []
    assert result.output["status"] == 200
    assert "body" in result.output and result.output["body"] == ""


async def test_a_streamed_body_over_the_limit_stops_reading():
    served: list[int] = []

    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(100):
            served.append(1)
            yield b"y" * 512

    recorder = Recorder(lambda request: httpx.Response(200, content=chunks()))
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "max_response_bytes": 2000})
    )
    assert result.success is False
    assert "larger than Max Response Size (2000 bytes)" in (result.error or "")
    # Reading stopped soon after the limit instead of draining the stream.
    assert len(served) < 10


async def test_a_head_response_declaring_a_large_body_is_fine():
    recorder = Recorder(
        lambda request: httpx.Response(200, headers={"Content-Length": "999999999"})
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "method": "HEAD", "max_response_bytes": 10})
    )
    assert result.success is True, result.error
    assert result.output["size_bytes"] == 0


async def test_a_slow_response_times_out():
    async def slow(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200)

    recorder = Recorder(slow)
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "request_timeout_seconds": 1})
    )
    assert result.success is False
    assert result.error == "the request timed out after 1 s"


async def test_sensitive_mode_keeps_the_response_out_of_output_and_evidence():
    raw = b'{"token": "issued-token-value"}'
    recorder = Recorder(
        lambda request: httpx.Response(
            200, content=raw, headers={"Content-Type": "application/json", "X-Kind": "token"}
        )
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/token", "method": "POST", "sensitive": True})
    )
    assert result.success is True, result.error
    assert "issued-token-value" not in _everything(result)
    out = result.output
    assert {"body", "body_truncated", "data", "data_truncated", "extracted"}.isdisjoint(out)
    assert out["status"] == 200 and out["headers"]["x-kind"] == "token"
    assert out["size_bytes"] == len(raw)
    assert out["body_sha256"] == hashlib.sha256(raw).hexdigest()
    assert "body_preview" not in result.evidence[0]["content_json"]


# --- Pagination --------------------------------------------------------------


def _pages(next_links: dict[str, str | None]) -> Recorder:
    """Pages keyed by path; each lists its path as an item and links to the next."""

    def respond(request: httpx.Request) -> httpx.Response:
        key = request.url.path + (f"?{request.url.query.decode()}" if request.url.query else "")
        return _json_response(
            {"count": 3, "next": next_links[key], "results": [{"page": key}]},
        )

    return Recorder(respond)


async def test_pages_are_followed_and_their_items_concatenated():
    recorder = _pages(
        {
            "/items": "https://api.example.test/items?page=2",
            "/items?page=2": "/items?page=3",
            "/items?page=3": None,
        }
    )
    services = FakeServices()
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "auth_type": "bearer",
                "auth_secret": SECRET_REF,
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 10,
                "extract": {"count": "count", "last": "results[-1].page"},
            },
            services,
        )
    )
    assert result.success is True, result.error
    assert recorder.urls == [
        "https://api.example.test/items",
        "https://api.example.test/items?page=2",
        "https://api.example.test/items?page=3",
    ]
    # Every page carries the credentials and walks the gate.
    assert all(r.headers["authorization"] == f"Bearer {SECRET_VALUE}" for r in recorder.requests)
    assert len(services.gated) == 3
    out = result.output
    assert out["pages"] == 3 and out["more_pages"] is False
    assert out["data"]["results"] == [
        {"page": "/items"},
        {"page": "/items?page=2"},
        {"page": "/items?page=3"},
    ]
    # The first page's other fields are kept.
    assert out["data"]["next"] == "https://api.example.test/items?page=2"
    assert out["extracted"] == {"count": 3, "last": "/items?page=3"}
    assert "(3 pages," in result.summary


async def test_max_pages_caps_the_pages_fetched():
    recorder = _pages(
        {
            "/items": "/items?page=2",
            "/items?page=2": "/items?page=3",
            "/items?page=3": None,
        }
    )
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 2,
            }
        )
    )
    assert result.success is True, result.error
    assert len(recorder.requests) == 2
    assert result.output["pages"] == 2
    assert result.output["more_pages"] is True
    assert len(result.output["data"]["results"]) == 2


async def test_a_next_page_on_another_host_is_refused():
    recorder = _pages({"/items": "https://other.example.test/items?page=2"})
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 5,
            }
        )
    )
    assert result.success is False
    assert "refused the next-page URL of page 1" in (result.error or "")
    assert recorder.urls == ["https://api.example.test/items"]


@pytest.mark.parametrize(
    ("respond", "fragment"),
    [
        (lambda r: httpx.Response(200, text="not json"), "is not JSON"),
        (lambda r: _json_response({"results": {"a": 1}}), "has no list at paginate_items"),
        (lambda r: _json_response({"results": [], "next": 5}), "not a URL"),
    ],
    ids=["not-json", "not-a-list", "next-not-a-string"],
)
async def test_a_malformed_page_fails_the_step(respond, fragment):
    result = await _handler(Recorder(respond)).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 5,
            }
        )
    )
    assert result.success is False
    assert fragment in (result.error or "")


async def test_a_failing_page_reports_its_own_response():
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.query:
            return _json_response({"error": "rate limited"}, 429)
        return _json_response({"next": "/items?page=2", "results": [1]})

    result = await _handler(Recorder(respond)).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 5,
            }
        )
    )
    assert result.success is False
    assert result.error == "page 2 answered HTTP 429 is not in expected_status 200-299"
    assert result.output["status"] == 429
    assert result.output["data"] == {"error": "rate limited"}
    assert result.output["pages"] == 2


async def test_the_size_limit_counts_every_page():
    def respond(request: httpx.Request) -> httpx.Response:
        nxt = None if request.url.query else "/items?page=2"
        return _json_response({"next": nxt, "results": ["z" * 400]})

    result = await _handler(Recorder(respond)).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 5,
                "max_response_bytes": 600,
            }
        )
    )
    assert result.success is False
    assert "summed over the pages" in (result.error or "")


# --- Validation --------------------------------------------------------------


def _errors(config: dict[str, Any]) -> list[str]:
    return HttpRequestHandler().validate_config(config)


@pytest.mark.parametrize(
    ("config", "fragment"),
    [
        ({}, "url"),
        ({"url": "ftp://api.example.test/"}, "must start with http:// or https://"),
        ({"url": "file:///etc/passwd"}, "must start with http:// or https://"),
        ({"url": "api.example.test/x"}, "must start with http:// or https://"),
        ({"url": "https://user:pw@api.example.test/"}, "must not carry credentials"),
        ({"url": "ftp://{{ inputs.host }}/"}, "must start with http:// or https://"),
        ({"url": "https://a.test/", "method": "TRACE"}, "method"),
        (
            {"url": "https://a.test/", "method": "POST", "json_body": {"a": 1}, "text_body": "x"},
            "cannot both be set",
        ),
        ({"url": "https://a.test/", "json_body": {"a": 1}}, "GET request sends no body"),
        ({"url": "https://a.test/", "method": "HEAD", "text_body": "x"}, "sends no body"),
        ({"url": "https://a.test/", "method": "POST", "json_body": "{nope"}, "not valid JSON"),
        ({"url": "https://a.test/", "expected_status": "2xx"}, "expected_status"),
        ({"url": "https://a.test/", "expected_status": "200-700"}, "expected_status"),
        ({"url": "https://a.test/", "request_timeout_seconds": 0}, "request_timeout_seconds"),
        ({"url": "https://a.test/", "max_response_bytes": 17 * 1024 * 1024}, "max_response"),
        ({"url": "https://a.test/", "headers": {"Bad Name": "x"}}, "not a valid header name"),
        ({"url": "https://a.test/", "headers": {"Host": "x"}}, "the step sets it"),
        ({"url": "https://a.test/", "headers": {"X-A": "a\r\nB: c"}}, "line breaks"),
        ({"url": "https://a.test/", "auth_type": "bearer"}, "'auth_secret' is required"),
        (
            {"url": "https://a.test/", "auth_type": "basic", "auth_secret": "x"},
            "'auth_username' is required",
        ),
        (
            {
                "url": "https://a.test/",
                "auth_type": "basic",
                "auth_secret": "x",
                "auth_username": "a:b",
            },
            "colon",
        ),
        (
            {
                "url": "https://a.test/",
                "auth_type": "bearer",
                "auth_secret": "x",
                "headers": {"authorization": "Bearer y"},
            },
            "Authentication sets it",
        ),
        (
            {
                "url": "https://a.test/",
                "auth_type": "header",
                "auth_secret": "x",
                "auth_header_name": "Content-Length",
            },
            "auth_header_name",
        ),
        ({"url": "https://a.test/", "ca_bundle": "not a certificate"}, "PEM"),
        ({"url": "https://a.test/", "extract": {"1bad": "a"}}, "'extract' name"),
        ({"url": "https://a.test/", "extract": {"a": "a..b"}}, "'extract.a'"),
        ({"url": "https://a.test/", "extract": {"a": "a"}, "sensitive": True}, "sensitive"),
        ({"url": "https://a.test/", "paginate_next": "next"}, "paginate_items"),
        (
            {"url": "https://a.test/", "paginate_next": "next", "paginate_items": "r"},
            "'max_pages' above 1",
        ),
        ({"url": "https://a.test/", "max_pages": 3}, "paginate_next"),
        (
            {
                "url": "https://a.test/",
                "method": "POST",
                "paginate_next": "next",
                "paginate_items": "r",
                "max_pages": 3,
            },
            "GET method",
        ),
        ({"url": "https://a.test/", "max_pages": 101}, "max_pages"),
    ],
)
def test_config_validation_errors(config, fragment):
    errors = _errors(config)
    assert any(fragment in error for error in errors), errors


def test_a_header_error_never_echoes_the_value():
    errors = _errors({"url": "https://a.test/", "headers": {"X-Key": "hidden-value\n"}})
    assert errors and not any("hidden-value" in e for e in errors)


@pytest.mark.parametrize(
    "config",
    [
        {"url": "https://api.example.test/"},
        {"url": "{{ inputs.base_url }}/items"},
        {"url": "https://{{ inputs.host }}/items"},
        {"url": "https://a.test/", "method": "POST", "json_body": '{"a": "{{ inputs.a }}"}'},
        {"url": "https://a.test/", "method": "POST", "json_body": "{{ steps.a.output.data }}"},
        {"url": "https://a.test/", "method": "POST", "json_body": "   "},
        {"url": "https://a.test/", "auth_type": "bearer", "auth_secret": SECRET_REF},
        {"url": "https://a.test/", "ca_bundle": SECRET_REF},
        {"url": "https://a.test/", "ca_bundle": "{{ secret('x') }}"},
        {"url": "https://a.test/", "ca_bundle": "junk", "verify_tls": False},
        {"url": "https://a.test/", "headers": {"X-A": "{{ inputs.value }}"}},
        {"url": "https://a.test/", "auth_type": "none", "auth_secret": "stale"},
        {
            "url": "https://a.test/",
            "paginate_next": "$.links.next",
            "paginate_items": "data",
            "max_pages": 100,
        },
    ],
)
def test_valid_configs(config):
    assert _errors(config) == []


async def test_a_rendered_value_is_checked_again_before_sending():
    """A template passes save-time validation; its rendering must hold up too."""
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "method": "POST", "json_body": "{not json"})
    )
    assert result.success is False
    assert "not valid JSON" in (result.error or "")
    assert recorder.requests == []


# --- Client settings ---------------------------------------------------------


def _spy_client(monkeypatch) -> list[dict[str, Any]]:
    """Record the options the handler builds its client with."""
    seen: list[dict[str, Any]] = []
    real_client = httpx.AsyncClient

    def client(**kwargs):
        seen.append(dict(kwargs))
        kwargs["transport"] = httpx.MockTransport(lambda request: httpx.Response(200))
        return real_client(**kwargs)

    monkeypatch.setattr(request_module.httpx, "AsyncClient", client)
    return seen


async def test_the_client_ignores_the_worker_environment_and_follows_no_redirects_itself(
    monkeypatch,
):
    seen = _spy_client(monkeypatch)
    result = await HttpRequestHandler().execute(_ctx({"url": "https://api.example.test/"}))
    assert result.success is True, result.error
    (options,) = seen
    assert options["trust_env"] is False
    assert options["follow_redirects"] is False
    assert options["verify"] is True


async def test_a_ca_bundle_replaces_the_default_trust_store(monkeypatch):
    import ssl

    import certifi

    pem = Path(certifi.where()).read_text(encoding="ascii")
    first = pem[pem.index("-----BEGIN CERTIFICATE-----") :]
    first = first[: first.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")]
    services = FakeServices(secrets={"vault://orgs/acme/secrets/ca": first})
    seen = _spy_client(monkeypatch)
    result = await HttpRequestHandler().execute(
        _ctx(
            {"url": "https://api.example.test/", "ca_bundle": "vault://orgs/acme/secrets/ca"},
            services,
        )
    )
    assert result.success is True, result.error
    verify = seen[0]["verify"]
    assert isinstance(verify, ssl.SSLContext)
    assert len(verify.get_ca_certs()) == 1
    assert services.resolved == [
        ("{{ secret('vault://orgs/acme/secrets/ca') }}", "http.request.ca_bundle")
    ]

    seen.clear()
    await HttpRequestHandler().execute(
        _ctx({"url": "https://api.example.test/", "ca_bundle": first, "verify_tls": False})
    )
    assert seen[0]["verify"] is False


def _private_ca_pem(name: str = "Org Private Root") -> str:
    """A self-signed CA certificate no public trust store holds."""
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


class OrgTrustServices(FakeServices):
    """A host that also serves the run organization's trusted CAs."""

    def __init__(self, org_pem: str = "", *, error: BaseException | None = None, **kwargs: Any):
        super().__init__(**kwargs)
        self.org_pem = org_pem
        self.error = error
        self.trust_calls = 0

    async def trusted_ca_certificates(self) -> str:
        self.trust_calls += 1
        if self.error is not None:
            raise self.error
        return self.org_pem


def _subjects(context: ssl.SSLContext) -> set[str]:
    names = set()
    for cert in context.get_ca_certs():
        for rdn in cert.get("subject", ()):
            names.update(value for key, value in rdn if key == "commonName")
    return names


async def test_the_organization_cas_join_the_default_trust_store(monkeypatch):
    import certifi

    services = OrgTrustServices(_private_ca_pem())
    seen = _spy_client(monkeypatch)
    result = await HttpRequestHandler().execute(
        _ctx({"url": "https://api.example.test/"}, services)
    )
    assert result.success is True, result.error
    verify = seen[0]["verify"]
    assert isinstance(verify, ssl.SSLContext)
    assert "Org Private Root" in _subjects(verify)
    # The public authorities stay trusted too: the default store is extended, not replaced.
    public = ssl.create_default_context(cafile=certifi.where())
    assert len(verify.get_ca_certs()) == len(public.get_ca_certs()) + 1


async def test_a_ca_bundle_pins_its_cas_over_the_organization_list(monkeypatch):
    bundle = _private_ca_pem("Pinned Root")
    services = OrgTrustServices(_private_ca_pem())
    seen = _spy_client(monkeypatch)
    result = await HttpRequestHandler().execute(
        _ctx({"url": "https://api.example.test/", "ca_bundle": bundle}, services)
    )
    assert result.success is True, result.error
    verify = seen[0]["verify"]
    assert _subjects(verify) == {"Pinned Root"}
    assert services.trust_calls == 0


@pytest.mark.parametrize("services", [FakeServices(), OrgTrustServices("")])
async def test_without_organization_cas_the_client_verifies_as_before(monkeypatch, services):
    seen = _spy_client(monkeypatch)
    result = await HttpRequestHandler().execute(
        _ctx({"url": "https://api.example.test/"}, services)
    )
    assert result.success is True, result.error
    assert seen[0]["verify"] is True


async def test_an_unavailable_organization_list_sends_nothing():
    services = OrgTrustServices(error=RuntimeError("database unavailable"))
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(_ctx({"url": "https://api.example.test/"}, services))
    assert result.success is False
    assert result.error == "Could not load the organization's trusted CAs: database unavailable"
    assert recorder.requests == []


async def test_a_ca_bundle_reference_without_a_certificate_fails():
    services = FakeServices(secrets={"vault://orgs/acme/secrets/ca": "just text"})
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(
        _ctx(
            {"url": "https://api.example.test/", "ca_bundle": "vault://orgs/acme/secrets/ca"},
            services,
        )
    )
    assert result.success is False
    assert "ca_bundle holds no PEM certificate" in (result.error or "")
    assert recorder.requests == []


class _JsonHandler(http.server.BaseHTTPRequestHandler):
    """Answers every GET with a small JSON document."""

    def do_GET(self) -> None:  # noqa: N802 - http.server's naming
        body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - signature
        pass


@pytest.fixture
def local_server() -> Iterator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _JsonHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


async def test_a_real_request_ignores_proxy_settings_of_the_worker(monkeypatch, local_server):
    """With trust_env on, these variables would send the request to a dead proxy."""
    monkeypatch.setattr(security, "blocked_address_reason", lambda address: None)
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://192.0.2.1:9")
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    services = FakeServices()
    result = await HttpRequestHandler().execute(
        _ctx({"url": f"{local_server}/v1/ping?x=1", "request_timeout_seconds": 5}, services)
    )
    assert result.success is True, result.error
    assert result.output["data"] == {"path": "/v1/ping?x=1"}
    assert services.gated[0][0] == "127.0.0.1"


async def test_the_loopback_refusal_applies_to_a_real_server(local_server):
    result = await HttpRequestHandler().execute(_ctx({"url": f"{local_server}/"}))
    assert result.success is False
    assert "loopback" in (result.error or "")


# --- Paths -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "parts"),
    [
        ("a", ("a",)),
        ("a.b[0].c", ("a", "b", 0, "c")),
        ("$.a.b", ("a", "b")),
        ("$", ()),
        ("[0].id", (0, "id")),
        ("$[-1]", (-1,)),
        ("a[\"b.c\"]['d e']", ("a", "b.c", "d e")),
        ("items.0.name", ("items", "0", "name")),
    ],
)
def test_parse_path(path, parts):
    assert parse_path(path) == parts


@pytest.mark.parametrize("path", ["", "a..b", "a[", "a[x]", "$a", "a.b c", "a[0]b"])
def test_parse_path_rejects_malformed_paths(path):
    with pytest.raises(PathError):
        parse_path(path)


def test_get_path_returns_none_for_anything_missing():
    data = {"a": [{"b": 1}, {"b": 2}], "c": None}
    assert get_path(data, parse_path("a[1].b")) == 2
    assert get_path(data, parse_path("a[-1].b")) == 2
    assert get_path(data, parse_path("a.0.b")) == 1
    assert get_path(data, parse_path("a[5].b")) is None
    assert get_path(data, parse_path("a.b")) is None
    assert get_path(data, parse_path("c.d")) is None
    assert get_path(data, parse_path("$")) == data


def test_replace_at():
    data = {"a": {"items": [1]}}
    assert replace_at(data, parse_path("a.items"), [1, 2]) == {"a": {"items": [1, 2]}}
    assert replace_at([0, 1], parse_path("[1]"), 5) == [0, 5]
    assert replace_at({"x": 1}, (), [9]) == [9]
    with pytest.raises(PathError):
        replace_at({"a": 1}, parse_path("b.c"), 1)


# --- Review follow-ups: compression, short secrets, pagination edges ----------


def _streamed(data: bytes, chunk: int = 4096) -> AsyncIterator[bytes]:
    """``data`` as a streamed body, the way a network response arrives."""

    async def chunks() -> AsyncIterator[bytes]:
        for start in range(0, len(data), chunk):
            yield data[start : start + chunk]

    return chunks()


def _gzip(data: bytes) -> bytes:
    return gzip.compress(data)


def _deflate(data: bytes, *, raw: bool = False) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS if raw else zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


@pytest.mark.parametrize(
    ("encoding", "encode"),
    [
        ("gzip", _gzip),
        ("deflate", _deflate),
        ("deflate", lambda data: _deflate(data, raw=True)),
    ],
    ids=["gzip", "deflate", "raw-deflate"],
)
async def test_compressed_bodies_are_decoded_by_the_step(encoding, encode):
    payload = json.dumps({"items": list(range(50))}).encode()
    recorder = Recorder(
        lambda request: httpx.Response(
            200, content=_streamed(encode(payload)), headers={"Content-Encoding": encoding}
        )
    )
    result = await _handler(recorder).execute(_ctx({"url": "https://api.example.test/"}))
    assert result.success is True, result.error
    assert result.output["data"] == {"items": list(range(50))}
    assert result.output["size_bytes"] == len(payload)
    assert recorder.requests[0].headers["accept-encoding"] == "gzip, deflate"


async def test_a_compressed_body_cannot_expand_past_the_limit(monkeypatch):
    bomb = _gzip(b"\0" * (8 * 1024 * 1024))
    assert len(bomb) < 64 * 1024
    produced: list[int] = []
    real_decompressobj = zlib.decompressobj

    class Tracking:
        """Records the size of every block the step's decompressor produces."""

        def __init__(self, *args: Any) -> None:
            self._inner = real_decompressobj(*args)

        def decompress(self, data: bytes, max_length: int = 0) -> bytes:
            out = self._inner.decompress(data, max_length)
            produced.append(len(out))
            return out

        def __getattr__(self, name: str) -> Any:
            return getattr(self._inner, name)

    monkeypatch.setattr(request_module.zlib, "decompressobj", Tracking)
    recorder = Recorder(
        lambda request: httpx.Response(
            200, content=_streamed(bomb), headers={"Content-Encoding": "gzip"}
        )
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "max_response_bytes": 4096})
    )
    assert result.success is False
    assert "larger than Max Response Size (4096 bytes)" in (result.error or "")
    # Decompression stopped at the budget instead of inflating the whole body.
    assert produced and max(produced) <= 4097
    assert sum(produced) <= 4097


async def test_an_encoding_the_step_does_not_decode_fails_the_step():
    recorder = Recorder(
        lambda request: httpx.Response(
            200, content=_streamed(b"xyz"), headers={"Content-Encoding": "br"}
        )
    )
    result = await _handler(recorder).execute(_ctx({"url": "https://api.example.test/"}))
    assert result.success is False
    assert "content encoding 'br'" in (result.error or "")


async def test_a_corrupt_compressed_body_fails_the_step():
    recorder = Recorder(
        lambda request: httpx.Response(
            200, content=_streamed(b"not gzip at all"), headers={"Content-Encoding": "gzip"}
        )
    )
    result = await _handler(recorder).execute(_ctx({"url": "https://api.example.test/"}))
    assert result.success is False
    assert "not valid gzip data" in (result.error or "")


async def test_a_secret_too_short_to_redact_is_refused_before_sending():
    recorder = Recorder(lambda request: httpx.Response(200))
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "auth_type": "bearer", "auth_secret": "abc"})
    )
    assert result.success is False
    assert "shorter than 4 characters" in (result.error or "")
    assert "abc" not in _everything(result)
    assert recorder.requests == []


async def test_a_blank_next_page_link_ends_pagination():
    recorder = _pages({"/items": "   "})
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 5,
            }
        )
    )
    assert result.success is True, result.error
    assert recorder.urls == ["https://api.example.test/items"]
    assert result.output["more_pages"] is False


async def test_a_next_page_link_back_to_a_fetched_page_stops_pagination():
    recorder = _pages({"/items": "/items?page=2", "/items?page=2": "/items"})
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 5,
            }
        )
    )
    assert result.success is False
    assert "page 2 links back to a page already fetched" in (result.error or "")
    assert len(recorder.requests) == 2


async def test_a_redirect_off_the_first_origin_is_refused_while_paginating():
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.example.test" and request.url.query:
            return httpx.Response(302, headers={"Location": "https://other.example.test/x"})
        if request.url.host == "other.example.test":
            return _json_response({"next": None, "results": ["foreign"]})
        return _json_response({"next": "/items?page=2", "results": ["first"]})

    recorder = Recorder(respond)
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 5,
                "follow_redirects": True,
                "expected_status": "200-299",
            }
        )
    )
    assert result.success is False
    assert "refused a redirect to https://other.example.test while paginating" in (
        result.error or ""
    )
    assert all(r.url.host == "api.example.test" for r in recorder.requests)


# ── credentials over plain HTTP ────────────────────────────────────────────────


@pytest.mark.parametrize("auth_type", ["bearer", "basic", "header"])
async def test_credentials_are_never_sent_to_a_plain_http_url_by_default(auth_type):
    recorder = Recorder(lambda request: httpx.Response(200))
    services = FakeServices()
    config = {
        "url": "http://api.example.test/v1/me",
        "auth_type": auth_type,
        "auth_secret": SECRET_REF,
        "auth_username": "svc",
    }
    result = await _handler(recorder).execute(_ctx(config, services))
    assert result.success is False
    assert "Authentication needs an https:// URL" in (result.error or "")
    assert recorder.urls == []
    assert services.resolved == []  # refused before the secret is even resolved


async def test_allow_insecure_auth_sends_credentials_over_http():
    recorder = Recorder(lambda request: httpx.Response(200))
    config = {
        "url": "http://api.example.test/v1/me",
        "auth_type": "bearer",
        "auth_secret": SECRET_REF,
        "allow_insecure_auth": True,
    }
    result = await _handler(recorder).execute(_ctx(config, FakeServices()))
    assert result.success is True, result.error
    assert recorder.requests[0].headers["authorization"] == f"Bearer {SECRET_VALUE}"


def test_a_templated_url_is_checked_for_http_once_rendered():
    handler = HttpRequestHandler()
    saved = {"url": "{{ vars.api_base }}/v1/me", "auth_type": "bearer", "auth_secret": SECRET_REF}
    assert handler.validate_config(saved) == []
    rendered = {**saved, "url": "http://api.example.test/v1/me"}
    assert any("https://" in error for error in handler.validate_config(rendered))
    # Without credentials a plain http:// URL stays fine.
    assert handler.validate_config({"url": "http://api.example.test/v1/me"}) == []


# --- Host names, redirects, bodies and output size ----------------------------


async def test_an_idna_host_is_checked_under_the_name_the_connection_uses(monkeypatch):
    """httpx dials the xn-- name; its Unicode form may encode to another name entirely."""
    looked_up = resolve_like_getaddrinfo(
        monkeypatch,
        {
            # What the Unicode form (straße) becomes under the resolver's older IDNA rules.
            "strasse.example.test": ["192.0.2.10"],
            # The name the connection dials.
            "xn--strae-oqa.example.test": ["169.254.169.254"],
        },
    )
    recorder = Recorder(lambda request: httpx.Response(200, text="ami-id"))
    services = FakeServices()
    result = await _handler(recorder).execute(
        _ctx({"url": "http://xn--strae-oqa.example.test/latest/meta-data/"}, services)
    )
    assert result.success is False
    assert "resolves to 169.254.169.254, a cloud instance metadata address" in (result.error or "")
    assert recorder.requests == []
    assert looked_up == ["xn--strae-oqa.example.test"]
    assert services.gated == [("xn--strae-oqa.example.test", 80, "tcp", "http request")]


async def test_a_redirect_to_an_idna_host_is_checked_under_the_name_the_connection_uses(
    monkeypatch,
):
    looked_up = resolve_like_getaddrinfo(
        monkeypatch,
        {
            "api.example.test": ["192.0.2.10"],
            "strasse.example.test": ["192.0.2.20"],
            "xn--strae-oqa.example.test": ["127.0.0.1"],
        },
    )
    location = "https://straße.example.test/".encode()
    recorder = Recorder(lambda request: httpx.Response(302, headers=[(b"Location", location)]))
    services = FakeServices()
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "follow_redirects": True}, services)
    )
    assert result.success is False
    assert "resolves to 127.0.0.1, a loopback address" in (result.error or "")
    assert recorder.urls == ["https://api.example.test/"]
    assert looked_up == ["api.example.test", "xn--strae-oqa.example.test"]
    assert [host for host, *_ in services.gated] == looked_up


@pytest.mark.parametrize(
    "url", ["https://bücher.example.test/items", "https://xn--bcher-kva.example.test/items"]
)
async def test_every_page_from_an_idna_host_checks_the_name_it_connects_to(monkeypatch, url):
    looked_up = resolve_like_getaddrinfo(
        monkeypatch, {"xn--bcher-kva.example.test": ["192.0.2.40"]}
    )

    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.query:
            return _json_response({"next": None, "results": [2]})
        return _json_response({"next": "/items?page=2", "results": [1]})

    recorder = Recorder(respond)
    services = FakeServices()
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": url,
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 5,
            },
            services,
        )
    )
    assert result.success is True, result.error
    connected = [request.url.raw_host.decode("ascii") for request in recorder.requests]
    assert connected == ["xn--bcher-kva.example.test"] * 2
    assert looked_up == connected
    assert [host for host, *_ in services.gated] == connected


@pytest.mark.parametrize("host", ["a..example.test", "a" * 64 + ".example.test"])
async def test_the_resolver_refusing_a_host_name_is_a_refusal(monkeypatch, host):
    """The worker's resolver raises UnicodeError for an empty or overlong label."""
    monkeypatch.setattr(security, "resolve_host", REAL_RESOLVE_HOST)
    with pytest.raises(security.RequestRefused, match="not a valid host name"):
        await security.check_destination(host, 443)


async def test_a_redirect_to_an_invalid_host_name_fails_the_step_with_its_output(monkeypatch):
    resolve_like_getaddrinfo(monkeypatch, {"api.example.test": ["192.0.2.10"]})
    recorder = Recorder(
        lambda request: httpx.Response(302, headers={"Location": "https://a..example.test/"})
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "follow_redirects": True})
    )
    assert result.success is False
    assert "cannot resolve host a..example.test: not a valid host name" in (result.error or "")
    assert recorder.urls == ["https://api.example.test/"]
    # The output and evidence are kept: the refused hop follows the 302.
    meta = result.evidence[0]["content_json"]
    assert [request["status"] for request in meta["requests"]] == [302, None]
    assert result.output["status"] is None and result.output["data_truncated"] is False
    assert meta["error"] == result.error


def test_numbers_written_for_text_settings_are_valid():
    config = {
        "url": "https://api.example.test/",
        "expected_status": 201,
        "query": {"limit": 100},
        "headers": {"X-Count": 5},
    }
    assert _errors(config) == []


async def test_numbers_written_for_text_settings_are_sent_as_their_text():
    recorder = Recorder(lambda request: httpx.Response(201))
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/",
                "expected_status": 201,
                "query": {"limit": 100},
                "headers": {"X-Count": 5},
            }
        )
    )
    assert result.success is True, result.error
    (request,) = recorder.requests
    assert request.url.params["limit"] == "100"
    assert request.headers["x-count"] == "5"


@pytest.mark.parametrize("location", ["http://[::1/x", "https://api.example.test:port/"])
async def test_without_follow_redirects_a_malformed_location_is_still_the_response(location):
    recorder = Recorder(
        lambda request: httpx.Response(302, headers={"Location": location}, text="moved")
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/login", "expected_status": "200-399"})
    )
    assert result.success is True, result.error
    assert result.output["status"] == 302 and result.output["ok"] is True
    assert result.output["headers"]["location"] == location
    assert result.output["body"] == "moved"
    assert recorder.urls == ["https://api.example.test/login"]


async def test_a_followed_redirect_with_a_malformed_location_fails_with_its_status():
    recorder = Recorder(
        lambda request: httpx.Response(302, headers={"Location": "http://[::1/x"}, text="moved")
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/login", "follow_redirects": True})
    )
    assert result.success is False
    assert (result.error or "").startswith(
        "cannot follow the HTTP 302 redirect: its Location header is not a valid URL ("
    )
    assert result.output["status"] == 302 and result.output["ok"] is False
    assert result.output["headers"]["location"] == "http://[::1/x"
    assert "-> 302, failed (" in result.summary
    assert recorder.urls == ["https://api.example.test/login"]


@pytest.mark.parametrize(
    ("encoding", "encode"),
    [
        ("gzip", _gzip),
        ("deflate", _deflate),
        ("deflate", lambda data: _deflate(data, raw=True)),
    ],
    ids=["gzip", "deflate", "raw-deflate"],
)
@pytest.mark.parametrize("chunk", [7, 4096])
async def test_a_compressed_body_cut_short_fails_the_step(encoding, encode, chunk):
    payload = json.dumps({"items": list(range(300))}).encode()
    cut = encode(payload)[:-30]
    recorder = Recorder(
        lambda request: httpx.Response(
            200, content=_streamed(cut, chunk), headers={"Content-Encoding": encoding}
        )
    )
    result = await _handler(recorder).execute(_ctx({"url": "https://api.example.test/"}))
    assert result.success is False
    assert result.error == f"the response body ended before its {encoding} data was complete"
    assert result.output["status"] == 200 and result.output["ok"] is False


@pytest.mark.parametrize("chunk", [5, 4096])
async def test_a_gzip_body_of_several_members_is_decoded_whole(chunk):
    payload = json.dumps({"items": list(range(50))}).encode()
    body = _gzip(payload[:20]) + _gzip(payload[20:60]) + _gzip(payload[60:]) + b"\0" * 4
    recorder = Recorder(
        lambda request: httpx.Response(
            200, content=_streamed(body, chunk), headers={"Content-Encoding": "gzip"}
        )
    )
    result = await _handler(recorder).execute(_ctx({"url": "https://api.example.test/"}))
    assert result.success is True, result.error
    assert result.output["data"] == {"items": list(range(50))}
    assert result.output["size_bytes"] == len(payload)


async def test_gzip_members_share_the_size_budget():
    body = _gzip(b"a" * 3000) + _gzip(b"b" * 3000)
    recorder = Recorder(
        lambda request: httpx.Response(
            200, content=_streamed(body), headers={"Content-Encoding": "gzip"}
        )
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "max_response_bytes": 4096})
    )
    assert result.success is False
    assert "larger than Max Response Size (4096 bytes)" in (result.error or "")


@pytest.mark.parametrize(
    "content_type", [None, "application/json", "application/json; charset=UTF-8"]
)
async def test_a_json_body_starting_with_a_utf8_byte_order_mark_is_parsed(content_type):
    raw = b"\xef\xbb\xbf" + json.dumps({"id": 7, "name": "café"}).encode()
    headers = {"Content-Type": content_type} if content_type else {}
    recorder = Recorder(lambda request: httpx.Response(200, content=raw, headers=headers))
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "extract": {"id": "id"}})
    )
    assert result.success is True, result.error
    assert result.output["data"] == {"id": 7, "name": "café"}
    assert result.output["extracted"] == {"id": 7}
    assert result.output["size_bytes"] == len(raw)


async def test_a_body_failure_is_not_ok_even_with_an_expected_status():
    recorder = Recorder(lambda request: httpx.Response(200, content=_streamed(b"x" * 100)))
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "max_response_bytes": 10})
    )
    assert result.success is False
    assert result.output["status"] == 200
    assert result.output["ok"] is False
    assert result.metrics["status"] == 200 and result.metrics["ok"] is False
    assert result.summary.startswith("GET https://api.example.test/ -> 200, failed (")


@pytest.mark.parametrize(("status", "method"), [(307, "POST"), (308, "PUT"), (301, "PATCH")])
async def test_a_redirect_that_would_send_the_body_to_another_origin_is_refused(status, method):
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.example.test":
            return httpx.Response(
                status, headers={"Location": "https://other.example.test/collect"}
            )
        return httpx.Response(200)

    recorder = Recorder(respond)
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/login",
                "method": method,
                "follow_redirects": True,
                "json_body": {"username": "svc", "password": "hunter2-not-for-elsewhere"},
            }
        )
    )
    assert result.success is False
    assert (result.error or "").startswith(
        f"refused to follow the HTTP {status} redirect to https://other.example.test: it "
        "would send the request body to another scheme, host or port"
    )
    assert recorder.urls == ["https://api.example.test/login"]
    assert result.output["status"] == status
    assert "hunter2" not in _everything(result)


async def test_a_redirect_repeats_the_body_on_its_origin_and_drops_it_with_a_get():
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(307, headers={"Location": "/login/v2"})
        if request.url.path == "/login/v2":
            return httpx.Response(303, headers={"Location": "https://other.example.test/done"})
        return httpx.Response(200)

    recorder = Recorder(respond)
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/login",
                "method": "POST",
                "follow_redirects": True,
                "json_body": {"username": "svc"},
            }
        )
    )
    assert result.success is True, result.error
    assert [request.method for request in recorder.requests] == ["POST", "POST", "GET"]
    assert recorder.bodies == [b'{"username":"svc"}', b'{"username":"svc"}', b""]


@pytest.mark.parametrize(
    ("auth", "secret", "echoed"),
    [
        ({"auth_type": "bearer"}, "abc/def-ghij-0001", "abc\\/def-ghij-0001"),
        ({"auth_type": "bearer"}, 'tok"en\\value-01', 'tok\\"en\\\\value-01'),
        (
            {"auth_type": "basic", "auth_username": "svc"},
            "pässwörd-1234",
            "p\\u00e4ssw\\u00f6rd-1234",
        ),
        (
            {"auth_type": "basic", "auth_username": "svc"},
            "pass/wörd\tx-1",
            "pass\\/wörd\\tx-1",
        ),
    ],
    ids=["escaped-slash", "escaped-quote-and-backslash", "unicode-escapes", "mixed"],
)
async def test_a_secret_the_response_repeats_json_escaped_is_redacted(auth, secret, echoed):
    services = FakeServices(secrets={SECRET_REF: secret})
    raw = ('{"echo":"' + echoed + '"}').encode()
    assert json.loads(raw)["echo"] == secret
    recorder = Recorder(
        lambda request: httpx.Response(
            200, content=raw, headers={"Content-Type": "application/json"}
        )
    )
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "auth_secret": SECRET_REF, **auth}, services)
    )
    assert result.success is True, result.error
    body = result.output["body"]
    preview = result.evidence[0]["content_json"]["body_preview"]
    assert echoed not in body and echoed not in preview
    assert body == preview == '{"echo":"' + security.REDACTED + '"}'
    assert result.output["data"] == {"echo": security.REDACTED}


@pytest.mark.parametrize(
    "limit", ["MAX_BODY_OUTPUT_CHARS", "EVIDENCE_PREVIEW_CHARS"], ids=["body", "evidence-preview"]
)
async def test_a_secret_crossing_the_preview_cut_is_redacted(limit):
    secret = "super-secret-api-credential-123456"
    services = FakeServices(secrets={SECRET_REF: secret})
    # The secret starts just before the cut and ends one character after it.
    text = "x" * (getattr(request_module, limit) - len(secret) + 1) + secret
    recorder = Recorder(
        lambda request: httpx.Response(200, text=text, headers={"Content-Type": "text/plain"})
    )
    result = await _handler(recorder).execute(
        _ctx(
            {"url": "https://api.example.test/", "auth_type": "bearer", "auth_secret": SECRET_REF},
            services,
        )
    )
    assert result.success is True, result.error
    body = result.output["body"]
    preview = result.evidence[0]["content_json"]["body_preview"]
    for shown in (body, preview):
        assert secret[:-1] not in shown and secret[:12] not in shown
    assert body.endswith(security.REDACTED)


async def test_a_numeric_secret_the_response_repeats_as_a_number_is_redacted():
    services = FakeServices(secrets={SECRET_REF: "123456789"})
    recorder = Recorder(
        lambda request: httpx.Response(200, json={"token": 123456789, "count": 42, "ok": True})
    )
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": "https://api.example.test/",
                "auth_type": "bearer",
                "auth_secret": SECRET_REF,
                "extract": {"token": "token", "count": "count"},
            },
            services,
        )
    )
    assert result.success is True, result.error
    assert result.output["data"] == {"token": security.REDACTED, "count": 42, "ok": True}
    assert result.output["extracted"] == {"token": security.REDACTED, "count": 42}
    assert "123456789" not in _everything(result)


@pytest.mark.parametrize(
    ("start", "target"),
    [
        ("https://api.example.test/start", "http://api.example.test/next"),
        ("http://api.example.test/start", "https://api.example.test/next"),
        ("https://api.example.test:8443/start", "http://api.example.test:8443/next"),
        ("http://api.example.test:8443/start", "https://api.example.test:8443/next"),
    ],
    ids=["https-to-http", "http-to-https", "https-to-http-same-port", "http-to-https-same-port"],
)
async def test_a_redirect_that_only_changes_the_scheme_drops_credentials_and_headers(start, target):
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": target})
        return httpx.Response(200)

    recorder = Recorder(respond)
    result = await _handler(recorder).execute(
        _ctx(
            {
                "url": start,
                "follow_redirects": True,
                "auth_type": "bearer",
                "auth_secret": SECRET_REF,
                "allow_insecure_auth": True,
                "headers": {"Accept": "application/json", "X-Tenant": "t1"},
            }
        )
    )
    assert result.success is True, result.error
    assert recorder.urls == [start, target]
    first, hop = recorder.requests
    assert first.headers["authorization"] == f"Bearer {SECRET_VALUE}"
    assert first.headers["x-tenant"] == "t1"
    assert "authorization" not in hop.headers
    assert "x-tenant" not in hop.headers
    assert hop.headers["accept"] == "application/json"


def _json_of_size(size: int) -> dict[str, Any]:
    """A JSON object whose compact UTF-8 form is exactly ``size`` bytes."""
    overhead = len(json.dumps({"id": 7, "pad": ""}, separators=(",", ":")))
    value = {"id": 7, "pad": "x" * (size - overhead)}
    assert len(json.dumps(value, separators=(",", ":")).encode()) == size
    return value


@pytest.mark.parametrize(("extra", "truncated"), [(0, False), (1, True)], ids=["at", "over"])
async def test_data_over_the_output_limit_is_left_out_but_still_extracted(extra, truncated):
    payload = _json_of_size(request_module.MAX_DATA_OUTPUT_BYTES + extra)
    recorder = Recorder(lambda request: _json_response(payload))
    result = await _handler(recorder).execute(
        _ctx({"url": "https://api.example.test/", "extract": {"id": "id"}})
    )
    assert result.success is True, result.error
    assert result.output["data_truncated"] is truncated
    assert result.output["data"] == (None if truncated else payload)
    assert result.output["extracted"] == {"id": 7}


async def test_merged_pages_over_the_output_limit_leave_data_out():
    def respond(request: httpx.Request) -> httpx.Response:
        page = 2 if request.url.query else 1
        items = [{"id": page * 10000 + i, "name": "x" * 20} for i in range(1000)]
        return _json_response({"next": None if page == 2 else "/items?page=2", "results": items})

    result = await _handler(Recorder(respond)).execute(
        _ctx(
            {
                "url": "https://api.example.test/items",
                "paginate_next": "next",
                "paginate_items": "results",
                "max_pages": 5,
                "extract": {"last": "results[-1].id", "first": "results[0].id"},
            }
        )
    )
    assert result.success is True, result.error
    assert result.output["pages"] == 2
    assert result.output["data"] is None and result.output["data_truncated"] is True
    assert result.output["extracted"] == {"last": 20999, "first": 10000}


def _connect_error_from(tls_error: ssl.SSLError) -> httpx.ConnectError:
    """A ConnectError with the chain httpx and httpcore build around a TLS failure.

    httpcore re-raises the ``ssl`` error ``from None``, so it survives only as the
    ``__context__`` of httpcore's error, which httpx then raises its own error from.
    """
    try:
        try:
            try:
                raise tls_error
            except ssl.SSLError as exc:
                raise httpcore.ConnectError(str(exc)) from None
        except httpcore.ConnectError as exc:
            raise httpx.ConnectError(str(exc)) from exc
    except httpx.ConnectError as exc:
        return exc


def _tls_failure() -> httpx.ConnectError:
    """The client does not trust the server's certificate."""
    return _connect_error_from(
        ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
        )
    )


def _tls_dropped() -> httpx.ConnectError:
    """The peer closed the connection during the handshake."""
    return _connect_error_from(ssl.SSLEOFError(8, "EOF occurred in violation of protocol"))


@pytest.mark.parametrize(
    ("url", "raise_error", "transient", "sent"),
    [
        ("https://api.example.test/x", httpx.ConnectError("refused"), True, False),
        ("https://api.example.test/x", httpx.ReadTimeout("slow"), True, False),
        ("https://api.example.test/x", httpx.RemoteProtocolError("dropped"), True, False),
        # A failed TLS handshake is a ConnectError too, but the next attempt meets the
        # same certificate; a peer that dropped the handshake may be back.
        ("https://api.example.test/x", _tls_failure(), False, False),
        ("https://api.example.test/x", _tls_dropped(), True, False),
        # Refused by the step itself: nothing was sent, and trying again changes nothing.
        ("https://loopback.example.test/x", None, False, False),
        ("https://api.example.test/x", None, False, True),
    ],
)
async def test_send_says_when_the_request_may_not_have_reached_the_server(
    url: str, raise_error: Exception | None, transient: bool, sent: bool
):
    """``transient`` is what another handler decides retries by, not the error's wording."""

    def respond(request: httpx.Request) -> httpx.Response:
        if raise_error is not None:
            raise raise_error
        return httpx.Response(200, json={"ok": True})

    handler = HttpRequestHandler(transport=httpx.MockTransport(respond))
    response = await handler.send(
        cast(HandlerServices, FakeServices()), HttpRequestConfig(url=url, method="GET")
    )
    assert response.transient is transient
    assert response.result.success is sent


async def test_a_plain_http_request_is_sent_when_the_organization_list_is_unavailable(
    monkeypatch,
):
    """Plain HTTP needs no trust; an HTTPS hop it is redirected to trusts the default store."""
    seen = _spy_client(monkeypatch)
    services = OrgTrustServices(error=RuntimeError("database unavailable"))
    result = await HttpRequestHandler().execute(_ctx({"url": "http://api.example.test/"}, services))
    assert result.success is True, result.error
    assert seen[0]["verify"] is True
