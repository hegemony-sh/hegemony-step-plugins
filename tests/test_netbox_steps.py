# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Behaviour of the NetBox steps (hegemony-steps-netbox).

NetBox is a function behind an httpx mock transport, and host names resolve
through a fake resolver, so the destination checks of ``http.request``'s
client run for real without touching the network.
"""

from __future__ import annotations

import asyncio
import email.utils
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs

import httpx
import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_step_sdk.docs import check_page, load_docs_bundle
from hegemony_steps_http import security
from hegemony_steps_netbox import ALL_HANDLERS, register
from hegemony_steps_netbox.ipam import AllocateHandler, ReleaseHandler
from hegemony_steps_netbox.render_config import RenderConfigHandler
from hegemony_steps_netbox.request import NetBoxRequestHandler

TOKEN_REF = "vault://orgs/acme/secrets/netbox/token"
V1_TOKEN = "0123456789abcdef0123456789abcdef01234567"
V2_TOKEN = "nbt_abcdef123456.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
NETBOX = "https://netbox.example.test"


@pytest.fixture(autouse=True)
def fake_dns(monkeypatch):
    async def resolve(host: str, port: int) -> list[str]:
        if host == "netbox.example.test":
            return ["192.0.2.10"]
        raise OSError(f"[Errno -2] Name or service not known: {host}")

    monkeypatch.setattr(security, "resolve_host", resolve)


@pytest.fixture(autouse=True)
def no_waiting(monkeypatch):
    """Retries wait without sleeping; the waits are recorded."""
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", sleep)
    return waits


class FakeServices:
    def __init__(self, token: str = V1_TOKEN, deny: set[str] | None = None) -> None:
        self.token = token
        self.deny = deny or set()
        self.gated: list[tuple[str, int]] = []

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        return self.token if ref == "{{ secret('" + TOKEN_REF + "') }}" else ""

    async def enforce_egress(
        self, host: str, port: int | None = None, *, proto: str | None = None, kind: str = ""
    ) -> None:
        self.gated.append((host, port or 0))
        if host in self.deny:
            raise PermissionError(f"{kind} to {host}:{port} refused by the flow egress policy")


class NetBox:
    """Answers requests from ``respond``; records every request with its JSON body."""

    def __init__(self, respond: Callable[[httpx.Request, Any], httpx.Response]) -> None:
        self.respond = respond
        self.requests: list[httpx.Request] = []
        self.bodies: list[Any] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        raw = await request.aread()
        body = json.loads(raw) if raw else None
        self.requests.append(request)
        self.bodies.append(body)
        return self.respond(request, body)

    @property
    def calls(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.requests]

    def query(self, index: int = -1) -> dict[str, list[str]]:
        return parse_qs(self.requests[index].url.query.decode())


def _json(payload: Any, status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(status, json=payload, headers=headers)


def _ctx(config: dict[str, Any], services: Any = None, **extra: Any) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        services=cast(HandlerServices, services or FakeServices()),
        **extra,
    )


def _config(**fields: Any) -> dict[str, Any]:
    return {"url": NETBOX, "token": TOKEN_REF, **fields}


async def _run(handler_class: type, netbox: NetBox, config: dict[str, Any], **ctx: Any):
    handler = handler_class(transport=httpx.MockTransport(netbox))
    return await handler.execute(_ctx(config, **ctx))


def _everything(result) -> str:
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


DEVICE = {"id": 33, "name": "web-01", "status": {"value": "active"}, "site": {"slug": "paris"}}


# --- Registration and docs ----------------------------------------------------


def test_the_wheel_registers_four_handlers_with_their_metadata():
    registered: list[Any] = []

    class _Registry:
        api_version = 1

        def register_handler_type(self, handler_class: type) -> None:
            registered.append(handler_class)

    register(_Registry())
    assert [cls.handler_id for cls in registered] == [
        "netbox.request",
        "netbox.ipam.allocate",
        "netbox.ipam.release",
        "netbox.render_config",
    ]
    for cls in registered:
        assert cls.category == "NetBox"
        assert cls.raw_config_keys == frozenset({"token", "ca_bundle"})
        assert cls.container_backed is False
    assert RenderConfigHandler.targeting.roles is True
    assert NetBoxRequestHandler.targeting.roles is False


def test_every_handler_has_a_valid_docs_page_and_the_readme_names_it():
    bundle = load_docs_bundle("hegemony_steps_netbox")
    assert set(bundle) == {cls.handler_id for cls in ALL_HANDLERS}
    for doc_id, text in bundle.items():
        assert check_page(doc_id, text) == []
    readme = (
        Path(__file__).resolve().parents[1] / "plugins" / "steps_netbox" / "README.md"
    ).read_text()
    for cls in ALL_HANDLERS:
        assert f"`{cls.handler_id}`" in readme


# --- netbox.request: reads --------------------------------------------------------


async def test_get_by_id_sends_a_v1_token_and_returns_the_object():
    netbox = NetBox(lambda request, body: _json(DEVICE))
    result = await _run(
        NetBoxRequestHandler, netbox, _config(endpoint="/api/dcim/devices/", object_id=33)
    )
    assert result.success, result.error
    assert netbox.calls == ["GET /api/dcim/devices/33/"]
    assert netbox.requests[0].headers["authorization"] == f"Token {V1_TOKEN}"
    assert netbox.requests[0].headers["accept"] == "application/json"
    assert result.output["object"] == DEVICE
    assert result.output["id"] == 33
    assert result.summary == "get dcim/devices/33: object 33"


@pytest.mark.parametrize(
    ("token", "token_type", "header"),
    [
        (V2_TOKEN, "auto", f"Bearer {V2_TOKEN}"),
        (V1_TOKEN, "auto", f"Token {V1_TOKEN}"),
        (V2_TOKEN, "v1", f"Token {V2_TOKEN}"),
        (V1_TOKEN, "v2", f"Bearer {V1_TOKEN}"),
    ],
)
async def test_the_token_header_follows_the_token_type(token, token_type, header):
    netbox = NetBox(lambda request, body: _json(DEVICE))
    handler = NetBoxRequestHandler(transport=httpx.MockTransport(netbox))
    config = _config(endpoint="dcim/devices", object_id="33", token_type=token_type)
    result = await handler.execute(_ctx(config, FakeServices(token=token)))
    assert result.success, result.error
    assert netbox.requests[0].headers["authorization"] == header


async def test_get_by_filters_returns_the_single_match():
    netbox = NetBox(lambda request, body: _json({"count": 1, "results": [DEVICE]}))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(
            endpoint="dcim/devices", filters={"name": "web-01", "tag": ["a", "b"], "managed": True}
        ),
    )
    assert result.success, result.error
    assert netbox.query() == {
        "name": ["web-01"],
        "tag": ["a", "b"],
        "managed": ["true"],
        "limit": ["2"],
    }
    assert result.output["object"] == DEVICE
    assert result.output["found"] is True


async def test_get_by_filters_fails_on_no_match_or_many_and_missing_ok_allows_none():
    none = NetBox(lambda request, body: _json({"count": 0, "results": []}))
    result = await _run(
        NetBoxRequestHandler, none, _config(endpoint="dcim/devices", filters={"name": "x"})
    )
    assert not result.success
    assert result.error == "no NetBox object matches the filters"

    result = await _run(
        NetBoxRequestHandler,
        none,
        _config(endpoint="dcim/devices", filters={"name": "x"}, missing_ok=True),
    )
    assert result.success
    assert result.output["found"] is False
    assert result.output["object"] is None

    many = NetBox(lambda request, body: _json({"count": 5, "results": [DEVICE, DEVICE]}))
    result = await _run(
        NetBoxRequestHandler, many, _config(endpoint="dcim/devices", filters={"site": "paris"})
    )
    assert not result.success
    assert "5 NetBox objects match the filters" in result.error


async def test_get_by_id_missing_ok_turns_a_404_into_found_false():
    netbox = NetBox(lambda request, body: _json({"detail": "Not found."}, 404))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(endpoint="dcim/devices", object_id="9", missing_ok=True),
    )
    assert result.success, result.error
    assert result.output["found"] is False
    assert result.output["object"] is None
    failed = await _run(
        NetBoxRequestHandler, netbox, _config(endpoint="dcim/devices", object_id="9")
    )
    assert not failed.success
    assert failed.error == "NetBox has no such object or endpoint (HTTP 404): Not found."


async def test_list_pages_by_offset_and_stops_at_max_results():
    devices = [{"id": n, "name": f"d{n}"} for n in range(1, 2501)]

    def respond(request, body):
        q = parse_qs(request.url.query.decode())
        offset, limit = int(q["offset"][0]), int(q["limit"][0])
        # A next link on another origin, as NetBox behind a TLS proxy may send: never followed.
        return _json(
            {
                "count": len(devices),
                "next": "http://internal:8080/api/dcim/devices/?offset=1",
                "results": devices[offset : offset + limit],
            }
        )

    netbox = NetBox(respond)
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(action="list", endpoint="dcim/devices", max_results=2500),
    )
    assert result.success, result.error
    assert [netbox.query(i)["offset"] for i in range(3)] == [["0"], ["1000"], ["2000"]]
    assert result.output["returned"] == 2500
    assert result.output["count"] == 2500
    assert result.output["more"] is False
    assert result.output["ids"][:3] == [1, 2, 3]
    assert result.summary == "list dcim/devices: 2500 objects"

    netbox = NetBox(respond)
    result = await _run(
        NetBoxRequestHandler, netbox, _config(action="list", endpoint="dcim/devices", max_results=5)
    )
    assert result.output["returned"] == 5
    assert result.output["more"] is True
    assert netbox.query()["limit"] == ["5"]
    assert result.summary == "list dcim/devices: 5 objects of 2500"


async def test_a_large_list_is_left_out_of_the_output_but_extract_reads_it():
    devices = [{"id": n, "name": "x" * 200} for n in range(1, 501)]
    netbox = NetBox(lambda request, body: _json({"count": 500, "results": devices}))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(action="list", endpoint="dcim/devices", extract={"last": "[-1].id"}),
    )
    assert result.success, result.error
    assert result.output["objects"] is None
    assert result.output["data_truncated"] is True
    assert result.output["extracted"] == {"last": 500}
    assert len(result.output["ids"]) == 500


async def test_reads_are_retried_while_netbox_is_busy_and_writes_are_not(no_waiting):
    answers = iter([_json({}, 503, **{"Retry-After": "3"}), _json({}, 502), _json(DEVICE)])
    netbox = NetBox(lambda request, body: next(answers))
    result = await _run(
        NetBoxRequestHandler, netbox, _config(endpoint="dcim/devices", object_id="33")
    )
    assert result.success, result.error
    assert len(netbox.requests) == 3
    assert no_waiting == [3.0, 2]

    busy = NetBox(lambda request, body: _json({"detail": "busy"}, 503))
    result = await _run(
        NetBoxRequestHandler,
        busy,
        _config(action="create", endpoint="dcim/sites", data={"name": "x", "slug": "x"}),
    )
    assert not result.success
    assert len(busy.requests) == 1
    assert "HTTP 503" in result.error


@pytest.mark.parametrize(
    ("retry_after", "waits"),
    [
        ({"Retry-After": "0"}, [0.0]),
        ({"Retry-After": "999"}, [30]),
        ({"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}, [0.0]),
        ({"Retry-After": "soon"}, [1]),
        ({}, [1]),
    ],
    ids=["zero", "capped", "past-date", "unreadable", "missing"],
)
async def test_reads_wait_as_retry_after_asks_or_back_off(no_waiting, retry_after, waits):
    answers = iter([_json({}, 503, **retry_after), _json(DEVICE)])
    netbox = NetBox(lambda request, body: next(answers))
    result = await _run(
        NetBoxRequestHandler, netbox, _config(endpoint="dcim/devices", object_id="33")
    )
    assert result.success, result.error
    assert no_waiting == waits


async def test_reads_wait_until_a_retry_after_date(no_waiting):
    when = email.utils.formatdate(time.time() + 20, usegmt=True)
    answers = iter([_json({}, 429, **{"Retry-After": when}), _json(DEVICE)])
    netbox = NetBox(lambda request, body: next(answers))
    result = await _run(
        NetBoxRequestHandler, netbox, _config(endpoint="dcim/devices", object_id="33")
    )
    assert result.success, result.error
    assert len(no_waiting) == 1
    assert 15 < no_waiting[0] <= 20


class _CutShort(httpx.AsyncByteStream):
    """A body whose connection drops after the status and part of the body arrived."""

    async def __aiter__(self):
        yield b'{"id": 33,'
        raise httpx.ReadError("connection reset while reading")


async def test_reads_are_retried_when_the_body_drops_after_the_status_and_writes_are_not(
    no_waiting,
):
    def dropping() -> Callable[[httpx.Request, Any], httpx.Response]:
        calls = iter([True, False])

        def respond(request: httpx.Request, body: Any) -> httpx.Response:
            if next(calls, False):
                return httpx.Response(
                    200, stream=_CutShort(), headers={"content-type": "application/json"}
                )
            return _json(DEVICE if request.method == "GET" else {"id": 33})

        return respond

    netbox = NetBox(dropping())
    result = await _run(
        NetBoxRequestHandler, netbox, _config(endpoint="dcim/devices", object_id="33")
    )
    assert result.success, result.error
    assert len(netbox.requests) == 2
    assert result.metrics["requests"] == 2
    assert no_waiting == [1]

    netbox = NetBox(dropping())
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(
            action="update", endpoint="dcim/devices", object_id="33", data={"status": "offline"}
        ),
    )
    assert not result.success
    assert len(netbox.requests) == 1
    assert result.output["status"] == 200
    assert result.metrics["requests"] == 1


async def test_reads_are_retried_after_a_dropped_connection_and_writes_are_not(no_waiting):
    def flaky() -> Callable[[httpx.Request, Any], httpx.Response]:
        calls = iter([True, False])

        def respond(request: httpx.Request, body: Any) -> httpx.Response:
            if next(calls, False):
                raise httpx.ConnectError("connection refused", request=request)
            return _json(DEVICE if request.method == "GET" else {"id": 1}, 200)

        return respond

    netbox = NetBox(flaky())
    result = await _run(
        NetBoxRequestHandler, netbox, _config(endpoint="dcim/devices", object_id="33")
    )
    assert result.success, result.error
    assert len(netbox.requests) == 2

    netbox = NetBox(flaky())
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(action="update", endpoint="dcim/devices", object_id="33", data={"name": "x"}),
    )
    assert not result.success
    assert len(netbox.requests) == 1
    assert "ConnectError" in result.error


async def test_evidence_lists_every_request_and_keeps_previews_of_failed_ones_only():
    def respond(request: httpx.Request, body: Any) -> httpx.Response:
        offset = int(request.url.params.get("offset", "0"))
        if offset >= 4:
            return _json({"count": 5, "results": [DEVICE]}, 200)
        return _json({"count": 5, "results": [DEVICE, DEVICE]}, 200)

    result = await _run(
        NetBoxRequestHandler, NetBox(respond), _config(action="list", endpoint="dcim/devices")
    )
    assert result.success, result.error
    assert [e["name"] for e in result.evidence] == ["netbox"]
    requests = result.evidence[0]["content_json"]["requests"]
    assert [r["status"] for r in requests] == [200, 200, 200]
    assert all(set(r) == {"method", "url", "status", "elapsed_ms"} for r in requests)

    gone = NetBox(lambda request, body: _json({"detail": "Not found."}, 404))
    result = await _run(
        NetBoxRequestHandler, gone, _config(endpoint="dcim/devices", object_id="33")
    )
    assert not result.success
    assert [e["name"] for e in result.evidence] == ["http_request", "netbox"]
    assert "Not found." in result.evidence[0]["content_json"]["body_preview"]


async def test_a_redirect_names_its_location():
    netbox = NetBox(
        lambda request, body: httpx.Response(
            301, headers={"Location": "https://netbox.example.test/netbox/api/dcim/devices/33/"}
        )
    )
    result = await _run(
        NetBoxRequestHandler, netbox, _config(endpoint="dcim/devices", object_id="33")
    )
    assert not result.success
    assert result.error.startswith(
        "NetBox answered with a redirect (HTTP 301) to "
        "https://netbox.example.test/netbox/api/dcim/devices/33/"
    )
    assert "set NetBox URL" in result.error


async def test_a_token_http_request_refuses_is_named_by_the_netbox_setting():
    netbox = NetBox(lambda request, body: _json(DEVICE))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(endpoint="dcim/devices", object_id="33"),
        services=FakeServices(token="0123456789abcdef0123456789abcdéf"),
    )
    assert not result.success
    assert result.error.startswith("Invalid netbox.request config: token resolved to a value")
    assert "auth_secret" not in result.error
    assert netbox.requests == []
    # Nothing was sent, and the metric says so, as the netbox record does.
    assert result.metrics["requests"] == 0
    [record] = [e for e in result.evidence if e["name"] == "netbox"]
    assert record["content_json"]["requests"] == []


# --- netbox.request: writes ---------------------------------------------------------


async def test_create_sends_the_data_with_the_change_log_message():
    netbox = NetBox(lambda request, body: _json({"id": 7, **body}, 201))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(
            action="create",
            endpoint="dcim/sites",
            data='{"name": "Paris", "slug": "paris"}',
            changelog_message="Hegemony run r",
        ),
    )
    assert result.success, result.error
    assert netbox.calls == ["POST /api/dcim/sites/"]
    assert netbox.bodies[0] == {
        "name": "Paris",
        "slug": "paris",
        "changelog_message": "Hegemony run r",
    }
    assert result.output["id"] == 7


async def test_update_one_and_many():
    netbox = NetBox(
        lambda request, body: _json(body if isinstance(body, list) else {"id": 33, **body})
    )
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(
            action="update", endpoint="dcim/devices", object_id="33", data={"status": "offline"}
        ),
    )
    assert result.success, result.error
    assert netbox.calls == ["PATCH /api/dcim/devices/33/"]

    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(
            action="update",
            endpoint="dcim/devices",
            data=[{"id": 1, "status": "offline"}, {"id": 2, "status": "offline"}],
        ),
    )
    assert result.success, result.error
    assert netbox.calls[-1] == "PATCH /api/dcim/devices/"
    assert result.output["ids"] == [1, 2]


async def test_delete_one_many_and_already_gone():
    netbox = NetBox(lambda request, body: httpx.Response(204))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(action="delete", endpoint="ipam/ip-addresses", object_id="5"),
    )
    assert result.success, result.error
    assert netbox.calls == ["DELETE /api/ipam/ip-addresses/5/"]
    assert netbox.bodies[0] is None

    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(
            action="delete",
            endpoint="ipam/ip-addresses",
            data=[5, "6", {"id": 7}],
            changelog_message="m",
        ),
    )
    assert result.success, result.error
    assert netbox.bodies[-1] == [
        {"id": 5, "changelog_message": "m"},
        {"id": 6, "changelog_message": "m"},
        {"id": 7, "changelog_message": "m"},
    ]

    gone = NetBox(lambda request, body: _json({"detail": "Not found."}, 404))
    result = await _run(
        NetBoxRequestHandler,
        gone,
        _config(action="delete", endpoint="ipam/ip-addresses", object_id="5", missing_ok=True),
    )
    assert result.success, result.error
    assert result.output["found"] is False


async def test_post_to_a_route():
    netbox = NetBox(lambda request, body: _json({"content": "hostname web-01\n"}))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(
            action="post", endpoint="dcim/devices", object_id="33", route="render-config", data={}
        ),
    )
    assert result.success, result.error
    assert netbox.calls == ["POST /api/dcim/devices/33/render-config/"]
    assert result.output["object"] == {"content": "hostname web-01\n"}


async def test_a_branch_is_sent_as_a_header():
    netbox = NetBox(lambda request, body: _json(DEVICE))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(endpoint="dcim/devices", object_id="33", branch="td5smq0f"),
    )
    assert result.success, result.error
    assert netbox.requests[0].headers["x-netbox-branch"] == "td5smq0f"


# --- netbox.request: errors and safety ------------------------------------------------


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (
            400,
            {"name": ["This field is required."], "slug": ["Too long."]},
            "NetBox refused the request (HTTP 400): name: This field is required.; slug: Too long.",
        ),
        (
            400,
            [{}, {"name": ["Duplicate."]}],
            "NetBox refused the request (HTTP 400): item 2: name: Duplicate.",
        ),
        (
            401,
            {"detail": "Invalid token"},
            "NetBox did not accept the token (HTTP 401): Invalid token. Check API Token and Token Type",
        ),
        (
            403,
            {"detail": "You do not have permission to perform this action."},
            "the token may not do this in NetBox (HTTP 403): You do not have permission to perform this action.",
        ),
    ],
)
async def test_netbox_errors_carry_netboxs_message(status, payload, expected):
    netbox = NetBox(lambda request, body: _json(payload, status))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(action="create", endpoint="dcim/sites", data=[{"name": "a"}, {"name": "b"}]),
    )
    assert not result.success
    assert result.error == expected
    assert result.output["ok"] is False


async def test_the_token_never_appears_in_what_the_step_reports():
    netbox = NetBox(lambda request, body: _json({"detail": f"bad token {V1_TOKEN}"}, 400))
    result = await _run(
        NetBoxRequestHandler, netbox, _config(endpoint="dcim/devices", object_id="1")
    )
    assert not result.success
    assert V1_TOKEN not in _everything(result)
    assert "[redacted]" in result.error


async def test_plain_http_needs_allow_insecure_auth():
    netbox = NetBox(lambda request, body: _json(DEVICE))
    config = _config(url="http://netbox.example.test:8080", endpoint="dcim/devices", object_id="1")
    result = await _run(NetBoxRequestHandler, netbox, config)
    assert not result.success
    assert "needs an https:// NetBox URL" in result.error
    assert netbox.requests == []
    result = await _run(NetBoxRequestHandler, netbox, {**config, "allow_insecure_auth": True})
    assert result.success, result.error
    assert str(netbox.requests[0].url) == "http://netbox.example.test:8080/api/dcim/devices/1/"


async def test_an_egress_denial_propagates_as_the_step_error():
    services = FakeServices(deny={"netbox.example.test"})
    netbox = NetBox(lambda request, body: _json(DEVICE))
    handler = NetBoxRequestHandler(transport=httpx.MockTransport(netbox))
    with pytest.raises(PermissionError, match="refused by the flow egress policy"):
        await handler.execute(_ctx(_config(endpoint="dcim/devices", object_id="1"), services))
    assert services.gated == [("netbox.example.test", 443)]
    assert netbox.requests == []


async def test_a_host_without_the_egress_gate_sends_nothing():
    class NoGate:
        async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
            return V1_TOKEN

    netbox = NetBox(lambda request, body: _json(DEVICE))
    handler = NetBoxRequestHandler(transport=httpx.MockTransport(netbox))
    result = await handler.execute(_ctx(_config(endpoint="dcim/devices", object_id="1"), NoGate()))
    assert not result.success
    assert "cannot apply the flow's network policy" in (result.error or "")
    assert netbox.requests == []


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        ({"action": "create", "endpoint": "dcim/sites"}, "create needs Data"),
        (
            {"action": "update", "endpoint": "dcim/devices", "object_id": "1", "data": [{"id": 1}]},
            "a list in Data updates many objects at once",
        ),
        (
            {"action": "list", "endpoint": "dcim/devices", "filters": {"limit": "5"}},
            "must not set limit",
        ),
        ({"endpoint": "dcim devices", "object_id": "1"}, "'endpoint' must be a NetBox REST path"),
        (
            {"endpoint": "dcim/devices", "object_id": "abc"},
            "'object_id' must be a NetBox object ID",
        ),
        ({"action": "post", "endpoint": "dcim/devices"}, "post needs a Route"),
        ({"action": "list", "endpoint": "dcim/devices", "data": {"a": 1}}, "list sends no data"),
        ({"endpoint": "dcim/devices", "url": "https://netbox.example.test/api"}, "without /api"),
        (
            {"action": "get", "endpoint": "dcim/devices", "changelog_message": "x"},
            "get records no change",
        ),
    ],
)
def test_config_errors(fields, message):
    errors = NetBoxRequestHandler().validate_config(_config(**fields))
    assert any(message in error for error in errors), errors


def test_templated_values_pass_when_the_flow_is_saved():
    config = _config(
        url="{{ vars.NETBOX.url }}",
        endpoint="{{ inputs.endpoint }}",
        object_id="{{ steps.lookup.output.id }}",
        action="update",
        data='{"status": "{{ inputs.status }}"}',
    )
    assert NetBoxRequestHandler().validate_config(config) == []


@pytest.mark.parametrize(
    ("action", "data", "message"),
    [
        ("delete", {"id": 5}, "delete needs an Object ID, or a list in Data of object IDs"),
        ("delete", "5", "delete needs an Object ID, or a list in Data of object IDs"),
        ("update", [1, 2], "'data' item 1 must be an object with its id"),
        ("update", [{"name": "x"}], "'data' item 1 must be an object with its id"),
        ("update", {"name": "x"}, "update needs an Object ID, or a list in Data of objects"),
        ("delete", [{"name": "x"}], "'data' item 1 must be an object ID or an object with its id"),
        ("delete", [5, 0], "'data' item 2 must be an object ID or an object with its id"),
        ("delete", [True], "'data' item 1 must be an object ID or an object with its id"),
        ("delete", [], "the list in Data is empty: nothing to delete"),
    ],
)
def test_bulk_update_and_delete_data_is_checked_when_the_flow_is_saved(action, data, message):
    config = _config(action=action, endpoint="dcim/devices", data=data)
    errors = NetBoxRequestHandler().validate_config(config)
    assert any(message in error for error in errors), errors


def test_bulk_update_and_delete_accept_ids_objects_and_templates():
    handler = NetBoxRequestHandler()
    for action, data in [
        ("delete", [5, "6", {"id": 7}]),
        ("delete", ["{{ steps.find.output.id }}", {"id": "{{ inputs.id }}"}]),
        ("update", [{"id": 5, "status": "active"}, {"id": "6", "status": "offline"}]),
        ("update", "{{ steps.build.output.objects | tojson }}"),
    ]:
        config = _config(action=action, endpoint="dcim/devices", data=data)
        assert handler.validate_config(config) == [], (action, data)


@pytest.mark.parametrize("data", [{"id": 5}, "null"])
async def test_a_malformed_bulk_delete_sends_nothing(data):
    """An object in Data, or JSON null (a truncated list output rendered with tojson)."""
    netbox = NetBox(lambda request, body: httpx.Response(204))
    result = await _run(
        NetBoxRequestHandler,
        netbox,
        _config(action="delete", endpoint="dcim/devices", data=data, changelog_message="m"),
    )
    assert not result.success
    assert "delete needs an Object ID" in result.error
    assert netbox.requests == []


def test_json_null_in_data_is_refused_for_a_bulk_update_or_delete_when_saved():
    """A chained list rendered with tojson is null when that output was too large."""
    for action, message in (
        ("delete", "delete needs an Object ID, or a list in Data"),
        ("update", "update needs an Object ID, or a list in Data"),
    ):
        errors = NetBoxRequestHandler().validate_config(
            _config(action=action, endpoint="dcim/devices", data="null")
        )
        assert any(message in error for error in errors), (action, errors)


# --- netbox.ipam.allocate / release ---------------------------------------------------------


PREFIX = {"id": 7, "prefix": "10.20.0.0/24", "vrf": {"id": 3}}


async def test_allocate_takes_the_next_ip_from_a_prefix():
    def respond(request, body):
        if request.method == "GET":
            return _json(PREFIX)
        return _json({"id": 99, "address": "10.20.0.5/24", **body}, 201)

    netbox = NetBox(respond)
    result = await _run(
        AllocateHandler,
        netbox,
        _config(pool_id="7", data={"dns_name": "web-01.example.com"}, changelog_message="m"),
    )
    assert result.success, result.error
    assert netbox.calls == ["GET /api/ipam/prefixes/7/", "POST /api/ipam/prefixes/7/available-ips/"]
    assert netbox.bodies[1] == {"dns_name": "web-01.example.com", "changelog_message": "m"}
    assert result.output["allocated"] is True
    assert result.output["value"] == "10.20.0.5/24"
    assert result.output["id"] == 99


async def test_allocate_reuses_what_existing_filters_find_in_the_pool():
    def respond(request, body):
        if request.url.path == "/api/ipam/prefixes/7/":
            return _json(PREFIX)
        return _json({"count": 1, "results": [{"id": 42, "address": "10.20.0.9/24"}]})

    netbox = NetBox(respond)
    result = await _run(
        AllocateHandler,
        netbox,
        _config(pool_id="7", existing_filters={"dns_name": "web-01.example.com"}),
    )
    assert result.success, result.error
    assert netbox.calls == ["GET /api/ipam/prefixes/7/", "GET /api/ipam/ip-addresses/"]
    assert netbox.query() == {
        "dns_name": ["web-01.example.com"],
        "parent": ["10.20.0.0/24"],
        "vrf_id": ["3"],
        "limit": ["2"],
        "offset": ["0"],
    }
    assert result.output["allocated"] is False
    assert result.output["value"] == "10.20.0.9/24"


async def test_allocate_refuses_when_existing_filters_match_too_many():
    def respond(request, body):
        if request.url.path == "/api/ipam/prefixes/7/":
            return _json(PREFIX)
        return _json({"count": 2, "results": [{"id": 1}, {"id": 2}]})

    netbox = NetBox(respond)
    result = await _run(
        AllocateHandler, netbox, _config(pool_id="7", existing_filters={"tenant": "a"})
    )
    assert not result.success
    assert "Existing Filters match 2 objects, expected none or 1" in result.error
    assert all(r.method == "GET" for r in netbox.requests)


async def test_allocate_counts_existing_matches_past_a_capped_page():
    """NetBox's MAX_PAGE_SIZE may hold the page to one object while three match."""

    def respond(request, body):
        if request.url.path == "/api/ipam/prefixes/7/":
            return _json(PREFIX)
        return _json({"count": 3, "results": [{"id": 1, "address": "10.20.0.9/24"}]})

    netbox = NetBox(respond)
    result = await _run(
        AllocateHandler, netbox, _config(pool_id="7", existing_filters={"tenant": "a"})
    )
    assert not result.success
    assert "Existing Filters match 3 objects, expected none or 1" in result.error
    assert all(r.method == "GET" for r in netbox.requests)


async def test_allocate_finds_the_pool_by_filters_and_takes_a_prefix():
    def respond(request, body):
        if request.method == "GET":
            return _json({"count": 1, "results": [PREFIX]})
        return _json({"id": 5, "prefix": "10.20.0.16/28"}, 201)

    netbox = NetBox(respond)
    result = await _run(
        AllocateHandler,
        netbox,
        _config(
            allocate="prefix_from_prefix", pool_filters={"prefix": "10.20.0.0/24"}, prefix_length=28
        ),
    )
    assert result.success, result.error
    assert netbox.calls[-1] == "POST /api/ipam/prefixes/7/available-prefixes/"
    assert netbox.bodies[-1] == {"prefix_length": 28}
    assert result.output["value"] == "10.20.0.16/28"


async def test_allocate_reports_a_full_pool():
    def respond(request, body):
        if request.method == "GET":
            return _json(PREFIX)
        return _json(
            {
                "detail": "Insufficient space is available to accommodate the requested number of IPs (1)"
            },
            409,
        )

    result = await _run(AllocateHandler, NetBox(respond), _config(pool_id="7"))
    assert not result.success
    assert result.error.startswith("the pool has not enough free space")


def test_allocate_config_errors():
    errors = AllocateHandler().validate_config(_config(allocate="prefix_from_prefix"))
    assert "give either Pool ID or Pool Filters to find the pool" in errors
    assert "a prefix needs Prefix Length" in errors
    errors = AllocateHandler().validate_config(_config(pool_id="7", data=[{"a": 1}]))
    assert any("one JSON object" in error for error in errors)


async def test_release_by_id_and_already_gone():
    netbox = NetBox(lambda request, body: httpx.Response(204))
    result = await _run(ReleaseHandler, netbox, _config(object_id="99"))
    assert result.success, result.error
    assert netbox.calls == ["DELETE /api/ipam/ip-addresses/99/"]
    assert result.output["released"] == 1

    gone = NetBox(lambda request, body: _json({"detail": "Not found."}, 404))
    result = await _run(ReleaseHandler, gone, _config(object_id="99"))
    assert result.success, result.error
    assert result.output["released"] == 0
    result = await _run(ReleaseHandler, gone, _config(object_id="99", missing_ok=False))
    assert not result.success


async def test_release_by_filters_refuses_to_delete_more_than_max_objects():
    def respond(request, body):
        if request.method == "GET":
            return _json({"count": 2, "results": [{"id": 1, "vid": 10}, {"id": 2, "vid": 11}]})
        return httpx.Response(204)

    netbox = NetBox(respond)
    result = await _run(ReleaseHandler, netbox, _config(resource="vlan", filters={"name": "web"}))
    assert not result.success
    assert "nothing was released" in result.error
    assert all(r.method == "GET" for r in netbox.requests)

    netbox = NetBox(respond)
    result = await _run(
        ReleaseHandler, netbox, _config(resource="vlan", filters={"name": "web"}, max_objects=2)
    )
    assert result.success, result.error
    assert netbox.calls[-1] == "DELETE /api/ipam/vlans/"
    assert netbox.bodies[-1] == [{"id": 1}, {"id": 2}]
    assert result.output["values"] == [10, 11]


async def test_release_by_filters_counts_matches_past_a_capped_page():
    """A page NetBox capped below Max Objects + 1 still says how many match in all."""

    def respond(request, body):
        if request.method == "GET":
            return _json({"count": 5, "results": [{"id": 1, "vid": 10}, {"id": 2, "vid": 11}]})
        return httpx.Response(204)

    netbox = NetBox(respond)
    result = await _run(
        ReleaseHandler, netbox, _config(resource="vlan", filters={"name": "web"}, max_objects=2)
    )
    assert not result.success
    assert "Filters match 5 vlan objects, more than Max Objects (2)" in result.error
    assert all(r.method == "GET" for r in netbox.requests)


def _capped(objects: list[dict[str, Any]], *, page_size: int = 1, lose_after: int | None = None):
    """A list endpoint whose MAX_PAGE_SIZE is ``page_size``; pages by offset."""

    def page(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params.get("offset", "0"))
        limit = min(int(request.url.params.get("limit", "50")), page_size)
        results = objects[offset : offset + limit]
        if lose_after is not None and offset >= lose_after:
            results = []
        return _json({"count": len(objects), "results": results})

    return page


async def test_release_by_filters_reads_every_match_past_a_capped_page():
    vlans = [{"id": 1, "vid": 10}, {"id": 2, "vid": 11}, {"id": 3, "vid": 12}]
    page = _capped(vlans)
    netbox = NetBox(
        lambda request, body: page(request) if request.method == "GET" else httpx.Response(204)
    )
    result = await _run(
        ReleaseHandler, netbox, _config(resource="vlan", filters={"name": "web"}, max_objects=3)
    )
    assert result.success, result.error
    assert [netbox.query(i)["offset"] for i in range(3)] == [["0"], ["1"], ["2"]]
    assert netbox.calls[-1] == "DELETE /api/ipam/vlans/"
    assert netbox.bodies[-1] == [{"id": 1}, {"id": 2}, {"id": 3}]
    assert result.output["released"] == 3


async def test_release_by_filters_releases_nothing_when_the_matches_change_while_read():
    vlans = [{"id": 1, "vid": 10}, {"id": 2, "vid": 11}, {"id": 3, "vid": 12}]
    page = _capped(vlans, lose_after=1)
    netbox = NetBox(
        lambda request, body: page(request) if request.method == "GET" else httpx.Response(204)
    )
    result = await _run(
        ReleaseHandler, netbox, _config(resource="vlan", filters={"name": "web"}, max_objects=3)
    )
    assert not result.success
    assert "NetBox listed 1 of the 3 ipam/vlans objects that match" in result.error
    assert all(r.method == "GET" for r in netbox.requests)


def _shifting(before: list[dict[str, Any]], after: list[dict[str, Any]]):
    """A list endpoint of one object per page that changes from ``before`` to ``after``
    after its first page was read."""
    first, later = _capped(before), _capped(after)

    def page(request: httpx.Request) -> httpx.Response:
        return (first if request.url.params.get("offset", "0") == "0" else later)(request)

    return page


@pytest.mark.parametrize(
    ("after", "why"),
    [
        (
            [{"id": 0, "vid": 9}, {"id": 1, "vid": 10}, {"id": 2, "vid": 11}, {"id": 3, "vid": 12}],
            "grew",
        ),
        ([{"id": 1, "vid": 10}, {"id": 3, "vid": 12}], "shrank"),
    ],
)
async def test_release_by_filters_releases_nothing_when_the_pages_shift_while_read(after, why):
    """An insert or a delete between two pages shifts the next offsets.

    The count then differs from the first page's, and an insert also repeats an
    object; either way nothing is deleted, since the step cannot tell which
    objects match.
    """
    vlans = [{"id": 1, "vid": 10}, {"id": 2, "vid": 11}, {"id": 3, "vid": 12}]
    page = _shifting(vlans, after)
    netbox = NetBox(
        lambda request, body: page(request) if request.method == "GET" else httpx.Response(204)
    )
    result = await _run(
        ReleaseHandler, netbox, _config(resource="vlan", filters={"name": "web"}, max_objects=4)
    )
    assert not result.success, why
    assert "changed while the step read them" in result.error
    assert "run the step again" in result.error
    assert all(r.method == "GET" for r in netbox.requests)
    assert result.output["released"] == 0


async def test_release_by_filters_releases_nothing_when_netbox_gives_no_count():
    """A list answer without NetBox's count cannot say whether the page is every match."""
    vlans = [{"id": 1, "vid": 10}, {"id": 2, "vid": 11}, {"id": 3, "vid": 12}]

    def page(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params.get("offset", "0"))
        return _json({"results": vlans[offset : offset + 1]})

    netbox = NetBox(
        lambda request, body: page(request) if request.method == "GET" else httpx.Response(204)
    )
    result = await _run(
        ReleaseHandler, netbox, _config(resource="vlan", filters={"name": "web"}, max_objects=3)
    )
    assert not result.success
    assert "did not say how many ipam/vlans objects match" in result.error
    assert all(r.method == "GET" for r in netbox.requests)
    assert result.output["released"] == 0


async def test_allocate_reuses_nothing_when_the_pages_shift_while_read():
    """The same shift under Existing Filters: nothing is reused and nothing allocated."""
    addresses = [{"id": n, "address": f"10.20.0.{n}/24"} for n in (1, 2, 3)]
    page = _shifting(addresses, [{"id": 0, "address": "10.20.0.9/24"}, *addresses])

    def respond(request, body):
        if request.url.path == "/api/ipam/prefixes/7/":
            return _json(PREFIX)
        return page(request)

    netbox = NetBox(respond)
    result = await _run(
        AllocateHandler, netbox, _config(pool_id="7", count=3, existing_filters={"tenant": "a"})
    )
    assert not result.success
    assert "changed while the step read them" in result.error
    assert all(r.method == "GET" for r in netbox.requests)
    assert result.output["allocated"] is False


async def test_allocate_reuses_every_existing_match_past_a_capped_page():
    addresses = [
        {"id": 1, "address": "10.20.0.1/24"},
        {"id": 2, "address": "10.20.0.2/24"},
        {"id": 3, "address": "10.20.0.3/24"},
    ]
    page = _capped(addresses)

    def respond(request, body):
        if request.url.path == "/api/ipam/prefixes/7/":
            return _json(PREFIX)
        return page(request)

    netbox = NetBox(respond)
    result = await _run(
        AllocateHandler, netbox, _config(pool_id="7", count=3, existing_filters={"tenant": "a"})
    )
    assert result.success, result.error
    assert result.output["allocated"] is False
    assert result.output["values"] == ["10.20.0.1/24", "10.20.0.2/24", "10.20.0.3/24"]
    assert all(r.method == "GET" for r in netbox.requests)


async def test_allocate_keeps_the_search_for_an_earlier_asn_inside_the_range():
    asn_range = {"id": 4, "start": 65000, "end": 65099}

    def respond(request, body):
        if request.url.path == "/api/ipam/asn-ranges/4/":
            return _json(asn_range)
        return _json({"count": 1, "results": [{"id": 9, "asn": 65010}]})

    netbox = NetBox(respond)
    result = await _run(
        AllocateHandler,
        netbox,
        _config(allocate="asn_from_range", pool_id="4", existing_filters={"description": "web"}),
    )
    assert result.success, result.error
    query = netbox.query()
    assert query["asn__gte"] == ["65000"] and query["asn__lte"] == ["65099"]
    assert result.output["value"] == 65010


async def test_get_without_an_id_or_filters_reads_a_single_object_endpoint_only():
    status = NetBox(lambda request, body: _json({"netbox-version": "4.4.1", "plugins": {}}))
    result = await _run(NetBoxRequestHandler, status, _config(endpoint="status"))
    assert result.success, result.error
    assert result.output["object"]["netbox-version"] == "4.4.1"

    page = NetBox(lambda request, body: _json({"count": 2, "results": [DEVICE, DEVICE]}))
    result = await _run(NetBoxRequestHandler, page, _config(endpoint="dcim/devices"))
    assert not result.success
    assert "get reads one object, and dcim/devices answered with a list" in result.error
    assert result.output["object"] is None


# --- netbox.render_config ---------------------------------------------------------------------


def _device(name: str, external_id: str, provider: str = "netbox:main") -> dict[str, Any]:
    return {"id": f"uuid-{name}", "name": name, "provider_id": provider, "external_id": external_id}


async def test_render_config_renders_for_each_target_device():
    def respond(request, body):
        device_id = request.url.path.split("/")[4]
        return _json({"configtemplate": {"name": "base"}, "content": f"hostname d{device_id}\n"})

    netbox = NetBox(respond)
    result = await _run(
        RenderConfigHandler,
        netbox,
        _config(context={"change": "CHG1"}),
        target_devices_by_role={"fleet": [_device("web-01", "33"), _device("web-02", "34")]},
        target_roles=["fleet"],
    )
    assert result.success, result.error
    assert netbox.calls == [
        "POST /api/dcim/devices/33/render-config/",
        "POST /api/dcim/devices/34/render-config/",
    ]
    assert netbox.bodies[0] == {"change": "CHG1"}
    assert result.output["configs"] == {"web-01": "hostname d33\n", "web-02": "hostname d34\n"}
    assert [entry["template"] for entry in result.output["rendered"]] == ["base", "base"]
    rendered = [e for e in result.evidence if e.get("kind") == "cli_output"]
    assert [e["name"] for e in rendered] == [
        "Rendered configuration (web-01)",
        "Rendered configuration (web-02)",
    ]
    assert rendered[0]["device_id"] == "uuid-web-01"


async def test_render_config_keys_devices_that_share_a_name_by_id_and_reports_progress():
    progress: list[tuple[str, str | None]] = []

    async def emit(message: str, device_id: str | None, attrs: Any) -> bool:
        progress.append((message, device_id))
        return True

    def respond(request, body):
        device_id = request.url.path.split("/")[4]
        return _json({"content": f"hostname d{device_id}\n"})

    result = await _run(
        RenderConfigHandler,
        NetBox(respond),
        _config(),
        target_devices_by_role={
            "fleet": [
                _device("web-01", "33"),
                {**_device("web-01", "34"), "id": "uuid-web-01-lyon"},
                _device("db-01", "35"),
            ]
        },
        target_roles=["fleet"],
        _emit_progress=emit,
    )
    assert result.success, result.error
    assert set(result.output["configs"]) == {"web-01 (33)", "web-01 (34)", "db-01"}
    assert progress == [
        ("web-01 (33): rendered (1 of 3)", "uuid-web-01"),
        ("web-01 (34): rendered (2 of 3)", "uuid-web-01-lyon"),
        ("db-01: rendered (3 of 3)", "uuid-db-01"),
    ]


async def test_render_config_keys_stay_unique_when_a_device_is_named_like_a_key():
    def respond(request, body):
        device_id = request.url.path.split("/")[4]
        return _json({"content": f"hostname d{device_id}\n"})

    result = await _run(
        RenderConfigHandler,
        NetBox(respond),
        _config(),
        target_devices_by_role={
            "fleet": [
                _device("web", "33"),
                {**_device("web", "34"), "id": "uuid-web-lyon"},
                _device("web (33)", "35"),
            ]
        },
        target_roles=["fleet"],
    )
    assert result.success, result.error
    assert result.output["configs"] == {
        "web (33)": "hostname d33\n",
        "web (34)": "hostname d34\n",
        "web (33) #2": "hostname d35\n",
    }
    rendered = [e["name"] for e in result.evidence if e.get("kind") == "cli_output"]
    assert rendered[2] == "Rendered configuration (web (33) #2)"


async def test_render_config_keeps_going_when_one_device_fails():
    def respond(request, body):
        if "/34/" in request.url.path:
            return _json({"detail": "No config template found for this device."}, 400)
        return _json({"content": "ok\n"})

    result = await _run(
        RenderConfigHandler,
        NetBox(respond),
        _config(object_ids="33, 34"),
    )
    assert not result.success
    assert result.output["configs"] == {"33": "ok\n"}
    assert result.output["failed"][0]["id"] == 34
    assert "No config template found" in result.error


async def test_render_config_refuses_devices_it_cannot_map_to_netbox():
    netbox = NetBox(lambda request, body: _json({"content": ""}))
    result = await _run(
        RenderConfigHandler,
        netbox,
        _config(),
        target_devices_by_role={"fleet": [_device("lab-1", "", provider="local")]},
        target_roles=["fleet"],
    )
    assert not result.success
    assert "does not come from a NetBox inventory provider" in result.error

    result = await _run(
        RenderConfigHandler,
        netbox,
        _config(),
        target_devices_by_role={
            "fleet": [_device("a", "1"), _device("b", "2", provider="netbox:other")]
        },
        target_roles=["fleet"],
    )
    assert not result.success
    assert "more than one inventory provider" in result.error
    assert netbox.requests == []


async def test_render_config_renders_virtual_machines_by_id():
    netbox = NetBox(lambda request, body: _json({"content": "vm\n"}))
    result = await _run(
        RenderConfigHandler, netbox, _config(object_type="virtual_machine", object_ids=["12"])
    )
    assert result.success, result.error
    assert netbox.calls == ["POST /api/virtualization/virtual-machines/12/render-config/"]
