# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Engine-API streaming pull for container.run.

The handler pulls via ``POST /images/create`` on the Docker daemon to stream
byte-accurate ``pull_progress`` events, and falls back to the plain
``docker pull`` CLI on any :class:`EnginePullError`. Covered here: the pure
pieces (reference parsing, endpoint resolution, auth-header construction,
progress aggregation), the streaming client over ``httpx.MockTransport``, and
the ``execute()``-level fallback wiring with mocked docker subprocesses.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerServices
from hegemony_steps_container.pull_progress import (
    EnginePullError,
    EnginePullUnsupported,
    PullProgressAggregator,
    build_registry_auth_header,
    parse_image_reference,
    resolve_engine_endpoint,
    stream_pull,
)
from hegemony_steps_container.run import RunContainerHandler

_DIGEST = f"sha256:{'0' * 64}"


@pytest.fixture(autouse=True)
def _isolate_docker_config(tmp_path_factory, monkeypatch) -> None:
    """Keep the host's own registry credentials out of these tests.

    ``build_registry_auth_header`` falls back to ``~/.docker/config.json``
    when the caller's env carries no ``DOCKER_CONFIG`` — that fallback is the
    point (it is how the handler matches what ``docker pull`` would send), but
    it makes any test that passes ``env={}`` depend on whether the machine
    happens to be logged into a registry. A CI runner that is logged into
    Docker Hub would otherwise turn the anonymous-pull assertions red.
    Tests that exercise credentials pass an explicit ``DOCKER_CONFIG``, which
    still wins over this isolation.
    """
    monkeypatch.setenv("HOME", str(tmp_path_factory.mktemp("docker-home")))


# --- parse_image_reference -------------------------------------------------


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        ("alpine", ("alpine", "latest")),
        ("alpine:3.20", ("alpine", "3.20")),
        ("python:3.12-slim", ("python", "3.12-slim")),
        ("localhost:5000/repo", ("localhost:5000/repo", "latest")),
        (
            "registry.example.com:5000/team/tool:v1",
            ("registry.example.com:5000/team/tool", "v1"),
        ),
        (f"repo@{_DIGEST}", ("repo", _DIGEST)),
        (f"repo:tag@{_DIGEST}", ("repo", _DIGEST)),
        (f"reg.io:5000/repo:tag@{_DIGEST}", ("reg.io:5000/repo", _DIGEST)),
    ],
)
def test_parse_image_reference(image: str, expected: tuple[str, str]) -> None:
    assert parse_image_reference(image) == expected


# --- resolve_engine_endpoint -----------------------------------------------


def test_resolve_endpoint_empty_targets_default_socket() -> None:
    endpoint = resolve_engine_endpoint("", {})
    assert endpoint.kind == "uds"
    assert endpoint.uds_path == "/var/run/docker.sock"
    assert endpoint.base_url == "http://docker"


def test_resolve_endpoint_unix_scheme_custom_path() -> None:
    endpoint = resolve_engine_endpoint("unix:///custom/docker.sock", {})
    assert endpoint.kind == "uds"
    assert endpoint.uds_path == "/custom/docker.sock"


def test_resolve_endpoint_plain_tcp() -> None:
    endpoint = resolve_engine_endpoint("tcp://dind:2375", {})
    assert endpoint.kind == "tcp"
    assert endpoint.uds_path is None
    assert endpoint.base_url == "http://dind:2375"


@pytest.mark.parametrize(
    ("docker_host", "env"),
    [
        ("tcp://dind:2376", {"DOCKER_TLS_VERIFY": "1"}),
        ("ssh://user@host", {}),
        ("npipe:////./pipe/docker_engine", {}),
        ("fd://", {}),
        ("https://daemon:2376", {}),
        ("tcp://", {}),
    ],
)
def test_resolve_endpoint_unsupported_shapes(docker_host: str, env: dict[str, str]) -> None:
    with pytest.raises(EnginePullUnsupported):
        resolve_engine_endpoint(docker_host, env)


# --- PullProgressAggregator ------------------------------------------------


def test_aggregator_two_layer_pull_math() -> None:
    agg = PullProgressAggregator()
    # The repo/tag banner carries an id (the tag) but is not a layer.
    agg.feed({"status": "Pulling from library/alpine", "id": "3.20"})
    assert agg.snapshot().layers_total == 0

    agg.feed({"status": "Pulling fs layer", "id": "aaa"})
    agg.feed({"status": "Pulling fs layer", "id": "bbb"})
    agg.feed({"status": "Already exists", "id": "ccc"})
    agg.feed(
        {"status": "Downloading", "id": "aaa", "progressDetail": {"current": 50, "total": 100}}
    )
    agg.feed(
        {"status": "Downloading", "id": "bbb", "progressDetail": {"current": 100, "total": 300}}
    )
    snap = agg.snapshot()
    assert snap.layers_total == 3
    assert snap.layers_complete == 1  # the cached layer counts as complete
    assert (snap.bytes_current, snap.bytes_total) == (150, 400)
    assert snap.phase == "downloading"
    assert snap.progress_pct == 30.0  # 0.8 * 150/400

    agg.feed({"status": "Download complete", "id": "aaa"})
    agg.feed({"status": "Download complete", "id": "bbb"})
    snap = agg.snapshot()
    assert snap.phase == "extracting"
    assert (snap.bytes_current, snap.bytes_total) == (400, 400)
    assert snap.progress_pct == 80.0

    agg.feed({"status": "Extracting", "id": "aaa", "progressDetail": {"current": 50, "total": 100}})
    snap = agg.snapshot()
    assert snap.progress_pct == 82.5  # 80 + 20 * (100 * 0.5)/400

    agg.feed({"status": "Pull complete", "id": "aaa"})
    agg.feed(
        {"status": "Extracting", "id": "bbb", "progressDetail": {"current": 300, "total": 300}}
    )
    agg.feed({"status": "Pull complete", "id": "bbb"})
    snap = agg.snapshot()
    assert snap.progress_pct == 100.0
    assert snap.layers_complete == 3


def test_aggregator_unknown_totals_yield_no_pct() -> None:
    agg = PullProgressAggregator()
    agg.feed({"status": "Pulling fs layer", "id": "aaa"})
    agg.feed({"status": "Downloading", "id": "aaa", "progressDetail": {}})
    snap = agg.snapshot()
    assert snap.progress_pct is None
    assert snap.bytes_total == 0
    assert snap.layers_total == 1


def test_aggregator_ignores_unknown_statuses() -> None:
    agg = PullProgressAggregator()
    agg.feed({"status": "Some future containerd status", "id": "aaa"})
    assert agg.snapshot().layers_total == 0


def test_aggregator_in_band_error_raises() -> None:
    agg = PullProgressAggregator()
    with pytest.raises(EnginePullError, match="access denied"):
        agg.feed({"error": "denied", "errorDetail": {"message": "access denied"}})


# --- build_registry_auth_header --------------------------------------------


def _write_config(tmp_path: Path, payload: dict[str, Any]) -> dict[str, str]:
    (tmp_path / "config.json").write_text(json.dumps(payload), encoding="utf-8")
    return {"DOCKER_CONFIG": str(tmp_path)}


def test_auth_header_static_entry_for_named_registry(tmp_path: Path) -> None:
    packed = base64.b64encode(b"user:secret").decode()
    env = _write_config(tmp_path, {"auths": {"registry.example.com": {"auth": packed}}})
    headers = build_registry_auth_header("registry.example.com/team/tool:v1", env)
    payload = json.loads(base64.urlsafe_b64decode(headers["X-Registry-Auth"]))
    assert payload == {
        "username": "user",
        "password": "secret",
        "serveraddress": "registry.example.com",
    }


def test_auth_header_docker_hub_legacy_key(tmp_path: Path) -> None:
    packed = base64.b64encode(b"hubuser:hubpass").decode()
    env = _write_config(tmp_path, {"auths": {"https://index.docker.io/v1/": {"auth": packed}}})
    headers = build_registry_auth_header("python:3.12", env)
    payload = json.loads(base64.urlsafe_b64decode(headers["X-Registry-Auth"]))
    assert payload["username"] == "hubuser"
    assert payload["password"] == "hubpass"


def test_auth_header_credsstore_only_is_anonymous(tmp_path: Path) -> None:
    env = _write_config(
        tmp_path, {"credsStore": "desktop", "auths": {"https://index.docker.io/v1/": {}}}
    )
    assert build_registry_auth_header("python:3.12", env) == {}


def test_auth_header_missing_config_is_anonymous(tmp_path: Path) -> None:
    assert build_registry_auth_header("python:3.12", {"DOCKER_CONFIG": str(tmp_path)}) == {}


# --- stream_pull over httpx.MockTransport ----------------------------------


def _stream_body(lines: list[dict[str, Any]]) -> bytes:
    return b"".join(json.dumps(obj).encode() + b"\r\n" for obj in lines)


class _Clock:
    """Scripted monotonic clock; repeats the last value when exhausted."""

    def __init__(self, values: list[float]) -> None:
        self._values = list(values)
        self._last = values[-1] if values else 0.0

    def __call__(self) -> float:
        if self._values:
            self._last = self._values.pop(0)
        return self._last


class _EmitRecorder:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __call__(self, message: str, attrs: dict[str, Any] | None = None) -> None:
        self.calls.append((message, dict(attrs or {})))


async def test_stream_pull_emits_throttled_progress_and_phase_change() -> None:
    lines = [
        {"status": "Pulling from library/alpine", "id": "3.20"},
        {"status": "Pulling fs layer", "id": "aaa"},
        {"status": "Downloading", "id": "aaa", "progressDetail": {"current": 10, "total": 100}},
        {"status": "Downloading", "id": "aaa", "progressDetail": {"current": 50, "total": 100}},
        {"status": "Download complete", "id": "aaa"},
    ]
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=_stream_body(lines))

    emit = _EmitRecorder()
    # start=0.0; layer registration at 1.0 and download at 1.5 are inside the
    # 2s window (suppressed); 2.5 emits; the phase change at 3.0 force-emits.
    clock = _Clock([0.0, 1.0, 1.5, 2.5, 3.0])
    await stream_pull(
        image="alpine:3.20",
        docker_host="",
        env={},
        emit=emit,
        transport=httpx.MockTransport(handler),
        now=clock,
    )

    (request,) = seen
    assert request.url.path == "/images/create"
    assert request.url.params["fromImage"] == "alpine"
    assert request.url.params["tag"] == "3.20"
    assert "X-Registry-Auth" not in request.headers

    assert len(emit.calls) == 2
    message1, attrs1 = emit.calls[0]
    assert attrs1["milestone"] == "pull_progress"
    assert attrs1["image"] == "alpine:3.20"
    assert attrs1["phase"] == "downloading"
    assert attrs1["progress_pct"] == 40.0
    assert attrs1["bytes_current"] == 50
    assert attrs1["bytes_total"] == 100
    assert (attrs1["layers_complete"], attrs1["layers_total"]) == (0, 1)
    assert "40%" in message1

    message2, attrs2 = emit.calls[1]
    assert attrs2["phase"] == "extracting"
    assert attrs2["progress_pct"] == 80.0
    assert "extracting" in message2


async def test_stream_pull_pct_never_regresses() -> None:
    # A second layer's total arriving late shrinks the honest percentage; the
    # emitted value must clamp while the byte fields stay truthful.
    lines = [
        {"status": "Pulling fs layer", "id": "aaa"},
        {"status": "Downloading", "id": "aaa", "progressDetail": {"current": 100, "total": 100}},
        {"status": "Pulling fs layer", "id": "bbb"},
        {"status": "Downloading", "id": "bbb", "progressDetail": {"current": 0, "total": 900}},
    ]
    emit = _EmitRecorder()
    clock = _Clock([0.0, 0.5, 2.1, 2.2, 4.5])
    await stream_pull(
        image="alpine:3.20",
        docker_host="",
        env={},
        emit=emit,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=_stream_body(lines))
        ),
        now=clock,
    )

    assert [attrs["progress_pct"] for _msg, attrs in emit.calls] == [80.0, 80.0]
    assert emit.calls[1][1]["bytes_total"] == 1000


async def test_stream_pull_in_band_error_raises() -> None:
    lines = [
        {"status": "Pulling fs layer", "id": "aaa"},
        {"error": "denied", "errorDetail": {"message": "manifest unknown"}},
    ]
    with pytest.raises(EnginePullError, match="manifest unknown"):
        await stream_pull(
            image="alpine:3.20",
            docker_host="",
            env={},
            emit=_EmitRecorder(),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=_stream_body(lines))
            ),
            now=_Clock([0.0]),
        )


async def test_stream_pull_http_error_raises() -> None:
    with pytest.raises(EnginePullError, match="HTTP 500: server broke"):
        await stream_pull(
            image="alpine:3.20",
            docker_host="",
            env={},
            emit=_EmitRecorder(),
            transport=httpx.MockTransport(
                lambda request: httpx.Response(500, json={"message": "server broke"})
            ),
            now=_Clock([0.0]),
        )


async def test_stream_pull_transport_error_wrapped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with pytest.raises(EnginePullError, match="connection refused"):
        await stream_pull(
            image="alpine:3.20",
            docker_host="",
            env={},
            emit=_EmitRecorder(),
            transport=httpx.MockTransport(handler),
            now=_Clock([0.0]),
        )


async def test_stream_pull_unsupported_docker_host_raises_without_io() -> None:
    with pytest.raises(EnginePullUnsupported):
        await stream_pull(
            image="alpine:3.20",
            docker_host="ssh://user@host",
            env={},
            emit=_EmitRecorder(),
        )


async def test_stream_pull_sends_registry_auth(tmp_path: Path) -> None:
    packed = base64.b64encode(b"user:secret").decode()
    env = _write_config(tmp_path, {"auths": {"registry.example.com": {"auth": packed}}})
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=_stream_body([{"status": "Already up to date"}]))

    await stream_pull(
        image="registry.example.com/tool:v1",
        docker_host="",
        env=env,
        emit=_EmitRecorder(),
        transport=httpx.MockTransport(handler),
        now=_Clock([0.0]),
    )
    assert "X-Registry-Auth" in seen[0].headers


# --- execute()-level fallback wiring ----------------------------------------


class _FakeServices:
    """Minimal HandlerServices stub exercising only the container.run path."""

    def __init__(self, docker_host: str = "") -> None:
        self._docker_host = docker_host

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
            docker_host=self._docker_host,
        )

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        return []

    async def fetch_run_step_outputs(self, run_id: str) -> dict[str, dict[str, Any]]:
        return {}

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        return []


def _ctx(events: list[tuple[str, dict[str, Any]]]) -> HandlerContext:
    async def record(message: str, device_id: str | None, attrs: dict[str, Any] | None) -> bool:
        events.append((message, dict(attrs or {})))
        return True

    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="step-1",
        phase="IMPLEMENTATION",
        kind="ACTION",
        config={"image": "alpine:3.20", "command": ["echo hi"]},
        services=cast(HandlerServices, _FakeServices()),
        _emit_progress=record,
    )


def _install_docker_mocks(monkeypatch, *, pull_returncode: int = 0) -> dict[str, list]:
    """Mock both docker subprocess seams; docker pull exits pull_returncode."""
    captured: dict[str, list] = {"run": [], "exec": []}

    def fake_subprocess_run(cmd, *args, **kwargs):
        captured["run"].append((list(cmd), kwargs.get("env")))
        argv = list(cmd)
        if len(argv) >= 2 and argv[0] == "docker" and argv[1] == "pull":
            return SimpleNamespace(returncode=pull_returncode, stdout="", stderr="pull exploded")
        # `docker ps` (preflight) must return no names so no extra rm is spawned.
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_subprocess_run)

    async def fake_create_subprocess_exec(*argv, **kwargs):
        captured["exec"].append((list(argv), kwargs.get("env")))
        proc = AsyncMock()
        proc.stdout = AsyncMock()
        proc.stdout.readline = AsyncMock(return_value=b"")
        proc.stderr = AsyncMock()
        proc.stderr.readline = AsyncMock(return_value=b"")
        proc.wait = AsyncMock(return_value=0)
        proc.returncode = 0
        proc.kill = AsyncMock()
        return proc

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_create_subprocess_exec)
    return captured


async def test_execute_falls_back_to_cli_pull_on_engine_error(monkeypatch) -> None:
    captured = _install_docker_mocks(monkeypatch)
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullError("boom")),
    )
    events: list[tuple[str, dict[str, Any]]] = []

    result = await RunContainerHandler().execute(_ctx(events))
    assert result.success is True

    pull_cmds = [cmd for cmd, _env in captured["run"] if cmd[:2] == ["docker", "pull"]]
    assert pull_cmds == [["docker", "pull", "alpine:3.20"]]

    milestones = [attrs.get("milestone") for _msg, attrs in events]
    assert milestones.index("pull_fallback") < milestones.index("pull_complete")
    fallback = next(attrs for _msg, attrs in events if attrs.get("milestone") == "pull_fallback")
    assert fallback["reason"] == "boom"
    complete = next(attrs for _msg, attrs in events if attrs.get("milestone") == "pull_complete")
    assert complete["pull_method"] == "cli"


async def test_execute_skips_cli_pull_when_engine_succeeds(monkeypatch) -> None:
    captured = _install_docker_mocks(monkeypatch)
    stream_mock = AsyncMock(return_value=None)
    monkeypatch.setattr("hegemony_steps_container.run.stream_pull", stream_mock)
    events: list[tuple[str, dict[str, Any]]] = []

    result = await RunContainerHandler().execute(_ctx(events))
    assert result.success is True

    stream_mock.assert_awaited_once()
    assert stream_mock.await_args is not None
    kwargs = stream_mock.await_args.kwargs
    assert kwargs["image"] == "alpine:3.20"
    assert kwargs["docker_host"] == ""

    pull_cmds = [cmd for cmd, _env in captured["run"] if cmd[:2] == ["docker", "pull"]]
    assert pull_cmds == []
    # The rest of the provisioning flow still ran (create + attached start).
    assert any(cmd[:2] == ["docker", "create"] for cmd, _env in captured["run"])
    assert captured["exec"], "docker start -a was never spawned"

    milestones = [attrs.get("milestone") for _msg, attrs in events]
    assert "pull_fallback" not in milestones
    complete = next(attrs for _msg, attrs in events if attrs.get("milestone") == "pull_complete")
    assert complete["pull_method"] == "api"


async def test_execute_fallback_pull_failure_matches_todays_result(monkeypatch) -> None:
    _install_docker_mocks(monkeypatch, pull_returncode=1)
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("TLS daemon")),
    )
    events: list[tuple[str, dict[str, Any]]] = []

    result = await RunContainerHandler().execute(_ctx(events))
    assert result.success is False
    assert result.error is not None and result.error.startswith("Docker pull failed:")
    assert result.summary == "Failed to pull image alpine:3.20"
