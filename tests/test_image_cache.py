# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The platform-registry cache: reference naming and the registry HTTP calls."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from pathlib import Path

import httpx
import pytest

from hegemony_step_sdk import ImageCache
from hegemony_steps_container.image_cache import (
    MANIFEST_ACCEPT,
    RegistryClient,
    RegistryDenied,
    RegistryUnavailable,
    cache_key_tag,
    login_for,
    parse_reference,
    pin_reference,
    plan_cache,
    upstream_api_url,
)
from hegemony_steps_container.pull_progress import RegistryLogin

CACHE = ImageCache(
    registry="registry.hegemony.internal",
    api_url="http://registry.hegemony.internal",
    namespace="orgs/acme",
    read_namespaces=("global",),
)
DIGEST = "sha256:" + "ab" * 32


# ── References and copy names ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("image", "host", "repo", "tag", "digest"),
    [
        ("alpine", "docker.io", "library/alpine", "latest", None),
        ("alpine:3.20", "docker.io", "library/alpine", "3.20", None),
        ("bitnami/kubectl:1.30", "docker.io", "bitnami/kubectl", "1.30", None),
        ("docker.io/library/nginx:1", "docker.io", "library/nginx", "1", None),
        ("index.docker.io/acme/tool", "docker.io", "acme/tool", "latest", None),
        (
            "ghcr.io/hegemony-sh/opentofu-runner:0.8",
            "ghcr.io",
            "hegemony-sh/opentofu-runner",
            "0.8",
            None,
        ),
        ("localhost:5000/tool:dev", "localhost:5000", "tool", "dev", None),
        ("registry.example.com:5000/a/b/c", "registry.example.com:5000", "a/b/c", "latest", None),
        (f"ghcr.io/x/y@{DIGEST}", "ghcr.io", "x/y", None, DIGEST),
        (f"ghcr.io/x/y:1.2@{DIGEST}", "ghcr.io", "x/y", "1.2", DIGEST),
    ],
)
def test_parse_reference_normalizes_like_the_docker_cli(image, host, repo, tag, digest) -> None:
    ref = parse_reference(image)
    assert (ref.host, ref.repo, ref.tag, ref.digest) == (host, repo, tag, digest)


def test_manifest_reference_prefers_the_digest() -> None:
    assert parse_reference(f"ghcr.io/x/y:1.2@{DIGEST}").manifest_reference == DIGEST
    assert parse_reference("ghcr.io/x/y:1.2").manifest_reference == "1.2"
    assert parse_reference("ghcr.io/x/y").manifest_reference == "latest"


@pytest.mark.parametrize(
    ("image", "pinned"),
    [
        ("alpine:3.20", "alpine@sha256:" + "11" * 32),
        ("alpine", "alpine@sha256:" + "11" * 32),
        ("localhost:5000/team/tool:1.2", "localhost:5000/team/tool@sha256:" + "11" * 32),
        ("ghcr.io/x/tool:1@sha256:" + "ab" * 32, "ghcr.io/x/tool@sha256:" + "11" * 32),
    ],
)
def test_pin_reference_replaces_the_tag_with_the_digest(image: str, pinned: str) -> None:
    assert pin_reference(image, "sha256:" + "11" * 32) == pinned


def test_cache_key_tag_is_a_legal_tag_naming_the_upstream_digest() -> None:
    tag = cache_key_tag(DIGEST)
    assert tag == "sha256-" + "ab" * 32
    assert ":" not in tag and len(tag) <= 128


def test_plan_names_the_copy_after_the_upstream_reference() -> None:
    plan = plan_cache("alpine:3.20", CACHE)
    assert plan is not None
    assert plan.write_repo == "orgs/acme/docker.io/library/alpine"
    assert plan.read_repos == (
        "orgs/acme/docker.io/library/alpine",
        "global/docker.io/library/alpine",
    )
    assert (
        plan.copy_reference(plan.write_repo, "3.20")
        == "registry.hegemony.internal/orgs/acme/docker.io/library/alpine:3.20"
    )


def test_plan_writes_a_registry_port_with_an_underscore() -> None:
    """A repository path component may not hold a colon; a port cannot clash with a host."""
    plan = plan_cache("registry.example.com:5000/team/tools/net:1", CACHE)
    assert plan is not None
    assert plan.write_repo == "orgs/acme/registry.example.com_5000/team/tools/net"
    local = plan_cache("localhost:5000/tool:dev", CACHE)
    assert local is not None
    assert local.write_repo == "orgs/acme/localhost_5000/tool"


def test_a_registry_named_without_a_dot_is_never_cached() -> None:
    """The platform registry knows a host segment by its dot or by localhost."""
    assert plan_cache("myregistry:5000/team/tool:1", CACHE) is None
    assert plan_cache("myregistry/team/tool:1", CACHE) is None
    assert plan_cache("localhost:5000/tool:dev", CACHE) is not None
    assert plan_cache("registry.example.com:5000/tool:1", CACHE) is not None


def test_an_image_already_in_the_platform_registry_is_not_cached_again() -> None:
    assert plan_cache(f"registry.hegemony.internal/orgs/acme/ghcr.io/x/y@{DIGEST}", CACHE) is None
    assert plan_cache("registry.hegemony.internal/global/base:1", CACHE) is None


def test_no_read_namespaces_means_only_the_own_copy() -> None:
    own_only = ImageCache(registry="r.internal", api_url="http://r.internal", namespace="orgs/x")
    plan = plan_cache("ghcr.io/a/b:1", own_only)
    assert plan is not None
    assert plan.read_repos == ("orgs/x/ghcr.io/a/b",)


def test_upstream_api_url_special_cases_docker_hub() -> None:
    assert upstream_api_url("docker.io") == "https://registry-1.docker.io"
    assert upstream_api_url("ghcr.io") == "https://ghcr.io"
    assert upstream_api_url("registry.example.com:5000") == "https://registry.example.com:5000"


def test_login_for_reads_docker_hub_under_its_legacy_key(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text(
        json.dumps(
            {
                "auths": {
                    "https://index.docker.io/v1/": {
                        "auth": base64.b64encode(b"hubuser:hubpass").decode()
                    },
                    "ghcr.io": {"auth": base64.b64encode(b"octo:tok").decode()},
                }
            }
        )
    )
    env = {"DOCKER_CONFIG": str(tmp_path)}
    hub = login_for("docker.io", env)
    assert hub is not None and (hub.username, hub.password) == ("hubuser", "hubpass")
    ghcr = login_for("ghcr.io", env)
    assert ghcr is not None and (ghcr.username, ghcr.password) == ("octo", "tok")
    assert login_for("quay.io", env) is None


# ── Registry HTTP ────────────────────────────────────────────────────────────


def _client(handler, login: RegistryLogin | None = None, base_url="https://ghcr.io"):
    return RegistryClient(base_url, login, trust_env=False, transport=httpx.MockTransport(handler))


async def test_anonymous_head_returns_the_digest_header() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, headers={"Docker-Content-Digest": DIGEST})

    digest = await _client(handler).manifest_digest("x/y", "1.2")
    assert digest == DIGEST
    assert len(seen) == 1
    assert seen[0].method == "HEAD"
    assert str(seen[0].url) == "https://ghcr.io/v2/x/y/manifests/1.2"
    assert seen[0].headers["accept"] == MANIFEST_ACCEPT


async def test_bearer_challenge_is_answered_with_a_token_from_the_realm() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "auth.example.com":
            assert request.url.params["service"] == "ghcr.io"
            assert request.url.params["scope"] == "repository:x/y:pull"
            # The login travels to the realm, as the docker CLI sends it.
            assert request.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, json={"token": "t0k"})
        if "authorization" not in request.headers:
            return httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer realm="https://auth.example.com/token",service="ghcr.io",'
                        'scope="repository:x/y:pull"'
                    )
                },
            )
        assert request.headers["authorization"] == "Bearer t0k"
        return httpx.Response(200, headers={"Docker-Content-Digest": DIGEST})

    client = _client(handler, RegistryLogin("octo", "tok"))
    assert await client.manifest_digest("x/y", "1.2") == DIGEST
    assert [r.method for r in seen] == ["HEAD", "GET", "HEAD"]


async def test_basic_challenge_is_answered_with_the_login() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("authorization") == "Basic " + base64.b64encode(b"u:p").decode():
            return httpx.Response(200, headers={"Docker-Content-Digest": DIGEST})
        return httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="registry"'})

    assert await _client(handler, RegistryLogin("u", "p")).manifest_digest("x/y", "1") == DIGEST


async def test_a_challenge_without_a_login_is_a_refusal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, headers={"WWW-Authenticate": 'Basic realm="registry"'})

    with pytest.raises(RegistryDenied):
        await _client(handler).manifest_digest("x/y", "1")


async def test_a_refused_token_is_a_refusal() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "auth.example.com":
            return httpx.Response(401, json={"errors": [{"code": "UNAUTHORIZED"}]})
        return httpx.Response(
            401, headers={"WWW-Authenticate": 'Bearer realm="https://auth.example.com/token"'}
        )

    with pytest.raises(RegistryDenied):
        await _client(handler, RegistryLogin("u", "wrong")).manifest_digest("x/y", "1")


async def test_a_missing_manifest_is_none() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    assert await _client(handler).manifest_digest("x/y", "nope") is None


async def test_a_head_without_a_digest_header_falls_back_to_hashing_the_body() -> None:
    body = b'{"schemaVersion": 2}'
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.method)
        if request.method == "HEAD":
            return httpx.Response(200)
        return httpx.Response(200, content=body)

    digest = await _client(handler).manifest_digest("x/y", "1")
    assert digest == "sha256:" + hashlib.sha256(body).hexdigest()
    assert seen == ["HEAD", "GET"]


@pytest.mark.parametrize("status", [500, 502, 503])
async def test_server_errors_are_unavailable(status: int) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status)

    with pytest.raises(RegistryUnavailable):
        await _client(handler).manifest_digest("x/y", "1")


async def test_connection_failures_are_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    with pytest.raises(RegistryUnavailable, match="no route to host"):
        await _client(handler).manifest_digest("x/y", "1")


async def test_the_platform_registry_is_asked_over_its_api_url() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(404)

    client = _client(handler, base_url=CACHE.api_url)
    assert await client.manifest_digest("orgs/acme/docker.io/library/alpine", "sha256-ab") is None
    assert seen == [
        "http://registry.hegemony.internal/v2/orgs/acme/docker.io/library/alpine/manifests/sha256-ab"
    ]


# ── Through the handler: hits, misses, fallbacks ─────────────────────────────

from types import SimpleNamespace  # noqa: E402
from typing import Any, cast  # noqa: E402
from unittest.mock import AsyncMock  # noqa: E402

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerServices  # noqa: E402
from hegemony_steps_container.pull_progress import EnginePullError, PullOutcome  # noqa: E402
from hegemony_steps_container.run import RunContainerHandler  # noqa: E402
from hegemony_steps_container.runner import ContainerJob, run_container_job  # noqa: E402

UPSTREAM_DIGEST = "sha256:" + "11" * 32
KEY_TAG = "sha256-" + "11" * 32
PINNED = f"alpine@{UPSTREAM_DIGEST}"
OWN_REPO = "orgs/acme/docker.io/library/alpine"
GLOBAL_REPO = "global/docker.io/library/alpine"
OWN_COPY = f"registry.hegemony.internal/{OWN_REPO}"
GLOBAL_COPY = f"registry.hegemony.internal/{GLOBAL_REPO}"


class _CacheServices:
    """HandlerServices stub whose runtime names the platform registry."""

    def __init__(self, cache: ImageCache | None = CACHE) -> None:
        self.cache = cache

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
            docker_host="tcp://dind:2375",
            docker_config_dir="",
            image_cache=self.cache,
        )

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        return []

    async def fetch_run_step_outputs(self, run_id: str) -> dict[str, dict[str, Any]]:
        return {}

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        return []


def _handler_ctx(
    events: list[tuple[str, dict[str, Any]]],
    config: dict[str, Any] | None = None,
    services: Any = None,
) -> HandlerContext:
    async def record(message: str, device_id: str | None, attrs: dict[str, Any] | None) -> bool:
        events.append((message, dict(attrs or {})))
        return True

    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="step-1",
        config=config or {"image": "alpine:3.20", "command": ["echo hi"]},
        services=cast(HandlerServices, services or _CacheServices()),
        _emit_progress=record,
    )


class _Registries:
    """Scripted answers for the platform registry and upstream manifest lookups.

    ``manifests`` maps ``(base_url, repo, reference)`` to a digest (200), None
    (404) or an exception to raise; a missing key is a 404. Every request is
    recorded so a test can assert what was asked.
    """

    def __init__(self) -> None:
        self.manifests: dict[tuple[str, str, str], Any] = {}
        self.requests: list[tuple[str, str]] = []
        self.unreachable: set[str] = set()
        # Seconds a registry sleeps before answering: a slow upstream.
        self.delays: dict[str, float] = {}

    def transport(self, base_url: str) -> httpx.MockTransport:
        async def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append((request.method, str(request.url)))
            if base_url in self.delays:
                await asyncio.sleep(self.delays[base_url])
            if base_url in self.unreachable:
                raise httpx.ConnectError("connection refused")
            path = request.url.path  # /v2/<repo>/manifests/<ref>
            _, _, rest = path.partition("/v2/")
            repo, _, reference = rest.rpartition("/manifests/")
            answer = self.manifests.get((base_url, repo, reference))
            if isinstance(answer, Exception):
                raise answer
            if isinstance(answer, httpx.Response):
                return answer
            if answer is None:
                return httpx.Response(404)
            return httpx.Response(200, headers={"Docker-Content-Digest": answer})

        return httpx.MockTransport(handler)


def _install(
    monkeypatch,
    *,
    pull_failures: frozenset[str] = frozenset(),
    push_returncode: int = 0,
    push_results: list[int] | None = None,
):
    """Script the registries, the Engine API pull and the docker CLI.

    The Engine API pull succeeds for every image but those in ``pull_failures``,
    which raise and whose CLI fallback also fails, so the handler reports the
    pull as failed for exactly those references. Pushes answer
    ``push_returncode``, or ``push_results`` one by one when given.
    """
    registries = _Registries()
    monkeypatch.setattr("hegemony_steps_container.run._registry_transport", registries.transport)

    pulled: list[str] = []

    async def fake_stream_pull(*, image: str, docker_host: str, env, emit) -> PullOutcome:
        if image in pull_failures:
            raise EnginePullError("no such manifest")
        pulled.append(image)
        return PullOutcome(up_to_date=False, bytes_downloaded=1234)

    monkeypatch.setattr("hegemony_steps_container.run.stream_pull", fake_stream_pull)

    captured: dict[str, list] = {"run": [], "exec": [], "pulled": pulled, "timeouts": []}
    remaining_push_results = list(push_results or [])

    def fake_subprocess_run(cmd, *args, **kwargs):
        captured["run"].append((list(cmd), kwargs.get("env")))
        captured["timeouts"].append((list(cmd), kwargs.get("timeout")))
        argv = list(cmd)
        if argv[:2] == ["docker", "pull"]:
            if argv[2] in pull_failures:
                return SimpleNamespace(returncode=1, stdout="", stderr="manifest unknown")
            pulled.append(argv[2])
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[:2] == ["docker", "push"]:
            code = remaining_push_results.pop(0) if remaining_push_results else push_returncode
            return SimpleNamespace(returncode=code, stdout="", stderr="denied: push")
        if argv[:3] == ["docker", "image", "inspect"]:
            if "RepoDigests" in " ".join(argv):
                name = argv[-1].split("@")[0].rsplit(":", 1)[0]
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps([f"{name}@sha256:{'cc' * 32}"]), stderr=""
                )
            return SimpleNamespace(returncode=0, stdout="120000000\n", stderr="")
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
    return registries, captured


def _docker(captured, verb: str) -> list[list[str]]:
    return [cmd for cmd, _env in captured["run"] if cmd[:2] == ["docker", verb]]


def _milestones(events) -> list[str]:
    return [attrs.get("milestone") for _msg, attrs in events if attrs.get("milestone")]


def _create_argv(captured) -> list[str]:
    return next(cmd for cmd, _env in captured["run"] if cmd[:2] == ["docker", "create"])


async def test_without_a_platform_registry_the_pull_is_as_before(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    events: list = []
    result = await RunContainerHandler().execute(
        _handler_ctx(events, services=_CacheServices(cache=None))
    )
    assert result.success is True
    assert captured["pulled"] == ["alpine:3.20"]
    assert registries.requests == []
    assert _docker(captured, "push") == []
    assert result.metrics["image_source"] == "upstream"
    assert result.metrics["image_cached"] is False
    assert not [m for m in _milestones(events) if m.startswith("image_cache")]


async def test_cache_image_off_pulls_straight_from_upstream(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    events: list = []
    ctx = _handler_ctx(
        events, config={"image": "alpine:3.20", "command": ["echo hi"], "cache_image": False}
    )
    result = await RunContainerHandler().execute(ctx)
    assert result.success is True
    assert captured["pulled"] == ["alpine:3.20"]
    assert registries.requests == []
    assert _docker(captured, "push") == []


async def test_a_miss_pulls_upstream_and_saves_a_copy_under_both_tags(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    # Upstream was asked once, by HEAD; both namespaces were checked for the key.
    assert registries.requests[0] == (
        "HEAD",
        "https://registry-1.docker.io/v2/library/alpine/manifests/3.20",
    )
    assert registries.requests[1:] == [
        ("HEAD", f"http://registry.hegemony.internal/v2/{OWN_REPO}/manifests/{KEY_TAG}"),
        ("HEAD", f"http://registry.hegemony.internal/v2/{GLOBAL_REPO}/manifests/{KEY_TAG}"),
    ]
    # Pulled by the digest the check named, so the copy holds that content
    # even if the tag moved in between.
    assert captured["pulled"] == [PINNED]
    # The digest key lands first, the human tag second, each tagged then pushed.
    assert _docker(captured, "tag") == [
        ["docker", "tag", PINNED, f"{OWN_COPY}:{KEY_TAG}"],
        ["docker", "tag", PINNED, f"{OWN_COPY}:3.20"],
    ]
    assert _docker(captured, "push") == [
        ["docker", "push", f"{OWN_COPY}:{KEY_TAG}"],
        ["docker", "push", f"{OWN_COPY}:3.20"],
    ]
    # Pushes run on the sandbox daemon with the step's Docker configuration.
    push_env = next(env for cmd, env in captured["run"] if cmd[:2] == ["docker", "push"])
    assert push_env["DOCKER_HOST"] == "tcp://dind:2375"
    assert PINNED in _create_argv(captured)
    assert "image_cache_store" in _milestones(events)
    assert result.metrics["image_served"] == PINNED
    assert result.metrics["image_source"] == "upstream"
    assert result.metrics["image_cached"] is True
    evidence = next(e for e in result.evidence if e["kind"] == "container_output")
    assert evidence["content_json"]["image"] == "alpine:3.20"
    assert evidence["content_json"]["image_served"] == PINNED
    assert evidence["content_json"]["image_cached"] is True


async def test_a_hit_in_the_own_namespace_runs_the_copy(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    registries.manifests[("http://registry.hegemony.internal", OWN_REPO, KEY_TAG)] = (
        "sha256:" + "22" * 32
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert captured["pulled"] == [f"{OWN_COPY}:{KEY_TAG}"]
    assert _docker(captured, "push") == []
    create = _create_argv(captured)
    assert f"{OWN_COPY}:{KEY_TAG}" in create and "alpine:3.20" not in create
    # The global namespace is not consulted once the own copy is found.
    assert all(GLOBAL_REPO not in url for _m, url in registries.requests)
    assert "image_cache_hit" in _milestones(events)
    assert result.metrics["image"] == "alpine:3.20"
    assert result.metrics["image_source"] == "cache"
    assert result.metrics["image_cached"] is False
    evidence = next(e for e in result.evidence if e["kind"] == "container_output")
    assert evidence["content_json"]["image_served"] == f"{OWN_COPY}:{KEY_TAG}"


async def test_a_copy_in_the_global_namespace_serves_when_the_own_one_is_missing(
    monkeypatch,
) -> None:
    registries, captured = _install(monkeypatch)
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    registries.manifests[("http://registry.hegemony.internal", GLOBAL_REPO, KEY_TAG)] = (
        "sha256:" + "33" * 32
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert captured["pulled"] == [f"{GLOBAL_COPY}:{KEY_TAG}"]
    assert _docker(captured, "push") == []
    assert result.metrics["image_source"] == "cache"


async def test_upstream_unreachable_falls_back_to_the_last_copy_by_tag(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    registries.unreachable.add("https://registry-1.docker.io")
    registries.manifests[("http://registry.hegemony.internal", OWN_REPO, "3.20")] = (
        "sha256:" + "44" * 32
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert captured["pulled"] == [f"{OWN_COPY}:3.20"]
    assert _docker(captured, "push") == []
    stale = next(attrs for _m, attrs in events if attrs.get("milestone") == "image_cache_stale")
    assert "connection refused" in stale["reason"]
    assert result.metrics["image_source"] == "cache"


async def test_upstream_unreachable_without_a_copy_pulls_upstream_without_saving(
    monkeypatch,
) -> None:
    registries, captured = _install(monkeypatch)
    registries.unreachable.add("https://registry-1.docker.io")
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert captured["pulled"] == ["alpine:3.20"]
    assert _docker(captured, "push") == []
    milestones = _milestones(events)
    assert "image_cache_store" not in milestones
    assert "image_cache_stale" not in milestones


async def test_platform_registry_unreachable_means_a_plain_pull(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    registries.unreachable.add("http://registry.hegemony.internal")
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    # The check named a digest, so that is what is pulled; just no copy is made.
    assert captured["pulled"] == [PINNED]
    assert _docker(captured, "push") == []
    skip = next(attrs for _m, attrs in events if attrs.get("milestone") == "image_cache_skip")
    assert "connection refused" in skip["reason"]
    assert result.metrics["image_cached"] is False


async def test_a_refused_push_never_fails_the_step(monkeypatch) -> None:
    registries, captured = _install(monkeypatch, push_returncode=1)
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert len(_docker(captured, "push")) == 1  # stops at the first refusal
    failed = next(
        attrs for _m, attrs in events if attrs.get("milestone") == "image_cache_store_failed"
    )
    assert "denied: push" in failed["reason"]
    assert result.metrics["image_cached"] is False


async def test_a_refused_check_pulls_upstream_without_the_cache(monkeypatch) -> None:
    """A registry that refuses the manifest check is not an outage: no stale copy."""
    registries, captured = _install(monkeypatch)
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        httpx.Response(403)
    )
    # A copy under the tag exists and must not stand in for the refused image.
    registries.manifests[("http://registry.hegemony.internal", OWN_REPO, "3.20")] = (
        "sha256:" + "44" * 32
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert captured["pulled"] == ["alpine:3.20"]
    assert _docker(captured, "push") == []
    assert all("registry.hegemony.internal" not in url for _m, url in registries.requests)
    skip = next(attrs for _m, attrs in events if attrs.get("milestone") == "image_cache_skip")
    assert "refused" in skip["reason"]
    assert "image_cache_stale" not in _milestones(events)
    assert result.metrics["image_source"] == "upstream"
    assert result.metrics["image_cached"] is False


async def test_a_copy_saved_under_its_key_alone_counts_as_saved(monkeypatch) -> None:
    registries, captured = _install(monkeypatch, push_results=[0, 1])
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert len(_docker(captured, "push")) == 2
    partial = next(
        attrs for _m, attrs in events if attrs.get("milestone") == "image_cache_store_partial"
    )
    assert partial["copy"] == f"{OWN_COPY}:{KEY_TAG}"
    assert partial["missing"] == f"{OWN_COPY}:3.20"
    assert "denied: push" in partial["reason"]
    assert "image_cache_store_failed" not in _milestones(events)
    assert result.metrics["image_cached"] is True


async def test_tagging_the_copy_is_capped_by_the_copy_budget(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    events: list = []
    # 40 s of step minus the 20 s reserve: a 20 s budget, under the 30 s a tag
    # may otherwise take.
    ctx = _handler_ctx(
        events, config={"image": "alpine:3.20", "command": ["true"], "timeout_seconds": 40}
    )
    result = await RunContainerHandler().execute(ctx)
    assert result.success is True
    tag_timeouts = [t for cmd, t in captured["timeouts"] if cmd[:2] == ["docker", "tag"]]
    assert tag_timeouts and all(t is not None and 15 < t <= 20 for t in tag_timeouts)


async def test_a_slow_manifest_check_is_the_steps_timeout(monkeypatch) -> None:
    """A registry that never answers does not carry the step past its deadline."""
    registries, captured = _install(monkeypatch)
    registries.delays["https://registry-1.docker.io"] = 5.0
    events: list = []
    ctx = _handler_ctx(
        events, config={"image": "alpine:3.20", "command": ["true"], "timeout_seconds": 1}
    )
    started = time.monotonic()
    result = await RunContainerHandler().execute(ctx)
    assert time.monotonic() - started < 4
    assert result.success is False
    assert "timed out" in (result.error or "")
    assert captured["pulled"] == []


async def test_a_cached_copy_that_cannot_be_pulled_falls_back_to_upstream(monkeypatch) -> None:
    registries, captured = _install(monkeypatch, pull_failures=frozenset({f"{OWN_COPY}:{KEY_TAG}"}))
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    registries.manifests[("http://registry.hegemony.internal", OWN_REPO, KEY_TAG)] = (
        "sha256:" + "22" * 32
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert captured["pulled"] == [PINNED]
    # No point pushing to the registry that just failed to serve the copy.
    assert _docker(captured, "push") == []
    assert "image_cache_miss" in _milestones(events)
    assert result.metrics["image_source"] == "upstream"


async def test_a_digest_reference_is_keyed_without_asking_upstream(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    image = f"ghcr.io/x/tool@{UPSTREAM_DIGEST}"
    events: list = []

    result = await RunContainerHandler().execute(
        _handler_ctx(events, config={"image": image, "command": ["true"]})
    )
    assert result.success is True
    assert all("ghcr.io/v2" not in url for _m, url in registries.requests)
    assert captured["pulled"] == [image]
    # Only the digest key: a digest reference carries no tag to mirror.
    assert _docker(captured, "push") == [
        ["docker", "push", f"registry.hegemony.internal/orgs/acme/ghcr.io/x/tool:{KEY_TAG}"]
    ]
    assert result.metrics["image_digest"] == image


async def test_an_image_in_the_platform_registry_is_pulled_as_it_is(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    image = "registry.hegemony.internal/orgs/acme/tools/net:1"
    events: list = []

    result = await RunContainerHandler().execute(
        _handler_ctx(events, config={"image": image, "command": ["true"]})
    )
    assert result.success is True
    assert registries.requests == []
    assert captured["pulled"] == [image]
    assert _docker(captured, "push") == []
    assert result.metrics["image_source"] == "platform"


async def test_no_time_left_skips_saving_the_copy(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    events: list = []
    ctx = _handler_ctx(
        events, config={"image": "alpine:3.20", "command": ["true"], "timeout_seconds": 30}
    )
    result = await RunContainerHandler().execute(ctx)
    assert result.success is True
    assert _docker(captured, "push") == []
    assert "image_cache_store_skipped" in _milestones(events)


async def test_a_pinned_job_served_from_the_cache_records_the_copy_digest(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    registries.manifests[("http://registry.hegemony.internal", OWN_REPO, KEY_TAG)] = (
        "sha256:" + "22" * 32
    )
    events: list = []
    job = ContainerJob(
        config={"image": "alpine:3.20", "command": ["true"]},
        handler_id="tool.run",
        pin_image=True,
    )
    outcome = await run_container_job(_handler_ctx(events), job)
    assert not hasattr(outcome, "success"), getattr(outcome, "error", None)
    # tf.apply then pulls this reference, which lives in the platform registry.
    assert outcome.image_digest == f"{OWN_COPY}@sha256:{'cc' * 32}"
    assert outcome.image_served == f"{OWN_COPY}:{KEY_TAG}"
    assert outcome.image_source == "cache"
    assert outcome.image_digest in _create_argv(captured)


async def test_tool_configs_pass_the_option_through(monkeypatch) -> None:
    from hegemony_steps_container.runner import container_config_from

    job_config = container_config_from(
        {"cache_image": False, "timeout_seconds": 60}, image="ghcr.io/x/y:1", command=["true"]
    )
    assert job_config["cache_image"] is False
    assert "cache_image" not in container_config_from({}, image="ghcr.io/x/y:1", command=["true"])
