# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
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
    assert tag == "sha256_" + "ab" * 32
    assert ":" not in tag and len(tag) <= 128
    # Not the OCI referrers-tag shape (sha256-<hex>), which zot hides from its
    # index, statistics and retention.
    assert "sha256-" not in tag


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
    # Without a port such a name is a Docker Hub path, not a registry: cached.
    assert plan_cache("myregistry/team/tool:1", CACHE) is not None
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
    assert await client.manifest_digest("orgs/acme/docker.io/library/alpine", "sha256_ab") is None
    assert seen == [
        "http://registry.hegemony.internal/v2/orgs/acme/docker.io/library/alpine/manifests/sha256_ab"
    ]


# ── Through the handler: hits, misses, fallbacks ─────────────────────────────

from types import SimpleNamespace  # noqa: E402
from typing import Any, cast  # noqa: E402
from unittest.mock import AsyncMock  # noqa: E402

from hegemony_step_sdk import (  # noqa: E402
    ContainerRuntime,
    HandlerContext,
    HandlerResult,
    HandlerServices,
)
from hegemony_steps_container.pull_progress import EnginePullError, PullOutcome  # noqa: E402
from hegemony_steps_container.run import RunContainerHandler  # noqa: E402
from hegemony_steps_container.runner import ContainerJob, run_container_job  # noqa: E402

# Upstream alpine:3.20, a single-platform image; a copy is that image when its
# image ID (configuration digest) is UPSTREAM_CONFIG.
UPSTREAM_CONFIG = "sha256:" + "42" * 32
UPSTREAM_MANIFEST = json.dumps(
    {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"digest": UPSTREAM_CONFIG},
        "layers": [],
    }
).encode()
UPSTREAM_DIGEST = "sha256:" + hashlib.sha256(UPSTREAM_MANIFEST).hexdigest()
KEY_TAG = cache_key_tag(UPSTREAM_DIGEST)
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
    pull_digests: dict[str, str] | None = None,
    image_id: str = "",
    copy_identity: str | dict[str, str] = "",
    image_store: str = "classic",
):
    """Script the registries, the Engine API pull and the docker CLI.

    ``pull_digests`` maps a pulled reference to the digest its pull reports
    (none by default, which leaves the digest to RepoDigests). ``image_id`` is
    the image ID the ID-and-platform inspect reports (as linux/amd64; nothing by
    default), ``copy_identity`` what that inspect prints instead, for every
    reference or, as a map, for the references it names.

    The Engine API pull succeeds for every image but those in ``pull_failures``,
    which raise and whose CLI fallback also fails, so the handler reports the
    pull as failed for exactly those references. Pushes answer
    ``push_returncode``, or ``push_results`` one by one when given.
    """
    registries = _Registries()
    registries.manifests[("https://registry-1.docker.io", "library/alpine", UPSTREAM_DIGEST)] = (
        httpx.Response(200, content=UPSTREAM_MANIFEST)
    )
    monkeypatch.setattr("hegemony_steps_container.run._registry_transport", registries.transport)

    pulled: list[str] = []

    async def fake_stream_pull(*, image: str, docker_host: str, env, emit) -> PullOutcome:
        if image in pull_failures:
            raise EnginePullError("no such manifest")
        pulled.append(image)
        return PullOutcome(
            up_to_date=False, bytes_downloaded=1234, digest=(pull_digests or {}).get(image, "")
        )

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
        if argv[:2] == ["docker", "info"]:
            if image_store == "broken":
                return SimpleNamespace(returncode=1, stdout="", stderr="daemon busy")
            if image_store == "starting":
                # A daemon that answers before it knows its storage driver.
                return SimpleNamespace(returncode=0, stdout="|null\n", stderr="")
            if image_store == "vfs":
                # A classic driver that prints no status list.
                return SimpleNamespace(returncode=0, stdout="vfs|null\n", stderr="")
            status = (
                [["driver-type", "io.containerd.snapshotter.v1"]]
                if image_store == "containerd"
                else [["Backing Filesystem", "extfs"]]
            )
            driver = "overlayfs" if image_store == "containerd" else "overlay2"
            return SimpleNamespace(
                returncode=0, stdout=f"{driver}|{json.dumps(status)}\n", stderr=""
            )
        if argv[:2] == ["docker", "push"]:
            code = remaining_push_results.pop(0) if remaining_push_results else push_returncode
            return SimpleNamespace(returncode=code, stdout="", stderr="denied: push")
        if argv[:3] == ["docker", "image", "inspect"]:
            if any("{{.Os}}" in arg for arg in argv):
                if isinstance(copy_identity, dict) and argv[-1] in copy_identity:
                    identity = copy_identity[argv[-1]]
                elif isinstance(copy_identity, str) and copy_identity:
                    identity = copy_identity
                else:
                    identity = f"{image_id} linux/amd64" if image_id else ""
                return SimpleNamespace(returncode=0, stdout=f"{identity}\n", stderr="")
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
        proc.stdout.read = AsyncMock(return_value=b"")
        proc.stderr = AsyncMock()
        proc.stderr.read = AsyncMock(return_value=b"")
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


def _digest_events(events) -> list[tuple[str, dict[str, Any]]]:
    return [
        (message, attrs) for message, attrs in events if attrs.get("milestone") == "image_digest"
    ]


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
    # The step's log names the digest the container runs by, as its evidence does.
    digest = f"alpine@sha256:{'cc' * 32}"
    assert _digest_events(events) == [
        (
            f"Running the image by digest: {digest}",
            {
                "milestone": "image_digest",
                "image": "alpine:3.20",
                "served": "alpine:3.20",
                "digest": digest,
                "image_id": "",
                "image_local_id": "",
            },
        )
    ]
    assert result.metrics["image_digest"] == digest


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


@pytest.mark.parametrize("rendered", ["false", "False", "0"])
async def test_a_rendered_false_turns_the_cache_off(monkeypatch, rendered) -> None:
    """A templated switch reaches the step as text, which must not read as true."""
    registries, captured = _install(monkeypatch)
    events: list = []
    ctx = _handler_ctx(
        events, config={"image": "alpine:3.20", "command": ["echo hi"], "cache_image": rendered}
    )
    result = await RunContainerHandler().execute(ctx)
    assert result.success is True
    assert captured["pulled"] == ["alpine:3.20"]
    assert registries.requests == []
    assert _docker(captured, "push") == []


@pytest.mark.parametrize(
    ("handler_path", "config"),
    [
        ("hegemony_steps_ansible.playbook:AnsiblePlaybookHandler", {"playbook": "site.yml"}),
        ("hegemony_steps_tf.plan:TfPlanHandler", {"state": "ephemeral"}),
    ],
)
@pytest.mark.parametrize(("rendered", "cached"), [("false", False), ("True", True)])
async def test_tool_steps_read_a_rendered_cache_switch(
    monkeypatch, handler_path, config, rendered, cached
) -> None:
    """Tool steps hand their config to the runner through container_config_from."""
    module_name, _, class_name = handler_path.partition(":")
    handler = getattr(__import__(module_name, fromlist=[class_name]), class_name)()
    registries, captured = _install(monkeypatch)
    events: list = []
    ctx = _handler_ctx(events, config={**config, "image": "alpine:3.20", "cache_image": rendered})
    await handler.execute(ctx)
    # The cache asks the image's registry first; without it, nothing is asked.
    assert bool(registries.requests) is cached
    if not cached:
        assert captured["pulled"] == ["alpine:3.20"]


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
    registries, captured = _install(
        monkeypatch,
        pull_digests={f"{OWN_COPY}:{KEY_TAG}": "sha256:" + "cc" * 32},
        copy_identity=f"{UPSTREAM_CONFIG} linux/amd64",
    )
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
    # The copy runs by the digest the daemon pulled it by, never the upstream tag.
    assert f"{OWN_COPY}@sha256:{'cc' * 32}" in create and "alpine:3.20" not in create
    # The global namespace is not consulted once the own copy is found.
    assert all(GLOBAL_REPO not in url for _m, url in registries.requests)
    assert "image_cache_hit" in _milestones(events)
    assert result.metrics["image"] == "alpine:3.20"
    assert result.metrics["image_source"] == "cache"
    assert result.metrics["image_cached"] is False
    evidence = next(e for e in result.evidence if e["kind"] == "container_output")
    assert evidence["content_json"]["image_served"] == f"{OWN_COPY}:{KEY_TAG}"
    assert evidence["content_json"]["image_digest"] == f"{OWN_COPY}@sha256:{'cc' * 32}"
    # The copy's digest is in the step's log too.
    [(message, attrs)] = _digest_events(events)
    assert message == f"Running the image by digest: {OWN_COPY}@sha256:{'cc' * 32}"
    assert attrs["served"] == f"{OWN_COPY}:{KEY_TAG}" and attrs["image"] == "alpine:3.20"


async def test_a_hit_runs_by_the_digest_its_own_pull_reported(monkeypatch) -> None:
    """The daemon is not asked afterwards: another pull of the tag could have moved it."""
    pulled_digest = "sha256:" + "dd" * 32
    registries, captured = _install(
        monkeypatch,
        pull_digests={f"{OWN_COPY}:{KEY_TAG}": pulled_digest},
        copy_identity=f"{UPSTREAM_CONFIG} linux/amd64",
    )
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    registries.manifests[("http://registry.hegemony.internal", OWN_REPO, KEY_TAG)] = (
        "sha256:" + "22" * 32
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert f"{OWN_COPY}@{pulled_digest}" in _create_argv(captured)
    inspects = [cmd for cmd, _env in captured["run"] if cmd[:3] == ["docker", "image", "inspect"]]
    assert not any("{{json .RepoDigests}}" in cmd for cmd in inspects)
    assert result.metrics["image_digest"] == f"{OWN_COPY}@{pulled_digest}"


async def test_a_copy_in_the_global_namespace_serves_when_the_own_one_is_missing(
    monkeypatch,
) -> None:
    registries, captured = _install(monkeypatch, copy_identity=f"{UPSTREAM_CONFIG} linux/amd64")
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


async def test_upstream_unreachable_never_runs_a_copy_by_tag(monkeypatch) -> None:
    """The copy under the tag could be anything a step pushed there: nothing checks it."""
    registries, captured = _install(monkeypatch, copy_identity=f"{UPSTREAM_CONFIG} linux/amd64")
    registries.unreachable.add("https://registry-1.docker.io")
    registries.manifests[("http://registry.hegemony.internal", OWN_REPO, "3.20")] = (
        "sha256:" + "44" * 32
    )
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True
    assert captured["pulled"] == ["alpine:3.20"]
    assert not any("registry.hegemony.internal" in url for _m, url in registries.requests)
    assert _docker(captured, "push") == []
    [(message, attrs)] = [(m, a) for m, a in events if a.get("milestone") == "image_cache_skip"]
    assert "cannot be checked" in message and "connection refused" in attrs["reason"]
    assert "image_cache_stale" not in _milestones(events)
    assert result.metrics["image_source"] == "upstream"


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


async def test_a_job_served_from_the_cache_records_the_copy_digest(monkeypatch) -> None:
    registries, captured = _install(
        monkeypatch,
        pull_digests={f"{OWN_COPY}:{KEY_TAG}": "sha256:" + "cc" * 32},
        copy_identity=f"{UPSTREAM_CONFIG} linux/amd64",
    )
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
    )
    outcome = await run_container_job(_handler_ctx(events), job)
    assert not hasattr(outcome, "success"), getattr(outcome, "error", None)
    # tf.apply then pulls this reference, which lives in the platform registry.
    assert outcome.image_digest == f"{OWN_COPY}@sha256:{'cc' * 32}"
    assert outcome.image_served == f"{OWN_COPY}:{KEY_TAG}"
    assert outcome.image_source == "cache"
    assert outcome.image_digest in _create_argv(captured)


IMAGE_ID = UPSTREAM_CONFIG


def _cache_hit(registries) -> None:
    registries.manifests[("https://registry-1.docker.io", "library/alpine", "3.20")] = (
        UPSTREAM_DIGEST
    )
    registries.manifests[("http://registry.hegemony.internal", OWN_REPO, KEY_TAG)] = (
        "sha256:" + "22" * 32
    )


async def test_a_job_records_the_image_id_it_ran(monkeypatch) -> None:
    registries, captured = _install(monkeypatch, image_id=IMAGE_ID)
    _cache_hit(registries)
    events: list = []
    job = ContainerJob(config={"image": "alpine:3.20", "command": ["true"]}, handler_id="tool.run")
    outcome = await run_container_job(_handler_ctx(events), job)
    assert not hasattr(outcome, "success"), getattr(outcome, "error", None)
    assert outcome.image_id == IMAGE_ID
    assert outcome.image_local_id == IMAGE_ID  # the classic store: the same ID
    # The pull reported no digest, so the container runs by the ID that was read.
    assert IMAGE_ID in _create_argv(captured)
    assert _digest_events(events)[0][1]["image_id"] == IMAGE_ID


async def test_a_copy_with_the_expected_image_id_runs(monkeypatch) -> None:
    registries, captured = _install(monkeypatch, image_id=IMAGE_ID)
    _cache_hit(registries)
    events: list = []
    job = ContainerJob(
        config={"image": "alpine:3.20", "command": ["true"]},
        handler_id="tool.run",
        expected_image_id=IMAGE_ID,
    )
    outcome = await run_container_job(_handler_ctx(events), job)
    assert not hasattr(outcome, "success"), getattr(outcome, "error", None)
    assert outcome.image_source == "cache"
    assert _docker(captured, "create")


@pytest.mark.parametrize("reported", ["sha256:" + "66" * 32, ""])
async def test_a_copy_with_another_image_id_is_refused_before_it_runs(
    monkeypatch, reported: str
) -> None:
    """A copy in the platform registry that is not the expected image never runs.

    Its key tag names the upstream digest, but a tag can be pushed over; the
    image ID cannot be faked. An ID the daemon does not report is refused too.
    """
    registries, captured = _install(monkeypatch, image_id=reported)
    _cache_hit(registries)
    events: list = []
    job = ContainerJob(
        config={"image": "alpine:3.20", "command": ["true"]},
        handler_id="tool.run",
        expected_image_id=IMAGE_ID,
    )
    outcome = await run_container_job(_handler_ctx(events), job)
    assert isinstance(outcome, HandlerResult) and outcome.success is False
    assert IMAGE_ID in (outcome.error or "")
    assert (reported or "could not be read") in (outcome.error or "")
    assert _docker(captured, "create") == []
    assert "image_id_mismatch" in _milestones(events)


async def test_tool_configs_pass_the_option_through(monkeypatch) -> None:
    from hegemony_steps_container.runner import container_config_from

    job_config = container_config_from(
        {"cache_image": False, "timeout_seconds": 60}, image="ghcr.io/x/y:1", command=["true"]
    )
    assert job_config["cache_image"] is False
    assert "cache_image" not in container_config_from({}, image="ghcr.io/x/y:1", command=["true"])


# ── A cache hit checks its copy against the image's registry ─────────────────

from hegemony_steps_container.image_cache import _platform_entry  # noqa: E402

CONFIG_AMD64 = "sha256:" + "a1" * 32
CONFIG_ARM64 = "sha256:" + "a2" * 32
HUB = "https://registry-1.docker.io"
PLATFORM_REGISTRY = "http://registry.hegemony.internal"


def _blob(document: dict[str, Any]) -> tuple[str, bytes]:
    body = json.dumps(document).encode()
    return "sha256:" + hashlib.sha256(body).hexdigest(), body


def _upstream_index(registries: _Registries) -> str:
    """Script an upstream index with amd64 and arm64 images; return its digest."""
    manifests = {}
    entries = []
    for arch, config in (("amd64", CONFIG_AMD64), ("arm64", CONFIG_ARM64)):
        digest, body = _blob(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": config},
                "layers": [],
            }
        )
        manifests[digest] = body
        entries.append({"digest": digest, "platform": {"os": "linux", "architecture": arch}})
    entries.append(
        {
            "digest": "sha256:" + "a3" * 32,
            "platform": {"os": "unknown", "architecture": "unknown"},
            "annotations": {"vnd.docker.reference.type": "attestation-manifest"},
        }
    )
    index_digest, index_body = _blob(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": entries,
        }
    )
    manifests[index_digest] = index_body
    for digest, body in manifests.items():
        registries.manifests[(HUB, "library/alpine", digest)] = httpx.Response(200, content=body)
    registries.manifests[(HUB, "library/alpine", "3.20")] = index_digest
    registries.manifests[(PLATFORM_REGISTRY, OWN_REPO, cache_key_tag(index_digest))] = (
        "sha256:" + "22" * 32
    )
    return index_digest


async def test_a_copy_that_is_the_upstream_image_runs(monkeypatch) -> None:
    registries, captured = _install(monkeypatch, copy_identity=f"{CONFIG_AMD64} linux/amd64")
    index = _upstream_index(registries)
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True, result.error
    assert result.metrics["image_source"] == "cache"
    assert captured["pulled"] == [f"{OWN_COPY}:{cache_key_tag(index)}"]
    assert "image_cache_verified" in _milestones(events)
    # The index, then the amd64 manifest, were read from upstream by digest.
    gets = [url for method, url in registries.requests if method == "GET"]
    assert any(url.endswith(f"/manifests/{index}") for url in gets)


async def test_a_copy_pushed_over_by_another_image_is_not_run(monkeypatch) -> None:
    """The key tag names the upstream digest, but a tag can be pushed over."""
    registries, captured = _install(
        monkeypatch, copy_identity=f"{'sha256:' + 'ee' * 32} linux/amd64"
    )
    index = _upstream_index(registries)
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True, result.error
    assert "image_cache_mismatch" in _milestones(events)
    # Upstream is pulled by the digest, and a true copy is saved over the bad one.
    assert captured["pulled"] == [f"{OWN_COPY}:{cache_key_tag(index)}", f"alpine@{index}"]
    assert ["docker", "push", f"{OWN_COPY}:{cache_key_tag(index)}"] in _docker(captured, "push")
    assert result.metrics["image_source"] == "upstream"
    assert f"{OWN_COPY}:{cache_key_tag(index)}" not in _create_argv(captured)


async def test_the_check_inspects_the_digest_the_pull_brought_not_the_tag(monkeypatch) -> None:
    """Another step can retag the copy between this pull and the check.

    The container runs by the digest this pull reported, so that is what is
    checked: a genuine image under the tag must not vouch for it.
    """
    pulled_digest = "sha256:" + "dd" * 32
    registries, captured = _install(monkeypatch)
    key = cache_key_tag(_upstream_index(registries))
    copy_tag = f"{OWN_COPY}:{key}"
    pinned = f"{OWN_COPY}@{pulled_digest}"
    registries, captured = _install(
        monkeypatch,
        pull_digests={copy_tag: pulled_digest},
        copy_identity={
            copy_tag: f"{CONFIG_AMD64} linux/amd64",
            pinned: f"{'sha256:' + 'ee' * 32} linux/amd64",
        },
    )
    _upstream_index(registries)
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True, result.error
    assert "image_cache_mismatch" in _milestones(events)
    inspected = [cmd[-1] for cmd, _env in captured["run"] if any("{{.Os}}" in a for a in cmd)]
    # The cache check inspected the pulled digest, never the tag.
    assert inspected[0] == pinned and copy_tag not in inspected
    assert pinned not in _create_argv(captured)


async def test_a_copy_pulled_without_a_digest_runs_by_the_checked_image_id(monkeypatch) -> None:
    registries, captured = _install(monkeypatch)
    key = cache_key_tag(_upstream_index(registries))
    copy_tag = f"{OWN_COPY}:{key}"
    registries, captured = _install(
        monkeypatch,
        image_id=CONFIG_AMD64,
        copy_identity={copy_tag: f"{CONFIG_AMD64} linux/amd64"},
    )
    _upstream_index(registries)
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True, result.error
    assert "image_cache_verified" in _milestones(events)
    create = _create_argv(captured)
    assert CONFIG_AMD64 in create and copy_tag not in create
    # No digest is looked up by the tag after the check.
    assert not any("{{json .RepoDigests}}" in cmd for cmd, _env in captured["run"])


async def test_a_copy_that_cannot_be_checked_is_not_run(monkeypatch) -> None:
    """A digest-pinned image whose registry is down at the check: the copy is no stand-in."""
    registries, captured = _install(monkeypatch, copy_identity=f"{CONFIG_AMD64} linux/amd64")
    index = _upstream_index(registries)
    registries.unreachable.add(HUB)
    events: list = []

    result = await RunContainerHandler().execute(
        _handler_ctx(events, config={"image": f"alpine@{index}", "command": ["true"]})
    )
    assert result.success is True, result.error
    assert result.metrics["image_source"] == "upstream"
    [message] = [m for m, a in events if a.get("milestone") == "image_cache_unverified"]
    assert "Not running it" in message
    assert captured["pulled"] == [f"{OWN_COPY}:{cache_key_tag(index)}", f"alpine@{index}"]
    assert f"{OWN_COPY}:{cache_key_tag(index)}" not in _create_argv(captured)


async def test_a_copy_of_a_platform_upstream_does_not_serve_is_not_run(monkeypatch) -> None:
    """A copy can be made to fail the check (a platform upstream has no image for).

    That must not get it run unchecked: it is refused like any copy that is
    not shown to be the image.
    """
    registries, captured = _install(
        monkeypatch, copy_identity=f"{'sha256:' + 'ee' * 32} linux/s390x"
    )
    index = _upstream_index(registries)
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True, result.error
    [attrs] = [a for _m, a in events if a.get("milestone") == "image_cache_unverified"]
    assert "linux/s390x" in attrs["reason"]
    assert result.metrics["image_source"] == "upstream"
    assert captured["pulled"][-1] == f"alpine@{index}"
    assert f"{OWN_COPY}:{cache_key_tag(index)}" not in _create_argv(captured)


async def test_a_copy_pulled_by_the_upstream_digest_itself_runs_without_asking_upstream(
    monkeypatch,
) -> None:
    """The same digest is the same content: no check against upstream is needed."""
    registries, captured = _install(
        monkeypatch, pull_digests={f"{OWN_COPY}:{KEY_TAG}": UPSTREAM_DIGEST}
    )
    registries.unreachable.add(HUB)
    registries.manifests[(PLATFORM_REGISTRY, OWN_REPO, KEY_TAG)] = UPSTREAM_DIGEST
    events: list = []

    result = await RunContainerHandler().execute(
        _handler_ctx(events, config={"image": PINNED, "command": ["true"]})
    )
    assert result.success is True, result.error
    assert result.metrics["image_source"] == "cache"
    assert "image_cache_verified" in _milestones(events)
    assert not any(url.startswith(HUB) for _m, url in registries.requests)
    assert f"{OWN_COPY}@{UPSTREAM_DIGEST}" in _create_argv(captured)


async def test_an_upstream_manifest_that_does_not_match_its_digest_is_not_trusted() -> None:
    digest = "sha256:" + "b4" * 32
    body = json.dumps({"config": {"digest": CONFIG_AMD64}}).encode()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    client = _client(handler)
    with pytest.raises(RegistryUnavailable, match="does not match"):
        await client.config_digest("x/tool", digest, "linux/amd64")


@pytest.mark.parametrize(
    ("platform", "expected"),
    [
        ("linux/amd64", "sha256:" + "01" * 32),
        ("linux/arm64/v8", "sha256:" + "03" * 32),
        ("linux/arm/v7", "sha256:" + "02" * 32),
        ("linux/arm/v6", None),
        ("windows/amd64", None),
    ],
)
def test_the_index_entry_is_picked_by_platform(platform: str, expected: str | None) -> None:
    entries = [
        {"digest": "sha256:" + "01" * 32, "platform": {"os": "linux", "architecture": "amd64"}},
        {
            "digest": "sha256:" + "02" * 32,
            "platform": {"os": "linux", "architecture": "arm", "variant": "v7"},
        },
        {"digest": "sha256:" + "03" * 32, "platform": {"os": "linux", "architecture": "arm64"}},
        {"digest": "sha256:" + "04" * 32, "platform": {"os": "unknown", "architecture": "unknown"}},
    ]
    assert _platform_entry(entries, platform) == expected


# ── The containerd image store: the image ID is read from the registry ───────
#
# Docker 29's default store reports a pulled image's ID as the digest of the
# manifest or index it was pulled by, not of its configuration. Checked by hand
# against a Docker 29 daemon on both stores: alpine:3.20's index and its copy in
# a registry resolve to the same configuration digest, which the classic store
# reports as the ID.


def _copy_manifest(registries: _Registries, config: str) -> str:
    """Script a single-platform copy in the platform registry; return its digest."""
    digest, body = _blob(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": config},
            "layers": [],
        }
    )
    registries.manifests[(PLATFORM_REGISTRY, OWN_REPO, digest)] = httpx.Response(200, content=body)
    return digest


@pytest.mark.parametrize(
    ("copy_config", "milestone", "source"),
    [
        (CONFIG_AMD64, "image_cache_verified", "cache"),
        ("sha256:" + "ee" * 32, "image_cache_mismatch", "upstream"),
    ],
)
async def test_on_the_containerd_store_a_copy_is_checked_by_its_registry_config(
    monkeypatch, copy_config: str, milestone: str, source: str
) -> None:
    registries, _ = _install(monkeypatch)
    key = cache_key_tag(_upstream_index(registries))
    copy_tag = f"{OWN_COPY}:{key}"
    copy_digest = _copy_manifest(registries, copy_config)
    pinned = f"{OWN_COPY}@{copy_digest}"
    # The containerd store's ID is the digest the copy was pulled by.
    registries, captured = _install(
        monkeypatch,
        image_store="containerd",
        pull_digests={copy_tag: copy_digest},
        copy_identity={pinned: f"{copy_digest} linux/amd64"},
    )
    _upstream_index(registries)
    _copy_manifest(registries, copy_config)
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True, result.error
    assert milestone in _milestones(events)
    assert result.metrics["image_source"] == source
    if source == "cache":
        # The recorded ID is the configuration digest, as on the classic store.
        assert result.metrics["image_id"] == CONFIG_AMD64


async def test_on_the_containerd_store_the_daemon_id_never_stands_in_for_the_image_id(
    monkeypatch,
) -> None:
    """The daemon's ID differs between an image and its copy there: it is not compared.

    A job expecting an ID whose registry will not give the configuration digest
    is refused, even when the expected value equals the daemon's ID; the error
    says the ID could not be read, not that the image is another one.
    """
    local_id = "sha256:" + "5a" * 32
    _, captured = _install(
        monkeypatch, image_store="containerd", copy_identity=f"{local_id} linux/amd64"
    )
    events: list = []
    job = ContainerJob(
        config={"image": "tools/runner:dev", "command": ["true"], "cache_image": False},
        handler_id="tool.run",
        expected_image_id=local_id,
    )
    outcome = await run_container_job(_handler_ctx(events, services=_CacheServices(None)), job)
    assert isinstance(outcome, HandlerResult) and outcome.success is False
    assert "could not be read" in (outcome.error or "") and local_id in (outcome.error or "")
    assert outcome.metrics["image_local_id"] == local_id
    assert _docker(captured, "create") == []


async def test_on_the_containerd_store_a_plain_job_asks_no_registry_for_its_image_id(
    monkeypatch,
) -> None:
    """Manifest requests can count against pull limits: only jobs that compare images pay."""
    local_id = "sha256:" + "5c" * 32
    registries, _ = _install(
        monkeypatch, image_store="containerd", copy_identity=f"{local_id} linux/amd64"
    )
    job = ContainerJob(
        config={"image": "ghcr.io/x/tool:1", "command": ["true"], "cache_image": False},
        handler_id="tool.run",
    )
    outcome = await run_container_job(_handler_ctx([], services=_CacheServices(None)), job)
    assert not hasattr(outcome, "success"), getattr(outcome, "error", None)
    assert (outcome.image_id, outcome.image_local_id) == ("", local_id)
    assert registries.requests == []

    asking = ContainerJob(
        config={"image": "ghcr.io/x/tool:1", "command": ["true"], "cache_image": False},
        handler_id="tool.run",
        needs_image_id=True,
    )
    await run_container_job(_handler_ctx([], services=_CacheServices(None)), asking)
    assert any("ghcr.io/v2/x/tool/manifests/" in url for _m, url in registries.requests)


async def test_on_the_containerd_store_an_unreadable_registry_config_is_no_id(
    monkeypatch,
) -> None:
    """A digest-pinned image whose registry cannot say: no ID, so a check refuses it."""
    digest = "sha256:" + "5b" * 32
    registries, _ = _install(
        monkeypatch, image_store="containerd", copy_identity=f"{digest} linux/amd64"
    )
    registries.unreachable.add("https://ghcr.io")
    identity = await RunContainerHandler()._image_identity(
        reference=f"ghcr.io/x/tool@{digest}",
        repository="ghcr.io/x/tool:1",
        cache=CACHE,
        docker_bin="docker",
        docker_env={"DOCKER_HOST": "tcp://dind:2375"},
        deadline=time.monotonic() + 60,
        resolve=True,
    )
    assert (identity.local_id, identity.image_id) == (digest, "")


@pytest.mark.parametrize(
    ("answer", "store"),
    [
        ("containerd", "containerd"),
        ("classic", "classic"),
        # A classic driver without a status list is still a real answer.
        ("vfs", "classic"),
        # No driver named, or no answer: never read as the classic store.
        ("starting", "unknown"),
        ("broken", "unknown"),
    ],
)
async def test_the_image_store_is_read_from_a_real_answer_only(
    monkeypatch, answer: str, store: str
) -> None:
    _, captured = _install(monkeypatch, image_store=answer)
    handler = RunContainerHandler()
    env = {"DOCKER_HOST": "tcp://dind:2375"}
    assert await handler._image_store(docker_bin="docker", docker_env=env, timeout=60) == store
    # Nothing is remembered: a daemon recreated with another store is asked again.
    await handler._image_store(docker_bin="docker", docker_env=env, timeout=60)
    assert len(_docker(captured, "info")) == 2


async def test_the_image_store_question_keeps_to_the_steps_deadline(monkeypatch) -> None:
    """A slow `docker info` must not carry a step past its timeout."""
    _, captured = _install(
        monkeypatch, image_store="containerd", copy_identity="sha256:" + "5d" * 32 + " linux/amd64"
    )
    handler = RunContainerHandler()
    await handler._image_identity(
        reference="tools/runner:dev",
        repository="tools/runner:dev",
        cache=None,
        docker_bin="docker",
        docker_env={"DOCKER_HOST": "tcp://dind:2375"},
        deadline=time.monotonic() + 3,
        resolve=True,
    )
    [info_timeout] = [t for cmd, t in captured["timeouts"] if cmd[:2] == ["docker", "info"]]
    assert info_timeout is not None and info_timeout <= 3
    # Out of time, the daemon is not asked at all.
    env = {"DOCKER_HOST": "tcp://other:2375"}
    assert await handler._image_store(docker_bin="docker", docker_env=env, timeout=0) == "unknown"
    assert len(_docker(captured, "info")) == 1


async def test_a_pulled_image_whose_registry_cannot_say_has_no_id_on_containerd(
    monkeypatch,
) -> None:
    """Its daemon ID is a manifest digest there: never offered as the configuration digest."""
    local_id = "sha256:" + "5e" * 32
    registries, _ = _install(
        monkeypatch, image_store="containerd", copy_identity=f"{local_id} linux/amd64"
    )
    registries.unreachable.add("https://ghcr.io")
    identity = await RunContainerHandler()._image_identity(
        reference="ghcr.io/x/tool:1",
        repository="ghcr.io/x/tool:1",
        cache=None,
        docker_bin="docker",
        docker_env={"DOCKER_HOST": "tcp://dind:2375"},
        deadline=time.monotonic() + 60,
        resolve=True,
    )
    assert (identity.local_id, identity.image_id) == (local_id, "")


async def test_an_unknown_store_reads_a_pinned_image_from_its_registry(monkeypatch) -> None:
    """`docker info` failed: the daemon's ID may be either kind, so the registry decides."""
    registries, _ = _install(monkeypatch)
    copy_digest = _copy_manifest(registries, CONFIG_AMD64)
    pinned = f"{OWN_COPY}@{copy_digest}"
    registries, captured = _install(
        monkeypatch, image_store="broken", copy_identity=f"{copy_digest} linux/amd64"
    )
    _copy_manifest(registries, CONFIG_AMD64)
    handler = RunContainerHandler()
    env = {"DOCKER_HOST": "tcp://dind:2375"}
    pinned_identity = await handler._image_identity(
        reference=pinned,
        repository=OWN_COPY,
        cache=CACHE,
        docker_bin="docker",
        docker_env=env,
        deadline=time.monotonic() + 60,
        resolve=True,
    )
    assert pinned_identity.image_id == CONFIG_AMD64
    tag_identity = await handler._image_identity(
        reference=f"{OWN_COPY}:x",
        repository=f"{OWN_COPY}:x",
        cache=CACHE,
        docker_bin="docker",
        docker_env=env,
        deadline=time.monotonic() + 60,
        resolve=True,
    )
    assert (tag_identity.local_id, tag_identity.image_id) == (copy_digest, "")
    assert len(_docker(captured, "info")) == 2


@pytest.mark.parametrize(
    ("platform", "entry_platform"),
    [
        # The configuration names no variant; the index says v8.
        ("linux/arm64", {"os": "linux", "architecture": "arm64", "variant": "v8"}),
        # And the other way round.
        ("linux/arm64/v8", {"os": "linux", "architecture": "arm64"}),
    ],
)
def test_a_missing_variant_means_the_architectures_default(
    platform: str, entry_platform: dict[str, str]
) -> None:
    digest = "sha256:" + "0a" * 32
    entries = [
        {"digest": "sha256:" + "0b" * 32, "platform": {"os": "linux", "architecture": "amd64"}},
        {"digest": digest, "platform": entry_platform},
    ]
    assert _platform_entry(entries, platform) == digest


def test_32_bit_arm_without_a_variant_matches_nothing() -> None:
    """A v6 sandbox reports plain linux/arm: assuming v7 could accept the wrong image."""
    v6, v7 = "sha256:" + "06" * 32, "sha256:" + "07" * 32
    entries = [
        {"digest": v6, "platform": {"os": "linux", "architecture": "arm", "variant": "v6"}},
        {"digest": v7, "platform": {"os": "linux", "architecture": "arm", "variant": "v7"}},
    ]
    assert _platform_entry(entries, "linux/arm") is None
    assert _platform_entry(entries, "linux/arm/v6") == v6
    assert _platform_entry(entries, "linux/arm/v7") == v7


@pytest.mark.parametrize(
    "duplicate",
    [
        {"os": "linux", "architecture": "amd64", "variant": "v1"},
        {"os": "linux", "architecture": "amd64"},
    ],
)
def test_an_index_with_two_entries_for_the_platform_matches_nothing(duplicate) -> None:
    """amd64/v1 and plain amd64 are one platform to containerd: which runs is unknown."""
    entries = [
        {"digest": "sha256:" + "0d" * 32, "platform": duplicate},
        {"digest": "sha256:" + "0e" * 32, "platform": {"os": "linux", "architecture": "amd64"}},
    ]
    assert _platform_entry(entries, "linux/amd64") is None


def test_a_missing_variant_does_not_match_another_one() -> None:
    entries = [
        {
            "digest": "sha256:" + "0c" * 32,
            "platform": {"os": "linux", "architecture": "arm", "variant": "v6"},
        }
    ]
    assert _platform_entry(entries, "linux/arm") is None


async def test_a_job_whose_image_cannot_be_pulled_never_runs(monkeypatch) -> None:
    """An image only the sandbox holds (built there, never pushed) fails at the pull.

    The identity fallback to the daemon's ID never lets a step run an image the
    registry did not serve: a container step always pulls first.
    """
    _, captured = _install(
        monkeypatch,
        image_store="containerd",
        pull_failures=frozenset({"local/tool:dev"}),
        copy_identity="sha256:" + "5a" * 32 + " linux/amd64",
    )
    job = ContainerJob(
        config={"image": "local/tool:dev", "command": ["true"], "cache_image": False},
        handler_id="tool.run",
        expected_image_id="sha256:" + "5a" * 32,
    )
    outcome = await run_container_job(_handler_ctx([], services=_CacheServices(None)), job)
    assert isinstance(outcome, HandlerResult) and outcome.success is False
    assert "pull" in (outcome.error or "").lower()
    assert _docker(captured, "create") == []


async def test_a_verified_cache_hit_reads_the_copy_once(monkeypatch) -> None:
    """The step reuses what the cache check read: no second inspect or registry lookup."""
    registries, _ = _install(monkeypatch)
    key = cache_key_tag(_upstream_index(registries))
    copy_tag = f"{OWN_COPY}:{key}"
    copy_digest = _copy_manifest(registries, CONFIG_AMD64)
    pinned = f"{OWN_COPY}@{copy_digest}"
    registries, captured = _install(
        monkeypatch,
        image_store="containerd",
        pull_digests={copy_tag: copy_digest},
        copy_identity={pinned: f"{copy_digest} linux/amd64"},
    )
    _upstream_index(registries)
    _copy_manifest(registries, CONFIG_AMD64)
    events: list = []

    result = await RunContainerHandler().execute(_handler_ctx(events))
    assert result.success is True, result.error
    assert "image_cache_verified" in _milestones(events)
    inspects = [cmd for cmd, _env in captured["run"] if any("{{.Os}}" in a for a in cmd)]
    assert len(inspects) == 1
    copy_gets = [
        url
        for m, url in registries.requests
        if m == "GET" and url.startswith(PLATFORM_REGISTRY) and copy_digest in url
    ]
    assert len(copy_gets) == 1
    assert result.metrics["image_id"] == CONFIG_AMD64
    assert result.metrics["image_local_id"] == copy_digest


async def test_the_cache_check_keeps_half_its_budget_for_the_upstream_lookup(monkeypatch) -> None:
    """Reading the copy may not use up the time the verdict's lookup needs."""
    registries, _ = _install(monkeypatch, copy_identity=f"{CONFIG_AMD64} linux/amd64")
    index = _upstream_index(registries)
    handler = RunContainerHandler()
    seen: dict[str, float] = {}
    real = handler._image_identity

    async def spy(**kwargs: Any):
        seen["budget"] = kwargs["deadline"] - time.monotonic()
        return await real(**kwargs)

    monkeypatch.setattr(handler, "_image_identity", spy)
    started = time.monotonic()
    matches, _identity = await handler._copy_matches_upstream(
        upstream=_client(registries.transport(HUB).handler, base_url=HUB),
        repo="library/alpine",
        upstream_digest=index,
        copy=f"{OWN_COPY}:{cache_key_tag(index)}",
        pinned=f"{OWN_COPY}:{cache_key_tag(index)}",
        cache=CACHE,
        image="alpine:3.20",
        docker_bin="docker",
        docker_env={"DOCKER_HOST": "tcp://dind:2375"},
        deadline=started + 600,
        emit=AsyncMock(),
    )
    assert matches is True
    # The whole budget is 30 s here: the copy's read gets at most half.
    assert 0 < seen["budget"] <= 15.01
