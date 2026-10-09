# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``container.build``: validation, the build command, and a build end to end.

The end-to-end tests run the handler against a fake ``docker`` executable
that records what it was asked (arguments, environment, the build context and
the secret files it was handed) and answers like ``docker buildx`` does:
a plain log on its output and the metadata file with the pushed digest.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock

import httpx
import pytest

from hegemony_step_sdk import (
    BUILD_NETWORK_DEFAULT,
    BUILD_NETWORK_NONE,
    ContainerRuntime,
    HandlerContext,
    HandlerServices,
    ImageBuild,
    ImageCache,
)
from hegemony_steps_container import ALL_HANDLERS
from hegemony_steps_container.build import (
    CREATED_LABEL,
    DESTINATION_LOCAL,
    DESTINATION_PLATFORM,
    DESTINATION_REMOTE,
    MAX_LOG_BYTES,
    RUN_LABEL,
    STEP_LABEL,
    BuildImageHandler,
    BuildRefused,
    _BuildLog,
    build_destination,
    build_environment,
    buildx_argv,
    frontend_error,
    image_name_error,
    looks_like_host,
    registry_host_of,
    run_tag,
    same_registry_host,
    tag_error,
)
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_container.streams import MAX_LIVE_OUTPUT_BYTES

RUN_ID = "1a2b3c4d-0000-4000-8000-000000000001"
DIGEST = "sha256:" + "ab" * 32
REGISTRY = "registry.hegemony.internal"


# ── Names, tags and the Dockerfile frontend ─────────────────────────────────


@pytest.mark.parametrize(
    "name",
    [
        "tools/netbox-sync",
        "app",
        "a/b/c",
        "my_app",
        "team/tools.v2",
        # With their registry in front: pushed there.
        "ghcr.io/acme/netbox-sync",
        "docker.io/acme/tool",
        "registry.example.com:5000/team/tool",
        "Registry.Example.com/team/tool",
        "tools.v2/net",
    ],
)
def test_valid_image_names(name: str) -> None:
    assert image_name_error(name) is None


@pytest.mark.parametrize(
    ("name", "fragment"),
    [
        ("", "required"),
        ("Tools/x", "not a valid image name"),
        ("tools/x:1.0", "not a valid image name"),
        ("/tools", "not a valid image name"),
        ("tools//x", "not a valid image name"),
        ("tools.v2", "registry host"),
        ("localhost_5000/x", "registry host"),
        ("localhost/x", "the sandbox itself"),
        ("localhost:5000/x", "the sandbox itself"),
        ("ghcr.io/acme/x:1.0", "without a tag"),
        ("ghcr.io/Acme/x", "after the registry host"),
        ("ghcr.io/acme//x", "after the registry host"),
        ("bad_host.io/x", "not a valid registry host"),
        ("-bad.io/x", "not a valid registry host"),
        ("a" * 201, "at most 200"),
    ],
)
def test_invalid_image_names(name: str, fragment: str) -> None:
    error = image_name_error(name)
    assert error is not None and fragment in error


def test_registry_hosts_are_read_the_way_docker_reads_them() -> None:
    assert registry_host_of("ghcr.io/acme/x") == "ghcr.io"
    assert registry_host_of("registry.example.com:5000/x") == "registry.example.com:5000"
    assert registry_host_of("localhost/x") == "localhost"
    assert registry_host_of("host:5000/x") == "host:5000"
    assert registry_host_of("tools/x") is None
    assert registry_host_of("tools.v2") is None
    assert registry_host_of("x") is None


def test_host_rule_mirrors_the_platform() -> None:
    assert looks_like_host("docker.io")
    assert looks_like_host("registry.example.com_5000")
    assert looks_like_host("localhost")
    assert looks_like_host("localhost_5000")
    assert not looks_like_host("foo_bar")
    assert not looks_like_host("tools")


def test_tags() -> None:
    assert tag_error("tags[0]", "latest") is None
    assert tag_error("tags[0]", "v1.2.3_rc-1") is None
    assert tag_error("tags[0]", "-x") is not None
    assert tag_error("tags[0]", "a b") is not None
    assert tag_error("tags[0]", "x" * 129) is not None
    for reserved in ("sha256_" + "ab" * 32, "sha256-" + "ab" * 32):
        error = tag_error("tags[0]", reserved)
        assert error is not None and "digest tag" in error
    # Templates are checked once rendered.
    assert tag_error("tags[0]", "{{ inputs.version }}", allow_template=True) is None
    assert tag_error("tags[0]", "{{ inputs.version }}") is not None


def test_run_tag_is_the_short_run_id() -> None:
    assert run_tag(RUN_ID) == "run-1a2b3c4d"
    assert run_tag("") == "run-unknown"


@pytest.mark.parametrize(
    "dockerfile",
    [
        "FROM alpine\n",
        "# syntax=docker/dockerfile:1\nFROM alpine\n",
        "# syntax = docker.io/docker/dockerfile:1.7\nFROM alpine\n",
        "#syntax=docker/dockerfile-upstream:master\nFROM alpine\n",
        f"# syntax=docker/dockerfile:1@{DIGEST}\nFROM alpine\n",
        "﻿# check=error=true\nFROM alpine\n",
        # After the first instruction it is a comment, not a directive.
        "FROM alpine\n# syntax=evil/frontend\n",
    ],
)
def test_official_frontends_are_taken(dockerfile: str) -> None:
    assert frontend_error(dockerfile) is None


@pytest.mark.parametrize(
    "dockerfile",
    [
        "# syntax=evil/frontend:1\nFROM alpine\n",
        "# SYNTAX=ghcr.io/x/dockerfile:1\nFROM alpine\n",
        "# escape=`\n\n# syntax=docker/dockerfile-evil\nFROM alpine\n",
    ],
)
def test_other_frontends_are_refused(dockerfile: str) -> None:
    error = frontend_error(dockerfile)
    assert error is not None and "official docker/dockerfile" in error


# ── Config validation ───────────────────────────────────────────────────────


def _errors(**config: Any) -> list[str]:
    return BuildImageHandler().validate_config({"image": "tools/x", **config})


def test_a_minimal_config_is_valid() -> None:
    assert _errors() == []


def test_the_image_is_required() -> None:
    assert BuildImageHandler().validate_config({})


def test_templated_values_wait_for_the_run() -> None:
    assert _errors(image="tools/{{ inputs.app }}", tags=["{{ inputs.version }}"]) == []


@pytest.mark.parametrize(
    ("config", "fragment"),
    [
        ({"image": "localhost/x"}, "the sandbox itself"),
        ({"image": "ghcr.io/acme/x:1"}, "without a tag"),
        ({"tags": ["sha256_" + "0" * 64]}, "digest tag"),
        ({"context_dir": "/abs"}, "relative path"),
        ({"context_dir": "a/../.."}, "'..'"),
        ({"dockerfile": "../Dockerfile"}, "'..'"),
        ({"build_args": {"BUILDKIT_SYNTAX": "x/y"}}, "reserved"),
        ({"build_args": {"buildkit_inline_cache": "1"}}, "reserved"),
        ({"build_args": {"1BAD": "x"}}, "not a valid ARG name"),
        ({"secrets": {"bad name": "vault://x/y"}}, "must start with a letter"),
        ({"secrets": {"tok": ""}}, "non-empty string"),
        ({"labels": {"sh.hegemony.run": "x"}}, "set by the step"),
        ({"labels": {CREATED_LABEL: "x"}}, "set by the step"),
        ({"labels": {"bad key": "x"}}, "not a valid label key"),
        ({"target": "9stage"}, "'target'"),
        ({"platform": "amd64"}, "'platform'"),
        ({"egress_mode": "allow-listed"}, "requires at least one 'egress_allow' rule"),
        ({"egress_mode": "sideways"}, "Invalid 'egress_mode'"),
    ],
)
def test_invalid_configs(config: dict[str, Any], fragment: str) -> None:
    errors = _errors(**config)
    assert any(fragment in error for error in errors), errors


def test_handler_declarations() -> None:
    handler = BuildImageHandler
    assert handler.handler_id == "container.build"
    assert handler.container_backed is True
    assert handler.builds_images is True
    assert handler.platform_api_access is False
    assert handler.raw_config_keys == frozenset({"secrets"})
    assert handler.default_timeout_seconds == 1800
    assert handler in ALL_HANDLERS
    schema = handler.config_model.model_json_schema() if handler.config_model else {}
    assert schema["required"] == ["image"]
    assert schema["properties"]["dockerfile"]["default"] == "Dockerfile"


# ── The build command ───────────────────────────────────────────────────────


def test_buildx_argv_pins_what_the_dockerfile_cannot_change() -> None:
    argv = buildx_argv(
        context="/tmp/ctx",
        dockerfile="/tmp/ctx/Dockerfile",
        references=[f"{REGISTRY}/orgs/acme/x:run-1", f"{REGISTRY}/orgs/acme/x:latest"],
        network=BUILD_NETWORK_NONE,
        metadata_file="/tmp/meta.json",
        build_args={"VERSION": "1.2", "A": "b"},
        labels={RUN_LABEL: "r"},
        secret_files={"tok": "/tmp/secrets/secret-0"},
        target="runtime",
        platform="linux/arm64",
        cache_namespace="hegemony-build-abc",
    )
    assert argv[:2] == ["buildx", "build"]
    for flag in (
        "--progress=plain",
        "--pull",
        "--no-cache",
        "--provenance=false",
        "--sbom=false",
        "--network=none",
        "--push",
    ):
        assert flag in argv
    assert argv[-1] == "/tmp/ctx"
    pairs = list(zip(argv, argv[1:], strict=False))
    assert ("--file", "/tmp/ctx/Dockerfile") in pairs
    assert ("--metadata-file", "/tmp/meta.json") in pairs
    assert ("--target", "runtime") in pairs
    assert ("--platform", "linux/arm64") in pairs
    assert ("--secret", "id=tok,src=/tmp/secrets/secret-0") in pairs
    assert ("--label", f"{RUN_LABEL}=r") in pairs
    build_args = [value for flag, value in pairs if flag == "--build-arg"]
    assert build_args == ["A=b", "VERSION=1.2", "BUILDKIT_CACHE_MOUNT_NS=hegemony-build-abc"]
    tags = [value for flag, value in pairs if flag == "--tag"]
    assert tags == [f"{REGISTRY}/orgs/acme/x:run-1", f"{REGISTRY}/orgs/acme/x:latest"]


def test_build_environment_selects_the_sandbox_and_drops_inherited_buildx_settings(
    monkeypatch,
) -> None:
    monkeypatch.setenv("BUILDX_BUILDER", "somewhere-else")
    monkeypatch.setenv("BUILDKIT_PROGRESS", "tty")
    monkeypatch.setenv("DOCKER_CONTEXT", "other")
    env = build_environment("tcp://dind:2375", "/tmp/step-config")
    assert env["DOCKER_HOST"] == "tcp://dind:2375"
    assert env["DOCKER_CONFIG"] == "/tmp/step-config"
    assert "BUILDX_BUILDER" not in env
    assert "BUILDKIT_PROGRESS" not in env
    assert "DOCKER_CONTEXT" not in env
    assert env["BUILDX_NO_DEFAULT_ATTESTATIONS"] == "1"
    assert env["BUILDX_METADATA_PROVENANCE"] == "disabled"


def test_buildx_argv_without_push_loads_the_image_into_the_sandbox() -> None:
    argv = buildx_argv(
        context="/tmp/ctx",
        dockerfile="/tmp/ctx/Dockerfile",
        references=[f"{REGISTRY}/orgs/acme/x:run-1"],
        network=BUILD_NETWORK_NONE,
        metadata_file="/tmp/meta.json",
        push=False,
    )
    assert argv[-2:] == ["--load", "/tmp/ctx"]
    assert "--push" not in argv
    # Base images are still pulled and nothing comes from the shared build cache.
    assert "--pull" in argv and "--no-cache" in argv


# ── Where the image goes ────────────────────────────────────────────────────


def test_a_short_name_goes_under_the_namespace_and_to_the_platform_registry() -> None:
    destination = build_destination("tools/x", _target())
    assert destination.kind == DESTINATION_PLATFORM
    assert destination.repository == f"{REGISTRY}/orgs/acme/tools/x"
    assert destination.host == REGISTRY
    assert destination.push


def test_without_a_platform_registry_a_short_name_stays_in_the_sandbox() -> None:
    destination = build_destination("tools/x", _target(push=False))
    assert destination.kind == DESTINATION_LOCAL
    # The name it would have in the platform registry, so a flow reads the same.
    assert destination.repository == f"{REGISTRY}/orgs/acme/tools/x"
    assert destination.host == ""
    assert not destination.push


@pytest.mark.parametrize("push", [True, False])
def test_a_name_with_its_registry_is_pushed_there_when_allowed(push: bool) -> None:
    destination = build_destination("ghcr.io/acme/x", _target(push=push, external_push=True))
    assert destination.kind == DESTINATION_REMOTE
    assert destination.repository == "ghcr.io/acme/x"
    assert destination.host == "ghcr.io"
    assert destination.push


def test_a_registry_host_is_spelled_in_lowercase() -> None:
    """Host names know no case; Docker looks a login up by the host as written."""
    destination = build_destination(
        "Registry.Example.com:5000/team/tool", _target(external_push=True)
    )
    assert destination.repository == "registry.example.com:5000/team/tool"
    assert destination.host == "registry.example.com:5000"


def test_another_registry_needs_the_hosts_permission() -> None:
    with pytest.raises(BuildRefused) as refused:
        build_destination("ghcr.io/acme/x", _target())
    assert refused.value.summary == "Push not allowed"
    assert refused.value.error.startswith("This step may not push to ghcr.io: ")
    assert "egress policy is open" in refused.value.error


@pytest.mark.parametrize(
    "name",
    [
        f"{REGISTRY}/orgs/acme/x",
        f"{REGISTRY.upper()}/orgs/other/x",
        # Its default ports name it too.
        f"{REGISTRY}:80/orgs/other/x",
        f"{REGISTRY}:443/orgs/other/x",
    ],
)
def test_the_platform_registry_is_named_by_short_names_only(name: str) -> None:
    """Its names are the namespace's to give: no step picks another organization's."""
    with pytest.raises(BuildRefused) as refused:
        build_destination(name, _target(external_push=True))
    assert refused.value.summary == "Config validation failed"
    assert "platform registry itself" in refused.value.error


def test_another_port_on_the_platform_registry_host_is_another_registry() -> None:
    destination = build_destination(f"{REGISTRY}:5000/team/x", _target(external_push=True))
    assert destination.kind == DESTINATION_REMOTE
    assert destination.host == f"{REGISTRY}:5000"


def test_a_platform_registry_named_with_its_port_matches_names_without_one() -> None:
    target = ImageBuild(registry=f"{REGISTRY}:80", namespace="orgs/acme", external_push=True)
    with pytest.raises(BuildRefused):
        build_destination(f"{REGISTRY}/orgs/other/x", target)


def test_registry_hosts_compare_without_case_or_default_ports() -> None:
    assert same_registry_host("Registry.Example.com:443", "registry.example.com")
    assert same_registry_host("registry.example.com", "registry.example.com:80")
    assert not same_registry_host("registry.example.com:5000", "registry.example.com")
    assert not same_registry_host("registry.example.com:8080", "registry.example.com:80")
    assert not same_registry_host("other.example.com", "registry.example.com")


def test_a_short_name_needs_a_namespace() -> None:
    with pytest.raises(BuildRefused) as refused:
        build_destination("tools/x", ImageBuild(registry=REGISTRY, namespace="", push=False))
    assert refused.value.summary == "Image build unavailable"


# ── A build end to end, against a fake docker ───────────────────────────────

_FAKE_DOCKER = r"""
import json, os, sys, time

record = os.environ["FAKE_DOCKER_RECORD"]
mode = os.environ.get("FAKE_DOCKER_MODE", "ok")
args = sys.argv[1:]

def save(entry):
    with open(record, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")

if args[:2] == ["buildx", "version"]:
    if mode == "no-buildx":
        print("docker: 'buildx' is not a docker command.", file=sys.stderr)
        sys.exit(1)
    print("github.com/docker/buildx v0.37.2 2d379c0")
    sys.exit(0)

if args[:2] == ["image", "rm"]:
    save({"argv": args})
    if mode == "rm-fails":
        print("Error response from daemon: conflict: unable to delete", file=sys.stderr)
        sys.exit(1)
    if mode in ("rm-missing", "fail"):
        for ref in args[3:]:
            print("Error response from daemon: No such image: " + ref, file=sys.stderr)
        sys.exit(1)
    sys.exit(0)

if args[:2] == ["image", "inspect"]:
    save({"argv": args})
    ref = args[-1]
    if mode == "no-digest":
        print("[]")
        sys.exit(0)
    print(json.dumps([ref.rsplit(":", 1)[0] + "@" + os.environ["FAKE_DOCKER_DIGEST"]]))
    sys.exit(0)

if args[:1] in (["pull"], ["tag"], ["push"]):
    save({"argv": args})
    if args[0] == "pull":
        print("Status: Downloaded newer image for " + args[1])
    sys.exit(0)

if args[:2] == ["buildx", "build"]:
    pairs = list(zip(args, args[1:]))
    context = args[-1]
    files = {}
    for root, _dirs, names in os.walk(context):
        for name in names:
            path = os.path.join(root, name)
            with open(path, encoding="utf-8") as handle:
                files[os.path.relpath(path, context)] = handle.read()
    secrets = {}
    for flag, value in pairs:
        if flag == "--secret":
            parts = dict(item.split("=", 1) for item in value.split(","))
            with open(parts["src"], encoding="utf-8") as handle:
                secrets[parts["id"]] = handle.read()
            secrets[parts["id"] + ".mode"] = oct(os.stat(parts["src"]).st_mode & 0o777)
    save({
        "argv": args,
        "files": files,
        "secrets": secrets,
        "context": context,
        "env": {k: v for k, v in os.environ.items() if k.startswith(("DOCKER_", "BUILDX_"))},
        "pid": os.getpid(),
    })
    print("#1 [internal] load build definition from Dockerfile", flush=True)
    print("#5 [2/2] RUN echo hello", flush=True)
    print("#5 0.105 hello", flush=True)
    if mode == "long-line":
        print("#5 0.200 " + "x" * 200_000, flush=True)
    if mode == "slow":
        time.sleep(30)
    if mode == "fail":
        print("#5 ERROR: process did not complete successfully: exit code: 1", flush=True)
        print("ERROR: failed to build: failed to solve: exit code: 1", flush=True)
        sys.exit(1)
    if mode not in ("no-metadata", "no-digest"):
        metadata = dict(pairs)["--metadata-file"]
        with open(metadata, "w", encoding="utf-8") as handle:
            json.dump({"containerimage.digest": os.environ["FAKE_DOCKER_DIGEST"]}, handle)
    print("#12 pushing layers done", flush=True)
    sys.exit(0)

print("unexpected docker call: " + " ".join(args), file=sys.stderr)
sys.exit(2)
"""


@pytest.fixture
def fake_docker(tmp_path: Path, monkeypatch) -> dict[str, Any]:
    script = tmp_path / "docker"
    script.write_text(f"#!{sys.executable}\n{_FAKE_DOCKER}", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    record = tmp_path / "record.jsonl"
    monkeypatch.setenv("FAKE_DOCKER_RECORD", str(record))
    monkeypatch.setenv("FAKE_DOCKER_DIGEST", DIGEST)
    monkeypatch.setenv("FAKE_DOCKER_MODE", "ok")

    def calls() -> list[dict[str, Any]]:
        if not record.exists():
            return []
        return [json.loads(line) for line in record.read_text(encoding="utf-8").splitlines()]

    return {"bin": str(script), "calls": calls, "config_dir": str(tmp_path / "docker-config")}


_ATTACHMENTS = [
    {"filename": "images/tool/Dockerfile", "content": "FROM alpine\nRUN echo hello\n"},
    {"filename": "images/tool/app/main.py", "content": "print('hi')\n"},
    {"filename": "images/other/Dockerfile", "content": "FROM busybox\n"},
    {"filename": "playbook.yml", "content": "- hosts: all\n"},
]


class _Services:
    def __init__(
        self,
        docker_bin: str,
        config_dir: str,
        *,
        build: ImageBuild | None,
        attachments: list[dict[str, Any]] | None = None,
        secrets: dict[str, str] | None = None,
        cache: ImageCache | None = None,
    ) -> None:
        self.docker_bin = docker_bin
        self.config_dir = config_dir
        self.build = build
        self.cache = cache
        self.attachments = _ATTACHMENTS if attachments is None else attachments
        self.secrets = secrets or {}
        self.resolved: list[str] = []

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin=self.docker_bin,
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
            docker_host="tcp://dind:2375",
            docker_config_dir=self.config_dir,
            image_build=self.build,
            image_cache=self.cache,
        )

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        return list(self.attachments)

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        assert ref is not None
        self.resolved.append(ref)
        for key, value in self.secrets.items():
            if key in ref:
                return value
        return None


def _ctx(
    config: dict[str, Any], services: _Services, events: list[tuple[str, dict]], timeout: int = 60
) -> HandlerContext:
    async def emit(message: str, device_id: str | None = None, attrs: dict | None = None) -> bool:
        events.append((message, dict(attrs or {})))
        return True

    return HandlerContext(
        run_id=RUN_ID,
        flow_id="flow-1",
        step_run_id="step-run-1",
        step_id="build_tool",
        config=config,
        timeout_seconds=timeout,
        services=cast(HandlerServices, services),
        _emit_progress=emit,
    )


def _target(
    network: str = BUILD_NETWORK_NONE, *, push: bool = True, external_push: bool = False
) -> ImageBuild:
    return ImageBuild(
        registry=REGISTRY,
        namespace="orgs/acme",
        network=network,
        push=push,
        external_push=external_push,
    )


def _removals(fake_docker: dict[str, Any]) -> list[list[str]]:
    return [call["argv"] for call in fake_docker["calls"]() if call["argv"][:2] == ["image", "rm"]]


def _save_login(config_dir: str, host: str) -> None:
    os.makedirs(config_dir, exist_ok=True)
    with open(os.path.join(config_dir, "config.json"), "w", encoding="utf-8") as handle:
        json.dump({"auths": {host: {"auth": "dXNlcjpwYXNz"}}}, handle)


def _builds(fake_docker: dict[str, Any]) -> list[dict[str, Any]]:
    return [call for call in fake_docker["calls"]() if call["argv"][:2] == ["buildx", "build"]]


def _pairs(argv: list[str]) -> list[tuple[str, str]]:
    return list(zip(argv, argv[1:], strict=False))


@pytest.mark.asyncio
async def test_a_build_pushes_the_run_tag_and_the_extra_tags(fake_docker) -> None:
    services = _Services(
        fake_docker["bin"],
        fake_docker["config_dir"],
        build=_target(),
        secrets={"vault://orgs/acme/secrets/pypi": "pypi-secret-value"},
    )
    events: list[tuple[str, dict]] = []
    config = {
        "image": "tools/netbox-sync",
        "tags": ["latest", "1.2"],
        "context_dir": "images/tool",
        "build_args": {"VERSION": "1.2"},
        "secrets": {"pypi_token": "vault://orgs/acme/secrets/pypi"},
        "labels": {"org.opencontainers.image.source": "https://git.example.com/x"},
    }
    result = await BuildImageHandler().execute(_ctx(config, services, events))

    assert result.success, result.error
    repository = f"{REGISTRY}/orgs/acme/tools/netbox-sync"
    references = [f"{repository}:run-1a2b3c4d", f"{repository}:latest", f"{repository}:1.2"]
    assert result.output == {
        "image": repository,
        "digest": DIGEST,
        "reference": f"{repository}@{DIGEST}",
        "tags": ["run-1a2b3c4d", "latest", "1.2"],
        "references": references,
        "destination": "platform",
        "pushed": True,
    }
    assert result.metrics["image_digest"] == DIGEST
    assert result.metrics["tag_count"] == 3

    (build,) = _builds(fake_docker)
    argv = build["argv"]
    pairs = _pairs(argv)
    assert [value for flag, value in pairs if flag == "--tag"] == references
    assert "--network=none" in argv
    assert "--pull" in argv and "--no-cache" in argv and "--push" in argv
    assert ("--build-arg", "VERSION=1.2") in pairs
    (namespace,) = [
        value.partition("=")[2]
        for flag, value in pairs
        if flag == "--build-arg" and value.startswith("BUILDKIT_CACHE_MOUNT_NS=")
    ]
    assert namespace.startswith("hegemony-build-")
    labels = dict(value.split("=", 1) for flag, value in pairs if flag == "--label")
    assert labels[RUN_LABEL] == RUN_ID
    assert labels[STEP_LABEL] == "build_tool"
    assert labels[CREATED_LABEL].endswith("Z")
    assert labels["org.opencontainers.image.source"] == "https://git.example.com/x"
    # Only the context folder's files, at their paths inside it.
    assert build["files"] == {
        "Dockerfile": "FROM alpine\nRUN echo hello\n",
        os.path.join("app", "main.py"): "print('hi')\n",
    }
    # The secret travels as a private file, never in the argument list.
    assert build["secrets"] == {"pypi_token": "pypi-secret-value", "pypi_token.mode": "0o600"}
    assert not any("pypi-secret-value" in arg for arg in argv)
    assert build["env"]["DOCKER_HOST"] == "tcp://dind:2375"
    assert build["env"]["DOCKER_CONFIG"] == fake_docker["config_dir"]
    # The private build directory is gone afterwards.
    assert not os.path.exists(build["context"])

    milestones = [attrs.get("milestone") for _message, attrs in events]
    assert milestones[0] == "build_start"
    assert "output" in milestones
    assert milestones[-1] == "image_pushed"
    pushed = events[-1][1]
    assert pushed["digest"] == DIGEST and pushed["references"] == references
    log = "".join(message for message, attrs in events if attrs.get("milestone") == "output")
    assert "#5 0.105 hello" in log

    by_name = {artifact["name"]: artifact for artifact in result.evidence}
    output = by_name["build_output_build_tool"]
    assert output["kind"] == "container_output"
    assert output["content_json"]["exit_code"] == 0
    assert output["content_json"]["image"] == f"{repository}@{DIGEST}"
    assert "#5 0.105 hello" in output["content_json"]["stdout"]
    details = by_name["image_build_build_tool"]
    assert details["kind"] == "step_result"
    assert details["content_json"]["references"] == references
    assert details["content_json"]["digest"] == DIGEST
    assert details["content_json"]["secrets"] == ["pypi_token"]
    assert details["content_json"]["build_args"] == ["VERSION"]
    assert details["content_json"]["destination"] == "platform"
    assert "saved_login" not in details["content_json"]
    assert "pypi-secret-value" not in json.dumps(result.evidence)
    # The platform registry's names belong to this organization: they stay.
    assert _removals(fake_docker) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("context_dir", ["images/tool/", "./images/tool", "images//tool"])
async def test_the_context_folder_is_normalized(fake_docker, context_dir: str) -> None:
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": context_dir}, services, [])
    )
    assert result.success, result.error
    assert set(_builds(fake_docker)[0]["files"]) == {"Dockerfile", os.path.join("app", "main.py")}


@pytest.mark.asyncio
async def test_the_attachments_root_is_the_default_context(fake_docker) -> None:
    attachments = [
        {"filename": "Dockerfile", "content": "FROM alpine\n"},
        {"filename": "src/app.py", "content": "print(1)\n"},
    ]
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(), attachments=attachments
    )
    for context_dir in ("", "."):
        result = await BuildImageHandler().execute(
            _ctx({"image": "tools/x", "context_dir": context_dir}, services, [])
        )
        assert result.success, result.error
    for build in _builds(fake_docker):
        assert set(build["files"]) == {"Dockerfile", os.path.join("src", "app.py")}


@pytest.mark.asyncio
async def test_an_open_policy_gives_the_build_the_default_network(fake_docker) -> None:
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(BUILD_NETWORK_DEFAULT)
    )
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, events)
    )
    assert result.success, result.error
    (build,) = _builds(fake_docker)
    assert "--network=default" in build["argv"]
    assert events[0][1]["network"] == "default"


@pytest.mark.asyncio
async def test_an_unknown_network_value_builds_without_network(fake_docker) -> None:
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target("bridge"))
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, [])
    )
    assert result.success, result.error
    assert "--network=none" in _builds(fake_docker)[0]["argv"]


@pytest.mark.asyncio
async def test_without_build_settings_nothing_is_built(fake_docker) -> None:
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=None)
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, [])
    )
    assert not result.success
    assert result.summary == "Image build unavailable"
    assert result.error is not None and "no build settings" in result.error
    assert fake_docker["calls"]() == []


@pytest.mark.asyncio
async def test_without_a_platform_registry_the_image_stays_in_the_sandbox(fake_docker) -> None:
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target(push=False))
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx(
            {"image": "tools/x", "context_dir": "images/tool", "tags": ["latest"]}, services, events
        )
    )

    assert result.success, result.error
    repository = f"{REGISTRY}/orgs/acme/tools/x"
    references = [f"{repository}:run-1a2b3c4d", f"{repository}:latest"]
    # No registry holds it, so the run tag names it: no other run's build takes that.
    assert result.output == {
        "image": repository,
        "digest": "",
        "reference": f"{repository}:run-1a2b3c4d",
        "tags": ["run-1a2b3c4d", "latest"],
        "references": references,
        "destination": "local",
        "pushed": False,
    }
    assert result.summary == f"Built {repository} (run-1a2b3c4d, latest), kept in the sandbox"
    (build,) = _builds(fake_docker)
    assert build["argv"][-2] == "--load"
    assert "--push" not in build["argv"]
    assert [value for flag, value in _pairs(build["argv"]) if flag == "--tag"] == references
    # Nothing was pushed, so no digest is looked up, and the names stay.
    calls = [call["argv"][:2] for call in fake_docker["calls"]()]
    assert ["image", "inspect"] not in calls
    assert _removals(fake_docker) == []
    assert "keeping it in the sandbox, unpushed" in events[0][0]
    assert events[0][1]["destination"] == "local"
    assert events[-1][1]["milestone"] == "image_built"
    details = {artifact["name"]: artifact for artifact in result.evidence}["image_build_build_tool"]
    assert details["content_json"]["pushed"] is False
    assert "Kept in the sandbox: " + references[0] in details["content_text"]


@pytest.mark.asyncio
async def test_a_name_with_its_registry_is_pushed_there_with_the_saved_login(fake_docker) -> None:
    _save_login(fake_docker["config_dir"], "ghcr.io")
    services = _Services(
        fake_docker["bin"],
        fake_docker["config_dir"],
        build=_target(BUILD_NETWORK_DEFAULT, push=False, external_push=True),
    )
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx({"image": "ghcr.io/acme/tool", "context_dir": "images/tool"}, services, events)
    )

    assert result.success, result.error
    references = ["ghcr.io/acme/tool:run-1a2b3c4d"]
    assert result.output["reference"] == f"ghcr.io/acme/tool@{DIGEST}"
    assert result.output["destination"] == "remote"
    assert result.output["pushed"] is True
    (build,) = _builds(fake_docker)
    assert build["argv"][-2] == "--push"
    assert [value for flag, value in _pairs(build["argv"]) if flag == "--tag"] == references
    # The push reads the login from the step's Docker configuration.
    assert build["env"]["DOCKER_CONFIG"] == fake_docker["config_dir"]
    assert "with the organization's saved login" in events[0][0]
    assert events[0][1]["saved_login"] is True
    details = {artifact["name"]: artifact for artifact in result.evidence}["image_build_build_tool"]
    assert details["content_json"]["saved_login"] is True
    # The name is taken off the shared sandbox once the push is done.
    assert _removals(fake_docker) == [["image", "rm", "--force", *references]]


@pytest.mark.asyncio
async def test_an_uppercase_registry_host_finds_the_saved_login(fake_docker) -> None:
    _save_login(fake_docker["config_dir"], "registry.example.com")
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(external_push=True)
    )
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx(
            {"image": "Registry.Example.com/team/tool", "context_dir": "images/tool"},
            services,
            events,
        )
    )
    assert result.success, result.error
    assert events[0][1]["saved_login"] is True
    assert result.output["image"] == "registry.example.com/team/tool"


@pytest.mark.asyncio
async def test_names_pushed_elsewhere_come_off_the_sandbox_as_the_build_ends(
    fake_docker, monkeypatch
) -> None:
    """Before the step reports anything, once the digest is read (through the names)."""
    monkeypatch.setenv("FAKE_DOCKER_MODE", "no-metadata")
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(external_push=True)
    )
    removed_before: list[int] = []

    async def emit(message: str, device_id: str | None = None, attrs: dict | None = None) -> bool:
        if (attrs or {}).get("milestone") == "image_pushed":
            removed_before.append(len(_removals(fake_docker)))
        return True

    ctx = HandlerContext(
        run_id=RUN_ID,
        flow_id="flow-1",
        step_run_id="step-run-1",
        step_id="build_tool",
        config={"image": "ghcr.io/acme/tool", "context_dir": "images/tool"},
        timeout_seconds=60,
        services=cast(HandlerServices, services),
        _emit_progress=emit,
    )
    result = await BuildImageHandler().execute(ctx)
    assert result.success, result.error
    assert result.output["digest"] == DIGEST
    order = [call["argv"][:2] for call in fake_docker["calls"]()]
    assert order == [["buildx", "build"], ["image", "inspect"], ["image", "rm"]]
    # Removed once, before the push was reported.
    assert removed_before == [1]


@pytest.mark.asyncio
async def test_a_timed_out_push_elsewhere_loses_its_names_once(fake_docker, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_DOCKER_MODE", "slow")
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(external_push=True)
    )
    result = await BuildImageHandler().execute(
        _ctx({"image": "ghcr.io/acme/tool", "context_dir": "images/tool"}, services, [], timeout=1)
    )
    assert result.summary == "Build timed out"
    assert _removals(fake_docker) == [["image", "rm", "--force", "ghcr.io/acme/tool:run-1a2b3c4d"]]


@pytest.mark.asyncio
async def test_a_push_elsewhere_cut_short_still_loses_its_names(fake_docker, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_DOCKER_MODE", "slow")

    async def broken_add(self, raw: bytes) -> None:
        raise RuntimeError("log sink broke")

    monkeypatch.setattr(_BuildLog, "add", broken_add)
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(external_push=True)
    )
    with pytest.raises(RuntimeError, match="log sink broke"):
        await BuildImageHandler().execute(
            _ctx({"image": "ghcr.io/acme/tool", "context_dir": "images/tool"}, services, [])
        )
    assert _removals(fake_docker) == [["image", "rm", "--force", "ghcr.io/acme/tool:run-1a2b3c4d"]]


@pytest.mark.asyncio
async def test_a_push_elsewhere_without_a_saved_login_says_so(fake_docker) -> None:
    _save_login(fake_docker["config_dir"], "other.example.com")
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(external_push=True)
    )
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx({"image": "docker.io/acme/tool", "context_dir": "images/tool"}, services, events)
    )
    assert result.success, result.error
    assert "pushing to docker.io without a login" in events[0][0]
    assert events[0][1]["saved_login"] is False


@pytest.mark.asyncio
async def test_a_failed_push_elsewhere_leaves_no_name_in_the_sandbox(
    fake_docker, monkeypatch
) -> None:
    monkeypatch.setenv("FAKE_DOCKER_MODE", "fail")
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(external_push=True)
    )
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx({"image": "ghcr.io/acme/tool", "context_dir": "images/tool"}, services, events)
    )
    assert not result.success
    assert _removals(fake_docker) == [["image", "rm", "--force", "ghcr.io/acme/tool:run-1a2b3c4d"]]
    # A name the build never set is not a problem worth an event.
    assert all(attrs.get("milestone") != "build_cleanup_failed" for _message, attrs in events)


@pytest.mark.asyncio
async def test_a_name_left_in_the_sandbox_is_reported(fake_docker, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_DOCKER_MODE", "rm-fails")
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(external_push=True)
    )
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx({"image": "ghcr.io/acme/tool", "context_dir": "images/tool"}, services, events)
    )
    assert result.success, result.error
    (cleanup,) = [
        attrs for _message, attrs in events if attrs.get("milestone") == "build_cleanup_failed"
    ]
    assert cleanup["references"] == ["ghcr.io/acme/tool:run-1a2b3c4d"]


@pytest.mark.asyncio
async def test_a_push_elsewhere_the_host_does_not_allow_builds_nothing(fake_docker) -> None:
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    result = await BuildImageHandler().execute(
        _ctx({"image": "ghcr.io/acme/tool", "context_dir": "images/tool"}, services, [])
    )
    assert not result.success
    assert result.summary == "Push not allowed"
    assert fake_docker["calls"]() == []


@pytest.mark.asyncio
async def test_a_cli_without_buildx_fails_clearly(fake_docker, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_DOCKER_MODE", "no-buildx")
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, [])
    )
    assert not result.success
    assert result.summary == "BuildKit not available"
    assert result.error is not None and "no working buildx plugin" in result.error
    assert _builds(fake_docker) == []


@pytest.mark.asyncio
async def test_a_failed_build_reports_the_builds_own_error(fake_docker, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_DOCKER_MODE", "fail")
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, events)
    )
    assert not result.success
    assert result.summary == "Image build failed"
    assert result.error == "failed to build: failed to solve: exit code: 1"
    (log,) = result.evidence
    assert log["kind"] == "container_output"
    assert log["content_json"]["exit_code"] == 1
    assert "ERROR: failed to build" in log["content_text"]
    assert events[-1][1]["milestone"] == "build_failed"


@pytest.mark.asyncio
async def test_the_digest_falls_back_to_what_the_daemon_recorded(fake_docker, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_DOCKER_MODE", "no-metadata")
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, [])
    )
    assert result.success, result.error
    assert result.output["digest"] == DIGEST
    inspects = [c for c in fake_docker["calls"]() if c["argv"][:2] == ["image", "inspect"]]
    assert inspects and inspects[0]["argv"][-1] == f"{REGISTRY}/orgs/acme/tools/x:run-1a2b3c4d"


@pytest.mark.asyncio
async def test_a_push_without_a_readable_digest_fails_the_step(fake_docker, monkeypatch) -> None:
    """A tag can move, so it never stands in for the digest later steps run."""
    monkeypatch.setenv("FAKE_DOCKER_MODE", "no-digest")
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, events)
    )
    assert not result.success
    assert result.summary == "Image digest unavailable"
    assert result.error is not None and "run-1a2b3c4d" in result.error
    assert result.output in (None, {})
    (log,) = result.evidence
    assert log["kind"] == "container_output"
    assert events[-1][1]["milestone"] == "build_failed"
    assert events[-1][1]["references"] == [f"{REGISTRY}/orgs/acme/tools/x:run-1a2b3c4d"]


@pytest.mark.asyncio
async def test_a_very_long_output_line_is_logged_whole(fake_docker, monkeypatch) -> None:
    """Longer than asyncio's 64 KiB line limit: read in pieces, not raised on."""
    monkeypatch.setenv("FAKE_DOCKER_MODE", "long-line")
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, events)
    )
    assert result.success, result.error
    log = result.evidence[0]["content_text"]
    assert "#5 0.200 " + "x" * 200_000 + "\n#12 pushing layers done" in log
    streamed = "".join(message for message, attrs in events if attrs.get("milestone") == "output")
    assert "x" * 200_000 in streamed


@pytest.mark.asyncio
async def test_the_live_log_stops_at_its_limit_and_the_log_is_still_kept() -> None:
    events: list[str] = []

    async def emit(message: str, attrs: dict | None = None) -> None:
        events.append(message)

    log = _BuildLog(emit)
    line = b"#7 " + b"z" * 96 + b"\n"
    for _ in range((MAX_LIVE_OUTPUT_BYTES + 1024 * 1024) // len(line)):
        await log.add(line)
    await log.add(b"ERROR: failed to build\n")
    await log.flush()
    live = "".join(events)
    assert live.count("[Live output stops here, at its 5 MB limit; the build goes on.") == 1
    assert len(live.encode()) <= MAX_LIVE_OUTPUT_BYTES + 300
    # The evidence and the error line still see the whole output.
    assert len(log.captured) == MAX_LOG_BYTES
    assert log.truncated
    assert list(log.tail)[-1] == "ERROR: failed to build"


@pytest.mark.asyncio
async def test_a_failure_reading_the_output_stops_the_build(fake_docker, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_DOCKER_MODE", "slow")

    async def broken_add(self, raw: bytes) -> None:
        raise RuntimeError("log sink broke")

    monkeypatch.setattr(_BuildLog, "add", broken_add)
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    with pytest.raises(RuntimeError, match="log sink broke"):
        await BuildImageHandler().execute(
            _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, [])
        )
    (build,) = _builds(fake_docker)
    # Killed and reaped: the build's client process is gone.
    with pytest.raises(ProcessLookupError):
        os.kill(build["pid"], 0)


@pytest.mark.asyncio
async def test_a_missing_dockerfile_fails_before_building(fake_docker) -> None:
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/none"}, services, [])
    )
    assert not result.success
    assert result.summary == "Build context unavailable"
    assert result.error is not None and "images/none/Dockerfile" in result.error
    assert _builds(fake_docker) == []


@pytest.mark.asyncio
async def test_another_frontend_is_refused_before_building(fake_docker) -> None:
    attachments = [{"filename": "Dockerfile", "content": "# syntax=evil/fe:1\nFROM alpine\n"}]
    services = _Services(
        fake_docker["bin"], fake_docker["config_dir"], build=_target(), attachments=attachments
    )
    result = await BuildImageHandler().execute(_ctx({"image": "tools/x"}, services, []))
    assert not result.success
    assert result.error is not None and "evil/fe:1" in result.error
    assert _builds(fake_docker) == []


@pytest.mark.asyncio
async def test_a_template_must_be_rendered_by_the_run(fake_docker) -> None:
    """Saving takes a templated tag; the run takes only what it rendered to."""
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    config = {"image": "tools/x", "context_dir": "images/tool", "tags": ["{{ inputs.v }}"]}
    assert BuildImageHandler().validate_config(config) == []
    result = await BuildImageHandler().execute(_ctx(config, services, []))
    assert not result.success
    assert result.summary == "Config validation failed"
    assert result.error is not None and "not a valid tag" in result.error
    assert _builds(fake_docker) == []


@pytest.mark.asyncio
async def test_an_unresolvable_secret_fails_the_step(fake_docker) -> None:
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    result = await BuildImageHandler().execute(
        _ctx(
            {
                "image": "tools/x",
                "context_dir": "images/tool",
                "secrets": {"tok": "vault://orgs/acme/secrets/missing"},
            },
            services,
            [],
        )
    )
    assert not result.success
    assert result.error is not None and "resolved to an empty value" in result.error
    assert _builds(fake_docker) == []


@pytest.mark.asyncio
async def test_a_build_past_the_step_timeout_is_stopped(fake_docker, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_DOCKER_MODE", "slow")
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=_target())
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, events, timeout=1)
    )
    assert not result.success
    assert result.summary == "Build timed out"
    (log,) = result.evidence
    assert "#5 0.105 hello" in log["content_text"]


# ── Base images from the platform registry's cache ───────────────────────────

CACHE = ImageCache(
    registry=REGISTRY,
    api_url=f"http://{REGISTRY}",
    namespace="orgs/acme",
    read_namespaces=("global",),
)
UPSTREAM = "https://registry-1.docker.io"
UPSTREAM_DIGEST = "sha256:" + "11" * 32
COPY_DIGEST = "sha256:" + "22" * 32
KEY_TAG = "sha256_" + "11" * 32
OWN_REPO = "orgs/acme/docker.io/library/alpine"
GLOBAL_REPO = "global/docker.io/library/alpine"


class _Registries:
    """Manifest answers by ``(base_url, repo, reference)``: a digest, None (404), an
    exception, an httpx response or a callable returning one of those."""

    def __init__(self) -> None:
        self.manifests: dict[tuple[str, str, str], Any] = {}
        self.unreachable: set[str] = set()
        self.requests: list[str] = []

    def transport(self, base_url: str) -> httpx.MockTransport:
        async def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(str(request.url))
            if base_url in self.unreachable:
                raise httpx.ConnectError("connection refused")
            _, _, rest = request.url.path.partition("/v2/")
            repo, _, reference = rest.rpartition("/manifests/")
            answer = self.manifests.get((base_url, repo, reference))
            if callable(answer):
                answer = answer()
            if isinstance(answer, Exception):
                raise answer
            if isinstance(answer, httpx.Response):
                return answer
            if answer is None:
                return httpx.Response(404)
            return httpx.Response(200, headers={"Docker-Content-Digest": answer})

        return httpx.MockTransport(handler)


@pytest.fixture
def registries(monkeypatch) -> _Registries:
    fake = _Registries()
    monkeypatch.setattr("hegemony_steps_container.run._registry_transport", fake.transport)
    # Pulls go through the docker CLI fake, which records them.
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("off in tests")),
    )
    fake.manifests[(UPSTREAM, "library/alpine", "3.20")] = UPSTREAM_DIGEST
    return fake


def _cached_build(
    fake_docker: dict[str, Any],
    events: list[tuple[str, dict]],
    dockerfile: str = "FROM alpine:3.20\nRUN echo hello\n",
    **config: Any,
) -> HandlerContext:
    services = _Services(
        fake_docker["bin"],
        fake_docker["config_dir"],
        build=_target(),
        attachments=[{"filename": "Dockerfile", "content": dockerfile}],
        cache=CACHE,
    )
    return _ctx({"image": "tools/tool", **config}, services, events)


def _contexts(fake_docker: dict[str, Any]) -> list[str]:
    (build,) = _builds(fake_docker)
    return [value for flag, value in _pairs(build["argv"]) if flag == "--build-context"]


def _docker_verbs(fake_docker: dict[str, Any], verb: str) -> list[list[str]]:
    return [call["argv"] for call in fake_docker["calls"]() if call["argv"][:1] == [verb]]


def _base_records(result) -> list[dict[str, Any]]:
    details = next(e for e in result.evidence if e["kind"] == "step_result")["content_json"]
    return details["base_images"]


def test_buildx_argv_hands_buildkit_the_base_image_copies() -> None:
    argv = buildx_argv(
        context="/ctx",
        dockerfile="/ctx/Dockerfile",
        references=["r:1"],
        network=BUILD_NETWORK_NONE,
        metadata_file="/m.json",
        build_contexts={
            "python:3.12": "docker-image://reg/orgs/acme/docker.io/library/python@sha256:b",
            "alpine:3.20": "docker-image://reg/orgs/acme/docker.io/library/alpine@sha256:a",
        },
    )
    assert [value for flag, value in _pairs(argv) if flag == "--build-context"] == [
        "alpine:3.20=docker-image://reg/orgs/acme/docker.io/library/alpine@sha256:a",
        "python:3.12=docker-image://reg/orgs/acme/docker.io/library/python@sha256:b",
    ]
    # The image still comes with --pull: BuildKit fetches the copy with the step's login.
    assert "--pull" in argv


@pytest.mark.asyncio
async def test_a_base_image_is_built_on_its_copy_in_the_platform_registry(
    fake_docker, registries
) -> None:
    registries.manifests[(CACHE.api_url, OWN_REPO, KEY_TAG)] = COPY_DIGEST
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(_cached_build(fake_docker, events))

    assert result.success, result.error
    copy = f"{REGISTRY}/{OWN_REPO}@{COPY_DIGEST}"
    assert _contexts(fake_docker) == [f"alpine:3.20=docker-image://{copy}"]
    # A copy was there: nothing pulled or pushed besides the build itself.
    assert _docker_verbs(fake_docker, "pull") == [] and _docker_verbs(fake_docker, "push") == []
    hit = next(attrs for _m, attrs in events if attrs.get("milestone") == "base_image_cache_hit")
    assert hit["copy"] == copy and hit["image"] == "alpine:3.20"
    assert _base_records(result) == [
        {"image": "alpine:3.20", "served": copy, "source": "cache", "cached": False}
    ]
    summary = next(e for e in result.evidence if e["kind"] == "step_result")["content_text"]
    assert f"Base image: alpine:3.20 from {copy}" in summary


@pytest.mark.asyncio
async def test_a_base_image_without_a_copy_is_saved_and_built_on(fake_docker, registries) -> None:
    def copy_once_pushed() -> str | None:
        return COPY_DIGEST if _docker_verbs(fake_docker, "push") else None

    registries.manifests[(CACHE.api_url, OWN_REPO, KEY_TAG)] = copy_once_pushed
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(_cached_build(fake_docker, events))

    assert result.success, result.error
    # Exactly the digest the check named is pulled, and saved under its key and tag.
    assert _docker_verbs(fake_docker, "pull") == [["pull", f"alpine@{UPSTREAM_DIGEST}"]]
    assert _docker_verbs(fake_docker, "push") == [
        ["push", f"{REGISTRY}/{OWN_REPO}:{KEY_TAG}"],
        ["push", f"{REGISTRY}/{OWN_REPO}:3.20"],
    ]
    copy = f"{REGISTRY}/{OWN_REPO}@{COPY_DIGEST}"
    assert _contexts(fake_docker) == [f"alpine:3.20=docker-image://{copy}"]
    assert "base_image_cached" in [attrs.get("milestone") for _m, attrs in events]
    assert _base_records(result) == [
        {"image": "alpine:3.20", "served": copy, "source": "cache", "cached": True}
    ]


@pytest.mark.asyncio
async def test_a_global_copy_serves_when_the_organization_has_none(fake_docker, registries) -> None:
    registries.manifests[(CACHE.api_url, GLOBAL_REPO, KEY_TAG)] = COPY_DIGEST
    result = await BuildImageHandler().execute(_cached_build(fake_docker, []))

    assert result.success, result.error
    assert _contexts(fake_docker) == [
        f"alpine:3.20=docker-image://{REGISTRY}/{GLOBAL_REPO}@{COPY_DIGEST}"
    ]
    assert _docker_verbs(fake_docker, "push") == []


@pytest.mark.asyncio
async def test_an_unreachable_registry_falls_back_to_the_last_copy_by_tag(
    fake_docker, registries
) -> None:
    registries.unreachable.add(UPSTREAM)
    registries.manifests[(CACHE.api_url, OWN_REPO, "3.20")] = COPY_DIGEST
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(_cached_build(fake_docker, events))

    assert result.success, result.error
    assert _contexts(fake_docker) == [
        f"alpine:3.20=docker-image://{REGISTRY}/{OWN_REPO}@{COPY_DIGEST}"
    ]
    assert "base_image_cache_stale" in [attrs.get("milestone") for _m, attrs in events]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (
            lambda r: r.manifests.__setitem__(
                (UPSTREAM, "library/alpine", "3.20"), httpx.Response(401)
            ),
            "refused the manifest check",
        ),
        (lambda r: r.unreachable.add(CACHE.api_url), "the platform registry is unavailable"),
        (lambda r: r.unreachable.add(UPSTREAM), "has no copy of it"),
    ],
)
async def test_a_base_image_the_cache_cannot_serve_comes_from_its_registry(
    fake_docker, registries, setup, reason
) -> None:
    setup(registries)
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(_cached_build(fake_docker, events))

    assert result.success, result.error
    assert _contexts(fake_docker) == []
    skips = [msg for msg, attrs in events if attrs.get("milestone") == "base_image_cache_skip"]
    assert len(skips) == 1 and reason in skips[0]
    assert _base_records(result) == [
        {"image": "alpine:3.20", "served": "", "source": "upstream", "cached": False}
    ]


@pytest.mark.asyncio
async def test_a_build_for_another_platform_pulls_its_base_images_upstream(
    fake_docker, registries
) -> None:
    events: list[tuple[str, dict]] = []
    result = await BuildImageHandler().execute(
        _cached_build(fake_docker, events, platform="linux/arm64")
    )

    assert result.success, result.error
    assert _contexts(fake_docker) == []
    assert registries.requests == []
    [skip] = [attrs for _m, attrs in events if attrs.get("milestone") == "base_image_cache_skip"]
    assert skip["platform"] == "linux/arm64"


@pytest.mark.asyncio
async def test_cache_base_images_off_leaves_the_base_images_alone(fake_docker, registries) -> None:
    result = await BuildImageHandler().execute(
        _cached_build(fake_docker, [], cache_base_images=False)
    )

    assert result.success, result.error
    assert _contexts(fake_docker) == []
    assert registries.requests == []
    assert _base_records(result) == []


@pytest.mark.asyncio
async def test_only_images_are_looked_up_not_stages_or_scratch(fake_docker, registries) -> None:
    registries.manifests[(CACHE.api_url, OWN_REPO, KEY_TAG)] = COPY_DIGEST
    dockerfile = (
        "FROM alpine:3.20 AS build\n"
        "RUN echo hello\n"
        "FROM scratch\n"
        "COPY --from=build /etc/os-release /\n"
    )
    result = await BuildImageHandler().execute(_cached_build(fake_docker, [], dockerfile))

    assert result.success, result.error
    assert [record["image"] for record in _base_records(result)] == ["alpine:3.20"]
    assert all("/scratch/" not in url and "/build/" not in url for url in registries.requests)


@pytest.mark.asyncio
async def test_no_context_replaces_a_stage_named_like_a_base_image(fake_docker, registries) -> None:
    """``alpine:latest`` is the context ``alpine``, which would replace the stage ``alpine``."""
    registries.manifests[(UPSTREAM, "library/alpine", "latest")] = UPSTREAM_DIGEST
    registries.manifests[(CACHE.api_url, OWN_REPO, KEY_TAG)] = COPY_DIGEST
    dockerfile = (
        "FROM alpine:latest AS base\n"
        "RUN echo base > /base\n"
        "FROM busybox AS alpine\n"
        "RUN echo final > /final\n"
        "COPY --from=base /base /base\n"
    )
    result = await BuildImageHandler().execute(_cached_build(fake_docker, [], dockerfile))

    assert result.success, result.error
    assert not any(context.startswith("alpine") for context in _contexts(fake_docker))
    assert [record["image"] for record in _base_records(result)] == ["busybox"]


@pytest.mark.asyncio
async def test_no_context_reaches_a_stage_built_for_another_platform(
    fake_docker, registries
) -> None:
    registries.manifests[(CACHE.api_url, OWN_REPO, KEY_TAG)] = COPY_DIGEST
    dockerfile = (
        "FROM alpine:3.20 AS native\n"
        "FROM --platform=linux/arm64 alpine:3.20 AS arm\n"
        "FROM scratch\n"
        "COPY --from=native / /native\n"
        "COPY --from=arm / /arm\n"
    )
    result = await BuildImageHandler().execute(_cached_build(fake_docker, [], dockerfile))

    assert result.success, result.error
    assert _contexts(fake_docker) == []
    assert registries.requests == []


@pytest.mark.asyncio
async def test_images_of_stages_the_target_does_not_need_are_not_pulled(
    fake_docker, registries
) -> None:
    registries.manifests[(CACHE.api_url, OWN_REPO, KEY_TAG)] = COPY_DIGEST
    dockerfile = (
        "FROM ubuntu:24.04 AS unused\n"
        "RUN apt-get update\n"
        "FROM alpine:3.20 AS runtime\n"
        "RUN echo hello\n"
        "FROM runtime AS debug\n"
        "RUN echo debug\n"
    )
    result = await BuildImageHandler().execute(
        _cached_build(fake_docker, [], dockerfile, target="runtime")
    )

    assert result.success, result.error
    assert _docker_verbs(fake_docker, "pull") == []
    assert not any("ubuntu" in url for url in registries.requests)
    assert _contexts(fake_docker) == [
        f"alpine:3.20=docker-image://{REGISTRY}/{OWN_REPO}@{COPY_DIGEST}"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "dockerfile",
    [
        # A stage named alpine after a tab: alpine:latest must get no context.
        "FROM alpine:latest AS base\nFROM\tbusybox AS alpine\nCOPY --from=base /base /base\n",
        # Another platform after a tab: alpine:3.20 must get no context either.
        (
            "FROM alpine:3.20 AS native\nFROM\t--platform=linux/arm64 alpine:3.20 AS arm\n"
            "FROM scratch\nCOPY --from=native / /native\nCOPY --from=arm / /arm\n"
        ),
    ],
)
async def test_tab_separated_instructions_keep_their_protections(
    fake_docker, registries, dockerfile: str
) -> None:
    registries.manifests[(UPSTREAM, "library/alpine", "latest")] = UPSTREAM_DIGEST
    registries.manifests[(CACHE.api_url, OWN_REPO, KEY_TAG)] = COPY_DIGEST
    result = await BuildImageHandler().execute(_cached_build(fake_docker, [], dockerfile))

    assert result.success, result.error
    assert not any(context.startswith("alpine") for context in _contexts(fake_docker))
