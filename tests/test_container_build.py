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

import pytest

from hegemony_step_sdk import (
    BUILD_NETWORK_DEFAULT,
    BUILD_NETWORK_NONE,
    ContainerRuntime,
    HandlerContext,
    HandlerServices,
    ImageBuild,
)
from hegemony_steps_container import ALL_HANDLERS
from hegemony_steps_container.build import (
    CREATED_LABEL,
    RUN_LABEL,
    STEP_LABEL,
    BuildImageHandler,
    build_environment,
    buildx_argv,
    frontend_error,
    image_name_error,
    looks_like_host,
    run_tag,
    tag_error,
)

RUN_ID = "1a2b3c4d-0000-4000-8000-000000000001"
DIGEST = "sha256:" + "ab" * 32
REGISTRY = "registry.hegemony.internal"


# ── Names, tags and the Dockerfile frontend ─────────────────────────────────


@pytest.mark.parametrize("name", ["tools/netbox-sync", "app", "a/b/c", "my_app", "team/tools.v2"])
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
        ("ghcr.io/x/y", "registry host"),
        ("tools.v2/net", "registry host"),
        ("localhost/x", "registry host"),
        ("localhost_5000/x", "registry host"),
        ("registry.hegemony.internal/orgs/acme/x", "registry host"),
        ("a" * 201, "at most 200"),
    ],
)
def test_invalid_image_names(name: str, fragment: str) -> None:
    error = image_name_error(name)
    assert error is not None and fragment in error


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
        ({"image": "ghcr.io/x"}, "registry host"),
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
    assert build_args == ["A=b", "VERSION=1.2"]
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

if args[:2] == ["image", "inspect"]:
    save({"argv": args})
    ref = args[-1]
    print(json.dumps([ref.rsplit(":", 1)[0] + "@" + os.environ["FAKE_DOCKER_DIGEST"]]))
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
    })
    print("#1 [internal] load build definition from Dockerfile", flush=True)
    print("#5 [2/2] RUN echo hello", flush=True)
    print("#5 0.105 hello", flush=True)
    if mode == "slow":
        time.sleep(30)
    if mode == "fail":
        print("#5 ERROR: process did not complete successfully: exit code: 1", flush=True)
        print("ERROR: failed to build: failed to solve: exit code: 1", flush=True)
        sys.exit(1)
    if mode != "no-metadata":
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
    ) -> None:
        self.docker_bin = docker_bin
        self.config_dir = config_dir
        self.build = build
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


def _target(network: str = BUILD_NETWORK_NONE) -> ImageBuild:
    return ImageBuild(registry=REGISTRY, namespace="orgs/acme", network=network)


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
    assert "pypi-secret-value" not in json.dumps(result.evidence)


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
async def test_without_a_build_grant_nothing_is_built(fake_docker) -> None:
    services = _Services(fake_docker["bin"], fake_docker["config_dir"], build=None)
    result = await BuildImageHandler().execute(
        _ctx({"image": "tools/x", "context_dir": "images/tool"}, services, [])
    )
    assert not result.success
    assert result.error is not None and "cannot push the image it builds" in result.error
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
