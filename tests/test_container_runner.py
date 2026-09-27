# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The public container runner and the step I/O contract.

Tool handlers reuse container.run's execution through
``hegemony_steps_container.runner``: a job's files are staged in the same
``docker cp`` as the container roots, its collect paths are copied back out
after exit, and the Docker label names the handler that launched it.
container.run itself gains the step I/O contract (context.json in,
out/output.json → ``output.data``) and secrets staged as files.
"""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerResult, HandlerServices
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_container.run import MAX_OUTPUT_DATA_BYTES, RunContainerHandler
from hegemony_steps_container.runner import (
    CONTEXT_PATH,
    OUTPUT_DIR,
    ContainerJob,
    ContainerJobResult,
    StagedFile,
    container_config_from,
    is_bare_secret_ref,
    resolve_secret_values,
    run_container_job,
    secret_map_errors,
)


class _FakeServices:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self.secrets = secrets or {}
        self.resolved: list[str] = []

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
            docker_host="tcp://dind:2375",
        )

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        return []

    async def fetch_run_step_outputs(self, run_id: str) -> dict[str, dict[str, Any]]:
        raise AssertionError("an empty step-output selection must not fetch")

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        return []

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        assert ref is not None
        self.resolved.append(ref)
        for key, value in self.secrets.items():
            if key in ref:
                return value
        return None


def _ctx(config: dict[str, Any], services: _FakeServices | None = None) -> HandlerContext:
    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="step-1",
        flow_name="Flow",
        run_name="Run",
        config=config,
        params={"service": "telemetry"},
        tags={"phase": "VERIFY"},
        services=cast(HandlerServices, services or _FakeServices()),
    )


def _install_docker(
    monkeypatch, *, out_files: dict[str, bytes] | None = None, exit_code: int = 0
) -> dict[str, Any]:
    """Fake the docker CLI: record staged roots, serve collected files."""
    state: dict[str, Any] = {"roots": {}, "calls": [], "collect_sources": []}
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("disabled in tests")),
    )

    def fake_run(cmd, *args, **kwargs):
        state["calls"].append(list(cmd))
        if len(cmd) >= 4 and cmd[1] == "cp":
            src, dest = cmd[2], cmd[3]
            if dest.endswith(":/"):
                root = src[: -len("/.")]
                for walk_root, _dirs, files in os.walk(root):
                    for name in files:
                        path = os.path.join(walk_root, name)
                        rel = "/" + os.path.relpath(path, root).replace(os.sep, "/")
                        with open(path, "rb") as fh:
                            state["roots"][rel] = (fh.read(), os.stat(path).st_mode & 0o777)
            elif src.endswith(f":{OUTPUT_DIR}/."):
                state["collect_sources"].append(src)
                for rel, data in (out_files or {}).items():
                    target = os.path.join(dest, rel)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "wb") as fh:
                        fh.write(data)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    async def fake_exec(*argv, **kwargs):
        proc = AsyncMock()
        proc.stdout = AsyncMock()
        proc.stdout.readline = AsyncMock(side_effect=[b"hello\n", b""])
        proc.stderr = AsyncMock()
        proc.stderr.readline = AsyncMock(return_value=b"")
        proc.wait = AsyncMock(return_value=exit_code)
        proc.returncode = exit_code
        proc.kill = AsyncMock()
        return proc

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    return state


def _create_args(state: dict[str, Any]) -> list[str]:
    return next(call for call in state["calls"] if call[1] == "create")


@pytest.mark.asyncio
async def test_container_run_stages_the_context_file(monkeypatch):
    state = _install_docker(monkeypatch)
    result = await RunContainerHandler().execute(_ctx({"image": "alpine:3.20"}))

    assert result.success is True
    content, _mode = state["roots"][CONTEXT_PATH]
    context = json.loads(content)
    assert context["run_id"] == "run-12345678"
    assert context["step_id"] == "step-1"
    assert context["inputs"] == {"service": "telemetry"}
    assert context["tags"] == {"phase": "VERIFY"}
    # The output directory exists even when the step writes nothing into it.
    assert state["collect_sources"] == ["hegemony-run-1234-step-123-a1:/hegemony/out/."]


@pytest.mark.asyncio
async def test_container_run_output_json_becomes_output_data(monkeypatch):
    _install_docker(monkeypatch, out_files={"output.json": b'{"vpc_id": "vpc-1", "n": 3}'})
    result = await RunContainerHandler().execute(_ctx({"image": "alpine:3.20"}))

    assert result.output["data"] == {"vpc_id": "vpc-1", "n": 3}
    assert result.output["stdout"] == "hello\n"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "problem"),
    [
        (b"[1, 2]", "must contain a JSON object"),
        (b"{not json", "not valid UTF-8 JSON"),
        (b'{"x": "' + b"a" * MAX_OUTPUT_DATA_BYTES + b'"}', "over the"),
    ],
)
async def test_container_run_rejected_output_json_is_reported(monkeypatch, payload, problem):
    _install_docker(monkeypatch, out_files={"output.json": payload})
    result = await RunContainerHandler().execute(_ctx({"image": "alpine:3.20"}))

    assert result.success is True
    assert "data" not in result.output
    notes = [e for e in result.evidence if e["name"] == "output_data_rejected_step-1"]
    assert len(notes) == 1
    assert problem in notes[0]["content_text"]


@pytest.mark.asyncio
async def test_container_run_secrets_are_files_not_environment(monkeypatch):
    services = _FakeServices(secrets={"db/password": "s3cr3t-value"})
    state = _install_docker(monkeypatch)
    config = {
        "image": "alpine:3.20",
        "secrets": {
            "db_password": "vault://orgs/acme/secrets/db/password",
            "api_token": "already-rendered-token",
        },
    }
    result = await RunContainerHandler().execute(_ctx(config, services))

    assert result.success is True
    assert state["roots"]["/run/secrets/db_password"][0] == b"s3cr3t-value"
    assert state["roots"]["/run/secrets/api_token"][0] == b"already-rendered-token"
    # A bare reference is resolved through the host (which registers it for
    # redaction); a rendered template value is used as is.
    assert services.resolved == ["{{ secret('vault://orgs/acme/secrets/db/password') }}"]
    create = " ".join(_create_args(state))
    assert "s3cr3t-value" not in create
    assert "already-rendered-token" not in create


@pytest.mark.asyncio
async def test_container_run_unresolvable_secret_fails_before_docker(monkeypatch):
    state = _install_docker(monkeypatch)
    config = {"image": "alpine:3.20", "secrets": {"x": "vault://missing/key"}}
    result = await RunContainerHandler().execute(_ctx(config))

    assert result.success is False
    assert "resolved to an empty value" in (result.error or "")
    assert state["calls"] == []


def test_secret_map_validation():
    assert secret_map_errors("secrets", None) == []
    assert secret_map_errors("secrets", {"ok_name": "v"}) == []
    assert secret_map_errors("secrets", ["x"])
    assert secret_map_errors("secrets", {"../etc": "v"})
    assert secret_map_errors("secrets", {"name": ""})
    handler = RunContainerHandler()
    assert handler.validate_config({"image": "alpine:3.20", "secrets": {"a b": "v"}})


def test_bare_secret_ref_detection():
    assert is_bare_secret_ref("vault://orgs/acme/secrets/db/password")
    assert not is_bare_secret_ref("{{ secret('vault://x/y') }}")
    assert not is_bare_secret_ref("plain value")
    assert not is_bare_secret_ref("vault://x/y') }}{{ env('X')")


@pytest.mark.asyncio
async def test_resolve_secret_values_rejects_bad_names():
    with pytest.raises(ValueError, match="invalid secret name"):
        await resolve_secret_values(_ctx({}), {"bad name": "x"}, source="t")


@pytest.mark.asyncio
async def test_run_container_job_stages_files_and_collects(monkeypatch):
    state = _install_docker(
        monkeypatch,
        out_files={"results.json": b'{"ok": true}', "nested/more.txt": b"x"},
        exit_code=2,
    )
    job = ContainerJob(
        config=container_config_from(
            {"memory": "", "egress_mode": "deny-all", "env": {"A": "1"}},
            image="tool:1",
            command=["sh /hegemony/run.sh"],
            env={"TOOL": "yes"},
        ),
        files=[
            StagedFile(path="/hegemony/run.sh", content="echo run\n", mode=0o755),
            StagedFile(path="/hegemony/in/data.bin", content=b"\x00\x01"),
        ],
        collect=[OUTPUT_DIR],
        handler_id="tool.run",
    )
    outcome = await run_container_job(_ctx({}), job)

    assert isinstance(outcome, ContainerJobResult)
    assert outcome.exit_code == 2
    assert outcome.collected == {
        "/hegemony/out/results.json": b'{"ok": true}',
        "/hegemony/out/nested/more.txt": b"x",
    }
    assert state["roots"]["/hegemony/run.sh"] == (b"echo run\n", 0o755)
    assert state["roots"]["/hegemony/in/data.bin"][0] == b"\x00\x01"
    create = _create_args(state)
    assert "hegemony.handler_id=tool.run" in create
    assert create[create.index("--memory") + 1] == "1g"
    assert "A=1" in create and "TOOL=yes" in create
    assert outcome.evidence[0]["kind"] == "container_output"


@pytest.mark.asyncio
async def test_run_container_job_validates_the_job_config(monkeypatch):
    state = _install_docker(monkeypatch)
    outcome = await run_container_job(
        _ctx({}), ContainerJob(config={"image": "/etc/passwd"}, handler_id="tool.run")
    )
    assert isinstance(outcome, HandlerResult)
    assert outcome.success is False
    assert "Invalid image reference" in (outcome.error or "")
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_run_container_job_rejects_relative_job_file(monkeypatch):
    _install_docker(monkeypatch)
    job = ContainerJob(
        config={"image": "alpine:3.20"},
        files=[StagedFile(path="relative/file", content="x")],
    )
    outcome = await run_container_job(_ctx({}), job)
    assert isinstance(outcome, HandlerResult)
    assert outcome.success is False
    assert "must be absolute" in (outcome.error or "")


def test_container_config_from_keeps_tool_wiring_over_user_env():
    config = container_config_from(
        {"env": {"TOOL": "user", "OTHER": "1"}, "cpus": "2", "privileged": True},
        image="tool:1",
        command=["x"],
        env={"TOOL": "tool"},
    )
    assert config["env"] == {"TOOL": "tool", "OTHER": "1"}
    assert config["cpus"] == "2"
    # Host-access options never pass through from a tool config.
    assert "privileged" not in config
