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
import shutil
import signal
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerResult, HandlerServices
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_container.run import MAX_OUTPUT_DATA_BYTES, RunContainerHandler
from hegemony_steps_container.runner import (
    COLLECT_GRACE_SECONDS,
    CONTEXT_PATH,
    OUTPUT_DIR,
    ContainerJob,
    ContainerJobResult,
    StagedFile,
    container_config_from,
    deadline_shell_lines,
    is_bare_secret_ref,
    resolve_secret_values,
    run_container_job,
    secret_map_errors,
)


class _FakeServices:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self.secrets = secrets or {}
        self.resolved: list[str] = []
        self.step_output_fetches = 0

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
        # Counted rather than raised: run_job treats step outputs as best-effort
        # context and would swallow an exception.
        self.step_output_fetches += 1
        return {"upstream": {"success": True, "output": {"k": "v"}}}

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
    monkeypatch,
    *,
    out_files: dict[str, bytes] | None = None,
    out_links: dict[str, str] | None = None,
    collect_returncode: int = 0,
    exit_code: int = 0,
    repo_digests: list[str] | None = None,
) -> dict[str, Any]:
    """Fake the docker CLI: record staged roots, serve collected files.

    ``state["roots"]`` maps each staged file to ``(content, mode)`` and
    ``state["dirs"]`` each staged directory to its mode. ``out_links`` adds
    symlinks (name -> target) to the collected copy, as ``docker cp`` would
    preserve them; ``collect_returncode`` makes the copy-out fail.
    ``repo_digests`` is the pulled image's RepoDigests (none by default).
    """
    state: dict[str, Any] = {"roots": {}, "dirs": {}, "calls": [], "collect_sources": []}
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("disabled in tests")),
    )

    def fake_run(cmd, *args, **kwargs):
        state["calls"].append(list(cmd))
        if cmd[1:3] == ["image", "inspect"] and "{{json .RepoDigests}}" in cmd:
            return SimpleNamespace(returncode=0, stdout=json.dumps(repo_digests or []), stderr="")
        if len(cmd) >= 4 and cmd[1] == "cp":
            src, dest = cmd[2], cmd[3]
            if dest.endswith(":/"):
                root = src[: -len("/.")]
                state["roots_staging"] = root
                state["roots_staging_parent_mode"] = os.stat(os.path.dirname(root)).st_mode & 0o777
                state["roots_staging_mode"] = os.stat(root).st_mode & 0o777
                for walk_root, dirs, files in os.walk(root):
                    for name in dirs:
                        path = os.path.join(walk_root, name)
                        rel = "/" + os.path.relpath(path, root).replace(os.sep, "/")
                        state["dirs"][rel] = os.stat(path).st_mode & 0o777
                    for name in files:
                        path = os.path.join(walk_root, name)
                        rel = "/" + os.path.relpath(path, root).replace(os.sep, "/")
                        with open(path, "rb") as fh:
                            state["roots"][rel] = (fh.read(), os.stat(path).st_mode & 0o777)
            elif src.endswith(f":{OUTPUT_DIR}/."):
                state["collect_sources"].append(src)
                state["collect_timeout"] = kwargs.get("timeout")
                if collect_returncode:
                    return SimpleNamespace(
                        returncode=collect_returncode, stdout="", stderr="daemon hiccup"
                    )
                for rel, data in (out_files or {}).items():
                    target = os.path.join(dest, rel)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "wb") as fh:
                        fh.write(data)
                for rel, link_target in (out_links or {}).items():
                    os.symlink(link_target, os.path.join(dest, rel))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    async def fake_exec(*argv, **kwargs):
        proc = AsyncMock()
        proc.stdout = AsyncMock()
        proc.stdout.read = AsyncMock(side_effect=[b"hello\n", b""])
        proc.stderr = AsyncMock()
        proc.stderr.read = AsyncMock(return_value=b"")
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
    # Flow inputs stay out: the run's params carry every input (secret
    # templates resolved to plaintext) and none of the defaults.
    assert "inputs" not in context
    assert "telemetry" not in content.decode()
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
    services = _FakeServices(
        secrets={"db/password": "s3cr3t-value", "db/url": "postgres://app:pw@db/app"}
    )
    state = _install_docker(monkeypatch)
    config = {
        "image": "alpine:3.20",
        "secrets": {
            "db_password": "vault://orgs/acme/secrets/db/password",
            "db_url": "{{ secret('vault://orgs/acme/secrets/db/url') }}",
            "api_token": "literal-token",
        },
    }
    result = await RunContainerHandler().execute(_ctx(config, services))

    assert result.success is True
    assert state["roots"]["/run/secrets/db_password"][0] == b"s3cr3t-value"
    # A secret whose value looks like a reference is not resolved a second time.
    assert state["roots"]["/run/secrets/db_url"][0] == b"postgres://app:pw@db/app"
    assert state["roots"]["/run/secrets/api_token"][0] == b"literal-token"
    # Readable by an image that runs as another user than root (docker cp
    # stages files root-owned); tighten only deliberately.
    assert state["roots"]["/run/secrets/db_password"][1] == 0o644
    # On the worker they sit under a directory only the worker's user can
    # enter, while the tree's root (the container's /) stays 0755.
    assert state["roots_staging_parent_mode"] == 0o700
    assert state["roots_staging_mode"] == 0o755
    # Removed after the run.
    assert not os.path.exists(os.path.dirname(state["roots_staging"]))
    # Both reference forms go through the host (which registers the value for
    # redaction), each exactly once; a literal is used as written.
    assert services.resolved == [
        "{{ secret('vault://orgs/acme/secrets/db/password') }}",
        "{{ secret('vault://orgs/acme/secrets/db/url') }}",
    ]
    create = " ".join(_create_args(state))
    assert "s3cr3t-value" not in create
    assert "literal-token" not in create


def test_container_run_receives_its_secrets_unrendered():
    """The host leaves the field alone, so the handler sees what the author wrote."""
    assert RunContainerHandler.raw_config_keys == {"secrets"}


@pytest.mark.asyncio
async def test_container_run_unresolvable_secret_fails_before_docker(monkeypatch):
    state = _install_docker(monkeypatch)
    config = {"image": "alpine:3.20", "secrets": {"x": "vault://missing/key"}}
    result = await RunContainerHandler().execute(_ctx(config))

    assert result.success is False
    assert "resolved to an empty value" in (result.error or "")
    assert "scheme 'vault'" in (result.error or "")
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_a_literal_url_secret_is_read_as_a_reference_and_says_so(monkeypatch):
    state = _install_docker(monkeypatch)
    config = {"image": "alpine:3.20", "secrets": {"hook": "https://hooks.example.com/T1/x"}}
    result = await RunContainerHandler().execute(_ctx(config))

    assert result.success is False
    error = result.error or ""
    assert "written as a secret reference (scheme 'https')" in error
    assert "store it in a secret backend" in error
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_an_empty_template_secret_keeps_the_plain_error(monkeypatch):
    _install_docker(monkeypatch)
    config = {"image": "alpine:3.20", "secrets": {"x": "{{ secret('vault://missing/key') }}"}}
    result = await RunContainerHandler().execute(_ctx(config))

    assert result.success is False
    assert (result.error or "").endswith("secret 'x' resolved to an empty value")


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
    services = _FakeServices()
    outcome = await run_container_job(_ctx({}, services), job)

    assert isinstance(outcome, ContainerJobResult)
    assert outcome.exit_code == 2
    # A tool job mounts no upstream step outputs, so it does not fetch them.
    assert services.step_output_fetches == 0
    assert not any(path.startswith("/step_outputs") for path in state["roots"])
    assert outcome.collected == {
        "/hegemony/out/results.json": b'{"ok": true}',
        "/hegemony/out/nested/more.txt": b"x",
    }
    assert state["roots"]["/hegemony/run.sh"] == (b"echo run\n", 0o755)
    assert state["roots"]["/hegemony/in/data.bin"][0] == b"\x00\x01"
    # docker cp creates the collect root owned by root; results are written by
    # whatever user the image runs as (the ansible image runs as `runner`).
    assert state["dirs"][OUTPUT_DIR] == 0o777
    create = _create_args(state)
    assert "hegemony.handler_id=tool.run" in create
    assert create[create.index("--memory") + 1] == "1g"
    assert "A=1" in create and "TOOL=yes" in create
    assert outcome.evidence[0]["kind"] == "container_output"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("image", "repo_digests", "pinned"),
    [
        (
            "ghcr.io/x/tool:1",
            ["registry.example.com/x/tool@sha256:aaa", "ghcr.io/x/tool@sha256:bbb"],
            "ghcr.io/x/tool@sha256:bbb",
        ),
        # The daemon writes Docker Hub names short; the image keeps its spelling.
        (
            "docker.io/library/python:3.12",
            ["python@sha256:ccc"],
            "docker.io/library/python@sha256:ccc",
        ),
        ("python", ["python@sha256:ccc"], "python@sha256:ccc"),
        # Built on the daemon, never pushed: no digest, the tag runs.
        ("tool:local", [], ""),
        # Already pinned: nothing to look up.
        ("ghcr.io/x/tool@sha256:ddd", [], "ghcr.io/x/tool@sha256:ddd"),
    ],
)
async def test_a_pinned_job_runs_and_reports_the_image_digest(
    monkeypatch, image, repo_digests, pinned
):
    state = _install_docker(monkeypatch, repo_digests=repo_digests)
    job = ContainerJob(
        config=container_config_from({}, image=image, command=["true"]), pin_image=True
    )
    outcome = await run_container_job(_ctx({}), job)

    assert isinstance(outcome, ContainerJobResult)
    assert outcome.image_digest == pinned
    assert outcome.image == image
    # The container is created from the digest, which a later pull cannot move.
    assert (pinned or image) in _create_args(state)


@pytest.mark.asyncio
async def test_an_unpinned_job_does_not_look_up_the_digest(monkeypatch):
    state = _install_docker(monkeypatch, repo_digests=["ghcr.io/x/tool@sha256:bbb"])
    job = ContainerJob(config=container_config_from({}, image="ghcr.io/x/tool:1", command=["true"]))
    outcome = await run_container_job(_ctx({}), job)

    assert isinstance(outcome, ContainerJobResult)
    assert outcome.image_digest == ""
    assert not any("{{json .RepoDigests}}" in call for call in state["calls"])
    assert "ghcr.io/x/tool:1" in _create_args(state)


@pytest.mark.asyncio
async def test_an_unpinned_job_with_a_digest_reference_reports_it_without_a_lookup(monkeypatch):
    """`image@sha256:…` already names exact content: it is the digest, no inspect needed."""
    state = _install_docker(monkeypatch, repo_digests=["ghcr.io/x/tool@sha256:bbb"])
    pinned = "ghcr.io/x/tool@sha256:" + "d" * 64
    job = ContainerJob(config=container_config_from({}, image=pinned, command=["true"]))
    outcome = await run_container_job(_ctx({}), job)

    assert isinstance(outcome, ContainerJobResult)
    assert outcome.image_digest == pinned
    assert outcome.image == pinned
    assert not any("{{json .RepoDigests}}" in call for call in state["calls"])
    assert pinned in _create_args(state)


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
    # Tool steps mount no upstream step outputs or artifacts.
    assert config["mounted_step_outputs"] == []
    assert config["mounted_artifacts"] == []


def _tool_job(*, files: list[StagedFile] | None = None) -> ContainerJob:
    return ContainerJob(
        config=container_config_from({}, image="tool:1", command=["true"]),
        files=files or [],
        collect=[OUTPUT_DIR],
        handler_id="tool.run",
    )


@pytest.mark.asyncio
async def test_collect_root_is_staged_writable_without_job_files(monkeypatch):
    state = _install_docker(monkeypatch)
    outcome = await run_container_job(_ctx({}), _tool_job())

    assert isinstance(outcome, ContainerJobResult)
    assert state["dirs"][OUTPUT_DIR] == 0o777


@pytest.mark.asyncio
async def test_collect_skips_symlinks_out_of_the_copy(monkeypatch, tmp_path):
    worker_secret = tmp_path / "worker_secret"
    worker_secret.write_text("worker-only")
    _install_docker(
        monkeypatch,
        out_files={"ok.json": b"{}"},
        out_links={"leak.json": str(worker_secret), "inner.json": "ok.json"},
    )
    outcome = await run_container_job(_ctx({}), _tool_job())

    assert isinstance(outcome, ContainerJobResult)
    # Neither a link out of the copy nor one inside it is followed.
    assert outcome.collected == {"/hegemony/out/ok.json": b"{}"}


@pytest.mark.asyncio
async def test_collect_survives_a_failed_docker_cp(monkeypatch):
    _install_docker(monkeypatch, out_files={"ok.json": b"{}"}, collect_returncode=1)
    outcome = await run_container_job(_ctx({}), _tool_job())

    assert isinstance(outcome, ContainerJobResult)
    assert outcome.exit_code == 0
    assert outcome.collected == {}
    # The handler can tell "not copied" from "not written".
    assert outcome.collect_errors == {OUTPUT_DIR: "docker cp failed: daemon hiccup"}


@pytest.mark.asyncio
async def test_container_run_notes_results_it_could_not_collect(monkeypatch):
    _install_docker(monkeypatch, out_files={"output.json": b"{}"}, collect_returncode=1)
    result = await RunContainerHandler().execute(_ctx({"image": "alpine:3.20"}))

    assert result.success is True
    assert "data" not in result.output
    [note] = [e for e in result.evidence if e["name"] == "output_not_collected_step-1"]
    assert f"{OUTPUT_DIR}: docker cp failed: daemon hiccup" in note["content_text"]


@pytest.mark.asyncio
async def test_collect_gets_a_grace_period_past_the_step_deadline(monkeypatch):
    state = _install_docker(monkeypatch)
    # The container exits with (almost) no time left of a 1 s step timeout.
    job = _tool_job()
    job.config["timeout_seconds"] = 1
    outcome = await run_container_job(_ctx({}), job)

    assert isinstance(outcome, ContainerJobResult)
    assert state["collect_timeout"] >= COLLECT_GRACE_SECONDS


@pytest.mark.asyncio
async def test_collect_enforces_the_byte_budget(monkeypatch):
    monkeypatch.setattr("hegemony_steps_container.run.MAX_COLLECTED_BYTES", 100)
    _install_docker(monkeypatch, out_files={"big.bin": b"x" * 101, "small.json": b"{}"})
    outcome = await run_container_job(_ctx({}), _tool_job())

    assert isinstance(outcome, ContainerJobResult)
    assert outcome.collected == {"/hegemony/out/small.json": b"{}"}
    assert list(outcome.collect_errors) == ["/hegemony/out/big.bin"]
    assert "over the 100-byte collection budget" in outcome.collect_errors["/hegemony/out/big.bin"]


def _run_bounded(command: str, deadline: int, path: str | None = None) -> tuple[int, float]:
    script = "\n".join([*deadline_shell_lines(deadline), command]) + "\n"
    env = {**os.environ, "PATH": path} if path is not None else None
    started = time.monotonic()
    done = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True)
    return done.returncode, time.monotonic() - started


def test_bounded_stops_a_command_at_the_deadline():
    """A worker that died stops nothing: the step's own script stops the tool."""
    code, took = _run_bounded("bounded sleep 30", int(time.time()) + 1)
    assert code in (124, 143)  # coreutils, BusyBox
    assert took < 10


def test_bounded_returns_the_commands_own_status():
    code, _ = _run_bounded("bounded sh -c 'exit 3'", int(time.time()) + 60)
    assert code == 3


def test_bounded_runs_a_command_past_the_deadline_for_a_second_at_least():
    code, _ = _run_bounded("bounded true", int(time.time()) - 60)
    assert code == 0


def test_bounded_runs_the_command_unbounded_without_timeout(tmp_path):
    for tool in ("sh", "date", "true"):
        found = shutil.which(tool)
        assert found is not None
        (tmp_path / tool).symlink_to(found)
    code, _ = _run_bounded("bounded sh -c 'exit 5'", int(time.time()) + 60, str(tmp_path))
    assert code == 5


def _mark_ready(ready: Path) -> str:
    """Shell lines (for a single-quoted ``sh -c``) that write ``ready`` once the
    command's parent sleeps.

    GNU timeout loses a SIGTERM that lands after its fork() but before it has
    noted the command's process id: it exits with 143 and the command runs on,
    never signalled. That window is timeout's, not ``bounded``'s, so the test's
    stop request waits until the parent sleeps in its wait (where BusyBox's
    timeout, which runs the command in its own process, leaves the script).
    """
    return (
        'while read -r _ _ state _ < /proc/$PPID/stat && [ "$state" != S ]; do sleep 0.01; done; '
        f": > {ready}"
    )


def test_bounded_passes_a_stop_request_on_to_the_command(tmp_path):
    """``docker stop`` signals the script (PID 1); the tool must get it, not wait for SIGKILL.

    A shell waiting for a foreground command would run its trap only after the
    command ends. The tool here saves and exits 7 on SIGTERM; after the stop
    request the script starts nothing new and keeps the tool's status.
    """
    ready = tmp_path / "ready"
    tool = (
        'sh -c \'trap "echo tool: saved; exit 7" TERM; '
        f"{_mark_ready(ready)}; i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; exit 0'"
    )
    script = "\n".join(
        [
            "set -eu",
            *deadline_shell_lines(int(time.time()) + 600),
            "set +e",
            f"bounded {tool}",
            "code=$?",
            "bounded echo 'started after the stop request'",
            'echo "second: $?"',
            'exit "$code"',
        ]
    )
    proc = subprocess.Popen(["sh", "-c", script], stdout=subprocess.PIPE, text=True)
    started = time.monotonic()
    while not ready.exists():
        assert time.monotonic() - started < 10, "the tool never started"
        time.sleep(0.05)
    proc.send_signal(signal.SIGTERM)
    out, _ = proc.communicate(timeout=10)

    assert proc.returncode == 7
    assert "tool: saved" in out
    assert "started after the stop request" not in out
    assert "second: 143" in out
    assert time.monotonic() - started < 10


def test_bounded_starts_nothing_when_stopped_while_it_prepares(tmp_path):
    """A stop request that comes while ``bounded`` works out the time left
    (the trap runs only after ``date`` returns) must still keep the command
    from starting."""
    started = tmp_path / "started"
    script = "\n".join(
        [
            "set -eu",
            # Stand-in for a SIGTERM that lands while bounded runs date.
            'date() { kill -TERM "$$"; command date "$@"; }',
            *deadline_shell_lines(int(time.time()) + 600),
            "set +e",
            f"bounded touch {started}",
            'echo "status: $?"',
        ]
    )
    done = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=10)

    assert "status: 143" in done.stdout
    assert not started.exists()


def test_bounded_passes_on_a_stop_request_that_came_as_the_command_started(tmp_path):
    """The command asks for the stop itself, right as it starts, before or
    after ``bounded`` has noted its process id: it must get one SIGTERM."""
    for tool in ("sh", "date", "true", "sleep"):
        found = shutil.which(tool)
        assert found is not None
        (tmp_path / tool).symlink_to(found)
    terms = tmp_path / "terms"
    # Without a timeout command, the command is the script's own child.
    tool = (
        f'sh -c \'trap "echo TERM >> {terms}; exit 7" TERM; kill -TERM "$PPID"; '
        "i=0; while [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; exit 0'"
    )
    code, took = _run_bounded(f"bounded {tool}", int(time.time()) + 600, str(tmp_path))

    assert code == 7
    assert terms.read_text().splitlines() == ["TERM"]
    assert took < 8


def test_bounded_passes_on_only_the_first_stop_request(tmp_path):
    """A second interrupt makes OpenTofu and Terraform exit without saving.

    The step's worker and the platform's container sweep may both stop the
    same container: the tool must see one SIGTERM, whatever the script gets.
    """
    ready = tmp_path / "ready"
    terms = tmp_path / "terms"
    tool = (
        f'sh -c \'trap "echo TERM >> {terms}" TERM; {_mark_ready(ready)}; '
        "i=0; while [ $i -lt 20 ]; do sleep 0.1; i=$((i+1)); done; exit 9'"
    )
    script = "\n".join(
        ["set -eu", *deadline_shell_lines(int(time.time()) + 600), f"bounded {tool}"]
    )
    proc = subprocess.Popen(["sh", "-c", script])
    started = time.monotonic()
    while not ready.exists():
        assert time.monotonic() - started < 10, "the tool never started"
        time.sleep(0.05)
    proc.send_signal(signal.SIGTERM)
    time.sleep(0.3)
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=10)

    assert proc.returncode == 9
    assert terms.read_text().splitlines() == ["TERM"]
