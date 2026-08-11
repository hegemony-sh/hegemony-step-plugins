# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""DOCKER_HOST daemon-selection plumbing for container.run.

The handler must place ``DOCKER_HOST`` on every docker subprocess it spawns
when ``ContainerRuntime.docker_host`` is set (selecting a Docker-in-Docker
sandbox daemon), and pass nothing when it is empty (inherit the worker's
environment / host socket — today's behavior). Daemon selection is
environment, never argv, so the ``docker create`` arguments must be identical
on either daemon.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerServices
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_container.run import RunContainerHandler, _docker_env


class _FakeServices:
    """Minimal HandlerServices stub exercising only the container.run path."""

    def __init__(self, docker_host: str) -> None:
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


def _ctx(services: _FakeServices) -> HandlerContext:
    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="step-1",
        phase="IMPLEMENTATION",
        kind="ACTION",
        config={"image": "alpine:3.20", "command": ["echo hi"]},
        services=cast(HandlerServices, services),
    )


def _install_docker_mocks(monkeypatch) -> dict[str, list]:
    """Capture the env= of every docker subprocess seam the handler drives.

    Returns a dict with ``run`` (list of (cmd, env) from subprocess.run) and
    ``exec`` (list of (argv, env) from asyncio.create_subprocess_exec).
    """
    captured: dict[str, list] = {"run": [], "exec": []}

    # Force the pull onto the mocked-CLI path: the Engine-API streaming pull
    # would otherwise dial a real docker socket from unit tests, and these
    # tests assert the DOCKER_HOST plumbing of the CLI `docker pull` itself.
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("disabled in tests")),
    )

    def fake_subprocess_run(cmd, *args, **kwargs):
        captured["run"].append((list(cmd), kwargs.get("env")))
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


def test_docker_env_helper_returns_none_when_unset() -> None:
    assert _docker_env("") is None


def test_docker_env_helper_overlays_docker_host() -> None:
    env = _docker_env("tcp://dind:2375")
    assert env is not None
    assert env["DOCKER_HOST"] == "tcp://dind:2375"
    # Inherits the rest of the process environment (e.g. PATH), never replaces it.
    assert "PATH" in env
    assert os.environ.get("PATH") == env.get("PATH")


def test_docker_env_helper_drops_inherited_docker_context(monkeypatch) -> None:
    """A worker-level DOCKER_CONTEXT must not ride along with a forced DOCKER_HOST.

    Daemon selection needs exactly one source of truth: the CLI resolves
    DOCKER_HOST first, but an inherited context name next to a forced host is
    ambiguous for other docker-compatible tooling.
    """
    monkeypatch.setenv("DOCKER_CONTEXT", "some-context")

    env = _docker_env("tcp://dind:2375")
    assert env is not None
    assert env["DOCKER_HOST"] == "tcp://dind:2375"
    assert "DOCKER_CONTEXT" not in env

    # Unset docker_host keeps the plain environment (no override dict at all).
    assert _docker_env("") is None


async def test_docker_host_set_applies_to_every_docker_call(monkeypatch) -> None:
    captured = _install_docker_mocks(monkeypatch)

    result = await RunContainerHandler().execute(_ctx(_FakeServices("tcp://dind:2375")))
    assert result.success is True

    docker_runs = [(cmd, env) for cmd, env in captured["run"] if cmd and cmd[0] == "docker"]
    # pull, create, cp (roots), cp (harvest), ps (preflight), rm (finally) at least.
    assert len(docker_runs) >= 5
    for cmd, env in docker_runs:
        assert env is not None, f"no env passed to {cmd[:3]}"
        assert env["DOCKER_HOST"] == "tcp://dind:2375", cmd[:3]
        assert "PATH" in env  # inherited, not replaced

    assert captured["exec"], "docker start -a was never spawned"
    for argv, env in captured["exec"]:
        assert argv[:3] == ["docker", "start", "-a"]
        assert env is not None
        assert env["DOCKER_HOST"] == "tcp://dind:2375"


async def test_docker_host_unset_passes_no_override(monkeypatch) -> None:
    captured = _install_docker_mocks(monkeypatch)

    result = await RunContainerHandler().execute(_ctx(_FakeServices("")))
    assert result.success is True

    docker_runs = [(cmd, env) for cmd, env in captured["run"] if cmd and cmd[0] == "docker"]
    assert docker_runs, "no docker subprocess was spawned"
    for cmd, env in docker_runs:
        # Unset => inherit the plain environment (env=None), byte-for-byte today.
        assert env is None, f"unexpected env override on {cmd[:3]}: {env!r}"

    for _argv, env in captured["exec"]:
        assert env is None


async def test_docker_create_argv_is_identical_regardless_of_daemon(monkeypatch) -> None:
    """Daemon selection must live in the environment, never in the create argv."""

    def create_argv(captured: dict[str, list]) -> list[str]:
        for cmd, _env in captured["run"]:
            if len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "create":
                return cmd
        raise AssertionError("docker create was never spawned")

    captured_set = _install_docker_mocks(monkeypatch)
    await RunContainerHandler().execute(_ctx(_FakeServices("tcp://dind:2375")))
    argv_set = create_argv(captured_set)

    captured_unset = _install_docker_mocks(monkeypatch)
    await RunContainerHandler().execute(_ctx(_FakeServices("")))
    argv_unset = create_argv(captured_unset)

    assert argv_set == argv_unset
    # DOCKER_HOST never leaks into the create arguments in either mode.
    assert not any("DOCKER_HOST" in tok for tok in argv_set)
