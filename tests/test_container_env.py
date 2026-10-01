# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""DOCKER_HOST daemon-selection plumbing for container.run.

The handler must place ``DOCKER_HOST`` on every docker subprocess it spawns,
pointing at the Docker-in-Docker sandbox daemon that
``ContainerRuntime.docker_host`` names. A value that names no daemon (empty,
blank, or a bare ``unix://``) is refused before any docker call: inheriting
the worker's environment instead would reach the worker's own Docker daemon.
Daemon selection is environment, never argv, so the ``docker create``
arguments must be identical whichever daemon is selected.
"""

from __future__ import annotations

import inspect
import os
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerServices
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_container.run import RunContainerHandler, _docker_env


class _FakeServices:
    """Minimal HandlerServices stub exercising only the container.run path."""

    def __init__(self, docker_host: str, docker_config_dir: str = "") -> None:
        self._docker_host = docker_host
        self._docker_config_dir = docker_config_dir

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
            docker_host=self._docker_host,
            docker_config_dir=self._docker_config_dir,
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


@pytest.mark.parametrize("docker_host", ["", "   ", "unix://", "tcp://", "tcp://:2375"])
def test_docker_env_helper_refuses_a_host_that_names_no_daemon(docker_host: str) -> None:
    with pytest.raises(ValueError, match="sandbox Docker daemon"):
        _docker_env(docker_host)


def test_docker_env_helper_places_the_host_without_surrounding_blanks() -> None:
    env = _docker_env("  tcp://dind:2375\n")
    assert env["DOCKER_HOST"] == "tcp://dind:2375"


def test_docker_env_helper_overlays_docker_host() -> None:
    env = _docker_env("tcp://dind:2375")
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
    assert env["DOCKER_HOST"] == "tcp://dind:2375"
    assert "DOCKER_CONTEXT" not in env

    # No host is refused rather than handing back the inherited context.
    with pytest.raises(ValueError):
        _docker_env("")


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


def test_docker_env_helper_points_docker_config_at_the_step_directory() -> None:
    """The step's registry logins ride on the same environment as the daemon."""
    env = _docker_env("tcp://dind:2375", "/tmp/hegemony-docker-config-abc")
    assert env["DOCKER_HOST"] == "tcp://dind:2375"
    assert env["DOCKER_CONFIG"] == "/tmp/hegemony-docker-config-abc"


def test_docker_env_helper_leaves_docker_config_alone_without_a_directory(monkeypatch) -> None:
    """No step directory means the worker's own configuration, as before."""
    monkeypatch.delenv("DOCKER_CONFIG", raising=False)
    assert "DOCKER_CONFIG" not in _docker_env("tcp://dind:2375")
    assert "DOCKER_CONFIG" not in _docker_env("tcp://dind:2375", "   ")
    monkeypatch.setenv("DOCKER_CONFIG", "/home/worker/.docker")
    assert _docker_env("tcp://dind:2375")["DOCKER_CONFIG"] == "/home/worker/.docker"


async def test_docker_config_dir_applies_to_every_docker_call(monkeypatch) -> None:
    """Both pull paths and every other docker call see the step's logins."""
    captured = _install_docker_mocks(monkeypatch)

    services = _FakeServices("tcp://dind:2375", docker_config_dir="/tmp/hegemony-docker-config-x")
    result = await RunContainerHandler().execute(_ctx(services))
    assert result.success is True

    # The cleanup helpers (preflight `ps`/`rm`, the final `rm`, `stop`) build
    # their own daemon-only environment: nothing they do talks to a registry.
    docker_runs = [
        (cmd, env)
        for cmd, env in captured["run"]
        if cmd and cmd[0] == "docker" and cmd[1] not in ("ps", "rm", "stop")
    ]
    assert any(cmd[1] == "create" for cmd, _env in docker_runs)
    for cmd, env in docker_runs:
        assert env is not None, f"no env passed to {cmd[:3]}"
        assert env["DOCKER_CONFIG"] == "/tmp/hegemony-docker-config-x", cmd[:3]
    assert captured["exec"], "docker start -a was never spawned"
    for _argv, env in captured["exec"]:
        assert env is not None
        assert env["DOCKER_CONFIG"] == "/tmp/hegemony-docker-config-x"


@pytest.mark.parametrize("docker_host", ["", "   ", "unix://", "tcp://", "tcp://:2375", None])
async def test_no_sandbox_daemon_fails_the_step_before_any_docker_call(
    monkeypatch, docker_host: str | None
) -> None:
    """A runtime naming no sandbox daemon never reaches the worker's own.

    The step fails like a config error, before preflight cleanup, the pull or
    the ``finally`` removal spawn anything: every one of those would otherwise
    inherit the worker's environment. ``None`` stands for a duck-typed host
    that leaves the field unset.
    """
    captured = _install_docker_mocks(monkeypatch)

    result = await RunContainerHandler().execute(_ctx(_FakeServices(cast(str, docker_host))))

    assert result.success is False
    assert result.summary == "Container sandbox not configured"
    assert result.error is not None and "sandbox Docker daemon" in result.error
    assert captured["run"] == []
    assert captured["exec"] == []


@pytest.mark.parametrize("helper", ["_preflight_cleanup", "_force_remove_container"])
def test_cleanup_helpers_take_the_daemon_explicitly(helper: str) -> None:
    """No default daemon to fall back on: every caller names the sandbox.

    An empty default used to mean the worker's own daemon, so a call site that
    left it out would sweep or remove containers there.
    """
    param = inspect.signature(getattr(RunContainerHandler, helper)).parameters["docker_host"]
    assert param.default is inspect.Parameter.empty
    assert param.kind is inspect.Parameter.KEYWORD_ONLY


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

    captured_unix = _install_docker_mocks(monkeypatch)
    await RunContainerHandler().execute(_ctx(_FakeServices("unix:///var/run/dind/docker.sock")))
    argv_unix = create_argv(captured_unix)

    assert argv_set == argv_unix
    # DOCKER_HOST never leaks into the create arguments on either daemon.
    assert not any("DOCKER_HOST" in tok for tok in argv_set)
