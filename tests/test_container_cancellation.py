# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Cancellation of a running container.run step.

A cancelled activity (workflow cancelled, or a heartbeat timeout) raises
``asyncio.CancelledError`` inside ``execute()``. Being a ``BaseException`` it
bypasses the handler's ``except Exception`` clause, so the only other thing
that would run is ``finally``. ``finally`` force-removes the container, which
is what normally ends the attached ``docker start -a`` client -- but it is an
unshielded ``await`` in a cancelled task, so it cannot be the only thing
standing between a cancelled step and a stranded docker client.

``execute()`` therefore catches the cancellation, kills the client, and
re-raises. Both halves are asserted here: the client dies, and cancellation
still propagates out of ``execute()``.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerServices
from hegemony_steps_container.run import RunContainerHandler


class _FakeServices:
    """Minimal HandlerServices stub exercising only the container.run path."""

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
            docker_host="",
        )

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        return []

    async def fetch_run_step_outputs(self, run_id: str) -> dict[str, dict[str, Any]]:
        return {}

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        return []


def _ctx() -> HandlerContext:
    async def record(message: str, device_id: str | None, attrs: dict[str, Any] | None) -> bool:
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


class _EmptyStream:
    """A pipe that is immediately at EOF, so the readers finish at once."""

    async def readline(self) -> bytes:
        return b""


class _AttachedProc:
    """``docker start -a`` that never exits on its own, and records SIGKILL.

    The real client stays attached for as long as the container runs, which is
    exactly the state a cancellation has to interrupt.
    """

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.killed = False
        self.stdout = _EmptyStream()
        self.stderr = _EmptyStream()

    async def wait(self) -> int:
        await asyncio.Event().wait()  # never set
        raise AssertionError("unreachable")

    def kill(self) -> None:
        self.killed = True


async def test_cancelled_step_kills_the_attached_docker_client(monkeypatch) -> None:
    started = asyncio.Event()
    procs: list[_AttachedProc] = []

    def fake_subprocess_run(cmd, *args, **kwargs):
        # Pull, image inspect, preflight ps, and the cleanup rm all land here.
        argv = list(cmd)
        if argv[:3] == ["docker", "image", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="120000000\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    async def fake_create_subprocess_exec(*argv, **kwargs):
        proc = _AttachedProc()
        procs.append(proc)
        started.set()
        return proc

    monkeypatch.setattr("subprocess.run", fake_subprocess_run)
    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_create_subprocess_exec)

    task = asyncio.create_task(RunContainerHandler().execute(_ctx()))
    await asyncio.wait_for(started.wait(), timeout=10)
    # Let the readers drain and the handler park on proc.wait().
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=10)
    except asyncio.CancelledError:
        pass
    else:
        raise AssertionError("cancellation should propagate out of execute()")

    assert procs, "the attached docker client was never spawned"
    assert procs[0].killed, "cancelled step left `docker start -a` running"
