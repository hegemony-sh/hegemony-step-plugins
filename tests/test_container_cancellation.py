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
re-raises. Covered here: the client dies whether cancellation lands while
waiting on the exited process or mid-stream with the readers still attached,
cancellation still propagates out of ``execute()``, and no helper task (the
output flusher, most of all) survives the cancelled step.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

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
        config={"image": "alpine:3.20", "command": ["echo hi"]},
        services=cast(HandlerServices, _FakeServices()),
        _emit_progress=record,
    )


class _EmptyStream:
    """A pipe that is immediately at EOF, so the readers finish at once."""

    async def readline(self) -> bytes:
        return b""


class _BlockingStream:
    """A pipe that never yields a line, keeping the readers parked mid-stream."""

    async def readline(self) -> bytes:
        await asyncio.Event().wait()  # never set
        raise AssertionError("unreachable")


class _AttachedProc:
    """``docker start -a`` that never exits on its own, and records SIGKILL.

    The real client stays attached for as long as the container runs, which is
    exactly the state a cancellation has to interrupt.
    """

    def __init__(self, stream_cls: type = _EmptyStream) -> None:
        self.returncode: int | None = None
        self.killed = False
        self.stdout = stream_cls()
        self.stderr = stream_cls()

    async def wait(self) -> int:
        await asyncio.Event().wait()  # never set
        raise AssertionError("unreachable")

    def kill(self) -> None:
        self.killed = True


def _install_mocks(monkeypatch, *, stream_cls: type) -> tuple[asyncio.Event, list[_AttachedProc]]:
    """Mock every seam that would touch a real docker daemon.

    ``stream_pull`` is mocked to succeed so the test never opens the local
    docker socket; everything else is the same subprocess fakery as the
    pull-progress harness.
    """
    started = asyncio.Event()
    procs: list[_AttachedProc] = []

    def fake_subprocess_run(cmd, *args, **kwargs):
        # Image inspect, create, preflight ps, and the cleanup rm all land here.
        argv = list(cmd)
        if argv[:3] == ["docker", "image", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="120000000\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    async def fake_create_subprocess_exec(*argv, **kwargs):
        proc = _AttachedProc(stream_cls)
        procs.append(proc)
        started.set()
        return proc

    monkeypatch.setattr("hegemony_steps_container.run.stream_pull", AsyncMock(return_value=None))
    monkeypatch.setattr("subprocess.run", fake_subprocess_run)
    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_create_subprocess_exec)
    return started, procs


async def _cancel_and_await(task: asyncio.Task) -> None:
    task.cancel()
    try:
        await asyncio.wait_for(task, timeout=10)
    except asyncio.CancelledError:
        pass
    else:
        raise AssertionError("cancellation should propagate out of execute()")


def _leaked_tasks() -> list[asyncio.Task]:
    return [t for t in asyncio.all_tasks() if t is not asyncio.current_task() and not t.done()]


async def test_cancelled_step_kills_the_attached_docker_client(monkeypatch) -> None:
    """Cancellation while parked on the exited-process wait."""
    started, procs = _install_mocks(monkeypatch, stream_cls=_EmptyStream)

    task = asyncio.create_task(RunContainerHandler().execute(_ctx()))
    await asyncio.wait_for(started.wait(), timeout=10)
    # Let the readers drain and the handler park on proc.wait().
    await asyncio.sleep(0)
    await asyncio.sleep(0)

    await _cancel_and_await(task)

    assert procs, "the attached docker client was never spawned"
    assert procs[0].killed, "cancelled step left `docker start -a` running"


async def test_cancelled_step_mid_stream_leaves_no_tasks_behind(monkeypatch) -> None:
    """Cancellation while the readers are still attached.

    This is the path where gather() cancels the readers before they set their
    done-flags, so the flusher's loop condition can never come true -- without
    the explicit flusher cancel, one immortal task per cancelled step.
    """
    started, procs = _install_mocks(monkeypatch, stream_cls=_BlockingStream)

    task = asyncio.create_task(RunContainerHandler().execute(_ctx()))
    await asyncio.wait_for(started.wait(), timeout=10)
    # Let the readers start and park on readline(), and the flusher on sleep().
    await asyncio.sleep(0.05)

    await _cancel_and_await(task)

    assert procs[0].killed, "cancelled step left `docker start -a` running"
    # Give the cancelled helpers one cycle to finish unwinding, then insist
    # nothing from the step is still running.
    await asyncio.sleep(0.05)
    assert not _leaked_tasks(), "cancelled step left helper tasks running"
