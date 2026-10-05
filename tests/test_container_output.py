# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""container.run reads its client's output to the end, and limits the live log.

A pipe nobody reads fills up and blocks the container, so the reader must
never stop early: not on a line longer than asyncio's 64 KiB line limit, and
not once the live log has shown all it may. A client whose pipe never closes
must not hold a timed-out step past a bounded wait either.

``docker start -a`` is a real child process here, writing to real pipes;
only the one-shot docker calls and the pull are faked.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
import time
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerResult, HandlerServices
from hegemony_steps_container.run import RunContainerHandler
from hegemony_steps_container.runner import ContainerJob, ContainerJobResult
from hegemony_steps_container.streams import (
    MAX_LIVE_OUTPUT_BYTES,
    READ_CHUNK_BYTES,
    LiveOutput,
    read_lines,
)


class _FakeServices:
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
        return {}

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        return []


def _ctx(events: list[tuple[str, dict]], timeout: int = 60) -> HandlerContext:
    async def record(message: str, device_id: str | None, attrs: dict[str, Any] | None) -> bool:
        events.append((message, dict(attrs or {})))
        return True

    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="step-1",
        config={"image": "alpine:3.20", "command": ["true"], "timeout_seconds": timeout},
        services=cast(HandlerServices, _FakeServices()),
        _emit_progress=record,
    )


@pytest.fixture
async def attached_client(monkeypatch):
    """Run ``docker start -a`` as a Python child running the script the test sets.

    The child gets its own process group, which is killed at the end, so a
    grandchild left holding the pipes does not outlive the test.
    """
    real_exec = asyncio.create_subprocess_exec
    state: dict[str, Any] = {"script": "", "procs": []}

    def fake_run(cmd, *args, **kwargs):
        if list(cmd[:3]) == ["docker", "image", "inspect"]:
            return SimpleNamespace(returncode=0, stdout="120000000\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    async def fake_exec(*argv, **kwargs):
        if list(argv[:3]) != ["docker", "start", "-a"]:
            raise AssertionError(f"unexpected exec: {argv}")
        kwargs.pop("env", None)
        proc = await real_exec(
            sys.executable, "-c", state["script"], start_new_session=True, **kwargs
        )
        state["procs"].append(proc)
        return proc

    monkeypatch.setattr("hegemony_steps_container.run.stream_pull", AsyncMock(return_value=None))
    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    yield state
    for proc in state["procs"]:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        # Read to the end on this test's event loop, so the pipes close before
        # the loop does: wait() alone returns once the child is reaped, while a
        # grandchild may still hold them.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(proc.communicate(), timeout=5)


async def _run(ctx: HandlerContext) -> HandlerResult | ContainerJobResult:
    return await RunContainerHandler().run_job(ctx, ContainerJob(config=ctx.config))


def _live(events: list[tuple[str, dict]]) -> str:
    return "".join(message for message, attrs in events if attrs.get("milestone") == "output")


async def test_a_line_longer_than_the_line_limit_does_not_stop_the_output(attached_client):
    attached_client["script"] = (
        "import sys\n"
        "sys.stdout.write('A' * 100_000 + '\\n')\n"
        "for i in range(20_000): sys.stdout.write('line %06d %s\\n' % (i, '.' * 40))\n"
        "sys.stdout.write('TAIL\\n')\n"
    )
    events: list[tuple[str, dict]] = []
    started = time.monotonic()

    result = await _run(_ctx(events, timeout=30))

    assert time.monotonic() - started < 15
    assert isinstance(result, ContainerJobResult)
    assert result.exit_code == 0
    assert result.stdout.startswith("A" * 100_000 + "\nline 000000 ")
    assert result.stdout.endswith("line 019999 " + "." * 40 + "\nTAIL\n")
    assert not result.truncated
    live = _live(events)
    assert "A" * 100_000 + "\n" in live
    assert live.endswith("TAIL\n")


async def test_a_pipe_that_never_closes_ends_in_the_timeout_result(attached_client, monkeypatch):
    """The client is killed at the deadline; a grandchild still holds its pipes.

    asyncio's ``wait()`` waits for the pipes to close too, so only the bounded
    wait after the kill returns the step at all.
    """
    monkeypatch.setattr("hegemony_steps_container.run.KILL_WAIT_SECONDS", 1.0)
    attached_client["script"] = (
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        "print('started', flush=True)\n"
        "time.sleep(60)\n"
    )
    events: list[tuple[str, dict]] = []
    started = time.monotonic()

    result = await _run(_ctx(events, timeout=2))

    assert time.monotonic() - started < 2 + 1 + 5
    assert isinstance(result, HandlerResult)
    assert result.summary == "Container timed out"
    assert result.error == "Container execution timed out after 2s"


async def test_the_live_log_stops_at_its_limit_and_the_output_is_still_read(attached_client):
    total = MAX_LIVE_OUTPUT_BYTES + 3 * 1024 * 1024
    attached_client["script"] = (
        "import sys\n"
        "line = 'x' * 99 + '\\n'\n"
        f"for i in range({total // 100}): sys.stdout.write(line)\n"
        "sys.stdout.flush()\n"
        "sys.stderr.write('done\\n')\n"
    )
    events: list[tuple[str, dict]] = []

    result = await _run(_ctx(events))

    # The child exited by itself: its whole output was read.
    assert isinstance(result, ContainerJobResult)
    assert result.exit_code == 0
    live = _live(events)
    notice = "[Live output stops here, at its 5 MB limit; the container goes on."
    assert live.count(notice) == 1
    assert len(live.encode()) <= MAX_LIVE_OUTPUT_BYTES + 300
    assert live.rstrip("\n").endswith("of stdout and of stderr.]")
    # What the evidence keeps is kept as before.
    assert result.truncated
    assert len(result.stdout) == 5 * 1024 * 1024 // 2


async def _lines_of(data: bytes) -> list[bytes]:
    stream = asyncio.StreamReader()
    stream.feed_data(data)
    stream.feed_eof()
    return [line async for line in read_lines(stream)]


async def test_read_lines_splits_long_lines_into_pieces():
    long = b"y" * (READ_CHUNK_BYTES * 2 + 10)
    data = b"one\n" + long + b"\ntwo"
    lines = await _lines_of(data)
    assert b"".join(lines) == data
    assert lines[0] == b"one\n"
    assert lines[-1] == b"two"
    pieces = lines[1:-1]
    assert len(pieces) > 1
    assert all(len(piece) < 2 * READ_CHUNK_BYTES for piece in pieces)
    assert [piece.endswith(b"\n") for piece in pieces] == [False] * (len(pieces) - 1) + [True]


def test_live_output_admits_pieces_until_its_limit_then_one_notice():
    live = LiveOutput("[stop]", limit=10)
    assert live.admit("abcd\n") == "abcd\n"
    assert live.admit("efg") == "efg"
    assert not live.stopped
    # Past the limit, mid-line: the notice starts a line of its own.
    assert live.admit("hijk\n") == "\n[stop]\n"
    assert live.stopped
    assert live.admit("l\n") == ""


def test_live_output_notice_after_a_whole_line_starts_at_once():
    live = LiveOutput("[stop]", limit=4)
    assert live.admit("ab\n") == "ab\n"
    assert live.admit("cd\n") == "[stop]\n"


def test_live_output_counts_the_utf8_the_log_receives():
    # Each invalid byte decodes to U+FFFD, three bytes of UTF-8: three read
    # bytes fill a limit of nine, so the log never gets more than its limit.
    live = LiveOutput("[stop]", limit=9)
    assert live.admit(b"\xff\xff\xff".decode("utf-8", errors="replace")) == "�" * 3
    assert live.admit("a") == "\n[stop]\n"


async def test_output_after_a_line_that_fills_the_budget_marks_it_truncated(
    attached_client, monkeypatch
):
    # 20 bytes for the evidence: 10 per stream, which the first line fills.
    monkeypatch.setattr(RunContainerHandler, "_MAX_OUTPUT_BYTES", 20)
    attached_client["script"] = "import sys\nsys.stdout.write('abcdefghi\\nmore\\n')\n"
    events: list[tuple[str, dict]] = []

    result = await _run(_ctx(events))

    assert isinstance(result, ContainerJobResult)
    assert result.stdout == "abcdefghi\n"
    assert result.truncated
