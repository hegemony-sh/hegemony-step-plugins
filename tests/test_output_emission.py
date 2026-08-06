# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Live output emission: ctx.emit_output and its handler wiring.

The host UI's Logs tab streams run events whose
``attrs={"milestone": "output", "stream": "stdout"|"stderr"}`` — the shape
established by ``container.run``. These tests pin the SDK helper's contract
(chunking, capping, device-id UUID guard, best-effort semantics) and that
the CLI/shell handlers emit their command output through it.
"""

from typing import Any, cast
from uuid import uuid4

import pytest

from hegemony_step_sdk import (
    OUTPUT_EVENT_CHUNK_CHARS,
    OUTPUT_EVENT_MAX_CHARS,
    OUTPUT_TRUNCATION_NOTICE,
    HandlerContext,
    HandlerServices,
)
from hegemony_step_sdk.contract import _chunk_on_line_boundaries


def _ctx(recorder, **overrides) -> HandlerContext:
    async def _record(message, device_id, attrs):
        recorder.append((message, device_id, attrs))
        return True

    defaults: dict[str, Any] = dict(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        phase="EXECUTE",
        kind="ACTION",
        config={},
        _emit_progress=_record,
    )
    defaults.update(overrides)
    return HandlerContext(**defaults)


class TestChunking:
    def test_prefers_line_boundaries(self):
        lines = [f"line {i}\n" for i in range(1000)]
        chunks = _chunk_on_line_boundaries("".join(lines), 100)
        assert all(len(c) <= 100 for c in chunks)
        # Every chunk except possibly the last ends on a line boundary
        assert all(c.endswith("\n") for c in chunks)
        assert "".join(chunks) == "".join(lines)

    def test_hard_splits_oversized_single_line(self):
        text = "x" * 250
        chunks = _chunk_on_line_boundaries(text, 100)
        assert [len(c) for c in chunks] == [100, 100, 50]
        assert "".join(chunks) == text


class TestEmitOutput:
    @pytest.mark.asyncio
    async def test_emits_output_attrs_shape(self):
        events = []
        ctx = _ctx(events)
        device_uuid = str(uuid4())
        ok = await ctx.emit_output(
            "hello\nworld",
            device={"id": device_uuid, "name": "sw1", "mgmt_host": "192.0.2.1"},
            command="show version",
        )
        assert ok is True
        assert len(events) == 1
        message, device_id, attrs = events[0]
        assert message == "hello\nworld"
        assert device_id == device_uuid
        assert attrs == {
            "milestone": "output",
            "stream": "stdout",
            "device_name": "sw1",
            "command": "show version",
        }

    @pytest.mark.asyncio
    async def test_stderr_stream(self):
        events = []
        ctx = _ctx(events)
        await ctx.emit_output("boom", stream="stderr")
        assert events[0][2]["stream"] == "stderr"

    @pytest.mark.asyncio
    async def test_non_uuid_device_id_is_withheld(self):
        """The host 400s events with a non-UUID device_id — never send one."""
        events = []
        ctx = _ctx(events)
        await ctx.emit_output("text", device={"id": "192.0.2.1", "name": "sw1"})
        _, device_id, attrs = events[0]
        assert device_id is None
        assert attrs["device_name"] == "sw1"

    @pytest.mark.asyncio
    async def test_device_name_falls_back_to_mgmt_host(self):
        events = []
        ctx = _ctx(events)
        await ctx.emit_output("text", device={"id": None, "mgmt_host": "192.0.2.9"})
        assert events[0][2]["device_name"] == "192.0.2.9"

    @pytest.mark.asyncio
    async def test_long_output_chunks_carry_attrs(self):
        events = []
        ctx = _ctx(events)
        text = "\n".join("y" * 80 for _ in range(200))  # ~16 KB
        await ctx.emit_output(text)
        assert len(events) > 1
        assert all(len(m) <= OUTPUT_EVENT_CHUNK_CHARS for m, _, _ in events)
        assert all(a["milestone"] == "output" for _, _, a in events)

    @pytest.mark.asyncio
    async def test_oversized_output_truncated_with_notice(self):
        events = []
        ctx = _ctx(events)
        await ctx.emit_output("z" * (OUTPUT_EVENT_MAX_CHARS + 10_000))
        emitted = "".join(m for m, _, _ in events)
        assert OUTPUT_TRUNCATION_NOTICE in emitted
        # Chunks are verbatim: exactly the capped text plus the notice line
        assert len(emitted) <= OUTPUT_EVENT_MAX_CHARS + len(OUTPUT_TRUNCATION_NOTICE) + 1

    @pytest.mark.asyncio
    async def test_empty_text_is_a_noop(self):
        events = []
        ctx = _ctx(events)
        assert await ctx.emit_output("") is False
        assert events == []

    @pytest.mark.asyncio
    async def test_unbound_emit_returns_false(self):
        ctx = _ctx([], _emit_progress=None)
        assert await ctx.emit_output("text") is False

    @pytest.mark.asyncio
    async def test_raising_callback_is_swallowed(self):
        async def _boom(message, device_id, attrs):
            raise RuntimeError("emit failed")

        ctx = _ctx([], _emit_progress=_boom)
        assert await ctx.emit_output("text") is False


DEVICE_UUID = str(uuid4())
DEVICE = {"id": DEVICE_UUID, "name": "sw1", "mgmt_host": "192.0.2.1", "platform": "ios-xe"}


def _output_events(events):
    return [e for e in events if e[2] and e[2].get("milestone") == "output"]


class TestHandlerWiring:
    @pytest.mark.asyncio
    async def test_netcli_execute_emits_per_command(self):
        from hegemony_steps_netcli.execute import ExecuteCLIActionHandler

        class _Result:
            def __init__(self, command):
                self.command = command
                self.output = f"output of {command}"
                self.exit_code = 0
                self.error = None
                self.latency_ms = 1.0

        class _Transport:
            async def execute_commands(self, commands):
                return [_Result(c) for c in commands]

        class _Services:
            def connect(self, device, *, platform=None, **kwargs):
                return _Transport()

        events = []
        ctx = _ctx(
            events,
            config={"commands": ["show version", "show inventory"]},
            target_roles=["primary"],
            target_devices_by_role={"primary": [DEVICE]},
            services=cast(HandlerServices, _Services()),
        )
        result = await ExecuteCLIActionHandler().execute(ctx)
        assert result.success is True

        out = _output_events(events)
        assert [e[2]["command"] for e in out] == ["show version", "show inventory"]
        assert all(e[1] == DEVICE_UUID for e in out)
        assert all(e[2]["stream"] == "stdout" for e in out)
        assert out[0][0] == "output of show version"

    @pytest.mark.asyncio
    async def test_netcli_execute_config_mode_streams_nothing(self):
        """Config-mode transcripts may echo credentials — artifact-only."""
        from hegemony_steps_netcli.execute import ExecuteCLIActionHandler

        class _Result:
            def __init__(self, command):
                self.command = command
                self.output = f"echo of {command}"
                self.exit_code = 0
                self.error = None
                self.latency_ms = 1.0

        class _Transport:
            async def execute_commands(self, commands):
                return [_Result(c) for c in commands]

        class _Services:
            def connect(self, device, *, platform=None, **kwargs):
                return _Transport()

        events = []
        ctx = _ctx(
            events,
            config={
                "commands": [
                    "configure terminal",
                    "username admin password hunter2",
                    "end",
                ]
            },
            target_roles=["primary"],
            target_devices_by_role={"primary": [DEVICE]},
            services=cast(HandlerServices, _Services()),
        )
        result = await ExecuteCLIActionHandler().execute(ctx)
        assert result.success is True
        assert _output_events(events) == []
        # The transcript still lands in evidence artifacts
        assert any(e.get("kind") == "cli_output" for e in result.evidence)

    @pytest.mark.asyncio
    async def test_netcli_collect_evidence_emits_per_command(self):
        from hegemony_steps_netcli.collect_evidence import CollectEvidenceHandler

        class _Result:
            command = "show version"
            output = "Cisco IOS XE"
            exit_code = 0
            error = None
            latency_ms = 1.0

        class _Transport:
            async def execute_commands(self, commands):
                return [_Result()]

        class _Services:
            def connect(self, device, *, platform=None, **kwargs):
                return _Transport()

        events = []
        ctx = _ctx(
            events,
            kind="CHECK",
            config={"commands": ["show version"]},
            target_roles=["primary"],
            target_devices_by_role={"primary": [DEVICE]},
            services=cast(HandlerServices, _Services()),
        )
        result = await CollectEvidenceHandler().execute(ctx)
        assert result.success is True
        assert [e[0] for e in _output_events(events)] == ["Cisco IOS XE"]

    @pytest.mark.asyncio
    async def test_poll_until_emits_each_attempt(self):
        from hegemony_steps_netcli.poll_until import PollUntilHandler

        outputs = iter(["not yet", "not yet", "READY"])

        class _Result:
            def __init__(self, output):
                self.command = "show status"
                self.output = output
                self.exit_code = 0
                self.error = None
                self.latency_ms = 1.0

        class _Transport:
            async def execute_command(self, command):
                return _Result(next(outputs))

        class _Services:
            def connect(self, device, *, platform=None, **kwargs):
                return _Transport()

        events = []
        ctx = _ctx(
            events,
            kind="CHECK",
            config={
                "command": "show status",
                "match_string": "READY",
                "interval_seconds": 0,
                "max_attempts": 5,
            },
            target_roles=["primary"],
            target_devices_by_role={"primary": [DEVICE]},
            services=cast(HandlerServices, _Services()),
        )
        result = await PollUntilHandler().execute(ctx)
        assert result.success is True
        assert [e[0] for e in _output_events(events)] == ["not yet", "not yet", "READY"]

    @pytest.mark.asyncio
    async def test_shell_execute_emits_stdout_and_stderr(self):
        from hegemony_steps_shell.execute import ShellExecuteHandler

        class _ShellResult:
            def __init__(self, command):
                self.command = command
                self.exit_code = 0
                self.stdout = "file listing"
                self.stderr = "a warning"

        class _ShellTransport:
            async def run(self, command, *, timeout=None):
                return _ShellResult(command)

            async def close(self):
                return None

        class _Services:
            async def open_shell(self, device, **kwargs):
                return _ShellTransport()

        events = []
        ctx = _ctx(
            events,
            config={"commands": ["ls /var"]},
            target_roles=["primary"],
            target_devices_by_role={"primary": [DEVICE]},
            services=cast(HandlerServices, _Services()),
        )
        result = await ShellExecuteHandler().execute(ctx)
        assert result.success is True

        out = _output_events(events)
        assert [(e[0], e[2]["stream"]) for e in out] == [
            ("file listing", "stdout"),
            ("a warning", "stderr"),
        ]
        assert all(e[2]["command"] == "ls /var" for e in out)
