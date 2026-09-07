# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Phase B live streaming: transport output sinks and handler dedup.

Pins the transport side of mid-command streaming — the feature-detected
``output_sink`` constructor kwarg, the ``$ command`` boundary marker, chunk
pushes from the timing-mode read loops (async push for scrapli/asyncssh,
thread-marshalled for netmiko), the end-of-command flush, best-effort
semantics (a broken sink never fails the command) — and the handler-side
``streams_*_output`` flags that suppress the Phase A completed-output
emissions a streaming transport would duplicate.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from scrapli.exceptions import ScrapliTimeout

from hegemony_step_sdk import DeviceConnectionSpec, HandlerContext, HandlerServices


class _FakeSink:
    """Recording TransportOutputSink double (both entry-point families)."""

    def __init__(self):
        self.pushed: list[str] = []
        self.thread_pushed: list[str] = []
        self.flushes = 0
        self.thread_flushes = 0

    async def push(self, text: str, *, stream: str = "stdout") -> None:
        self.pushed.append(text)

    def push_from_thread(self, text: str, *, stream: str = "stdout") -> None:
        self.thread_pushed.append(text)

    async def flush(self) -> None:
        self.flushes += 1

    def flush_from_thread(self, timeout: float = 5.0) -> None:
        self.thread_flushes += 1


class _BrokenSink(_FakeSink):
    """A sink whose every entry point raises — streaming must stay best-effort."""

    async def push(self, text: str, *, stream: str = "stdout") -> None:
        raise RuntimeError("sink broken")

    def push_from_thread(self, text: str, *, stream: str = "stdout") -> None:
        raise RuntimeError("sink broken")

    async def flush(self) -> None:
        raise RuntimeError("sink broken")

    def flush_from_thread(self, timeout: float = 5.0) -> None:
        raise RuntimeError("sink broken")


_SPEC = DeviceConnectionSpec(host="10.0.0.1", username="admin", password="pw")


# ── Scrapli ──────────────────────────────────────────────────────────────────


def _scrapli_connection() -> MagicMock:
    connection = MagicMock()
    connection.open = AsyncMock()
    connection.close = AsyncMock()
    connection.channel.write = MagicMock()
    return connection


def test_scrapli_advertises_sink_support():
    from hegemony_transport_scrapli.transport import ScrapliTransport

    assert ScrapliTransport.supports_output_sink is True
    assert ScrapliTransport(_SPEC).streams_timing_output is False
    assert ScrapliTransport(_SPEC, output_sink=_FakeSink()).streams_timing_output is True


async def test_scrapli_timing_streams_marker_and_chunks():
    import hegemony_transport_scrapli.transport as transport_module
    from hegemony_transport_scrapli.transport import ScrapliTransport

    sink = _FakeSink()
    transport = ScrapliTransport(_SPEC, output_sink=sink)
    connection = _scrapli_connection()
    connection.channel.read = AsyncMock(
        side_effect=[b"copying...", ScrapliTimeout("quiet"), b"1234 bytes copied"]
    )

    with patch.object(transport_module, "AsyncScrapli", return_value=connection):
        result = await transport.execute_command_timing(
            "copy tftp: flash:", read_timeout=30.0, wait_for_patterns=["bytes copied"]
        )

    assert result.exit_code == 0
    assert sink.pushed == ["$ copy tftp: flash:\n", "copying...", "1234 bytes copied"]
    assert sink.flushes == 1


async def test_scrapli_broken_sink_never_fails_the_command():
    import hegemony_transport_scrapli.transport as transport_module
    from hegemony_transport_scrapli.transport import ScrapliTransport

    transport = ScrapliTransport(_SPEC, output_sink=_BrokenSink())
    connection = _scrapli_connection()
    connection.channel.read = AsyncMock(
        side_effect=[b"done", ScrapliTimeout("q1"), ScrapliTimeout("q2"), ScrapliTimeout("q3")]
    )

    with patch.object(transport_module, "AsyncScrapli", return_value=connection):
        result = await transport.execute_command_timing("reload in 5", read_timeout=30.0)

    assert result.exit_code == 0
    assert result.output == "done"


# ── AsyncSSH ─────────────────────────────────────────────────────────────────


def test_asyncssh_advertises_sink_support():
    from hegemony_transport_asyncssh.transport import AsyncSSHTransport

    assert AsyncSSHTransport.supports_output_sink is True
    assert AsyncSSHTransport(_SPEC).streams_timing_output is False
    assert AsyncSSHTransport(_SPEC, output_sink=_FakeSink()).streams_timing_output is True


def _pty_process(chunks: list[bytes], exit_status: int = 0) -> SimpleNamespace:
    reads = iter(chunks)

    async def _read(_n: int) -> bytes:
        return next(reads, b"")

    return SimpleNamespace(
        stdout=SimpleNamespace(read=_read),
        stdin=SimpleNamespace(write=MagicMock()),
        exit_status=exit_status,
        terminate=MagicMock(),
    )


async def test_asyncssh_timing_streams_marker_and_chunks():
    from hegemony_transport_asyncssh.transport import AsyncSSHTransport

    sink = _FakeSink()
    transport = AsyncSSHTransport(_SPEC, output_sink=sink)
    process = _pty_process([b"hello ", b"world"])
    connection = MagicMock()
    connection.create_process = AsyncMock(return_value=process)
    connection.close = MagicMock()
    connection.wait_closed = AsyncMock()

    with patch.object(transport, "_connect", AsyncMock(return_value=connection)):
        result = await transport.execute_command_timing("uname -a", read_timeout=30.0)

    assert result.exit_code == 0
    assert result.output == "hello world"
    assert sink.pushed == ["$ uname -a\n", "hello ", "world"]
    assert sink.flushes == 1


async def test_asyncssh_exec_path_stays_buffered():
    """Exec channels batch config-like commands — they must never stream."""
    from hegemony_transport_asyncssh.transport import AsyncSSHTransport

    sink = _FakeSink()
    transport = AsyncSSHTransport(_SPEC, output_sink=sink)
    connection = MagicMock()
    connection.run = AsyncMock(return_value=SimpleNamespace(exit_status=0, stdout="out", stderr=""))
    connection.close = MagicMock()
    connection.wait_closed = AsyncMock()

    with patch.object(transport, "_connect", AsyncMock(return_value=connection)):
        results = await transport.execute_commands(["show version"])

    assert results[0].exit_code == 0
    assert sink.pushed == []
    assert sink.thread_pushed == []


# ── Netmiko ──────────────────────────────────────────────────────────────────


def test_netmiko_advertises_sink_support():
    import hegemony_transport_netmiko.transport as transport_module
    from hegemony_transport_netmiko.transport import SSHTransport

    assert SSHTransport.supports_output_sink is True
    with patch.object(transport_module, "ConnectHandler", MagicMock()):
        assert SSHTransport(_SPEC).streams_timing_output is False
        assert SSHTransport(_SPEC, output_sink=_FakeSink()).streams_timing_output is True


async def test_netmiko_timing_streams_via_thread_marshalling():
    import hegemony_transport_netmiko.transport as transport_module
    from hegemony_transport_netmiko.transport import SSHTransport

    sink = _FakeSink()
    connection = MagicMock()
    connection.send_command_timing.return_value = "Install completed"

    with (
        patch.object(transport_module, "ConnectHandler", return_value=connection),
        patch.object(transport_module, "_safe_disconnect"),
    ):
        transport = SSHTransport(_SPEC, output_sink=sink)
        result = await transport.execute_command_timing("install add file x", read_timeout=30.0)

    assert result.exit_code == 0
    # Netmiko runs in an executor thread: chunks arrive via push_from_thread.
    assert sink.thread_pushed == ["$ install add file x\n", "Install completed"]
    assert sink.thread_flushes == 1
    assert sink.pushed == []


async def test_netmiko_broken_sink_never_fails_the_command():
    import hegemony_transport_netmiko.transport as transport_module
    from hegemony_transport_netmiko.transport import SSHTransport

    connection = MagicMock()
    connection.send_command_timing.return_value = "ok"

    with (
        patch.object(transport_module, "ConnectHandler", return_value=connection),
        patch.object(transport_module, "_safe_disconnect"),
    ):
        transport = SSHTransport(_SPEC, output_sink=_BrokenSink())
        result = await transport.execute_command_timing("show version", read_timeout=30.0)

    assert result.exit_code == 0
    assert result.output == "ok"


# ── Handler dedup: streams_*_output suppresses Phase A emissions ─────────────

DEVICE_UUID = str(uuid4())
DEVICE = {"id": DEVICE_UUID, "name": "sw1", "mgmt_host": "192.0.2.1", "platform": "ios-xe"}


def _ctx(recorder: list, **overrides) -> HandlerContext:
    async def _record(message, device_id, attrs):
        recorder.append((message, device_id, attrs))
        return True

    defaults: dict[str, Any] = dict(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={},
        _emit_progress=_record,
    )
    defaults.update(overrides)
    return HandlerContext(**defaults)


def _output_events(events):
    return [e for e in events if e[2] and e[2].get("milestone") == "output"]


async def test_shell_execute_skips_emission_when_transport_streams():
    from hegemony_steps_shell.execute import ShellExecuteHandler

    class _ShellTransport:
        streams_exec_output = True

        async def run(self, command, *, timeout=None):
            return SimpleNamespace(command=command, exit_code=0, stdout="listing", stderr="warn")

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
    # The transport streamed live — re-emitting would duplicate every command.
    assert _output_events(events) == []
    # The transcript still lands in evidence artifacts.
    assert any(e.get("kind") == "cli_output" for e in result.evidence)


async def test_iosxe_install_skips_transcript_when_transport_streams():
    import hegemony_steps_cisco_iosxe.upgrade.handlers.install as install_module
    from hegemony_steps_cisco_iosxe.upgrade.handlers.install import UpgradeInstallHandler

    def _driver_result():
        return SimpleNamespace(
            success=True,
            reboot_triggered=True,
            activated=True,
            committed=True,
            note=None,
            error=None,
            cli_output="install transcript",
        )

    class _Driver:
        async def install(self, ssh, **kwargs):
            return _driver_result()

    async def _run(streams: bool) -> list:
        class _Ssh:
            streams_timing_output = streams

        class _Services:
            def connect(self, device, *, platform=None, **kwargs):
                return _Ssh()

        events: list = []
        ctx = _ctx(
            events,
            config={"image_name": "img.bin"},
            target_roles=["primary"],
            target_devices_by_role={"primary": [DEVICE]},
            services=cast(HandlerServices, _Services()),
        )
        with patch.object(install_module, "get_driver", return_value=_Driver()):
            result = await UpgradeInstallHandler().execute(ctx)
        assert result.success is True
        return _output_events(events)

    # Legacy transport (no streaming): the transcript tail is emitted.
    assert [e[0] for e in await _run(streams=False)] == ["install transcript"]
    # Streaming transport: the tail emission would duplicate the live stream.
    assert await _run(streams=True) == []
