# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The CLI transports' ``watch_output``, which ``netcli.watch`` reads devices with.

Run against the in-process SSH device of ``tests/ssh_fakes.py``: after
``terminal monitor`` it logs a few messages to the session, and after
``reload in 1`` it closes the session a moment later.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor

import asyncssh
import pytest

from hegemony_step_sdk import CliWatchTransport, DeviceConnectionSpec
from hegemony_transport_asyncssh.transport import AsyncSSHTransport
from hegemony_transport_netmiko.transport import SSHTransport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests.ssh_fakes import MONITOR_MESSAGES, PASSWORD, USERNAME, Servers, checks_off, ssh_servers

HOST = "127.0.0.1"
CLI_TRANSPORTS = {"netmiko": SSHTransport, "scrapli": ScrapliTransport}


@pytest.fixture
async def servers() -> AsyncIterator[Servers]:
    async with ssh_servers() as started:
        yield started


@pytest.fixture(params=sorted(CLI_TRANSPORTS))
def transport_id(request) -> str:
    return request.param


def _spec(port: int, password: str = PASSWORD) -> DeviceConnectionSpec:
    return DeviceConnectionSpec(
        host=HOST,
        port=port,
        username=USERNAME,
        password=password,
        platform="ios-xe",
        connect_timeout=5.0,
        command_timeout=5.0,
    )


async def _transport(servers: Servers, transport_id: str, **kwargs):
    port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
    return CLI_TRANSPORTS[transport_id](_spec(port, **kwargs), host_key_verifier=checks_off())


class Sink:
    def __init__(self) -> None:
        self.chunks: list[str] = []

    async def push(self, text: str, *, stream: str = "stdout") -> None:
        self.chunks.append(text)

    def push_from_thread(self, text: str, *, stream: str = "stdout") -> None:
        self.chunks.append(text)

    async def flush(self) -> None:
        return None

    def flush_from_thread(self, timeout: float = 5.0) -> None:
        return None


async def test_the_watch_reads_what_the_device_logs(servers, transport_id):
    transport = await _transport(servers, transport_id)
    # The type checker holds both transports to the SDK's protocol.
    watcher: CliWatchTransport = transport
    assert watcher is transport
    assert transport.supports_cli_watch is True

    result = await transport.watch_output(["terminal monitor"], duration_seconds=1.0)

    assert result.error is None
    assert result.disconnected is False
    assert result.cancelled is False
    assert [r.exit_code for r in result.setup] == [0]
    for message in MONITOR_MESSAGES:
        assert message in result.output
    assert 0.9 <= result.elapsed_seconds < 5
    # The transport logged in and out by itself.
    assert len(servers.seen.connections) == 1
    assert transport.session_open is False


async def test_the_watch_streams_to_the_live_log(servers, transport_id):
    port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
    sink = Sink()
    transport = CLI_TRANSPORTS[transport_id](
        _spec(port), host_key_verifier=checks_off(), output_sink=sink
    )
    assert transport.streams_watch_output is True

    result = await transport.watch_output(["terminal monitor"], duration_seconds=1.0)

    assert MONITOR_MESSAGES[0] in "".join(sink.chunks)
    assert result.output == "".join(sink.chunks)


async def test_keepalives_make_the_device_print_its_prompt(servers, transport_id):
    transport = await _transport(servers, transport_id)

    result = await transport.watch_output([], duration_seconds=1.2, keepalive_seconds=0.3)

    assert result.error is None
    assert result.output.count("r1#") >= 2


async def test_a_device_that_closes_the_session_ends_the_watch(servers, transport_id):
    transport = await _transport(servers, transport_id)

    result = await transport.watch_output(["reload in 1"], duration_seconds=10.0)

    assert result.disconnected is True
    assert result.error is None
    assert "%SYS-5-RELOAD" in result.output
    assert result.elapsed_seconds < 5


async def test_a_failed_setup_command_skips_the_watch(servers, transport_id):
    transport = await _transport(servers, transport_id)

    result = await transport.watch_output(["bad-reload", "terminal monitor"], duration_seconds=5.0)

    assert len(result.setup) == 1
    assert result.setup[0].exit_code != 0
    assert result.output == ""


async def test_a_refused_login_is_the_result_error(servers, transport_id):
    transport = await _transport(servers, transport_id, password="wrong")

    result = await transport.watch_output(["terminal monitor"], duration_seconds=1.0)

    assert result.error is not None
    assert result.setup == []


async def test_the_watch_runs_on_the_held_session(servers, transport_id):
    transport = await _transport(servers, transport_id)
    await transport.open_session()

    result = await transport.watch_output(["terminal monitor"], duration_seconds=0.6)
    after = await transport.execute_commands(["show version"])

    assert result.error is None
    assert after[0].exit_code == 0
    assert len(servers.seen.connections) == 1
    await transport.close_session()


async def test_cancelling_the_watch_stops_it(servers, transport_id):
    transport = await _transport(servers, transport_id)

    task = asyncio.create_task(transport.watch_output([], duration_seconds=30.0))
    await asyncio.sleep(1.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The device sees the session end soon after.
    for _ in range(50):
        if all(conn.is_closed() for conn in servers.seen.connections):
            break
        await asyncio.sleep(0.1)
    assert all(conn.is_closed() for conn in servers.seen.connections)


async def test_a_message_logged_right_after_setup_is_kept(servers, transport_id):
    transport = await _transport(servers, transport_id)

    result = await transport.watch_output(["log-now"], duration_seconds=0.8)

    # It reaches the result: in the setup command's output when the transport
    # read it with the command, or else in the watch output.
    assert result.error is None
    seen = "".join(item.output for item in result.setup) + result.output
    assert "%SYS-5-QUEUED" in seen


class _BreakingConnection:
    """A netmiko-like session: one message, then the read fails (the connection resets)."""

    remote_conn = None

    def __init__(self) -> None:
        self.reads = 0

    def read_channel(self) -> str:
        self.reads += 1
        if self.reads == 1:
            return "%LINK-3-UPDOWN: Interface Gi1, changed state to down\n"
        raise OSError("connection reset by peer")

    def write_channel(self, data: str) -> None:
        return None


async def test_netmiko_keeps_what_it_read_before_a_read_fails(servers, monkeypatch):
    transport = await _transport(servers, "netmiko")
    monkeypatch.setattr(transport, "_login", _BreakingConnection)
    monkeypatch.setattr(transport, "_logout", lambda connection: None)

    result = await transport.watch_output([], duration_seconds=5.0)

    assert result.error is not None
    assert "changed state to down" in result.output
    assert result.elapsed_seconds < 5


class _ScrapliChannel:
    def write(self, data: str) -> None:
        raise OSError("broken pipe")


class _ScrapliConnection:
    channel = _ScrapliChannel()


async def test_scrapli_keeps_what_it_read_before_a_keepalive_fails(servers, monkeypatch):
    transport = await _transport(servers, "scrapli")
    chunks = iter(["%LINK-3-UPDOWN: Interface Gi1, changed state to down\n"])

    async def login():
        return _ScrapliConnection()

    async def logout(connection):
        return None

    async def read(connection, timeout=None):
        await asyncio.sleep(0.05)
        return next(chunks, "")

    monkeypatch.setattr(transport, "_login", login)
    monkeypatch.setattr(transport, "_logout", logout)
    monkeypatch.setattr(transport, "_read_channel_chunk", read)
    monkeypatch.setattr("hegemony_transport_scrapli.transport._session_open", lambda c: True)

    result = await transport.watch_output([], duration_seconds=5.0, keepalive_seconds=0.2)

    assert result.error is not None
    assert "changed state to down" in result.output


async def test_a_netmiko_watch_leaves_the_shared_executor_free(servers):
    transport = await _transport(servers, "netmiko")
    loop = asyncio.get_running_loop()
    shared = ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(shared)
    try:
        watch = asyncio.create_task(transport.watch_output([], duration_seconds=3.0))
        await asyncio.sleep(1.0)
        # A command of the change being watched still gets a thread at once.
        assert await asyncio.wait_for(loop.run_in_executor(None, lambda: "ran"), 1.0) == "ran"
        assert not watch.done()
        result = await watch
        assert result.error is None
    finally:
        shared.shutdown(wait=False)


def test_asyncssh_does_not_offer_the_watch():
    assert getattr(AsyncSSHTransport, "supports_cli_watch", False) is False
