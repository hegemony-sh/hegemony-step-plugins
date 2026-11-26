# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The transports' held session, which the ``wait_for`` steps poll on.

``open_session`` logs in once; later ``execute_commands`` calls run on that
login instead of logging in each time. ``session_open`` turns False when the
device closes the session (a reload), and ``open_session`` logs in again.
Run against the in-process SSH device of ``tests/ssh_fakes.py``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import asyncssh
import pytest

from hegemony_step_sdk import DeviceConnectionSpec
from hegemony_step_sdk.cli_prompts import CliPrompt
from hegemony_transport_asyncssh.transport import AsyncSSHTransport
from hegemony_transport_netmiko.transport import SSHTransport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests.ssh_fakes import PASSWORD, USERNAME, Servers, checks_off, ssh_servers

HOST = "127.0.0.1"
CLI_TRANSPORTS = {"netmiko": SSHTransport, "scrapli": ScrapliTransport}
RELOAD_PROMPTS = [CliPrompt(command=r"^reload", expect=r"\[confirm\]")]


@pytest.fixture
async def servers() -> AsyncIterator[Servers]:
    async with ssh_servers() as started:
        yield started


@pytest.fixture(params=sorted(CLI_TRANSPORTS))
def cli_transport_id(request) -> str:
    return request.param


def _spec(port: int, platform: str = "ios-xe") -> DeviceConnectionSpec:
    return DeviceConnectionSpec(
        host=HOST,
        port=port,
        username=USERNAME,
        password=PASSWORD,
        platform=platform,
        connect_timeout=5.0,
        command_timeout=5.0,
    )


async def _cli_transport(servers: Servers, transport_id: str):
    port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
    return CLI_TRANSPORTS[transport_id](_spec(port), host_key_verifier=checks_off())


async def test_commands_run_on_the_held_login(servers, cli_transport_id):
    transport = await _cli_transport(servers, cli_transport_id)
    assert transport.supports_held_session is True
    assert transport.session_open is False

    await transport.open_session()
    first = await transport.execute_commands(["show version"])
    second = await transport.execute_commands(["show install summary"])

    assert [r.exit_code for r in (*first, *second)] == [0, 0]
    assert "output of show install summary" in second[0].output
    assert len(servers.seen.connections) == 1
    assert transport.session_open is True

    await transport.close_session()
    assert transport.session_open is False
    await transport.close_session()  # idempotent


async def test_without_a_held_session_every_call_logs_in(servers, cli_transport_id):
    transport = await _cli_transport(servers, cli_transport_id)

    await transport.execute_commands(["show version"])
    await transport.execute_commands(["show version"])

    assert len(servers.seen.connections) == 2
    assert transport.session_open is False


async def test_a_reload_ends_the_held_session_and_a_new_login_follows(servers, cli_transport_id):
    transport = await _cli_transport(servers, cli_transport_id)
    transport.configure_cli_prompts(RELOAD_PROMPTS)
    await transport.open_session()

    results = await transport.execute_commands(["reload"])

    assert results[0].disconnected is True
    assert transport.session_open is False

    await transport.open_session()
    again = await transport.execute_commands(["show version"])
    assert again[0].exit_code == 0
    assert len(servers.seen.connections) == 2
    await transport.close_session()


async def test_a_failed_login_raises_and_holds_nothing(cli_transport_id):
    # Nothing listens on this port.
    probe = await asyncio.start_server(lambda r, w: None, HOST, 0)
    port = probe.sockets[0].getsockname()[1]
    probe.close()
    await probe.wait_closed()
    transport = CLI_TRANSPORTS[cli_transport_id](_spec(port), host_key_verifier=checks_off())

    with pytest.raises(Exception):  # noqa: B017 - each library raises its own error
        await transport.open_session()
    assert transport.session_open is False


async def test_asyncssh_runs_exec_channels_on_the_held_connection(servers):
    port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
    transport = AsyncSSHTransport(_spec(port, "linux"), host_key_verifier=checks_off())
    assert transport.supports_held_session is True

    await transport.open_session()
    first = await transport.execute_commands(["uptime"])
    second = await transport.execute_commands(["uptime"])

    assert [r.output for r in (*first, *second)] == ["ran uptime\n", "ran uptime\n"]
    assert len(servers.seen.connections) == 1
    assert transport.session_open is True

    # The server going away closes the held connection.
    servers.seen.connections[0].close()
    for _ in range(50):
        if not transport.session_open:
            break
        await asyncio.sleep(0.05)
    assert transport.session_open is False

    await transport.open_session()
    third = await transport.execute_commands(["uptime"])
    assert third[0].exit_code == 0
    assert len(servers.seen.connections) == 2
    await transport.close_session()
    assert transport.session_open is False


async def test_netmiko_closes_a_login_whose_caller_was_cancelled(monkeypatch):
    """The login thread outlives a cancelled open_session; its connection is closed."""
    import threading

    transport = SSHTransport(_spec(22), host_key_verifier=checks_off())
    proceed = threading.Event()
    connection = object()
    closed: list[object] = []

    def slow_login():
        proceed.wait(5)
        return connection

    monkeypatch.setattr(transport, "_login", slow_login)
    monkeypatch.setattr(transport, "_logout", closed.append)

    task = asyncio.ensure_future(transport.open_session())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    proceed.set()
    for _ in range(100):
        if closed:
            break
        await asyncio.sleep(0.02)

    assert closed == [connection]
    assert transport.session_open is False


def test_netmiko_bounds_the_tcp_connect_by_connect_timeout():
    spec = DeviceConnectionSpec(
        host=HOST, port=22, username=USERNAME, password=PASSWORD, connect_timeout=7.0
    )
    params = SSHTransport(spec, host_key_verifier=checks_off())._get_connection_params()

    assert params["timeout"] == 7.0
    assert params["conn_timeout"] == 7.0


async def test_scrapli_closes_a_session_whose_shell_channel_failed(monkeypatch):
    from unittest.mock import AsyncMock, MagicMock

    connection = MagicMock()
    connection.open = AsyncMock(side_effect=OSError("channel refused"))
    monkeypatch.setattr(
        "hegemony_transport_scrapli.transport.AsyncScrapli", MagicMock(return_value=connection)
    )
    transport = ScrapliTransport(_spec(22), host_key_verifier=checks_off())

    with pytest.raises(OSError):
        await transport.open_session()

    connection.transport.close.assert_called_once()
    assert transport.session_open is False


async def test_asyncssh_closes_the_bastion_even_when_closing_is_cancelled():
    from unittest.mock import AsyncMock, MagicMock

    from hegemony_transport_asyncssh.transport import _JUMP_TUNNEL_ATTR, _close_connection

    connection = MagicMock()
    connection.wait_closed = AsyncMock(side_effect=asyncio.CancelledError)
    tunnel = MagicMock()
    tunnel.wait_closed = AsyncMock()
    setattr(connection, _JUMP_TUNNEL_ATTR, tunnel)

    with pytest.raises(asyncio.CancelledError):
        await _close_connection(connection)

    tunnel.close.assert_called_once()
