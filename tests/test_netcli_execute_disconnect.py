# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""netcli.execute's Allow disconnect after the last command.

The transports mark a command ``disconnected`` when the device closed the
session while it ran; the step counts that as success for the last command
only, and only with the setting on. The transport tests run against the
in-process SSH device of ``tests/ssh_fakes.py``, whose ``reload`` confirms
and then closes the session.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast

import asyncssh
import pytest

from hegemony_step_sdk import DeviceConnectionSpec, HandlerContext, HandlerServices
from hegemony_step_sdk.cli_prompts import CliPrompt
from hegemony_steps_netcli.execute import ExecuteCLIActionHandler
from hegemony_transport_netmiko.transport import SSHTransport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests.ssh_fakes import PASSWORD, USERNAME, Servers, checks_off, ssh_servers

HOST = "127.0.0.1"
TRANSPORTS = {"netmiko": SSHTransport, "scrapli": ScrapliTransport}
RELOAD_PROMPTS = [CliPrompt(command=r"^reload", expect=r"\[confirm\]")]
DEVICE = {"id": "d1", "name": "sw1", "mgmt_host": "192.0.2.1", "platform": "ios-xe"}


@pytest.fixture
async def servers() -> AsyncIterator[Servers]:
    async with ssh_servers() as started:
        yield started


@pytest.fixture(params=sorted(TRANSPORTS))
def transport_id(request) -> str:
    return request.param


async def _transport(servers: Servers, transport_id: str, timeout: float = 5.0):
    port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
    return TRANSPORTS[transport_id](
        DeviceConnectionSpec(
            host=HOST,
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform="ios-xe",
            connect_timeout=5.0,
            command_timeout=timeout,
        ),
        host_key_verifier=checks_off(),
    )


# --- the transports -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_reload_that_closes_the_session_is_reported(servers, transport_id):
    transport = await _transport(servers, transport_id)
    transport.configure_cli_prompts(RELOAD_PROMPTS)

    results = await transport.execute_commands(["show version", "reload"])

    assert [r.disconnected for r in results] == [False, True]
    assert results[1].exit_code == -1
    assert results[1].error == "The device closed the session"
    # What the device said before it went is kept.
    assert "Reload requested" in results[1].output


@pytest.mark.asyncio
async def test_the_commands_after_a_closed_session_are_skipped(servers, transport_id):
    transport = await _transport(servers, transport_id)
    transport.configure_cli_prompts(RELOAD_PROMPTS)

    results = await transport.execute_commands(["reload", "show version"])

    assert results[0].disconnected is True
    assert results[-1].command == "show version"
    assert results[-1].error == "Skipped: the device closed the session"
    assert results[-1].disconnected is False


@pytest.mark.asyncio
async def test_an_unanswered_question_is_not_a_closed_session(servers, transport_id):
    """The device still waits at [confirm]: the session is open, so it fails as before."""
    transport = await _transport(servers, transport_id, timeout=1.0)

    results = await transport.execute_commands(["reload"])

    assert results[0].disconnected is False
    assert results[0].exit_code == -1


# --- the step -------------------------------------------------------------------------------


def _ctx(config: dict[str, Any], services: Any) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        target_roles=["primary"],
        target_devices_by_role={"primary": [DEVICE]},
        services=cast(HandlerServices, services),
    )


class _RealServices:
    """connect() hands out a real transport to the fake device."""

    def __init__(self, transport: Any) -> None:
        self.transport = transport

    def connect(self, device, *, platform=None, **kwargs):
        return self.transport


def _reload_config(**extra: Any) -> dict[str, Any]:
    return {
        "commands": ["reload"],
        "prompts": [p.model_dump() for p in RELOAD_PROMPTS],
        **extra,
    }


@pytest.mark.asyncio
async def test_with_the_setting_a_reload_succeeds(servers, transport_id):
    services = _RealServices(await _transport(servers, transport_id))

    result = await ExecuteCLIActionHandler().execute(
        _ctx(_reload_config(allow_disconnect_after_last_command=True), services)
    )

    assert result.success is True, result.error
    assert result.output["disconnected"] == ["sw1"]
    assert "1 closed the session after the last command" in (result.summary or "")
    meta = result.evidence[0]["content_json"]
    assert meta["success"] is True and meta["disconnected"] is True
    assert "Reload requested" in result.evidence[0]["content_text"]


@pytest.mark.asyncio
async def test_without_the_setting_a_reload_fails(servers, transport_id):
    services = _RealServices(await _transport(servers, transport_id))

    result = await ExecuteCLIActionHandler().execute(_ctx(_reload_config(), services))

    assert result.success is False
    assert "The device closed the session" in (result.error or "")
    assert result.output["disconnected"] == []


@pytest.mark.asyncio
async def test_a_session_closed_before_the_last_command_fails(servers, transport_id):
    services = _RealServices(await _transport(servers, transport_id))
    config = _reload_config(allow_disconnect_after_last_command=True)
    config["commands"] = ["reload", "show version"]

    result = await ExecuteCLIActionHandler().execute(_ctx(config, services))

    assert result.success is False
    assert result.output["disconnected"] == []


@pytest.mark.asyncio
async def test_blank_lines_after_the_last_command_do_not_count(servers):
    services = _RealServices(await _transport(servers, "netmiko"))
    config = _reload_config(allow_disconnect_after_last_command=True)
    config["commands"] = ["reload", ""]

    result = await ExecuteCLIActionHandler().execute(_ctx(config, services))

    assert result.success is True, result.error
    assert [e["content_json"]["command"] for e in result.evidence] == ["reload"]


@dataclass
class _Result:
    command: str
    output: str = ""
    exit_code: int = 0
    error: str | None = None
    latency_ms: float = 0.0
    disconnected: bool = False


class _ScriptedTransport:
    supports_disconnect_reports = True

    def __init__(self, results: list[_Result]) -> None:
        self.results = results

    async def execute_commands(self, commands):
        return self.results


@pytest.mark.asyncio
async def test_a_device_error_on_the_last_command_still_fails():
    transport = _ScriptedTransport(
        [_Result("reload", "% Invalid input", exit_code=1, error="% Invalid input")]
    )
    result = await ExecuteCLIActionHandler().execute(
        _ctx(
            {"commands": ["reload"], "allow_disconnect_after_last_command": True},
            _RealServices(transport),
        )
    )
    assert result.success is False


@pytest.mark.asyncio
async def test_a_configuration_session_may_end_with_a_reload():
    commands = ["configure terminal", "boot system flash:new.bin", "end", "write memory", "reload"]
    transport = _ScriptedTransport(
        [
            *(_Result(cmd) for cmd in commands[:-1]),
            _Result(
                "reload",
                "Reload requested",
                exit_code=-1,
                error="The device closed the session",
                disconnected=True,
            ),
        ]
    )
    result = await ExecuteCLIActionHandler().execute(
        _ctx(
            {"commands": commands, "allow_disconnect_after_last_command": True},
            _RealServices(transport),
        )
    )
    assert result.success is True, result.error
    assert result.evidence[0]["content_json"]["disconnected"] is True
    assert result.output["disconnected"] == ["sw1"]


@pytest.mark.asyncio
async def test_a_transport_that_cannot_report_a_closed_session_fails_the_step():
    class _OldTransport:
        async def execute_commands(self, commands):
            return [_Result("reload")]

    result = await ExecuteCLIActionHandler().execute(
        _ctx(
            {"commands": ["reload"], "allow_disconnect_after_last_command": True},
            _RealServices(_OldTransport()),
        )
    )
    assert result.success is False
    assert "cannot tell a closed session" in (result.error or "")


def test_the_setting_is_an_advanced_one_and_off_by_default():
    from hegemony_steps_netcli.execute import ExecuteCliConfig

    prop = ExecuteCliConfig.model_json_schema()["properties"]["allow_disconnect_after_last_command"]
    assert prop["default"] is False
    assert prop["x_advanced"] is True


class _QuietScrapliConnection:
    """Just enough of an AsyncScrapli connection for the prompt-answering read loop."""

    def __init__(self, alive: bool) -> None:
        import re
        from types import SimpleNamespace

        self.default_desired_privilege_level = "privilege_exec"
        self.privilege_levels = {
            "privilege_exec": SimpleNamespace(pattern=re.compile(r"^r1#$").pattern)
        }
        self.channel = SimpleNamespace(write=lambda data: None)
        # The device closing the session leaves the stream at EOF.
        self.transport = SimpleNamespace(stdout=SimpleNamespace(at_eof=lambda: not alive))
        self.alive = alive

    async def acquire_priv(self, level):
        return None

    def isalive(self) -> bool:
        return self.alive


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scrapli_closed", "alive", "disconnected"),
    [
        (False, False, True),  # the device closed the session
        (True, False, False),  # scrapli's own timeout closed it
        (False, True, False),  # a read error on a session that is still open
    ],
)
async def test_scrapli_reports_only_a_session_the_device_closed(
    monkeypatch, scrapli_closed, alive, disconnected
):
    transport = ScrapliTransport(
        DeviceConnectionSpec(
            host=HOST, port=22, username=USERNAME, password=PASSWORD, platform="ios-xe"
        ),
        host_key_verifier=checks_off(),
    )
    transport.configure_cli_prompts(RELOAD_PROMPTS)

    async def _read(connection, timeout=None):
        transport._scrapli_closed = scrapli_closed
        return None

    monkeypatch.setattr(transport, "_read_channel_chunk", _read)
    result = await transport._send_exec_command(_QuietScrapliConnection(alive), "reload")

    assert result.disconnected is disconnected
    assert result.exit_code == -1


# --- review follow-ups: what is not a device disconnect ---------------------------------------


class _Registry:
    """Cancellation registry stand-in."""

    def __init__(self, cancelled: bool) -> None:
        self.cancelled = cancelled

    def register(self, key, connection) -> None:
        pass

    def unregister(self, key, connection) -> None:
        pass

    def is_cancelled(self, key) -> bool:
        return self.cancelled


def _netmiko() -> SSHTransport:
    transport = SSHTransport(
        DeviceConnectionSpec(
            host=HOST, port=22, username=USERNAME, password=PASSWORD, platform="ios-xe"
        ),
        host_key_verifier=checks_off(),
    )
    transport.configure_cli_prompts(RELOAD_PROMPTS)
    return transport


@pytest.mark.parametrize(
    ("cancelled", "output", "disconnected", "exit_code"),
    [
        (False, "Reload requested", True, -1),
        (True, "Reload requested", False, -1),  # the run's cancellation closed it
        (False, "% Invalid input detected at '^' marker.", True, 1),  # a device error first
    ],
)
def test_netmiko_reports_a_device_close_only(
    monkeypatch, cancelled, output, disconnected, exit_code
):
    from hegemony_transport_netmiko import transport as netmiko_transport

    transport = _netmiko()
    monkeypatch.setattr(transport, "_cancellation_registry", _Registry(cancelled))

    def _closed(connection, command, prompts):
        transport._command_sent = True  # the command went out, then the session closed
        raise netmiko_transport._SessionClosed(output)

    monkeypatch.setattr(transport, "_send_with_prompts", _closed)
    result = transport._run_exec_command(object(), "reload")

    assert result.disconnected is disconnected
    assert result.exit_code == exit_code


def test_netmiko_keeps_a_read_error_on_an_open_session_a_failure():
    from types import SimpleNamespace

    transport = _netmiko()
    transport._cancellation_registry = _Registry(False)  # type: ignore[assignment]

    def _broken_read():
        raise OSError("read failed")

    open_channel = SimpleNamespace(
        closed=False, eof_received=False, transport=SimpleNamespace(is_active=lambda: True)
    )
    connection = SimpleNamespace(
        find_prompt=lambda: "r1#",
        write_channel=lambda data: None,
        read_channel=_broken_read,
        RETURN="\n",
        remote_conn=open_channel,
    )
    result = transport._run_exec_command(connection, "reload")

    assert result.disconnected is False
    assert "read failed" in (result.error or "")


@pytest.mark.asyncio
async def test_scrapli_does_not_take_a_cancelled_run_for_a_reload(monkeypatch):
    transport = ScrapliTransport(
        DeviceConnectionSpec(
            host=HOST, port=22, username=USERNAME, password=PASSWORD, platform="ios-xe"
        ),
        host_key_verifier=checks_off(),
    )
    transport.configure_cli_prompts(RELOAD_PROMPTS)
    monkeypatch.setattr(transport, "_cancellation_registry", _Registry(True))

    async def _read(connection, timeout=None):
        return None

    monkeypatch.setattr(transport, "_read_channel_chunk", _read)
    result = await transport._send_exec_command(_QuietScrapliConnection(alive=False), "reload")

    assert result.disconnected is False


@pytest.mark.asyncio
async def test_a_device_error_before_the_close_fails_the_step():
    transport = _ScriptedTransport(
        [
            _Result(
                "reload",
                "% Invalid input",
                exit_code=1,
                error="% Invalid input",
                disconnected=True,
            )
        ]
    )
    result = await ExecuteCLIActionHandler().execute(
        _ctx(
            {"commands": ["reload"], "allow_disconnect_after_last_command": True},
            _RealServices(transport),
        )
    )
    assert result.success is False
    assert result.output["disconnected"] == []


def test_netmiko_does_not_take_a_close_before_the_command_was_sent_for_a_reload(monkeypatch):
    """The session closed while the prompt was being found: reload never went out."""
    transport = _netmiko()
    monkeypatch.setattr(transport, "_cancellation_registry", _Registry(False))

    def _no_prompt():
        raise OSError("Socket is closed")

    closed_channel = SimpleNamespace(closed=True, eof_received=True, transport=None)
    connection = SimpleNamespace(
        find_prompt=_no_prompt,
        write_channel=lambda data: None,
        read_channel=lambda: "",
        RETURN="\n",
        remote_conn=closed_channel,
    )
    result = transport._run_exec_command(connection, "reload")

    assert result.disconnected is False
    assert result.exit_code == -1


@pytest.mark.asyncio
async def test_scrapli_does_not_take_a_close_before_the_command_was_sent_for_a_reload(
    monkeypatch,
):
    transport = ScrapliTransport(
        DeviceConnectionSpec(
            host=HOST, port=22, username=USERNAME, password=PASSWORD, platform="ios-xe"
        ),
        host_key_verifier=checks_off(),
    )
    transport.configure_cli_prompts(RELOAD_PROMPTS)
    monkeypatch.setattr(transport, "_cancellation_registry", _Registry(False))
    connection = _QuietScrapliConnection(alive=False)

    async def _closed_priv(level):
        raise ConnectionError("transport at EOF; no more data to be read")

    monkeypatch.setattr(connection, "acquire_priv", _closed_priv)
    result = await transport._send_exec_command(connection, "reload")

    assert result.disconnected is False


@pytest.mark.asyncio
async def test_scrapli_forgets_an_earlier_connections_timeout(monkeypatch):
    transport = ScrapliTransport(
        DeviceConnectionSpec(
            host=HOST, port=22, username=USERNAME, password=PASSWORD, platform="ios-xe"
        ),
        host_key_verifier=checks_off(),
    )
    transport._scrapli_closed = True

    class _Opened(Exception):
        pass

    def _stop(*args, **kwargs):
        raise _Opened

    from hegemony_transport_scrapli import transport as scrapli_transport

    monkeypatch.setattr(scrapli_transport, "AsyncScrapli", _stop)
    with pytest.raises(Exception):  # noqa: B017 - only the reset before opening matters
        await transport._open_connection()
    assert transport._scrapli_closed is False


@pytest.mark.asyncio
async def test_without_a_prompts_entry_a_close_is_never_the_commands(servers, transport_id):
    """send_command drops what it read when the session closes, so the step
    could not see a device error: the close fails the command."""
    transport = await _transport(servers, transport_id, timeout=2.0)

    results = await transport.execute_commands(["bad-reload"])

    assert results[0].disconnected is False


@pytest.mark.asyncio
async def test_a_prompts_entry_keeps_a_device_error_printed_before_the_close(servers, transport_id):
    transport = await _transport(servers, transport_id)
    # The question never comes; the entry only routes the command through
    # the read loop that keeps its output.
    transport.configure_cli_prompts([CliPrompt(command=r"^bad-reload", expect=r"\[confirm\]")])

    results = await transport.execute_commands(["bad-reload"])

    assert results[0].disconnected is True
    assert results[0].exit_code == 1
    assert "Invalid input" in results[0].output


_ERROR_THEN_QUESTION = "% Invalid input detected at '^' marker.\nProceed with reload? [confirm]"


def test_netmiko_keeps_a_device_error_when_the_answer_cannot_be_written(monkeypatch):
    transport = _netmiko()
    monkeypatch.setattr(transport, "_cancellation_registry", _Registry(False))
    writes: list[str] = []

    def _write(data: str) -> None:
        writes.append(data)
        if len(writes) > 1:  # the command goes out; the answer meets a closed session
            raise OSError("Socket is closed")

    connection = SimpleNamespace(
        find_prompt=lambda: "r1#",
        write_channel=_write,
        read_channel=lambda: _ERROR_THEN_QUESTION,
        RETURN="\n",
        remote_conn=SimpleNamespace(closed=True, eof_received=True, transport=None),
    )
    result = transport._run_exec_command(connection, "reload")

    assert result.disconnected is True
    assert result.exit_code == 1  # the device error keeps it failed
    assert "Invalid input" in result.output


@pytest.mark.asyncio
async def test_scrapli_keeps_a_device_error_when_the_answer_cannot_be_written(monkeypatch):
    transport = ScrapliTransport(
        DeviceConnectionSpec(
            host=HOST, port=22, username=USERNAME, password=PASSWORD, platform="ios-xe"
        ),
        host_key_verifier=checks_off(),
    )
    transport.configure_cli_prompts(RELOAD_PROMPTS)
    monkeypatch.setattr(transport, "_cancellation_registry", _Registry(False))
    connection = _QuietScrapliConnection(alive=False)
    writes: list[str] = []

    def _write(data: str) -> None:
        writes.append(data)
        if len(writes) > 1:
            raise ConnectionError("transport closed")

    connection.channel = SimpleNamespace(write=_write)

    async def _read(conn, timeout=None):
        return _ERROR_THEN_QUESTION

    monkeypatch.setattr(transport, "_read_channel_chunk", _read)
    result = await transport._send_exec_command(connection, "reload")

    assert result.disconnected is True
    assert result.exit_code == 1
    assert "Invalid input" in result.output
