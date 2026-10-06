# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the netmiko device transport wheel.

Covers registration under hegemony.device_transports, spec-based construction,
and config-set result building (regression: the full send_config_set session
output must attach to exactly one result, not every entry equal to the trailing
command), and how a config command set runs: `exit` stays inside its block,
blocks and exec commands run in the order written, config lines go out one at
a time, and nothing runs after the first failure (a rejected config line
included) or a cancellation.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
from netmiko.exceptions import ReadTimeout

import hegemony_transport_netmiko
from hegemony_step_sdk import DeviceConnectionSpec
from hegemony_transport_netmiko.transport import (
    _CANCELLED_ERROR,
    _SKIPPED_ERROR,
    SSHTransport,
    _NullCancellationRegistry,
)


def test_register_registers_the_netmiko_transport():
    registered: list[type] = []

    class _Registry:
        def register_transport(self, transport_class: type) -> None:
            registered.append(transport_class)

    hegemony_transport_netmiko.register(_Registry())
    assert registered == [SSHTransport]
    assert SSHTransport.transport_id == "netmiko"


def test_construct_from_spec_resolves_fields():
    spec = DeviceConnectionSpec(
        host="10.0.0.1",
        port=2022,
        username="admin",
        password="pw",
        enable_secret="en",
        platform="ios-xe",
    )
    with patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", MagicMock()):
        t = SSHTransport(spec)
    assert t.host == "10.0.0.1"
    assert t.port == 2022
    assert t.username == "admin"
    assert t.device_type == "cisco_ios"
    assert isinstance(t._cancellation_registry, _NullCancellationRegistry)


def test_construct_requires_username():
    import pytest

    spec = DeviceConnectionSpec(host="10.0.0.1", username="")
    with (
        patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", MagicMock()),
        pytest.raises(ValueError, match="username"),
    ):
        SSHTransport(spec)


def _make_transport() -> SSHTransport:
    """Build an SSHTransport without running the connecting __init__."""
    t = SSHTransport.__new__(SSHTransport)
    t.host = "10.0.0.1"
    t.port = 22
    t.platform = "ios-xe"
    t.device_type = "cisco_ios"
    t.username = "admin"
    t.password = "pw"
    t.secret = ""
    t.connect_timeout = 10.0
    t.command_timeout = 30.0
    t.step_run_id = None
    t.jump_host = None
    t._cancellation_registry = _NullCancellationRegistry()
    t._output_sink = None
    t.streams_timing_output = False
    return t


def _echo_config_lines(lines, **kwargs):
    """send_config_set stand-in: echo each line after a config prompt."""
    return "".join(f"sw(config)#{line}\n" for line in lines)


def test_config_set_output_not_duplicated_with_blank_lines():
    transport = _make_transport()

    commands = [
        "configure terminal",
        "vlan 75",
        "name vlan_75",
        "",
        "interface Vlan 75",
        "no shutdown",
        "",
        "end",
        "write memory",
    ]
    session_output = "".join(_echo_config_lines([line]) for line in commands[1:7])

    connection = MagicMock()
    connection.send_config_set.side_effect = _echo_config_lines
    connection.find_prompt.return_value = "cml-switch02#"
    connection.send_command.return_value = "Building configuration...\n[OK]"

    with (
        patch.object(
            hegemony_transport_netmiko.transport, "ConnectHandler", return_value=connection
        ),
        patch.object(hegemony_transport_netmiko.transport, "_safe_disconnect"),
    ):
        results = transport._execute_commands_sync(commands)

    # One call per line, blank lines included, and the block's transcript
    # lands on exactly one result.
    assert connection.send_config_set.call_count == 6
    outputs_with_session = [r for r in results if session_output in (r.output or "")]
    assert len(outputs_with_session) == 1
    assert sum((r.output or "").count("vlan 75\n") for r in results) == 1
    assert connection.send_command.call_count == 1
    write_results = [r for r in results if r.command == "write memory"]
    assert len(write_results) == 1
    assert "Building configuration" in (write_results[0].output or "")


def test_config_set_cli_error_skips_post_commands():
    transport = _make_transport()
    commands = ["configure terminal", "vlan 75", "end", "write memory"]
    session_output = (
        "configure terminal\n"
        "router(config)#vlan 75\n"
        "% Invalid input detected at '^' marker.\n"
        "router(config)#end\nrouter#"
    )
    connection = MagicMock()
    connection.send_config_set.return_value = session_output
    connection.find_prompt.return_value = "router#"

    with (
        patch.object(
            hegemony_transport_netmiko.transport, "ConnectHandler", return_value=connection
        ),
        patch.object(hegemony_transport_netmiko.transport, "_safe_disconnect"),
    ):
        results = transport._execute_commands_sync(commands)

    assert connection.send_command.call_count == 0
    assert [r.command for r in results] == commands
    assert any(r.command == "vlan 75" and r.exit_code == 1 for r in results)
    assert any((r.error or "") == "% Invalid input detected at '^' marker." for r in results)
    # The save after the failed block is reported as not run, not left out.
    assert (results[-1].exit_code, results[-1].error) == (-1, _SKIPPED_ERROR)


def test_config_set_exception_skips_post_commands():
    transport = _make_transport()
    commands = ["configure terminal", "hostname branch-router", "end", "write memory"]
    connection = MagicMock()
    connection.send_config_set.side_effect = RuntimeError("config exploded")
    connection.find_prompt.return_value = "router#"

    with (
        patch.object(
            hegemony_transport_netmiko.transport, "ConnectHandler", return_value=connection
        ),
        patch.object(hegemony_transport_netmiko.transport, "_safe_disconnect"),
    ):
        results = transport._execute_commands_sync(commands)

    assert connection.send_command.call_count == 0
    assert any(r.command == "hostname branch-router" and r.exit_code == -1 for r in results)
    assert any((r.error or "") == "config exploded" for r in results)
    assert (results[-1].command, results[-1].error) == ("write memory", _SKIPPED_ERROR)


def _run_on_connection(commands: list[str], connection: MagicMock):
    transport = _make_transport()
    with (
        patch.object(
            hegemony_transport_netmiko.transport, "ConnectHandler", return_value=connection
        ),
        patch.object(hegemony_transport_netmiko.transport, "_safe_disconnect"),
    ):
        return transport._execute_commands_sync(commands)


def test_exit_inside_a_config_block_is_sent_as_a_config_line():
    # Only `end` closes a config block. An ` exit` that leaves an interface
    # sub-mode used to end the block, so the rest of it ran at the exec prompt.
    commands = [
        "configure terminal",
        "interface GigabitEthernet1",
        " description uplink",
        " exit",
        "interface GigabitEthernet2",
        " no shutdown",
        "end",
        "write memory",
    ]
    connection = MagicMock()
    connection.send_config_set.return_value = "r1(config)#"
    connection.send_command.return_value = "Building configuration...\n[OK]"

    results = _run_on_connection(commands, connection)

    sent = [c.args[0] for c in connection.send_config_set.call_args_list]
    assert sent == [[line] for line in commands[1:6]]
    assert [c.args[0] for c in connection.send_command.call_args_list] == ["write memory"]
    assert [r.command for r in results] == commands
    assert all(r.exit_code == 0 for r in results)


def test_failed_post_command_fails_and_skips_the_rest():
    commands = [
        "configure terminal",
        "hostname r1",
        "end",
        "show bork",
        "write memory",
    ]
    connection = MagicMock()
    connection.send_config_set.return_value = "r1(config)#end\nr1#"
    connection.send_command.return_value = "        ^\n% Invalid input detected at '^' marker."

    results = _run_on_connection(commands, connection)

    assert connection.send_command.call_count == 1
    assert [r.command for r in results] == commands
    bork = results[3]
    assert bork.exit_code == 1
    assert bork.error == "% Invalid input detected at '^' marker."
    assert (results[4].exit_code, results[4].error) == (-1, _SKIPPED_ERROR)


def test_config_blocks_and_exec_commands_run_in_written_order():
    commands = [
        "configure terminal",
        "hostname r1",
        "end",
        "show clock",
        "conf t",
        "ntp server 192.0.2.5",
        "end",
        "write memory",
    ]
    calls: list[tuple[str, object]] = []
    connection = MagicMock()

    def send_config_set(lines, **kwargs):
        calls.append(("config", list(lines)))
        return "r1(config)#end\nr1#"

    def send_command(command, **kwargs):
        calls.append(("exec", command))
        return "ok"

    connection.send_config_set.side_effect = send_config_set
    connection.send_command.side_effect = send_command

    results = _run_on_connection(commands, connection)

    assert calls == [
        ("config", ["hostname r1"]),
        ("exec", "show clock"),
        ("config", ["ntp server 192.0.2.5"]),
        ("exec", "write memory"),
    ]
    assert [r.command for r in results] == commands
    assert all(r.exit_code == 0 for r in results)


def test_a_leading_blank_line_keeps_the_configuration_session():
    # A blank first line, which a template easily leaves, used to make the
    # list a show/exec list: the config lines ran one by one at the exec
    # prompt, and the save after them ran even when one of them failed.
    commands = ["", "  ", "configure terminal", "hostname r1", "end", "write memory"]
    connection = MagicMock()
    connection.read_channel.return_value = ""
    connection.send_config_set.return_value = "% Invalid input detected at '^' marker."

    results = _run_on_connection(commands, connection)

    assert [c.args[0] for c in connection.send_config_set.call_args_list] == [["hostname r1"]]
    assert connection.send_command.call_count == 0
    assert [r.command for r in results] == commands
    assert (results[3].exit_code, results[-1].error) == (1, _SKIPPED_ERROR)


def test_a_rejected_config_line_stops_its_block():
    # A config set used to be written to the device in one go, so the lines
    # after a rejected one were applied all the same.
    commands = [
        "configure terminal",
        "interface GigabitEthernet1",
        " ip address 10.0.0.1",
        " no shutdown",
        "end",
        "write memory",
    ]

    def send_config_set(lines, **kwargs):
        if lines == [" ip address 10.0.0.1"]:
            return " ip address 10.0.0.1\n% Incomplete command.\n\nr1(config-if)#"
        return f"{lines[0]}\nr1(config-if)#"

    connection = MagicMock()
    connection.send_config_set.side_effect = send_config_set

    results = _run_on_connection(commands, connection)

    sent = [c.args[0] for c in connection.send_config_set.call_args_list]
    assert sent == [["interface GigabitEthernet1"], [" ip address 10.0.0.1"]]
    assert connection.send_command.call_count == 0
    assert [(r.command, r.exit_code, r.error) for r in results] == [
        ("configure terminal", 0, None),
        ("interface GigabitEthernet1", 0, None),
        (" ip address 10.0.0.1", 1, "% Incomplete command."),
        (" no shutdown", -1, _SKIPPED_ERROR),
        ("end", -1, _SKIPPED_ERROR),
        ("write memory", -1, _SKIPPED_ERROR),
    ]
    # The transcript of what ran goes on the line that failed.
    assert "% Incomplete command." in results[2].output
    assert "interface GigabitEthernet1" in results[2].output


def test_config_mode_is_entered_before_the_first_line_and_left_after_the_last():
    commands = ["configure terminal", "hostname r1", "ip domain-name lab", "ntp server 192.0.2.5"]
    connection = MagicMock()
    connection.send_config_set.return_value = "r1(config)#"

    _run_on_connection(commands, connection)

    calls = connection.send_config_set.call_args_list
    assert [c.args[0] for c in calls] == [[line] for line in commands[1:]]
    # Like one config set: enter before the first line, leave after the last.
    assert [
        (c.kwargs.get("enter_config_mode", True), c.kwargs.get("exit_config_mode", True))
        for c in calls
    ] == [(True, False), (False, False), (False, True)]
    # Each line's echo and prompt are checked, within the command timeout.
    assert all(c.kwargs["cmd_verify"] is True for c in calls)
    assert all(c.kwargs["read_timeout"] == 30.0 for c in calls)


def test_a_block_with_banner_text_is_sent_without_echo_checks():
    # Banner text lines get no prompt back, so waiting for one after each
    # line would time out: like netmiko's own bypass for a banner, the whole
    # block is sent without echo checks.
    commands = [
        "configure terminal",
        "hostname r1",
        "banner motd ^",
        "Authorised access only",
        "^",
        "end",
    ]
    connection = MagicMock()
    connection.send_config_set.return_value = "r1(config)#"

    results = _run_on_connection(commands, connection)

    calls = connection.send_config_set.call_args_list
    assert len(calls) == 4
    assert all(c.kwargs["cmd_verify"] is False for c in calls)
    assert all(r.exit_code == 0 for r in results)


def test_a_config_line_timeout_does_not_repeat_the_line_in_its_error():
    # netmiko's ReadTimeout names the pattern it waited for, the escaped
    # line itself; escaped, a secret would slip past the host's redaction.
    from netmiko.exceptions import ReadTimeout

    secret_line = "username admin secret Very.Secret-Value"
    connection = MagicMock()
    connection.send_config_set.side_effect = ReadTimeout(
        "Pattern not detected: 'username\\ admin\\ secret\\ Very\\.Secret\\-Value'"
    )

    results = _run_on_connection(["configure terminal", secret_line, "end"], connection)

    failed = results[1]
    assert (failed.command, failed.exit_code) == (secret_line, -1)
    assert failed.error == "Timed out after 30 seconds reading the device's answer"
    assert "Secret" not in (failed.error or "")


class _Cancellation(_NullCancellationRegistry):
    """Cancellation registry whose run is cancelled once ``cancelled`` is set."""

    def __init__(self) -> None:
        self.cancelled = False

    def is_cancelled(self, key: str | None) -> bool:
        return self.cancelled


def test_commands_after_a_cancellation_say_the_run_was_cancelled():
    cancellation = _Cancellation()

    def send_config_set(lines, **kwargs):
        # Cancelling the run closes the session under the running config set.
        cancellation.cancelled = True
        raise OSError("Socket is closed")

    connection = MagicMock()
    connection.send_config_set.side_effect = send_config_set
    commands = ["configure terminal", "hostname r1", "end", "show clock", "write memory"]

    transport = _make_transport()
    transport.step_run_id = "sr-1"
    transport._cancellation_registry = cancellation
    with (
        patch.object(
            hegemony_transport_netmiko.transport, "ConnectHandler", return_value=connection
        ),
        patch.object(hegemony_transport_netmiko.transport, "_safe_disconnect"),
    ):
        results = transport._execute_commands_sync(commands)

    assert connection.send_command.call_count == 0
    assert [(r.command, r.exit_code, r.error) for r in results] == [
        ("configure terminal", 0, None),
        ("hostname r1", -1, "Socket is closed"),
        ("end", -1, _CANCELLED_ERROR),
        ("show clock", -1, _CANCELLED_ERROR),
        ("write memory", -1, _CANCELLED_ERROR),
    ]


async def test_execute_step_fails_when_a_post_command_fails():
    """End to end: netcli.execute over this transport reports the failure."""
    from typing import cast

    from hegemony_step_sdk import HandlerContext, HandlerServices
    from hegemony_steps_netcli.execute import ExecuteCLIActionHandler

    transport = _make_transport()
    connection = MagicMock()
    connection.send_config_set.return_value = "r1(config)#end\nr1#"
    connection.send_command.return_value = "        ^\n% Invalid input detected at '^' marker."

    class _Services:
        def connect(self, device, **kwargs):
            return transport

    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"commands": ["configure terminal", "hostname r1", "end", "write mem"]},
        target_roles=["primary"],
        target_devices_by_role={"primary": [{"id": "d1", "name": "r1", "mgmt_host": "192.0.2.1"}]},
        services=cast(HandlerServices, _Services()),
    )
    with (
        patch.object(
            hegemony_transport_netmiko.transport, "ConnectHandler", return_value=connection
        ),
        patch.object(hegemony_transport_netmiko.transport, "_safe_disconnect"),
    ):
        result = await ExecuteCLIActionHandler().execute(ctx)

    assert result.success is False
    assert "% Invalid input detected" in (result.error or "")
    assert result.evidence[0]["content_json"]["success"] is False


# ── Command text stays out of the logs ──────────────────────────────────────

#: Stands for a value a step rendered from {{ secret(...) }}: the platform has
#: no log redaction, so command text must never reach a log message.
_SECRET = "Sw0rdfish-42.x"


def _send_command(output: str | Exception):
    def send_command(command, **kwargs):
        if isinstance(output, Exception):
            raise output
        return output

    return send_command


@pytest.mark.parametrize(
    "outcome",
    [
        f"{_SECRET} ok",
        f"show {_SECRET}\n% Invalid input detected at '^' marker.",
        ReadTimeout(f"Pattern not detected: 'show\\ {_SECRET}'"),
    ],
    ids=["success", "cli-error", "exception"],
)
def test_exec_commands_are_not_logged(caplog, outcome):
    caplog.set_level(logging.DEBUG)
    connection = MagicMock()
    connection.send_command.side_effect = _send_command(outcome)

    _run_on_connection([f"show running-config | include {_SECRET}"], connection)

    assert caplog.records
    assert _SECRET not in caplog.text


@pytest.mark.parametrize(
    "outcome",
    [
        f"r1(config)#username admin secret {_SECRET}\nr1(config)#",
        f"username admin secret {_SECRET}\n% Invalid input detected at '^' marker.",
        ReadTimeout(f"Pattern not detected: 'username\\ admin\\ secret\\ {_SECRET}'"),
    ],
    ids=["success", "cli-error", "exception"],
)
def test_config_lines_are_not_logged(caplog, outcome):
    caplog.set_level(logging.DEBUG)
    connection = MagicMock()
    connection.send_config_set.side_effect = _send_command(outcome)
    connection.send_command.return_value = "[OK]"

    _run_on_connection(
        ["configure terminal", f"username admin secret {_SECRET}", "end", "write memory"],
        connection,
    )

    assert caplog.records
    assert _SECRET not in caplog.text


def _run_timing(connection: MagicMock, command: str, **kwargs):
    transport = _make_transport()
    with (
        patch.object(
            hegemony_transport_netmiko.transport, "ConnectHandler", return_value=connection
        ),
        patch.object(hegemony_transport_netmiko.transport, "_safe_disconnect"),
        patch.object(hegemony_transport_netmiko.transport.time, "sleep"),
    ):
        return transport._execute_command_timing_sync(command, **kwargs)


def test_timing_commands_and_answers_are_not_logged(caplog):
    caplog.set_level(logging.DEBUG)
    connection = MagicMock()
    connection.send_command_timing.return_value = f"{_SECRET}\nPassword:"
    # The device echoes the answer back before the awaited pattern.
    connection.read_channel.side_effect = [f"{_SECRET}\n", "Install done"]

    result = _run_timing(
        connection,
        f"install add file flash:{_SECRET}.bin",
        read_timeout=60.0,
        answers={"Password:": _SECRET},
        wait_for_patterns=["Install done"],
    )

    assert result.exit_code == 0
    assert caplog.records
    assert _SECRET not in caplog.text


def test_failed_timing_commands_are_not_logged(caplog):
    caplog.set_level(logging.DEBUG)
    connection = MagicMock()
    connection.send_command_timing.side_effect = ReadTimeout(f"no prompt after {_SECRET}")

    result = _run_timing(connection, f"install add file flash:{_SECRET}.bin")

    assert result.exit_code == -1
    assert caplog.records
    assert _SECRET not in caplog.text


def test_http_transfer_url_is_not_logged(caplog):
    caplog.set_level(logging.DEBUG)
    url = f"https://files.example.test/a/{_SECRET}/image.bin"
    connection = MagicMock()
    connection.read_channel.return_value = f"copy {url} flash:image.bin\n%Error opening {url}"
    transport = _make_transport()

    with (
        patch.object(
            hegemony_transport_netmiko.transport, "ConnectHandler", return_value=connection
        ),
        patch.object(hegemony_transport_netmiko.transport, "_safe_disconnect"),
        patch.object(hegemony_transport_netmiko.transport.time, "sleep"),
    ):
        result = transport._http_transfer_sync(
            url=url, dest_fs="flash:", dest_filename="image.bin", timeout_seconds=10
        )

    assert result["transferred"] is False
    assert caplog.records
    assert _SECRET not in caplog.text


# ── Jump host (bastion) hop ──────────────────────────────────────────────────


def _jump_transport(*, private_key: str = "") -> SSHTransport:
    from hegemony_step_sdk import JumpHostSpec

    spec = DeviceConnectionSpec(
        host="172.20.30.11",
        username="admin",
        password="device-pw",
        platform="ios-xe",
        jump_host=JumpHostSpec(
            host="dind",
            port=2222,
            username="jump",
            password="bastion-pw",
            private_key=private_key,
        ),
    )
    with patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", MagicMock()):
        return SSHTransport(spec)


def test_connect_device_tunnels_through_the_bastion_channel():
    """ProxyJump parity: paramiko session #1, device session on its channel."""
    transport = _jump_transport()

    channel = MagicMock(name="direct-tcpip-channel")
    bastion_client = MagicMock()
    bastion_client.get_transport.return_value.open_channel.return_value = channel
    paramiko_mock = MagicMock()
    paramiko_mock.SSHClient.return_value = bastion_client
    connect_handler = MagicMock()

    with (
        patch.object(hegemony_transport_netmiko.transport, "paramiko", paramiko_mock),
        patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", connect_handler),
    ):
        connection = transport._connect_device()

    # Session #1: bastion endpoint with bastion credentials only.
    bastion_kwargs = bastion_client.connect.call_args.kwargs
    assert bastion_client.connect.call_args.args == ("dind",)
    assert bastion_kwargs["port"] == 2222
    assert bastion_kwargs["username"] == "jump"
    assert bastion_kwargs["password"] == "bastion-pw"
    assert "device-pw" not in repr(bastion_kwargs)

    # The direct-tcpip channel targets the device and feeds netmiko's sock=.
    open_channel = bastion_client.get_transport.return_value.open_channel
    assert open_channel.call_args.args[0] == "direct-tcpip"
    assert open_channel.call_args.args[1] == ("172.20.30.11", 22)
    device_kwargs = connect_handler.call_args.kwargs
    assert device_kwargs["sock"] is channel
    assert device_kwargs["password"] == "device-pw"
    assert "bastion-pw" not in repr(device_kwargs)

    # The bastion client rides the connection for _safe_disconnect teardown.
    from hegemony_transport_netmiko.transport import _JUMP_CLIENT_ATTR, _safe_disconnect

    assert getattr(connection, _JUMP_CLIENT_ATTR) is bastion_client
    _safe_disconnect(connection)
    bastion_client.close.assert_called()


def test_bastion_is_closed_after_the_device_session_it_carries():
    # The device socket is a direct-tcpip channel of the bastion transport.
    # Closing the bastion first pulls that channel away before the device
    # shutdown below runs, leaving the device session for the peer to time out
    # instead of closing it cleanly.
    from hegemony_transport_netmiko.transport import _JUMP_CLIENT_ATTR, _safe_disconnect

    order: list[str] = []
    bastion_client = MagicMock()
    bastion_client.close.side_effect = lambda: order.append("bastion")

    connection = MagicMock()
    connection.remote_conn_pre.sock.shutdown.side_effect = lambda *_: order.append("device-sock")
    connection.remote_conn_pre.close.side_effect = lambda: order.append("device-transport")
    connection.remote_conn.close.side_effect = lambda: order.append("device-channel")
    setattr(connection, _JUMP_CLIENT_ATTR, bastion_client)

    _safe_disconnect(connection)

    assert order[-1] == "bastion", order
    assert "device-sock" in order and "device-channel" in order


def test_bastion_is_still_closed_when_the_device_teardown_explodes():
    from hegemony_transport_netmiko.transport import _JUMP_CLIENT_ATTR, _safe_disconnect

    bastion_client = MagicMock()
    connection = MagicMock()
    connection.remote_conn_pre.sock.shutdown.side_effect = RuntimeError("already dead")
    setattr(connection, _JUMP_CLIENT_ATTR, bastion_client)

    _safe_disconnect(connection)

    bastion_client.close.assert_called_once()


def test_connect_timeout_is_one_budget_across_both_hops():
    # connect_timeout is the budget for reaching the device, not a per-hop
    # allowance: charging it separately to the bastion login, the direct-tcpip
    # channel and the device login turns a 30 s setting into 90 s of waiting.
    transport = _jump_transport()
    transport.connect_timeout = 30.0

    channel = MagicMock(name="direct-tcpip-channel")
    bastion_client = MagicMock()
    bastion_client.get_transport.return_value.open_channel.return_value = channel
    # The bastion login eats 20 of the 30 seconds.
    clock = iter([100.0, 120.0, 120.0])
    paramiko_mock = MagicMock()
    paramiko_mock.SSHClient.return_value = bastion_client
    connect_handler = MagicMock()

    with (
        patch.object(hegemony_transport_netmiko.transport, "paramiko", paramiko_mock),
        patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", connect_handler),
        patch.object(
            hegemony_transport_netmiko.transport.time, "perf_counter", lambda: next(clock)
        ),
    ):
        transport._connect_device()

    open_channel = bastion_client.get_transport.return_value.open_channel
    assert open_channel.call_args.kwargs["timeout"] == 10.0
    assert connect_handler.call_args.kwargs["timeout"] == 10.0


def test_connect_budget_floors_rather_than_going_to_zero():
    # A bastion that ate the whole budget must still surface as a *device*
    # connect timeout, not an instant zero-timeout failure that hides the hop.
    transport = _jump_transport()
    transport.connect_timeout = 5.0

    bastion_client = MagicMock()
    bastion_client.get_transport.return_value.open_channel.return_value = MagicMock()
    clock = iter([100.0, 400.0, 400.0])
    paramiko_mock = MagicMock()
    paramiko_mock.SSHClient.return_value = bastion_client
    connect_handler = MagicMock()

    with (
        patch.object(hegemony_transport_netmiko.transport, "paramiko", paramiko_mock),
        patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", connect_handler),
        patch.object(
            hegemony_transport_netmiko.transport.time, "perf_counter", lambda: next(clock)
        ),
    ):
        transport._connect_device()

    assert connect_handler.call_args.kwargs["timeout"] == 1.0


def test_connect_device_without_jump_passes_no_sock():
    transport = _make_transport()
    connect_handler = MagicMock()
    with patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", connect_handler):
        transport._connect_device()
    assert "sock" not in connect_handler.call_args.kwargs


def test_connect_device_closes_bastion_when_device_connect_fails():
    transport = _jump_transport()

    bastion_client = MagicMock()
    bastion_client.get_transport.return_value.open_channel.return_value = MagicMock()
    paramiko_mock = MagicMock()
    paramiko_mock.SSHClient.return_value = bastion_client
    connect_handler = MagicMock(side_effect=OSError("connection refused"))

    import pytest

    with (
        patch.object(hegemony_transport_netmiko.transport, "paramiko", paramiko_mock),
        patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", connect_handler),
        pytest.raises(OSError, match="connection refused"),
    ):
        transport._connect_device()

    bastion_client.close.assert_called()


# ── Bastion private-key loading ──────────────────────────────────────────────


def test_jump_private_key_is_parsed_and_presented_to_the_bastion():
    # _load_jump_private_key tries Ed25519/ECDSA/RSA with every failure
    # suppressed, so a silent regression there degrades to password-only auth
    # without any test noticing. Assert the parsed key reaches client.connect.
    transport = _jump_transport(private_key="-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")

    bastion_client = MagicMock()
    bastion_client.get_transport.return_value.open_channel.return_value = MagicMock()
    paramiko_mock = MagicMock()
    paramiko_mock.SSHClient.return_value = bastion_client
    parsed = object()
    paramiko_mock.Ed25519Key.from_private_key.return_value = parsed

    with (
        patch.object(hegemony_transport_netmiko.transport, "paramiko", paramiko_mock),
        patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", MagicMock()),
    ):
        transport._connect_device()

    kwargs = bastion_client.connect.call_args.kwargs
    assert kwargs["pkey"] is parsed
    # An explicit key means exactly that key — an agent or an on-disk identity
    # silently standing in for the configured credential is not acceptable.
    assert kwargs["allow_agent"] is False
    assert kwargs["look_for_keys"] is False


def test_unparsable_jump_private_key_raises_a_clear_error():
    transport = _jump_transport(private_key="not a key")

    paramiko_mock = MagicMock()
    for name in ("Ed25519Key", "ECDSAKey", "RSAKey"):
        getattr(paramiko_mock, name).from_private_key.side_effect = ValueError("nope")

    import pytest

    with (
        patch.object(hegemony_transport_netmiko.transport, "paramiko", paramiko_mock),
        pytest.raises(ValueError, match="unsupported jump-host private key format"),
    ):
        transport._load_jump_private_key("not a key")


def test_agent_and_default_keys_are_used_when_no_key_is_configured():
    # Parity with the asyncssh transport, which now omits client_keys so the
    # agent and default identities still apply. Pinning allow_agent=False here
    # unconditionally made a bastion reachable only by agent key unreachable.
    transport = _jump_transport()

    bastion_client = MagicMock()
    bastion_client.get_transport.return_value.open_channel.return_value = MagicMock()
    paramiko_mock = MagicMock()
    paramiko_mock.SSHClient.return_value = bastion_client

    with (
        patch.object(hegemony_transport_netmiko.transport, "paramiko", paramiko_mock),
        patch.object(hegemony_transport_netmiko.transport, "ConnectHandler", MagicMock()),
    ):
        transport._connect_device()

    kwargs = bastion_client.connect.call_args.kwargs
    assert kwargs["pkey"] is None
    assert kwargs["allow_agent"] is True
    assert kwargs["look_for_keys"] is True
