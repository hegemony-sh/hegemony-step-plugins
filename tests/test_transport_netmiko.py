# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the netmiko device transport wheel.

Covers registration under hegemony.device_transports, spec-based construction,
and config-set result building (regression: the full send_config_set session
output must attach to exactly one result, not every entry equal to the trailing
command).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import hegemony_transport_netmiko
from hegemony_step_sdk import DeviceConnectionSpec
from hegemony_transport_netmiko.transport import SSHTransport, _NullCancellationRegistry


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
    return t


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
    session_output = (
        "configure terminal\n"
        "cml-switch02(config)#vlan 75\n"
        "cml-switch02(config-vlan)#name vlan_75\n"
        "cml-switch02(config-if)#no shutdown\n"
        "cml-switch02(config-if)#end\ncml-switch02#"
    )

    connection = MagicMock()
    connection.send_config_set.return_value = session_output
    connection.find_prompt.return_value = "cml-switch02#"
    connection.send_command.return_value = "Building configuration...\n[OK]"

    with (
        patch.object(
            hegemony_transport_netmiko.transport, "ConnectHandler", return_value=connection
        ),
        patch.object(hegemony_transport_netmiko.transport, "_safe_disconnect"),
    ):
        results = transport._execute_commands_sync(commands)

    assert connection.send_config_set.call_count == 1
    outputs_with_session = [r for r in results if session_output in (r.output or "")]
    assert len(outputs_with_session) == 1
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
    assert all(r.command != "write memory" for r in results)
    assert any(r.command == "vlan 75" and r.exit_code == 1 for r in results)
    assert any((r.error or "") == "% Invalid input detected at '^' marker." for r in results)


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
    assert all(r.command != "write memory" for r in results)
    assert any(r.command == "hostname branch-router" and r.exit_code == -1 for r in results)
    assert any((r.error or "") == "config exploded" for r in results)


# ── Jump host (bastion) hop ──────────────────────────────────────────────────


def _jump_transport() -> SSHTransport:
    from hegemony_step_sdk import JumpHostSpec

    spec = DeviceConnectionSpec(
        host="172.20.30.11",
        username="admin",
        password="device-pw",
        platform="ios-xe",
        jump_host=JumpHostSpec(host="dind", port=2222, username="jump", password="bastion-pw"),
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
