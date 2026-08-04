# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the scrapli device transport wheel.

Covers registration under hegemony.device_transports, spec-based construction
and platform mapping, show/config execution paths (per-response result
mapping, post-command skip on config failure), timing-mode prompt answering,
and the explicit NotImplementedError staging seam.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from scrapli.exceptions import ScrapliAuthenticationFailed, ScrapliTimeout

import hegemony_transport_scrapli
from hegemony_step_sdk import DeviceConnectionSpec
from hegemony_transport_scrapli.transport import (
    ScrapliTransport,
    _NullCancellationRegistry,
)


def test_register_registers_the_scrapli_transport():
    registered: list[type] = []

    class _Registry:
        def register_transport(self, transport_class: type) -> None:
            registered.append(transport_class)

    hegemony_transport_scrapli.register(_Registry())
    assert registered == [ScrapliTransport]
    assert ScrapliTransport.transport_id == "scrapli"


def test_construct_from_spec_maps_platform():
    spec = DeviceConnectionSpec(
        host="10.0.0.1",
        port=2022,
        username="admin",
        password="pw",
        enable_secret="en",
        platform="ios-xr",
    )
    t = ScrapliTransport(spec)
    assert t.host == "10.0.0.1"
    assert t.port == 2022
    assert t.username == "admin"
    assert t.scrapli_platform == "cisco_iosxr"
    assert isinstance(t._cancellation_registry, _NullCancellationRegistry)
    # auth_secondary only present when an enable secret is set; asyncssh backend
    params = t._get_connection_params()
    assert params["auth_secondary"] == "en"
    assert params["transport"] == "asyncssh"


def test_construct_unknown_platform_defaults_to_iosxe():
    spec = DeviceConnectionSpec(host="10.0.0.1", username="admin", platform="weirdos")
    assert ScrapliTransport(spec).scrapli_platform == "cisco_iosxe"


def test_construct_requires_username():
    spec = DeviceConnectionSpec(host="10.0.0.1", username="")
    with pytest.raises(ValueError, match="username"):
        ScrapliTransport(spec)


def _make_transport() -> ScrapliTransport:
    spec = DeviceConnectionSpec(host="10.0.0.1", username="admin", password="pw")
    return ScrapliTransport(spec)


def _response(result: str = "", failed: bool = False, elapsed: float = 0.01) -> MagicMock:
    response = MagicMock()
    response.result = result
    response.failed = failed
    response.elapsed_time = elapsed
    return response


def _connection() -> MagicMock:
    connection = MagicMock()
    connection.open = AsyncMock()
    connection.close = AsyncMock()
    connection.send_command = AsyncMock()
    connection.send_configs = AsyncMock()
    connection.channel.write = MagicMock()
    return connection


async def test_show_commands_map_to_per_command_results():
    transport = _make_transport()
    connection = _connection()
    connection.send_command.side_effect = [
        _response("Cisco IOS XE"),
        _response("% Invalid input detected at '^' marker.", failed=True),
    ]

    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        results = await transport.execute_commands(["show version", "show bork", ""])

    assert connection.open.await_count == 1
    assert [r.exit_code for r in results] == [0, 1]
    assert results[0].output == "Cisco IOS XE"
    assert results[1].error == "% Invalid input detected at '^' marker."
    # Blank commands are skipped, not sent
    assert connection.send_command.await_count == 2
    connection.close.assert_awaited_once()


async def test_config_set_strips_framing_and_runs_post_commands():
    transport = _make_transport()
    connection = _connection()
    connection.send_configs.return_value = [_response("ok1"), _response("ok2")]
    connection.send_command.return_value = _response("Building configuration...\n[OK]")

    commands = ["configure terminal", "vlan 75", "name vlan_75", "end", "write memory"]
    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        results = await transport.execute_commands(commands)

    connection.send_configs.assert_awaited_once_with(
        ["vlan 75", "name vlan_75"], stop_on_failed=True
    )
    assert connection.send_command.await_count == 1
    write_results = [r for r in results if r.command == "write memory"]
    assert len(write_results) == 1 and write_results[0].exit_code == 0
    assert all(r.command not in ("configure terminal", "end") for r in results)


async def test_config_failure_skips_post_and_marks_unattempted():
    transport = _make_transport()
    connection = _connection()
    # stop_on_failed truncates the responses after the failure
    connection.send_configs.return_value = [
        _response("ok"),
        _response("% Invalid input detected at '^' marker.", failed=True),
    ]

    commands = ["configure terminal", "vlan 75", "bork", "name x", "end", "write memory"]
    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        results = await transport.execute_commands(commands)

    assert connection.send_command.await_count == 0
    assert all(r.command != "write memory" for r in results)
    assert any(r.command == "bork" and r.exit_code == 1 for r in results)
    skipped = [r for r in results if r.command == "name x"]
    assert len(skipped) == 1 and skipped[0].exit_code == -1
    assert "Skipped" in (skipped[0].error or "")


async def test_auth_failure_fills_all_results():
    transport = _make_transport()
    connection = _connection()
    connection.open.side_effect = ScrapliAuthenticationFailed("bad creds")

    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        results = await transport.execute_commands(["show version", "show ip int brief"])

    assert len(results) == 2
    assert all(r.exit_code == -1 for r in results)
    assert all("Authentication failed" in (r.error or "") for r in results)


async def test_timing_mode_answers_prompts_and_finds_pattern():
    transport = _make_transport()
    connection = _connection()
    connection.channel.read = AsyncMock(
        side_effect=[
            b"Proceed? [confirm]",
            ScrapliTimeout("no data"),
            b"Done: 1234 bytes copied in 1.0 secs",
        ]
    )

    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        result = await transport.execute_command_timing(
            "copy tftp: flash:",
            read_timeout=30.0,
            answers={"[confirm]": ""},
            wait_for_patterns=["bytes copied"],
        )

    assert result.exit_code == 0
    assert "bytes copied" in result.output
    written = [call.args[0] for call in connection.channel.write.call_args_list]
    assert written[0] == "copy tftp: flash:\n"
    assert "\n" in written[1:]  # the [confirm] answer


async def test_timing_mode_settles_when_channel_goes_quiet():
    transport = _make_transport()
    connection = _connection()
    connection.channel.read = AsyncMock(
        side_effect=[
            b"Reload scheduled",
            ScrapliTimeout("q1"),
            ScrapliTimeout("q2"),
            ScrapliTimeout("q3"),
        ]
    )

    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        result = await transport.execute_command_timing("reload in 5", read_timeout=30.0)

    assert result.exit_code == 0
    assert result.output == "Reload scheduled"
    # Settled after exactly three consecutive quiet reads — no further polling
    assert connection.channel.read.await_count == 4


async def test_timing_mode_stops_on_hard_read_error():
    transport = _make_transport()
    connection = _connection()
    connection.channel.read = AsyncMock(
        side_effect=[b"System going down", ConnectionResetError("gone")]
    )

    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        result = await transport.execute_command_timing(
            "reload", read_timeout=30.0, wait_for_patterns=["never appears"]
        )

    # Connection drop ends the poll loop instead of spinning until the deadline
    assert connection.channel.read.await_count == 2
    assert result.exit_code == 0
    assert "System going down" in result.output


async def test_staging_methods_are_an_explicit_seam():
    transport = _make_transport()
    with pytest.raises(NotImplementedError, match="netmiko"):
        await transport.scp_put(local_path="/tmp/x", dest_fs="flash:", dest_filename="x")
    with pytest.raises(NotImplementedError, match="netmiko"):
        await transport.http_transfer(url="https://x", dest_fs="flash:", dest_filename="x")


# ── Jump host (bastion) hop ──────────────────────────────────────────────────


def _jump_transport() -> ScrapliTransport:
    from hegemony_step_sdk import JumpHostSpec

    spec = DeviceConnectionSpec(
        host="172.20.30.11",
        username="admin",
        password="device-pw",
        platform="ios-xe",
        jump_host=JumpHostSpec(host="dind", port=2222, username="jump", password="bastion-pw"),
    )
    return ScrapliTransport(spec)


async def test_open_connection_rides_the_bastion_tunnel():
    """The bastion session reaches scrapli's asyncssh transport as tunnel=."""
    import hegemony_transport_scrapli.transport as transport_module

    transport = _jump_transport()
    bastion = MagicMock()
    connection = _connection()
    scrapli_cls = MagicMock(return_value=connection)
    asyncssh_mock = MagicMock()
    asyncssh_mock.connect = AsyncMock(return_value=bastion)

    with (
        patch.object(transport_module, "AsyncScrapli", scrapli_cls),
        patch.object(transport_module, "asyncssh", asyncssh_mock),
    ):
        opened = await transport._open_connection()

    bastion_call = asyncssh_mock.connect.await_args
    assert bastion_call is not None
    bastion_kwargs = bastion_call.kwargs
    assert bastion_call.args == ("dind",)
    assert bastion_kwargs["port"] == 2222
    assert bastion_kwargs["username"] == "jump"
    assert bastion_kwargs["password"] == "bastion-pw"
    assert "device-pw" not in repr(bastion_kwargs)
    # asyncssh reads an explicit client_keys=None as "no public-key auth" and
    # clears agent_path with it, so a password-only bastion must omit the
    # argument rather than pin it to None (parity with the asyncssh transport).
    assert "client_keys" not in bastion_kwargs

    scrapli_kwargs = scrapli_cls.call_args.kwargs
    assert scrapli_kwargs["transport_options"] == {"asyncssh": {"tunnel": bastion}}
    assert scrapli_kwargs["auth_password"] == "device-pw"
    assert "bastion-pw" not in repr(scrapli_kwargs)

    # The tunnel rides the connection; _safe_close tears both down.
    from hegemony_transport_scrapli.transport import _JUMP_TUNNEL_ATTR, _safe_close

    assert getattr(opened, _JUMP_TUNNEL_ATTR) is bastion
    await _safe_close(opened)
    bastion.close.assert_called()


async def test_open_connection_without_jump_sets_no_transport_options():
    import hegemony_transport_scrapli.transport as transport_module

    transport = _make_transport()
    connection = _connection()
    scrapli_cls = MagicMock(return_value=connection)

    with patch.object(transport_module, "AsyncScrapli", scrapli_cls):
        await transport._open_connection()

    assert "transport_options" not in scrapli_cls.call_args.kwargs


async def test_open_connection_closes_bastion_when_device_open_fails():
    import hegemony_transport_scrapli.transport as transport_module

    transport = _jump_transport()
    bastion = MagicMock()
    connection = _connection()
    connection.open = AsyncMock(side_effect=OSError("connection refused"))
    scrapli_cls = MagicMock(return_value=connection)
    asyncssh_mock = MagicMock()
    asyncssh_mock.connect = AsyncMock(return_value=bastion)

    import pytest

    with (
        patch.object(transport_module, "AsyncScrapli", scrapli_cls),
        patch.object(transport_module, "asyncssh", asyncssh_mock),
        pytest.raises(OSError, match="connection refused"),
    ):
        await transport._open_connection()

    bastion.close.assert_called()
