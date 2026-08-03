# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the asyncssh device transport wheel.

Covers registration under hegemony.device_transports, spec-based construction,
exec-channel result mapping (genuine exit codes, stderr surfacing), timing-mode
prompt answering on a PTY, SFTP upload semantics, and the remote-curl HTTP
transfer command shape.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest

import hegemony_transport_asyncssh
from hegemony_step_sdk import DeviceConnectionSpec, JumpHostSpec
from hegemony_transport_asyncssh.transport import (
    AsyncSSHTransport,
    _NullCancellationRegistry,
)


def test_register_registers_the_asyncssh_transport():
    registered: list[type] = []

    class _Registry:
        def register_transport(self, transport_class: type) -> None:
            registered.append(transport_class)

    hegemony_transport_asyncssh.register(_Registry())
    assert registered == [AsyncSSHTransport]
    assert AsyncSSHTransport.transport_id == "asyncssh"


def test_construct_from_spec_resolves_fields():
    spec = DeviceConnectionSpec(
        host="192.0.2.10",
        port=2222,
        username="ops",
        password="pw",
        platform="linux",
    )
    t = AsyncSSHTransport(spec)
    assert t.host == "192.0.2.10"
    assert t.port == 2222
    assert t.username == "ops"
    assert isinstance(t._cancellation_registry, _NullCancellationRegistry)


def test_construct_requires_username():
    spec = DeviceConnectionSpec(host="192.0.2.10", username="")
    with pytest.raises(ValueError, match="username"):
        AsyncSSHTransport(spec)


def _make_transport() -> AsyncSSHTransport:
    spec = DeviceConnectionSpec(host="192.0.2.10", username="ops", password="pw", platform="linux")
    return AsyncSSHTransport(spec)


def _completed(stdout: str = "", stderr: str = "", exit_status: int = 0) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr=stderr, exit_status=exit_status)


def _connection() -> MagicMock:
    connection = MagicMock()
    connection.run = AsyncMock()
    connection.close = MagicMock()
    return connection


async def test_execute_commands_maps_exit_codes_and_stderr():
    transport = _make_transport()
    connection = _connection()
    connection.run.side_effect = [
        _completed(stdout="ok\n"),
        _completed(stdout="", stderr="No such file or directory", exit_status=2),
    ]

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        results = await transport.execute_commands(["uname -a", "cat /nope", " "])

    assert [r.exit_code for r in results] == [0, 2]
    assert results[0].output == "ok\n"
    assert results[0].error is None
    assert results[1].error == "No such file or directory"
    assert "No such file" in results[1].output
    # Blank commands are skipped, not sent
    assert connection.run.await_count == 2
    connection.close.assert_called_once()


async def test_connect_failure_fills_all_results():
    transport = _make_transport()
    with patch.object(asyncssh, "connect", AsyncMock(side_effect=OSError("connection refused"))):
        results = await transport.execute_commands(["uptime", "id"])

    assert len(results) == 2
    assert all(r.exit_code == -1 for r in results)
    assert all("SSH connection failed" in (r.error or "") for r in results)


async def test_execute_command_timing_answers_prompts():
    transport = _make_transport()
    connection = _connection()
    process = MagicMock()
    process.exit_status = None
    process.stdin.write = MagicMock()
    process.stdout.read = AsyncMock(
        side_effect=["[sudo] password for ops:", "", "upgrade complete", "", "", ""]
    )
    connection.create_process = AsyncMock(return_value=process)

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        result = await transport.execute_command_timing(
            "sudo apply-upgrade",
            read_timeout=30.0,
            answers={"password for ops:": "pw"},
            wait_for_patterns=["upgrade complete"],
        )

    assert result.exit_code == 0
    assert "upgrade complete" in result.output
    process.stdin.write.assert_called_once_with("pw\n")
    process.terminate.assert_called_once()


async def test_scp_put_skips_existing_without_overwrite(tmp_path):
    transport = _make_transport()
    local = tmp_path / "image.bin"
    local.write_bytes(b"payload")

    sftp = MagicMock()
    sftp.exists = AsyncMock(return_value=True)
    sftp.put = AsyncMock()
    sftp_ctx = MagicMock()
    sftp_ctx.__aenter__ = AsyncMock(return_value=sftp)
    sftp_ctx.__aexit__ = AsyncMock(return_value=False)

    connection = _connection()
    connection.start_sftp_client = MagicMock(return_value=sftp_ctx)

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        result = await transport.scp_put(
            local_path=str(local), dest_fs="/var/tmp", dest_filename="image.bin"
        )

    assert result["transferred"] is False
    assert result["exists"] is True
    sftp.put.assert_not_awaited()


async def test_scp_put_uploads_and_verifies_size(tmp_path):
    transport = _make_transport()
    local = tmp_path / "image.bin"
    local.write_bytes(b"payload")

    sftp = MagicMock()
    sftp.exists = AsyncMock(return_value=False)
    sftp.put = AsyncMock()
    sftp.stat = AsyncMock(return_value=SimpleNamespace(size=len(b"payload")))
    sftp_ctx = MagicMock()
    sftp_ctx.__aenter__ = AsyncMock(return_value=sftp)
    sftp_ctx.__aexit__ = AsyncMock(return_value=False)

    connection = _connection()
    connection.start_sftp_client = MagicMock(return_value=sftp_ctx)

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        result = await transport.scp_put(
            local_path=str(local), dest_fs="/var/tmp", dest_filename="image.bin"
        )

    assert result["transferred"] is True
    assert result["verified"] is True
    sftp.put.assert_awaited_once_with(str(local), "/var/tmp/image.bin")


async def test_http_transfer_runs_curl_remotely():
    transport = _make_transport()
    connection = _connection()
    connection.run.return_value = _completed(stdout="", stderr="", exit_status=0)

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        result = await transport.http_transfer(
            url="https://example.test/fw.bin?sig=abc",
            dest_fs="/var/tmp",
            dest_filename="fw.bin",
            timeout_seconds=600,
        )

    assert result["transferred"] is True
    command = connection.run.await_args.args[0]
    assert command.startswith("curl ")
    assert "--max-time 600" in command
    assert "-o /var/tmp/fw.bin" in command
    # The URL carries shell metacharacters, so shlex.quote must wrap it
    assert "'https://example.test/fw.bin?sig=abc'" in command


def _jump_spec() -> DeviceConnectionSpec:
    return DeviceConnectionSpec(
        host="172.20.30.11",
        username="admin",
        password="device-pw",
        platform="linux",
        jump_host=JumpHostSpec(host="dind", port=2222, username="jump", password="bastion-pw"),
    )


async def test_jump_host_tunnels_the_device_session():
    """ProxyJump: session #1 to the bastion, session #2 tunneled through it."""
    transport = AsyncSSHTransport(_jump_spec())
    bastion = _connection()
    device = _connection()
    device.run.return_value = _completed(stdout="ok\n")
    connect = AsyncMock(side_effect=[bastion, device])

    with patch.object(asyncssh, "connect", connect):
        results = await transport.execute_commands(["uname -a"])

    assert results[0].exit_code == 0
    assert connect.await_count == 2

    bastion_call = connect.await_args_list[0]
    assert bastion_call.args == ("dind",)
    assert bastion_call.kwargs["port"] == 2222
    assert bastion_call.kwargs["username"] == "jump"
    assert bastion_call.kwargs["password"] == "bastion-pw"
    # Credential isolation: the bastion never sees device credentials.
    assert "device-pw" not in bastion_call.kwargs.values()

    device_call = connect.await_args_list[1]
    assert device_call.args == ("172.20.30.11",)
    assert device_call.kwargs["username"] == "admin"
    assert device_call.kwargs["password"] == "device-pw"
    assert device_call.kwargs["tunnel"] is bastion
    # ...and the device never sees bastion credentials.
    assert "bastion-pw" not in device_call.kwargs.values()

    # Both sessions are torn down with the device connection.
    device.close.assert_called_once()
    bastion.close.assert_called_once()


async def test_no_jump_host_passes_the_no_tunnel_sentinel():
    transport = _make_transport()
    connection = _connection()
    connection.run.return_value = _completed(stdout="ok\n")
    connect = AsyncMock(return_value=connection)

    with patch.object(asyncssh, "connect", connect):
        await transport.execute_commands(["uptime"])

    assert connect.await_count == 1
    assert connect.await_args is not None
    assert connect.await_args.kwargs["tunnel"] == ()


async def test_device_connect_failure_closes_the_bastion_session():
    transport = AsyncSSHTransport(_jump_spec())
    bastion = _connection()
    connect = AsyncMock(side_effect=[bastion, OSError("connection refused")])

    with patch.object(asyncssh, "connect", connect):
        results = await transport.execute_commands(["uptime"])

    assert all("SSH connection failed" in (r.error or "") for r in results)
    bastion.close.assert_called_once()
