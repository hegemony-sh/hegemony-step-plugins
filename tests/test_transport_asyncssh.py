# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the asyncssh device transport wheel.

Covers registration under hegemony.device_transports, spec-based construction,
exec-channel result mapping (genuine exit codes, stderr surfacing), a
configuration session stopping at its first failure, timing-mode prompt
answering on a PTY, SFTP upload semantics, and the remote-curl HTTP transfer
command shape.
"""

from __future__ import annotations

import asyncio
import logging
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest

import hegemony_transport_asyncssh
from hegemony_step_sdk import DeviceConnectionSpec, JumpHostSpec
from hegemony_transport_asyncssh.transport import (
    _CANCELLED_ERROR,
    _SKIPPED_ERROR,
    AsyncSSHTransport,
    _NullCancellationRegistry,
)
from tests.ssh_fakes import checks_off


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
    return AsyncSSHTransport(spec, host_key_verifier=checks_off())


def _completed(stdout: str = "", stderr: str = "", exit_status: int = 0) -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, stderr=stderr, exit_status=exit_status)


def _connection() -> MagicMock:
    connection = MagicMock()
    connection.run = AsyncMock()
    connection.close = MagicMock()
    # Awaitable on purpose: the close helpers `await wait_closed()` inside a
    # contextlib.suppress(Exception). A plain MagicMock returns a non-awaitable,
    # so every await would raise TypeError and be swallowed — the awaited
    # teardown would have no coverage at all while the test still passed.
    connection.wait_closed = AsyncMock()
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


async def test_a_configuration_session_stops_at_the_first_failure():
    # Like the CLI transports: once a command of a configuration session
    # fails, the rest do not run, so a later save never stores a change that
    # failed part way.
    transport = _make_transport()
    connection = _connection()
    connection.run.side_effect = [
        _completed(),
        _completed(stderr="% Invalid input detected", exit_status=1),
    ]
    commands = ["", "configure terminal", "bork", "hostname r1", "", "write memory"]

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        results = await transport.execute_commands(commands)

    assert [c.args[0] for c in connection.run.await_args_list] == ["configure terminal", "bork"]
    assert [(r.command, r.exit_code, r.error) for r in results] == [
        ("configure terminal", 0, None),
        ("bork", 1, "% Invalid input detected"),
        ("hostname r1", -1, _SKIPPED_ERROR),
        ("write memory", -1, _SKIPPED_ERROR),
    ]


async def test_other_command_lists_run_every_command_after_a_failure():
    transport = _make_transport()
    connection = _connection()
    connection.run.side_effect = [_completed(exit_status=2), _completed(stdout="up\n")]

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        results = await transport.execute_commands(["cat /nope", "uptime"])

    assert [r.exit_code for r in results] == [2, 0]


class _Cancellation(_NullCancellationRegistry):
    """Cancellation registry whose run is cancelled once ``cancelled`` is set."""

    def __init__(self) -> None:
        self.cancelled = False

    def is_cancelled(self, key: str | None) -> bool:
        return self.cancelled


async def test_a_cancelled_configuration_session_says_the_rest_were_cancelled():
    cancellation = _Cancellation()
    transport = _make_transport()
    transport.step_run_id = "sr-1"
    transport._cancellation_registry = cancellation
    connection = _connection()

    async def run(command, **kwargs):
        cancellation.cancelled = True  # cancelling closes the connection
        raise OSError("Connection lost")

    connection.run.side_effect = run

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        results = await transport.execute_commands(
            ["configure terminal", "hostname r1", "write memory"]
        )

    assert [(r.command, r.exit_code, r.error) for r in results] == [
        ("configure terminal", -1, "Connection lost"),
        ("hostname r1", -1, _CANCELLED_ERROR),
        ("write memory", -1, _CANCELLED_ERROR),
    ]


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


async def test_execute_command_timing_answers_a_prompt_split_across_reads():
    transport = _make_transport()
    connection = _connection()
    process = MagicMock()
    process.exit_status = None
    process.stdin.write = MagicMock()
    process.stdout.read = AsyncMock(
        side_effect=["Proceed with reload? [y/", "n]", "", "SUCCESS", "", "", ""]
    )
    connection.create_process = AsyncMock(return_value=process)

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        result = await transport.execute_command_timing(
            "install activate",
            read_timeout=30.0,
            answers={"[y/n]": "y"},
            wait_for_patterns=["SUCCESS"],
        )

    assert result.exit_code == 0
    process.stdin.write.assert_called_once_with("y\n")


# ── Command text stays out of the logs ──────────────────────────────────────

#: Stands for a value a step rendered from {{ secret(...) }}: the platform has
#: no log redaction, so command text must never reach a log message.
_SECRET = "Sw0rdfish-42.x"


async def _hang(*args, **kwargs):
    await asyncio.sleep(60)


@pytest.mark.parametrize(
    "outcome",
    [
        _completed(stdout=f"{_SECRET}\n"),
        _completed(stderr=f"sh: {_SECRET}: not found", exit_status=127),
        OSError(f"channel closed running {_SECRET}"),
        "timeout",
    ],
    ids=["success", "exit-status", "exception", "timeout"],
)
async def test_commands_are_not_logged(caplog, outcome):
    caplog.set_level(logging.DEBUG, logger="hegemony_transport_asyncssh")
    transport = _make_transport()
    transport.command_timeout = 0.01
    connection = _connection()
    if outcome == "timeout":
        connection.run.side_effect = _hang
    elif isinstance(outcome, Exception):
        connection.run.side_effect = outcome
    else:
        connection.run.return_value = outcome

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        await transport.execute_commands([f"echo {_SECRET}", f"printf {_SECRET}"])

    assert caplog.records
    assert _SECRET not in caplog.text


async def test_timing_commands_and_output_are_not_logged(caplog):
    caplog.set_level(logging.DEBUG, logger="hegemony_transport_asyncssh")
    transport = _make_transport()
    connection = _connection()
    process = MagicMock()
    process.exit_status = None
    process.stdin.write = MagicMock()
    # The command's output echoes the secret; the awaited pattern never comes.
    process.stdout.read = AsyncMock(side_effect=[f"{_SECRET}\n", OSError("gone")])
    connection.create_process = AsyncMock(return_value=process)

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        await transport.execute_command_timing(
            f"sudo apply-upgrade {_SECRET}",
            read_timeout=30.0,
            wait_for_patterns=["upgrade complete"],
        )

    assert caplog.records
    assert _SECRET not in caplog.text


async def test_failed_timing_commands_are_not_logged(caplog):
    caplog.set_level(logging.DEBUG, logger="hegemony_transport_asyncssh")
    transport = _make_transport()
    connection = _connection()
    connection.create_process = AsyncMock(side_effect=OSError(f"cannot run {_SECRET}"))

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        result = await transport.execute_command_timing(f"sudo apply-upgrade {_SECRET}")

    assert result.exit_code == -1
    assert caplog.records
    assert _SECRET not in caplog.text


async def test_http_transfer_url_is_not_logged(caplog):
    caplog.set_level(logging.DEBUG, logger="hegemony_transport_asyncssh")
    transport = _make_transport()
    url = f"https://files.example.test/a/{_SECRET}/fw.bin"
    connection = _connection()
    connection.run.return_value = _completed(
        stderr=f"curl: (22) The requested URL returned error: 403 {url}", exit_status=22
    )

    with patch.object(asyncssh, "connect", AsyncMock(return_value=connection)):
        result = await transport.http_transfer(url=url, dest_fs="/var/tmp", dest_filename="fw.bin")

    assert result["transferred"] is False
    assert caplog.records
    assert _SECRET not in caplog.text


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
    transport = AsyncSSHTransport(_jump_spec(), host_key_verifier=checks_off())
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
    # Credential isolation: the bastion never sees device credentials —
    # checked on the serialized kwargs so nested containers are covered.
    assert "device-pw" not in repr(bastion_call.kwargs)

    device_call = connect.await_args_list[1]
    assert device_call.args == ("172.20.30.11",)
    assert device_call.kwargs["username"] == "admin"
    assert device_call.kwargs["password"] == "device-pw"
    assert device_call.kwargs["tunnel"] is bastion
    # ...and the device never sees bastion credentials.
    assert "bastion-pw" not in repr(device_call.kwargs)

    # Both sessions are torn down with the device connection, and the close
    # is actually awaited to completion rather than merely requested.
    device.close.assert_called_once()
    bastion.close.assert_called_once()
    device.wait_closed.assert_awaited()
    bastion.wait_closed.assert_awaited()


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
    transport = AsyncSSHTransport(_jump_spec(), host_key_verifier=checks_off())
    bastion = _connection()
    connect = AsyncMock(side_effect=[bastion, OSError("connection refused")])

    with patch.object(asyncssh, "connect", connect):
        results = await transport.execute_commands(["uptime"])

    assert all("SSH connection failed" in (r.error or "") for r in results)
    bastion.close.assert_called_once()


async def test_jump_host_private_key_is_used_for_the_bastion():
    spec = DeviceConnectionSpec(
        host="172.20.30.11",
        username="admin",
        password="device-pw",
        platform="linux",
        jump_host=JumpHostSpec(host="dind", username="jump", private_key="PEM"),
    )
    transport = AsyncSSHTransport(spec, host_key_verifier=checks_off())
    bastion = _connection()
    device = _connection()
    device.run.return_value = _completed(stdout="ok\n")
    connect = AsyncMock(side_effect=[bastion, device])
    imported = object()

    with (
        patch.object(asyncssh, "connect", connect),
        patch.object(asyncssh, "import_private_key", MagicMock(return_value=imported)) as imp,
    ):
        await transport.execute_commands(["uname -a"])

    imp.assert_called_once_with("PEM")
    assert connect.await_args_list[0].kwargs["client_keys"] == [imported]
    # The key stays on the bastion hop; the device hop authenticates on its own.
    assert "client_keys" not in connect.await_args_list[1].kwargs


async def test_password_only_bastion_does_not_pin_client_keys_to_none():
    # asyncssh reads an explicit client_keys=None as "no public-key auth" and
    # clears agent_path along with it. Passing None whenever the inventory
    # carries no private_key would therefore strip agent and default-key auth
    # from the bastion hop while the device hop below keeps both — so the
    # argument must be *absent*, not None.
    transport = AsyncSSHTransport(_jump_spec(), host_key_verifier=checks_off())
    bastion = _connection()
    device = _connection()
    device.run.return_value = _completed(stdout="ok\n")
    connect = AsyncMock(side_effect=[bastion, device])

    with patch.object(asyncssh, "connect", connect):
        await transport.execute_commands(["uname -a"])

    assert "client_keys" not in connect.await_args_list[0].kwargs
