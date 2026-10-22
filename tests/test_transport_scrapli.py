# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Tests for the scrapli device transport wheel.

Covers registration under hegemony.device_transports, spec-based construction
and platform mapping, show/config execution paths (per-response result
mapping, `exit` kept inside its config block, blocks and exec commands in the
order written, nothing run after the first failure or a cancellation),
answering the questions of a copy to startup-config, timing-mode prompt
answering, and the explicit NotImplementedError staging seam.
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from scrapli.exceptions import ScrapliAuthenticationFailed, ScrapliTimeout

import hegemony_transport_scrapli
from hegemony_step_sdk import DeviceConnectionSpec
from hegemony_transport_scrapli.transport import (
    _CANCELLED_ERROR,
    _SKIPPED_ERROR,
    ScrapliTransport,
    _NullCancellationRegistry,
)
from tests.ssh_fakes import checks_off


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
    return ScrapliTransport(spec, host_key_verifier=checks_off())


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
    assert any(r.command == "bork" and r.exit_code == 1 for r in results)
    skipped = [r for r in results if r.command == "name x"]
    assert len(skipped) == 1 and skipped[0].exit_code == -1
    assert "Skipped" in (skipped[0].error or "")
    # The save after the failed block is reported as not run, not left out.
    assert (results[-1].command, results[-1].exit_code) == ("write memory", -1)
    assert results[-1].error == _SKIPPED_ERROR


async def _run_on_connection(commands: list[str], connection: MagicMock):
    transport = _make_transport()
    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        return await transport.execute_commands(commands)


async def test_exit_inside_a_config_block_is_sent_as_a_config_line():
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
    connection = _connection()
    connection.send_configs.return_value = [_response() for _ in range(5)]
    connection.send_command.return_value = _response("Building configuration...\n[OK]")

    results = await _run_on_connection(commands, connection)

    connection.send_configs.assert_awaited_once_with(commands[1:6], stop_on_failed=True)
    assert [c.args[0] for c in connection.send_command.await_args_list] == ["write memory"]
    assert [r.command for r in results] == commands[1:6] + ["write memory"]
    assert all(r.exit_code == 0 for r in results)


async def test_a_leading_blank_line_keeps_the_configuration_session():
    # A blank first line used to make the list a show/exec list, so the save
    # ran even when a config line failed.
    connection = _connection()
    connection.send_configs.return_value = [
        _response("% Invalid input detected at '^' marker.", failed=True)
    ]

    results = await _run_on_connection(
        ["", "  ", "conf t", "hostname r1", "end", "write memory"], connection
    )

    connection.send_configs.assert_awaited_once_with(["hostname r1"], stop_on_failed=True)
    assert connection.send_command.await_count == 0
    assert [(r.command, r.exit_code) for r in results] == [("hostname r1", 1), ("write memory", -1)]
    assert results[-1].error == _SKIPPED_ERROR


async def test_failed_post_command_fails_and_skips_the_rest():
    connection = _connection()
    connection.send_configs.return_value = [_response()]
    connection.send_command.return_value = _response(
        "        ^\n% Invalid input detected at '^' marker."
    )

    results = await _run_on_connection(
        ["configure terminal", "hostname r1", "end", "show bork", "write memory"], connection
    )

    assert connection.send_command.await_count == 1
    assert [r.command for r in results] == ["hostname r1", "show bork", "write memory"]
    assert results[1].exit_code == 1
    assert results[1].error == "% Invalid input detected at '^' marker."
    assert (results[2].exit_code, results[2].error) == (-1, _SKIPPED_ERROR)


async def test_config_blocks_and_exec_commands_run_in_written_order():
    calls: list[tuple[str, object]] = []

    async def send_configs(lines, **kwargs):
        calls.append(("config", list(lines)))
        return [_response() for _ in lines]

    async def send_command(command, **kwargs):
        calls.append(("exec", command))
        return _response("ok")

    connection = _connection()
    connection.send_configs.side_effect = send_configs
    connection.send_command.side_effect = send_command

    results = await _run_on_connection(
        [
            "configure terminal",
            "hostname r1",
            "end",
            "show clock",
            "conf t",
            "ntp server 192.0.2.5",
            "end",
            "write memory",
        ],
        connection,
    )

    assert calls == [
        ("config", ["hostname r1"]),
        ("exec", "show clock"),
        ("config", ["ntp server 192.0.2.5"]),
        ("exec", "write memory"),
    ]
    assert [r.command for r in results] == [
        "hostname r1",
        "show clock",
        "ntp server 192.0.2.5",
        "write memory",
    ]
    assert all(r.exit_code == 0 for r in results)


def _iosxe_connection() -> MagicMock:
    from scrapli.driver.core.cisco_iosxe.base_driver import PRIVS

    connection = _connection()
    connection.privilege_levels = PRIVS
    connection.default_desired_privilege_level = "privilege_exec"
    connection.send_interactive = AsyncMock()
    return connection


@pytest.mark.parametrize(
    "command",
    [
        "copy running-config startup-config",
        "copy run start",
        "copy system:running-config nvram:startup-config",
    ],
)
async def test_a_copy_to_startup_config_answers_the_destination_question(command):
    # IOS asks for the destination file name before it copies, which the
    # prompt-only wait of send_command ran into the command timeout.
    connection = _iosxe_connection()
    connection.send_interactive.side_effect = [
        _response(f"{command}\nDestination filename [startup-config]?"),
        _response("Building configuration...\n[OK]\nr1#"),
    ]

    results = await _run_on_connection([command], connection)

    calls = connection.send_interactive.await_args_list
    exec_prompt = r"^[\w.\-@/:]{1,63}#\s*$"
    assert [c.args[0] for c in calls] == [[(command, exec_prompt)], [("", exec_prompt)]]
    connection.send_command.assert_not_awaited()
    assert (results[0].exit_code, results[0].error) == (0, None)
    assert (
        results[0].output
        == "Destination filename [startup-config]?\nBuilding configuration...\n[OK]"
    )


def test_the_copy_questions_are_read_as_patterns_that_match_the_device():
    # send_interactive escapes a pattern unless it is anchored with ^ and $,
    # and the exec prompt pattern must not take a question for the prompt.
    from scrapli.channel.base_channel import BaseChannel
    from scrapli.driver.core.cisco_iosxe.base_driver import PRIVS

    from hegemony_transport_scrapli.transport import _COPY_QUESTION_PATTERNS

    questions = [
        b"Destination filename [startup-config]? ",
        b"Overwrite the previous NVRAM configuration?[confirm]",
    ]
    patterns = [BaseChannel._get_prompt_pattern("", pattern) for pattern in _COPY_QUESTION_PATTERNS]
    for question in questions:
        assert any(p.search(question) for p in patterns), question
        assert not BaseChannel._get_prompt_pattern("", PRIVS["privilege_exec"].pattern).search(
            question
        )


async def test_a_copy_to_startup_config_answers_a_confirmation_too():
    connection = _iosxe_connection()
    connection.send_configs.return_value = [_response()]
    connection.send_interactive.side_effect = [
        _response("copy run start\nDestination filename [startup-config]?"),
        _response("Overwrite the previous NVRAM configuration?[confirm]"),
        _response("Building configuration...\n[OK]\nr1#"),
    ]

    results = await _run_on_connection(
        ["configure terminal", "hostname r1", "end", "copy run start"], connection
    )

    inputs = [c.args[0][0][0] for c in connection.send_interactive.await_args_list]
    assert inputs == ["copy run start", "", ""]
    assert [r.exit_code for r in results] == [0, 0]
    assert results[-1].output.endswith("[OK]")


async def test_a_copy_to_startup_config_without_questions_waits_for_the_prompt():
    connection = _iosxe_connection()
    connection.send_interactive.return_value = _response(
        "copy run start\nBuilding configuration...\n[OK]\nr1#"
    )

    results = await _run_on_connection(["copy run start"], connection)

    assert connection.send_interactive.await_count == 1
    assert (results[0].exit_code, results[0].output) == (0, "Building configuration...\n[OK]")


async def test_a_copy_that_keeps_asking_fails():
    connection = _iosxe_connection()
    connection.send_interactive.return_value = _response("Destination filename [startup-config]?")

    results = await _run_on_connection(["copy run start"], connection)

    assert connection.send_interactive.await_count == 3
    assert results[0].exit_code == -1


class _Cancellation(_NullCancellationRegistry):
    """Cancellation registry whose run is cancelled once ``cancelled`` is set."""

    def __init__(self) -> None:
        self.cancelled = False

    def is_cancelled(self, key: str | None) -> bool:
        return self.cancelled


async def _run_with_cancellation(
    commands: list[str], connection: MagicMock, cancellation: _Cancellation
):
    transport = _make_transport()
    transport.step_run_id = "sr-1"
    transport._cancellation_registry = cancellation
    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        return await transport.execute_commands(commands)


async def test_commands_after_a_cancellation_say_the_run_was_cancelled():
    cancellation = _Cancellation()

    async def send_command(command, **kwargs):
        cancellation.cancelled = True  # the run is cancelled while this runs
        return _response("10:00")

    connection = _connection()
    connection.send_configs.return_value = [_response()]
    connection.send_command.side_effect = send_command

    results = await _run_with_cancellation(
        [
            "configure terminal",
            "hostname r1",
            "end",
            "show clock",
            "conf t",
            "ntp server 192.0.2.5",
            "ntp server 192.0.2.6",
            "end",
            "write memory",
        ],
        connection,
        cancellation,
    )

    connection.send_configs.assert_awaited_once()
    assert connection.send_command.await_count == 1
    assert [(r.command, r.exit_code, r.error) for r in results] == [
        ("hostname r1", 0, None),
        ("show clock", 0, None),
        ("ntp server 192.0.2.5", -1, "Cancelled"),
        ("ntp server 192.0.2.6", -1, _CANCELLED_ERROR),
        ("write memory", -1, _CANCELLED_ERROR),
    ]


async def test_a_command_cut_off_by_a_cancellation_skips_the_rest_as_cancelled():
    cancellation = _Cancellation()

    async def send_configs(lines, **kwargs):
        # Cancelling closes the session: the first line fails, and
        # stop_on_failed leaves the rest of the block unattempted.
        cancellation.cancelled = True
        return [_response(failed=True)]

    connection = _connection()
    connection.send_configs.side_effect = send_configs

    results = await _run_with_cancellation(
        ["configure terminal", "hostname r1", "ntp server 192.0.2.5", "end", "write memory"],
        connection,
        cancellation,
    )

    assert connection.send_command.await_count == 0
    assert [(r.command, r.exit_code) for r in results] == [
        ("hostname r1", 1),
        ("ntp server 192.0.2.5", -1),
        ("write memory", -1),
    ]
    assert [r.error for r in results[1:]] == [_CANCELLED_ERROR, _CANCELLED_ERROR]


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


async def test_timing_mode_answers_a_prompt_split_across_reads():
    transport = _make_transport()
    connection = _connection()
    connection.channel.read = AsyncMock(
        side_effect=[b"Proceed with reload? [y/", b"n]", ScrapliTimeout("no data"), b"SUCCESS"]
    )

    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        result = await transport.execute_command_timing(
            "install activate",
            read_timeout=30.0,
            answers={"[y/n]": "y"},
            wait_for_patterns=["SUCCESS"],
        )

    assert result.exit_code == 0
    written = [call.args[0] for call in connection.channel.write.call_args_list]
    assert written == ["install activate\n", "y\n"]


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


# ── Command text stays out of the logs ──────────────────────────────────────

#: Stands for a value a step rendered from {{ secret(...) }}: the platform has
#: no log redaction, so command text must never reach a log message.
_SECRET = "Sw0rdfish-42.x"


def _respond(outcome: object):
    async def respond(*args, **kwargs):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return respond


_OUTCOMES = [
    _response(f"{_SECRET} ok"),
    _response(f"{_SECRET}\n% Invalid input detected at '^' marker.", failed=True),
    ScrapliTimeout(f"timed out sending {_SECRET}"),
]
_OUTCOME_IDS = ["success", "cli-error", "exception"]


@pytest.mark.parametrize("outcome", _OUTCOMES, ids=_OUTCOME_IDS)
async def test_exec_commands_are_not_logged(caplog, outcome):
    caplog.set_level(logging.DEBUG)
    connection = _connection()
    connection.send_command.side_effect = _respond(outcome)

    await _run_on_connection([f"show running-config | include {_SECRET}"], connection)

    assert caplog.records
    assert _SECRET not in caplog.text


@pytest.mark.parametrize("outcome", _OUTCOMES, ids=_OUTCOME_IDS)
async def test_config_lines_are_not_logged(caplog, outcome):
    caplog.set_level(logging.DEBUG)
    connection = _connection()
    configs = outcome if isinstance(outcome, Exception) else [outcome]
    connection.send_configs.side_effect = _respond(configs)
    connection.send_command.return_value = _response("[OK]")

    await _run_on_connection(
        ["configure terminal", f"username admin secret {_SECRET}", "end", "write memory"],
        connection,
    )

    assert caplog.records
    assert _SECRET not in caplog.text


async def test_timing_commands_and_output_are_not_logged(caplog):
    caplog.set_level(logging.DEBUG)
    transport = _make_transport()
    connection = _connection()
    # The device echoes the command; the awaited pattern never comes.
    connection.channel.read = AsyncMock(side_effect=[f"{_SECRET}\n".encode(), OSError("gone")])

    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        await transport.execute_command_timing(
            f"install add file flash:{_SECRET}.bin",
            read_timeout=30.0,
            wait_for_patterns=["Install done"],
        )

    assert caplog.records
    assert _SECRET not in caplog.text


async def test_failed_timing_commands_are_not_logged(caplog):
    caplog.set_level(logging.DEBUG)
    transport = _make_transport()
    connection = _connection()
    connection.channel.write.side_effect = OSError(f"write of {_SECRET} failed")

    with patch.object(
        hegemony_transport_scrapli.transport, "AsyncScrapli", return_value=connection
    ):
        result = await transport.execute_command_timing(f"install add file flash:{_SECRET}.bin")

    assert result.exit_code == -1
    assert caplog.records
    assert _SECRET not in caplog.text


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
    return ScrapliTransport(spec, host_key_verifier=checks_off())


async def test_open_connection_rides_the_bastion_tunnel():
    """The bastion session reaches scrapli's asyncssh transport as tunnel=."""
    import hegemony_transport_scrapli.transport as transport_module

    transport = _jump_transport()
    bastion = MagicMock()
    # Awaitable: _safe_close awaits wait_closed() under suppress(Exception), so
    # a plain MagicMock would make the await raise and vanish, leaving the
    # awaited teardown untested.
    bastion.wait_closed = AsyncMock()
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
    bastion.wait_closed.assert_awaited()


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
    # Awaitable: _safe_close awaits wait_closed() under suppress(Exception), so
    # a plain MagicMock would make the await raise and vanish, leaving the
    # awaited teardown untested.
    bastion.wait_closed = AsyncMock()
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


async def test_connect_budget_is_shared_across_both_hops():
    # connect_timeout is the budget for reaching the device. Charging it to the
    # bastion login and again to timeout_socket lets a slow bastion double the
    # caller's deadline — the same defect fixed in the netmiko and asyncssh
    # transports.
    import hegemony_transport_scrapli.transport as transport_module

    transport = _jump_transport()
    transport.connect_timeout = 30.0
    bastion = MagicMock()
    bastion.wait_closed = AsyncMock()
    connection = _connection()
    scrapli_cls = MagicMock(return_value=connection)
    asyncssh_mock = MagicMock()
    asyncssh_mock.connect = AsyncMock(return_value=bastion)
    clock = iter([100.0, 120.0, 120.0, 120.0])  # the bastion login eats 20 s

    with (
        patch.object(transport_module, "AsyncScrapli", scrapli_cls),
        patch.object(transport_module, "asyncssh", asyncssh_mock),
        patch.object(transport_module.time, "perf_counter", lambda: next(clock)),
    ):
        await transport._open_connection()

    assert scrapli_cls.call_args.kwargs["timeout_socket"] == 10.0


async def test_connect_budget_floors_rather_than_going_to_zero():
    import hegemony_transport_scrapli.transport as transport_module

    transport = _jump_transport()
    transport.connect_timeout = 5.0
    bastion = MagicMock()
    bastion.wait_closed = AsyncMock()
    connection = _connection()
    scrapli_cls = MagicMock(return_value=connection)
    asyncssh_mock = MagicMock()
    asyncssh_mock.connect = AsyncMock(return_value=bastion)
    clock = iter([100.0, 400.0, 400.0, 400.0])

    with (
        patch.object(transport_module, "AsyncScrapli", scrapli_cls),
        patch.object(transport_module, "asyncssh", asyncssh_mock),
        patch.object(transport_module.time, "perf_counter", lambda: next(clock)),
    ):
        await transport._open_connection()

    assert scrapli_cls.call_args.kwargs["timeout_socket"] == 1.0


async def test_without_a_jump_host_the_full_budget_applies():
    import hegemony_transport_scrapli.transport as transport_module

    transport = _make_transport()
    transport.connect_timeout = 30.0
    connection = _connection()
    scrapli_cls = MagicMock(return_value=connection)
    with patch.object(transport_module, "AsyncScrapli", scrapli_cls):
        await transport._open_connection()
    assert scrapli_cls.call_args.kwargs["timeout_socket"] == 30.0
