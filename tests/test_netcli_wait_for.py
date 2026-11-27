# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``netcli.wait_for``: poll a CLI command until its output matches.

The handlers run against scripted fake transports and a fake clock, so a
ten-minute wait takes no time. One test runs ``netcli.wait_for`` end to end
against the in-process SSH device of ``tests/ssh_fakes.py``.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any, cast

import asyncssh
import pytest

import hegemony_steps_netcli.waiting as netcli_waiting
from hegemony_step_sdk import (
    DeviceConnectionSpec,
    HandlerContext,
    HandlerServices,
    HostKeyRejectedError,
)
from hegemony_steps_netcli.wait_for import WaitForCliHandler
from hegemony_transport_netmiko.transport import SSHTransport
from tests.ssh_fakes import PASSWORD, USERNAME, Servers, checks_off, ssh_servers

DEVICE = {"id": "d1", "name": "sw1", "mgmt_host": "192.0.2.1", "platform": "ios-xe"}
SECRET = "s3cr3t-Pa55word"
COMMITTED = "Install state: COMMITTED"
INSTALLING = "Install state: INSTALLING"


# --- fakes ----------------------------------------------------------------------------------


class FakeClock:
    """Replaces the loop's clock and pause: sleeping only moves the time on."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        target = self.now + seconds
        await asyncio.sleep(0)
        self.now = max(self.now, target)


@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(netcli_waiting, "monotonic", fake.monotonic)
    monkeypatch.setattr(netcli_waiting, "sleep", fake.sleep)
    return fake


@dataclass
class CliResult:
    command: str
    output: str = ""
    exit_code: int = 0
    error: str | None = None
    latency_ms: float = 0.0
    disconnected: bool = False


class Refused(ConnectionRefusedError):
    def __init__(self) -> None:
        super().__init__("[Errno 111] Connection refused")


class NetmikoAuthenticationException(Exception):
    """Named like the netmiko error the transport raises for a refused login."""


class FakeCliTransport:
    """A held-session transport whose logins and command outputs follow a script.

    ``logins`` holds, per ``open_session`` call, None (it works) or the
    exception it raises; past its end every login works. ``outputs`` holds
    one item per ``execute_commands`` call: a string is the output of a
    command that succeeded, a ``CliResult`` is returned as it is (its
    command filled in), and ``"DROP"`` is the device closing the session.
    Past its end the last item repeats.
    """

    supports_held_session = True

    def __init__(self, outputs: list[Any], logins: list[Exception | None] | None = None) -> None:
        self.outputs = list(outputs)
        self.logins = list(logins or [])
        self.login_calls = 0
        self.commands_run: list[str] = []
        self.held = False
        self.closes = 0
        self.legacy: bool | None = None

    def configure_ssh_security(self, *, allow_legacy: bool = False) -> None:
        self.legacy = allow_legacy

    async def open_session(self) -> None:
        self.login_calls += 1
        outcome = self.logins.pop(0) if self.logins else None
        await asyncio.sleep(0)
        if outcome is not None:
            raise outcome
        self.held = True

    @property
    def session_open(self) -> bool:
        return self.held

    async def close_session(self) -> None:
        if self.held:
            self.closes += 1
        self.held = False

    async def execute_commands(self, commands: list[str]) -> list[CliResult]:
        assert self.held, "a command ran without a held session"
        await asyncio.sleep(0)
        command = commands[0]
        self.commands_run.append(command)
        item = self.outputs.pop(0) if len(self.outputs) > 1 else self.outputs[0]
        if item == "DROP":
            self.held = False
            return [
                CliResult(
                    command,
                    "Reload requested",
                    -1,
                    "The device closed the session",
                    disconnected=True,
                )
            ]
        if isinstance(item, CliResult):
            item.command = command
            return [item]
        return [CliResult(command, item)]


class CliServices:
    def __init__(self, transports: dict[str, Any]) -> None:
        self.transports = transports
        self.connect_calls: list[dict[str, Any]] = []

    def connect(self, device, **kwargs):
        self.connect_calls.append(kwargs)
        return self.transports[device["name"]]


def _ctx(config: dict[str, Any], services: Any, events: list, devices=None) -> HandlerContext:
    async def _record(message, device_id, attrs):
        events.append((message, attrs))
        return True

    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        target_roles=["primary"],
        target_devices_by_role={"primary": devices or [DEVICE]},
        services=cast(HandlerServices, services),
        _emit_progress=_record,
    )


def _cli_config(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "command": "show install summary",
        "pattern": r"Install state:\s+COMMITTED",
        "poll_interval_seconds": 10,
        "max_wait_seconds": 600,
    }
    config.update(overrides)
    return config


def _log(events: list) -> str:
    return "".join(message for message, _ in events)


async def _run_cli(transport: Any, events: list | None = None, **config: Any) -> tuple[Any, list]:
    events = [] if events is None else events
    services = CliServices({"sw1": transport})
    result = await WaitForCliHandler().execute(_ctx(_cli_config(**config), services, events))
    return result, events


# --- netcli.wait_for ------------------------------------------------------------------------


async def test_a_match_on_the_first_attempt(clock):
    transport = FakeCliTransport([COMMITTED])

    result, events = await _run_cli(transport)

    assert result.success is True
    device = result.output["devices"]["sw1"]
    assert device["matched"] is True
    assert device["attempts"] == 1
    assert device["reconnects"] == 0
    assert device["elapsed_seconds"] == 0
    assert device["matched_at"].endswith("+00:00")
    assert device["last_output"] == COMMITTED
    assert device["error"] is None
    assert result.output["matched"] is True
    assert result.output["truncated"] == []
    assert set(result.output) == {field.name for field in WaitForCliHandler.output_fields}
    [evidence] = result.evidence
    assert evidence["kind"] == "cli_output"
    assert evidence["name"] == "show install summary"
    assert evidence["content_text"] == COMMITTED
    assert evidence["content_json"]["success"] is True
    assert "matched" in _log(events)
    assert transport.closes == 1  # closed at the end


async def test_a_match_after_several_attempts_on_one_login(clock):
    transport = FakeCliTransport([INSTALLING, INSTALLING, INSTALLING, COMMITTED])

    result, events = await _run_cli(transport)

    assert result.success is True
    device = result.output["devices"]["sw1"]
    assert device["attempts"] == 4
    assert device["elapsed_seconds"] == 30
    # One login served every poll.
    assert transport.login_calls == 1
    assert transport.commands_run == ["show install summary"] * 4
    log = _log(events)
    assert log.count("$ show install summary\n") == 4
    assert "[attempt 3, 20 s elapsed] match not yet; next poll in 10 s" in log


async def test_a_timeout_fails_the_device(clock):
    transport = FakeCliTransport([INSTALLING])

    result, events = await _run_cli(transport, max_wait_seconds=30)

    assert result.success is False
    device = result.output["devices"]["sw1"]
    assert device["matched"] is False
    assert device["matched_at"] is None
    assert device["attempts"] == 3
    assert device["last_output"] == INSTALLING
    assert "condition not met within 30 s (3 attempts)" in device["error"]
    assert (result.error or "").startswith("sw1: condition not met within 30 s")
    assert result.output["matched"] is False
    assert result.evidence[0]["content_json"]["success"] is False
    assert "gave up after 3 attempts" in _log(events)


async def test_does_not_match_mode_waits_for_the_pattern_to_go(clock):
    transport = FakeCliTransport(["alarm: FAN FAIL", "alarm: FAN FAIL", "no alarms"])

    result, _ = await _run_cli(transport, pattern="FAN FAIL", until="not_matches")

    assert result.success is True
    assert result.output["devices"]["sw1"]["attempts"] == 3


async def test_a_failed_command_never_meets_does_not_match(clock):
    transport = FakeCliTransport(
        [CliResult("", "% Invalid input detected", 1, "% Invalid input"), "no alarms"]
    )

    result, events = await _run_cli(transport, pattern="FAN FAIL", until="not_matches")

    assert result.success is True
    assert result.output["devices"]["sw1"]["attempts"] == 2
    assert "command failed: the device reported an error (% Invalid input)" in _log(events)
    # The command error did not end the session.
    assert transport.login_calls == 1


async def test_stable_for_needs_consecutive_matches(clock):
    transport = FakeCliTransport([COMMITTED, INSTALLING, COMMITTED, COMMITTED, COMMITTED])

    result, events = await _run_cli(transport, stable_polls=3)

    assert result.success is True
    assert result.output["devices"]["sw1"]["attempts"] == 5
    log = _log(events)
    assert "match 1 of 3 in a row" in log
    assert "match 2 of 3 in a row" in log
    assert "matched (3 polls in a row)" in log


async def test_any_line_scope_anchors_to_each_line(clock):
    output = "Gi1 down\nGi2 up\n"
    whole = FakeCliTransport([output])
    lines = FakeCliTransport([output])

    by_output, _ = await _run_cli(whole, pattern=r"^Gi2 up$", max_wait_seconds=5)
    by_line, _ = await _run_cli(lines, pattern=r"^Gi2 up$", match_scope="lines")

    assert by_output.success is False
    assert by_line.success is True


async def test_a_reload_drops_the_session_and_the_step_reconnects(clock):
    transport = FakeCliTransport(
        [INSTALLING, "DROP", INSTALLING, COMMITTED],
        logins=[None, Refused(), Refused(), None],
    )

    result, events = await _run_cli(transport)

    assert result.success is True
    device = result.output["devices"]["sw1"]
    # 1 installing, 2 drop, 3-4 refused, 5 installing, 6 committed.
    assert device["attempts"] == 6
    assert device["reconnects"] == 1
    assert transport.login_calls == 4
    log = _log(events)
    assert "session lost (The device closed the session); reconnecting in 10 s" in log
    assert "not reachable ([Errno 111] Connection refused); trying again in 10 s" in log


async def test_a_command_without_an_answer_counts_as_a_lost_session(clock):
    timeout = CliResult("", "", -1, "Read timed out")
    transport = FakeCliTransport([timeout, COMMITTED])

    result, events = await _run_cli(transport)

    assert result.success is True
    assert transport.login_calls == 2
    assert result.output["devices"]["sw1"]["reconnects"] == 1
    assert "session lost (Read timed out)" in _log(events)


async def test_connection_refused_for_a_while_then_success(clock):
    transport = FakeCliTransport([COMMITTED], logins=[Refused(), Refused(), Refused()])

    result, _ = await _run_cli(transport)

    assert result.success is True
    device = result.output["devices"]["sw1"]
    assert device["attempts"] == 4
    assert device["elapsed_seconds"] == 30
    # The first login, however late, is no reconnect.
    assert device["reconnects"] == 0


async def test_an_unreachable_device_times_out_with_the_reason(clock):
    transport = FakeCliTransport([COMMITTED], logins=[Refused()] * 10)

    result, _ = await _run_cli(transport, max_wait_seconds=20)

    assert result.success is False
    error = result.output["devices"]["sw1"]["error"]
    assert "condition not met within 20 s (2 attempts)" in error
    # The exception's text stays in the live log; the error names its type.
    assert "not reachable: Refused" in error


@pytest.mark.parametrize(
    "error",
    [
        NetmikoAuthenticationException("Authentication to device failed."),
        HostKeyRejectedError("the host key of 192.0.2.1:22 is not trusted"),
        PermissionError("egress to 192.0.2.1 is denied"),
    ],
)
async def test_a_login_refused_for_good_stops_at_once(clock, error):
    transport = FakeCliTransport([COMMITTED], logins=[error])

    result, _ = await _run_cli(transport)

    assert result.success is False
    device = result.output["devices"]["sw1"]
    assert device["attempts"] == 1
    assert device["error"].startswith("cannot log in: ")
    assert clock.now == 1000.0  # no waiting


async def test_the_live_log_goes_through_the_hosts_redaction_only(clock, caplog):
    """Like netcli.execute, output reaches the Logs tab only through ctx.emit_output.

    The host redacts every secret it resolved from those events; the step
    itself must not put output or commands anywhere else (Python logs, the
    error or the summary), where nothing redacts them.
    """
    caplog.set_level(logging.DEBUG)
    leaky = f"username admin password {SECRET}\n{INSTALLING}"
    transport = FakeCliTransport([leaky], logins=[None])
    events: list = []

    async def _redacting(message, device_id, attrs):
        events.append((message.replace(SECRET, "[redacted]"), attrs))
        return True

    ctx = _ctx(_cli_config(max_wait_seconds=20), CliServices({"sw1": transport}), [])
    ctx._emit_progress = _redacting
    result = await WaitForCliHandler().execute(ctx)

    assert result.success is False
    log = _log(events)
    assert "password [redacted]" in log
    assert SECRET not in log
    assert all(attrs["milestone"] == "output" for _, attrs in events)
    assert all(attrs["device_name"] == "sw1" for _, attrs in events)
    assert SECRET not in caplog.text
    assert "show install summary" not in caplog.text
    assert SECRET not in (result.error or "")
    assert SECRET not in result.summary


async def test_several_devices_in_parallel_with_one_failing(clock):
    names = ["sw1", "sw2", "sw3"]
    devices = [{"id": n, "name": n, "mgmt_host": f"192.0.2.{i}"} for i, n in enumerate(names, 1)]
    running = 0
    most = 0

    class Counting(FakeCliTransport):
        async def execute_commands(self, commands):
            nonlocal running, most
            running += 1
            most = max(most, running)
            try:
                await asyncio.sleep(0)
                return await super().execute_commands(commands)
            finally:
                running -= 1

    transports = {
        "sw1": Counting([INSTALLING, COMMITTED]),
        "sw2": Counting([INSTALLING]),
        "sw3": Counting([COMMITTED]),
    }
    events: list = []
    ctx = _ctx(_cli_config(max_wait_seconds=60), CliServices(transports), events, devices)

    result = await WaitForCliHandler().execute(ctx)

    assert result.success is False
    error = result.error or ""
    assert error.startswith("sw2: condition not met within 60 s")
    assert "sw1" not in error and "sw3" not in error
    out = result.output["devices"]
    assert [out[n]["matched"] for n in names] == [True, False, True]
    assert [e["name"] for e in result.evidence] == [f"show install summary ({n})" for n in names]
    assert most > 1
    assert result.metrics["matched_count"] == 2


async def test_a_long_last_output_is_cut_in_the_output_only(clock):
    long_output = COMMITTED + "\n" + "x" * 10_000
    transport = FakeCliTransport([long_output])

    result, _ = await _run_cli(transport)

    assert len(result.output["devices"]["sw1"]["last_output"]) == 4096
    assert result.output["truncated"] == ["sw1"]
    assert result.evidence[0]["content_text"] == long_output


async def test_the_step_settings_reach_the_transport(clock):
    transport = FakeCliTransport([COMMITTED])
    services = CliServices({"sw1": transport})
    config = _cli_config(connect_timeout_seconds=7, command_timeout_seconds=40)
    config["allow_legacy_ssh"] = True

    result = await WaitForCliHandler().execute(_ctx(config, services, []))

    assert result.success is True
    [call] = services.connect_calls
    assert call["connect_timeout"] == 7.0
    assert call["command_timeout"] == 40.0
    assert call["step_run_id"] == "sr"
    assert transport.legacy is True


async def test_a_transport_without_held_sessions_logs_in_every_poll(clock):
    calls: list[str] = []

    class PerCall:
        async def execute_commands(self, commands):
            calls.append(commands[0])
            if len(calls) == 1:
                return [CliResult(commands[0], "", -1, "SSH connection failed: refused")]
            return [CliResult(commands[0], COMMITTED if len(calls) > 2 else INSTALLING)]

    result, _ = await _run_cli(PerCall())

    assert result.success is True
    device = result.output["devices"]["sw1"]
    assert device["attempts"] == 3
    # The failed first login was no session, so nothing reconnected.
    assert device["reconnects"] == 0
    assert len(calls) == 3


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"pattern": "("}, "not a valid regular expression"),
        ({"pattern": ""}, "pattern"),
        ({"command": ""}, "command"),
        ({"until": "sometimes"}, "until"),
    ],
)
async def test_a_bad_config_fails_before_connecting(clock, config, message):
    transport = FakeCliTransport([COMMITTED])
    services = CliServices({"sw1": transport})

    result = await WaitForCliHandler().execute(_ctx(_cli_config(**config), services, []))

    assert result.success is False
    assert message in (result.error or "")
    assert services.connect_calls == []


@pytest.mark.parametrize("missing", ["pattern", "command"])
async def test_an_omitted_pattern_or_command_is_refused(clock, missing):
    """An empty pattern would match any output, so the step would pass at once."""
    transport = FakeCliTransport([COMMITTED])
    services = CliServices({"sw1": transport})
    config = _cli_config()
    del config[missing]

    result = await WaitForCliHandler().execute(_ctx(config, services, []))

    assert result.success is False
    assert missing in (result.error or "")
    assert services.connect_calls == []


async def test_a_device_error_line_reaches_the_live_log_only(clock):
    """The error line is device output: only the redacted live log may carry it."""
    failed = CliResult("", f"% Bad secret {SECRET}", 1, f"% Bad secret {SECRET}")
    transport = FakeCliTransport([failed])

    result, events = await _run_cli(transport, max_wait_seconds=10)

    assert result.success is False
    assert "command failed: the device reported an error" in (result.error or "")
    assert SECRET not in (result.error or "")
    assert SECRET not in result.summary
    assert SECRET not in str(result.output["devices"]["sw1"]["error"])
    assert f"(% Bad secret {SECRET})" in _log(events)


async def test_netcli_wait_for_end_to_end_on_one_ssh_login():
    async with ssh_servers() as servers:
        await _end_to_end(servers)


async def _end_to_end(servers: Servers) -> None:
    port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))

    class Services:
        def connect(self, device, *, connect_timeout=None, command_timeout=None, **kwargs):
            spec = DeviceConnectionSpec(
                host="127.0.0.1",
                port=port,
                username=USERNAME,
                password=PASSWORD,
                platform="ios-xe",
                connect_timeout=connect_timeout or 5.0,
                command_timeout=command_timeout or 5.0,
            )
            return SSHTransport(spec, host_key_verifier=checks_off())

    events: list = []
    config = _cli_config(command="show clock", pattern="output of show clock", stable_polls=2)
    config["poll_interval_seconds"] = 1
    result = await WaitForCliHandler().execute(_ctx(config, Services(), events))

    assert result.success is True, result.error
    assert result.output["devices"]["sw1"]["attempts"] == 2
    assert len(servers.seen.connections) == 1


async def test_a_per_call_transport_that_cannot_log_in_stops_at_once(clock):
    class PerCall:
        async def execute_commands(self, commands):
            return [CliResult(commands[0], "", -1, "Authentication failed: bad password")]

    result, _ = await _run_cli(PerCall())

    assert result.success is False
    device = result.output["devices"]["sw1"]
    assert device["attempts"] == 1
    assert device["error"] == "cannot log in: the device refused the login"


async def test_a_one_second_wait_still_polls_once(clock):
    transport = FakeCliTransport([COMMITTED])

    result, _ = await _run_cli(transport, max_wait_seconds=1)

    assert result.success is True
    assert result.output["devices"]["sw1"]["attempts"] == 1


def test_output_too_long_to_search_never_meets_the_condition():
    MAX_REGEX_INPUT_CHARS = netcli_waiting.MAX_REGEX_INPUT_CHARS
    condition_met = netcli_waiting.condition_met

    compiled = re.compile("FAILED")
    long_text = "x" * MAX_REGEX_INPUT_CHARS + "FAILED"
    assert condition_met(compiled, long_text, until="not_matches", scope="output") is False
    assert condition_met(compiled, "x" * 10, until="not_matches", scope="output") is True
    # A cut-off prefix proves nothing for "matches" either: no match at the cut.
    found_early = "FAILED" + "x" * MAX_REGEX_INPUT_CHARS
    assert condition_met(compiled, found_early, until="matches", scope="lines") is False
    anchored = re.compile("x$")
    assert (
        condition_met(
            anchored, "x" * (MAX_REGEX_INPUT_CHARS + 1) + "\n!", until="matches", scope="output"
        )
        is False
    )
    exact = "y" * (MAX_REGEX_INPUT_CHARS - 6) + "FAILED"
    assert condition_met(compiled, exact, until="matches", scope="output") is True


async def test_a_reconnect_counts_every_new_login_after_a_loss(clock):
    """Session A drops, B drops on its first command, C matches: two reconnects."""
    transport = FakeCliTransport([INSTALLING, "DROP", "DROP", COMMITTED])

    result, _ = await _run_cli(transport)

    assert result.success is True
    assert transport.login_calls == 3
    assert result.output["devices"]["sw1"]["reconnects"] == 2


async def test_a_channel_refusal_reason_reaches_the_live_log_only(clock):
    refused = CliResult("", "", -1, f"Channel open failed: {SECRET}")
    transport = FakeCliTransport([refused])

    result, events = await _run_cli(transport, max_wait_seconds=10)

    assert result.success is False
    error = result.output["devices"]["sw1"]["error"]
    assert "session lost: the command did not complete" in error
    assert SECRET not in (result.error or "") and SECRET not in result.summary
    assert SECRET in _log(events)


async def test_a_match_that_ends_after_max_wait_does_not_count(clock):
    class Slow(FakeCliTransport):
        async def execute_commands(self, commands):
            clock.now += 15  # the command outlasts the 10 s Max Wait
            return await super().execute_commands(commands)

    transport = Slow([COMMITTED])

    result, events = await _run_cli(transport, max_wait_seconds=10)

    assert result.success is False
    assert result.output["devices"]["sw1"]["matched"] is False
    assert "ended after Max Wait" in _log(events)


async def test_devices_that_share_a_name_keep_their_own_entries(clock):
    devices = [
        {"id": "d1", "name": "sw1", "mgmt_host": "192.0.2.1"},
        {"id": "d2", "name": "sw1", "mgmt_host": "192.0.2.2"},
    ]

    class ById(CliServices):
        def connect(self, device, **kwargs):
            self.connect_calls.append(kwargs)
            return self.transports[device["id"]]

    transports = {"d1": FakeCliTransport([COMMITTED]), "d2": FakeCliTransport([INSTALLING])}
    ctx = _ctx(_cli_config(max_wait_seconds=10), ById(transports), [], devices)

    result = await WaitForCliHandler().execute(ctx)

    out = result.output["devices"]
    assert set(out) == {"sw1 (d1)", "sw1 (d2)"}
    assert out["sw1 (d1)"]["matched"] is True and out["sw1 (d2)"]["matched"] is False
    assert (result.error or "").startswith("sw1 (d2): ")


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"command": "   "}, "command must not be blank"),
        ({"pattern": "a{99999999999}"}, "not a valid regular expression"),
    ],
)
async def test_a_blank_command_or_an_oversized_repeat_is_refused(clock, config, message):
    services = CliServices({"sw1": FakeCliTransport([COMMITTED])})

    result = await WaitForCliHandler().execute(_ctx(_cli_config(**config), services, []))

    assert result.success is False
    assert message in (result.error or "")
    assert services.connect_calls == []
