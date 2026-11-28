# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``shell.watch``: follow a long command on every host for a set time."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_steps_shell.watch import (
    KILL_AFTER_SECONDS,
    RUN_GRACE_SECONDS,
    ShellWatchHandler,
    build_watch_command,
)

SW1 = {"id": "d1", "name": "web1", "mgmt_host": "192.0.2.10"}
SW2 = {"id": "d2", "name": "web2", "mgmt_host": "192.0.2.11"}


@dataclass
class ShellResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str = ""


class FakeShell:
    def __init__(self, item: Any, owner: Services, streams: bool) -> None:
        self.item = item
        self.owner = owner
        self.closed = False
        if streams:
            self.streams_exec_output = True

    async def run(self, command, *, timeout=None):
        self.owner.runs.append((command, timeout))
        await asyncio.sleep(0)
        if isinstance(self.item, Exception):
            raise self.item
        exit_code, stdout, stderr = self.item
        return ShellResult(command, exit_code, stdout, stderr)

    async def close(self):
        self.closed = True


class Services:
    """``results`` maps a host's mgmt_host to its run result, or a login exception."""

    def __init__(self, results: dict[str, Any], *, streams: bool = False) -> None:
        self.results = results
        self.streams = streams
        self.opened: list[dict[str, Any]] = []
        self.shells: list[FakeShell] = []
        self.runs: list[tuple[str, float | None]] = []

    async def open_shell(self, device, **kwargs):
        self.opened.append(kwargs)
        item = self.results[device["mgmt_host"]]
        if isinstance(item, tuple) and item and item[0] == "LOGIN":
            raise item[1]
        shell = FakeShell(item, self, self.streams)
        self.shells.append(shell)
        return shell


def _ctx(config: dict[str, Any], services: Any, events: list, devices=None, timeout=None):
    async def _record(message, device_id, attrs):
        events.append((message, attrs))
        return True

    handler = ShellWatchHandler()
    duration = config.get("duration_seconds", 300)
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        target_roles=["primary"],
        target_devices_by_role={"primary": devices or [SW1]},
        services=cast(HandlerServices, services),
        timeout_seconds=timeout or duration + handler.run_timeout_margin_seconds,
        _emit_progress=_record,
    )


def _config(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {"command": "tail -F /var/log/syslog", "duration_seconds": 60}
    config.update(overrides)
    return config


def _log(events: list) -> str:
    return "".join(message for message, _ in events)


LOG = "Nov 28 10:00:01 web1 nginx: started\nNov 28 10:00:05 web1 kernel: link up\n"


async def _run(results, events=None, devices=None, timeout=None, streams=False, **config):
    events = [] if events is None else events
    services = Services(results, streams=streams)
    ctx = _ctx(_config(**config), services, events, devices=devices, timeout=timeout)
    return await ShellWatchHandler().execute(ctx), services, events


async def test_a_watch_that_runs_until_duration_passes():
    result, services, events = await _run({"192.0.2.10": (124, LOG, "")})

    assert result.success is True
    command, timeout = services.runs[0]
    assert command == build_watch_command(
        "tail -F /var/log/syslog", shell="sh", duration_seconds=60
    )
    assert command == f"timeout -k {KILL_AFTER_SECONDS} 60 sh -c 'tail -F /var/log/syslog'"
    assert timeout == 60 + KILL_AFTER_SECONDS + RUN_GRACE_SECONDS
    assert services.opened[0]["connect_timeout"] == 10.0
    assert services.shells[0].closed is True
    device = result.output["devices"]["web1"]
    assert device == {
        "ended": "duration",
        "exit_code": 124,
        "lines": 2,
        "fail_matches": [],
        "expect_matched": None,
        "error": None,
    }
    assert result.output["passed"] is True
    assert result.output["stdout"] == LOG
    assert result.metrics["duration_seconds"] == 60
    [evidence] = result.evidence
    assert evidence["name"] == "tail -F /var/log/syslog"
    assert evidence["content_text"] == LOG
    assert evidence["content_json"]["ended"] == "duration"
    log = _log(events)
    assert "watching for 60 s: tail -F /var/log/syslog\n" in log
    assert LOG in log


@pytest.mark.parametrize("exit_code", [124, 137, 143])
async def test_every_timeout_exit_code_ends_the_watch_normally(exit_code):
    result, _, _ = await _run({"192.0.2.10": (exit_code, LOG, "")})

    assert result.success is True
    assert result.output["devices"]["web1"]["ended"] == "duration"


async def test_a_command_that_ends_by_itself_with_zero_passes():
    result, _, _ = await _run({"192.0.2.10": (0, LOG, "")}, command="journalctl -n 20")

    assert result.success is True
    assert result.output["devices"]["web1"]["ended"] == "exited"


async def test_a_command_that_fails_early_fails_the_host():
    result, _, _ = await _run(
        {"192.0.2.10": (1, "", "tail: cannot open '/var/log/nope' for reading\n")},
        command="tail -f /var/log/nope",
    )

    assert result.success is False
    device = result.output["devices"]["web1"]
    assert device["ended"] == "failed"
    assert device["error"] == "exit 1 (tail: cannot open '/var/log/nope' for reading)"
    assert "web1: exit 1" in result.error


async def test_a_host_without_timeout_fails_plainly():
    result, _, _ = await _run({"192.0.2.10": (127, "", "sh: timeout: not found\n")})

    assert result.success is False
    assert "timeout: not found" in result.error


async def test_a_line_that_matches_fail_pattern_fails_the_host():
    text = LOG + "Nov 28 10:00:09 web1 kernel: Out of memory: Killed process 42\n"
    result, _, _ = await _run({"192.0.2.10": (124, text, "")}, fail_pattern="(?i)out of memory")

    assert result.success is False
    device = result.output["devices"]["web1"]
    assert device["fail_matches"] == [
        "Nov 28 10:00:09 web1 kernel: Out of memory: Killed process 42"
    ]
    assert device["error"] == "1 line(s) matched fail_pattern"
    assert result.output["passed"] is False


async def test_fail_pattern_also_reads_stderr():
    result, _, _ = await _run(
        {"192.0.2.10": (124, LOG, "ERROR: disk full\n")}, fail_pattern="ERROR"
    )

    assert result.success is False
    assert result.output["devices"]["web1"]["fail_matches"] == ["ERROR: disk full"]


async def test_fail_matches_are_capped():
    text = "".join(f"error {n}\n" for n in range(50))
    result, _, _ = await _run({"192.0.2.10": (124, text, "")}, fail_pattern="error")

    device = result.output["devices"]["web1"]
    assert len(device["fail_matches"]) == 20
    assert device["error"] == "at least 20 lines matched fail_pattern"


async def test_expect_pattern_must_match_a_line():
    seen, _, _ = await _run({"192.0.2.10": (124, LOG, "")}, expect_pattern="nginx: started$")
    missing, _, _ = await _run({"192.0.2.10": (124, LOG, "")}, expect_pattern="BGP.*Established")

    assert seen.success is True
    assert seen.output["devices"]["web1"]["expect_matched"] is True
    assert missing.success is False
    assert missing.output["devices"]["web1"]["expect_matched"] is False
    assert missing.output["devices"]["web1"]["error"] == "no line matched expect_pattern"


async def test_one_failing_host_keeps_the_others_results():
    results = {
        "192.0.2.10": (124, LOG, ""),
        "192.0.2.11": ("LOGIN", ConnectionRefusedError("[Errno 111] Connection refused")),
    }
    result, services, _ = await _run(results, devices=[SW1, SW2])

    assert result.success is False
    assert result.output["devices"]["web1"]["error"] is None
    assert result.output["devices"]["web2"]["error"] == "[Errno 111] Connection refused"
    assert [item["name"] for item in result.evidence] == ["tail -F /var/log/syslog (web1)"]
    assert result.error == "web2: [Errno 111] Connection refused"


async def test_hosts_are_watched_at_the_same_time():
    running = 0
    peak = 0

    class Slow(FakeShell):
        async def run(self, command, *, timeout=None):
            nonlocal running, peak
            running += 1
            peak = max(peak, running)
            await asyncio.sleep(0.01)
            running -= 1
            return await super().run(command, timeout=timeout)

    devices = [{"id": f"d{n}", "name": f"h{n}", "mgmt_host": f"192.0.2.{n}"} for n in range(5)]

    class SlowServices(Services):
        async def open_shell(self, device, **kwargs):
            return Slow(self.results[device["mgmt_host"]], self, False)

    services = SlowServices({d["mgmt_host"]: (124, "x\n", "") for d in devices})
    result = await ShellWatchHandler().execute(_ctx(_config(), services, [], devices=devices))

    assert result.success is True
    assert peak == 5


async def test_more_hosts_than_can_be_watched_at_once_are_refused():
    devices = [{"id": f"d{n}", "name": f"h{n}", "mgmt_host": f"192.0.2.{n}"} for n in range(33)]
    result, services, _ = await _run({}, devices=devices)

    assert result.success is False
    assert "at most 32 hosts" in result.error
    assert services.opened == []


async def test_a_lost_connection_fails_the_host():
    result, _, events = await _run({"192.0.2.10": ConnectionResetError("reset by peer")})

    assert result.success is False
    assert result.output["devices"]["web1"]["error"] == (
        "the connection was lost (ConnectionResetError)"
    )
    assert "reset by peer" in _log(events)


async def test_a_command_that_does_not_stop_fails_the_host():
    result, _, _ = await _run({"192.0.2.10": TimeoutError("timed out")})

    assert result.success is False
    assert "did not stop when Duration was up" in result.error


async def test_a_short_step_timeout_shortens_the_watch():
    margin = ShellWatchHandler.run_timeout_margin_seconds
    result, services, _ = await _run(
        {"192.0.2.10": (124, LOG, "")}, duration_seconds=600, timeout=margin + 100
    )

    assert result.success is True
    assert " 100 sh -c " in services.runs[0][0]
    assert result.metrics["duration_seconds"] == 100


async def test_a_step_timeout_that_leaves_no_time_is_refused():
    margin = ShellWatchHandler.run_timeout_margin_seconds
    result, services, _ = await _run({"192.0.2.10": (124, LOG, "")}, timeout=margin)

    assert result.success is False
    assert "leaves no time to watch" in result.error
    assert services.opened == []


async def test_streamed_output_is_not_written_twice():
    result, _, events = await _run({"192.0.2.10": (124, LOG, "")}, streams=True)

    assert result.success is True
    assert LOG not in _log(events)


async def test_bash_interpreter():
    _, services, _ = await _run({"192.0.2.10": (124, LOG, "")}, shell="bash")

    assert services.runs[0][0].endswith(" 60 bash -c 'tail -F /var/log/syslog'")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"command": "   "}, "command"),
        ({"fail_pattern": "("}, "fail_pattern is not a valid regular expression"),
        ({"expect_pattern": "[a-"}, "expect_pattern is not a valid regular expression"),
        ({"duration_seconds": 0}, "duration_seconds"),
        ({"shell": "pwsh"}, "shell"),
    ],
)
async def test_invalid_settings_are_refused(overrides, message):
    result, services, _ = await _run({"192.0.2.10": (124, LOG, "")}, **overrides)

    assert result.success is False
    assert message in (result.error or "")
    assert services.opened == []


async def test_no_targets():
    services = Services({})
    ctx = _ctx(_config(), services, [])
    ctx.target_devices_by_role = {"primary": []}

    result = await ShellWatchHandler().execute(ctx)

    assert result.success is False
    assert result.error == "No target devices configured"


def test_template_values_must_be_quoted():
    handler = ShellWatchHandler()

    assert handler.template_errors(_config(command="tail -F {{ inputs.file | quote }}")) == []
    errors = handler.template_errors(_config(command="tail -F {{ inputs.file }}"))
    assert len(errors) == 1
    assert errors[0].startswith("commands line 1:")


def test_run_timeout_covers_the_duration():
    handler = ShellWatchHandler()

    assert handler.run_timeout_field == "duration_seconds"
    assert handler.run_timeout_margin_seconds >= KILL_AFTER_SECONDS + RUN_GRACE_SECONDS


@pytest.mark.skipif(shutil.which("timeout") is None, reason="needs the timeout tool")
def test_the_remote_command_stops_a_follower_and_keeps_its_output():
    command = build_watch_command(
        "while true; do echo tick; sleep 0.2; done", shell="sh", duration_seconds=1
    )

    completed = subprocess.run(  # noqa: S602 - a fixed, local test command
        command, shell=True, capture_output=True, text=True, timeout=20, check=False
    )

    assert completed.returncode == 124
    assert completed.stdout.count("tick") >= 2
