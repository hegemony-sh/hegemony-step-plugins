# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``shell.wait_for``: poll a shell command until its output matches.

Uses the fake clock and context of ``tests/test_netcli_wait_for.py``; the
polling loop is the same module in both wheels.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import hegemony_steps_netcli.waiting as netcli_waiting
import hegemony_steps_shell.waiting as shell_waiting
from hegemony_steps_netcli.wait_for import WaitForCliHandler
from hegemony_steps_shell.wait_for import ShellWaitForHandler
from tests.test_netcli_wait_for import SECRET, FakeClock, Refused, _ctx, _log

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    fake = FakeClock()
    for module in (netcli_waiting, shell_waiting):
        monkeypatch.setattr(module, "monotonic", fake.monotonic)
        monkeypatch.setattr(module, "sleep", fake.sleep)
    return fake


# --- shell.wait_for -------------------------------------------------------------------------


@dataclass
class ShellResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str = ""


class FakeShell:
    """One shell connection; ``script`` items are ShellResult args or an exception to raise."""

    def __init__(self, script: list[Any], owner: ShellServices) -> None:
        self.script = script
        self.owner = owner
        self.closed = False

    async def run(self, command, *, timeout=None):
        assert not self.closed
        self.owner.runs.append((command, timeout))
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        await asyncio.sleep(0)
        if isinstance(item, Exception):
            raise item
        exit_code, stdout, stderr = item
        return ShellResult(command, exit_code, stdout, stderr)

    async def close(self):
        self.closed = True


class ShellServices:
    def __init__(self, script: list[Any], logins: list[Exception | None] | None = None) -> None:
        self.script = script
        self.logins = list(logins or [])
        self.opened: list[dict[str, Any]] = []
        self.shells: list[FakeShell] = []
        self.runs: list[tuple[str, float | None]] = []

    async def open_shell(self, device, **kwargs):
        self.opened.append(kwargs)
        outcome = self.logins.pop(0) if self.logins else None
        if outcome is not None:
            raise outcome
        shell = FakeShell(self.script, self)
        self.shells.append(shell)
        return shell


def _shell_config(**overrides: Any) -> dict[str, Any]:
    config: dict[str, Any] = {
        "command": "systemctl is-active nginx",
        "pattern": "^active$",
        "match_scope": "lines",
        "poll_interval_seconds": 5,
        "max_wait_seconds": 120,
    }
    config.update(overrides)
    return config


async def test_shell_waits_on_one_connection_until_the_service_is_active(clock):
    services = ShellServices(
        [(3, "activating\n", ""), (3, "activating\n", ""), (0, "active\n", "")]
    )
    events: list = []

    result = await ShellWaitForHandler().execute(_ctx(_shell_config(), services, events))

    assert result.success is True
    device = result.output["devices"]["sw1"]
    assert device["attempts"] == 3
    assert device["reconnects"] == 0
    assert len(services.opened) == 1
    assert services.shells[0].closed is True
    assert services.opened[0]["connect_timeout"] == 10.0
    assert all(timeout == 30.0 for _, timeout in services.runs)
    log = _log(events)
    assert log.count("$ systemctl is-active nginx\n") == 3
    assert "command failed: exit 3 (activating)" in log
    assert [attrs["stream"] for _, attrs in events if attrs.get("stream")]


async def test_shell_reconnects_after_a_reboot(clock):
    services = ShellServices(
        [(3, "inactive\n", ""), ConnectionResetError("Connection lost"), (0, "active\n", "")],
        logins=[None, Refused(), None],
    )
    events: list = []

    result = await ShellWaitForHandler().execute(_ctx(_shell_config(), services, events))

    assert result.success is True
    device = result.output["devices"]["sw1"]
    assert device["reconnects"] == 1
    assert len(services.opened) == 3
    assert services.shells[0].closed is True
    log = _log(events)
    assert "session lost (Connection lost)" in log
    assert "not reachable ([Errno 111] Connection refused)" in log


async def test_shell_counts_a_missing_exit_status_as_a_lost_connection(clock):
    services = ShellServices([(-1, "", ""), (0, "active\n", "")])

    result = await ShellWaitForHandler().execute(_ctx(_shell_config(), services, []))

    assert result.success is True
    assert len(services.opened) == 2


async def test_shell_times_out_and_records_the_last_output(clock):
    services = ShellServices([(3, "failed\n", "")])

    result = await ShellWaitForHandler().execute(
        _ctx(_shell_config(max_wait_seconds=10), services, [])
    )

    assert result.success is False
    device = result.output["devices"]["sw1"]
    assert device["last_output"] == "failed\n"
    assert "last poll: command failed: exit 3 (failed)" in device["error"]
    assert result.evidence[0]["content_text"] == "failed\n"


async def test_shell_command_time_is_cut_to_the_deadline(clock):
    services = ShellServices([(0, "activating\n", "")])

    await ShellWaitForHandler().execute(
        _ctx(_shell_config(max_wait_seconds=12, command_timeout_seconds=30), services, [])
    )

    timeouts = [timeout for _, timeout in services.runs]
    assert timeouts[0] == 12.0
    assert (timeouts[-1] or 0) < 12.0


async def test_shell_refuses_an_unquoted_template_value():
    errors = ShellWaitForHandler().template_errors(
        {"command": "systemctl is-active {{ inputs.service }}"}
    )
    assert errors and "quote" in errors[0]
    assert (
        ShellWaitForHandler().template_errors(
            {"command": "systemctl is-active {{ inputs.service | quote }}"}
        )
        == []
    )


async def test_shell_live_log_goes_through_the_hosts_redaction_only(clock, caplog):
    caplog.set_level(logging.DEBUG)
    services = ShellServices([(0, f"token={SECRET}\nactive\n", f"warn {SECRET}\n")])
    events: list = []

    async def _redacting(message, device_id, attrs):
        events.append((message.replace(SECRET, "[redacted]"), attrs))
        return True

    ctx = _ctx(_shell_config(), services, [])
    ctx._emit_progress = _redacting
    result = await ShellWaitForHandler().execute(ctx)

    assert result.success is True
    log = _log(events)
    assert "token=[redacted]" in log and "warn [redacted]" in log
    assert SECRET not in caplog.text
    assert SECRET not in result.summary


async def test_shell_several_hosts_with_one_failing(clock):
    devices = [
        {"id": "h1", "name": "h1", "mgmt_host": "192.0.2.1"},
        {"id": "h2", "name": "h2", "mgmt_host": "192.0.2.2"},
    ]

    class PerHost(ShellServices):
        async def open_shell(self, device, **kwargs):
            self.script = [(0, "active\n", "")] if device["name"] == "h1" else [(3, "failed\n", "")]
            return await super().open_shell(device, **kwargs)

    services = PerHost([])
    result = await ShellWaitForHandler().execute(
        _ctx(_shell_config(max_wait_seconds=20), services, [], devices)
    )

    assert result.success is False
    assert (result.error or "").startswith("h2: ")
    assert result.output["devices"]["h1"]["matched"] is True
    assert result.output["devices"]["h2"]["matched"] is False


# --- the shared module ----------------------------------------------------------------------


def test_both_wheels_carry_the_same_waiting_module():
    """Plugins may not import each other, so each wheel has a copy; they stay equal."""
    netcli = ROOT / "plugins/steps_netcli/src/hegemony_steps_netcli/waiting.py"
    shell = ROOT / "plugins/steps_shell/src/hegemony_steps_shell/waiting.py"
    assert netcli.read_text() == shell.read_text()


def test_both_steps_extend_the_run_timeout_by_their_longest_poll():
    for handler in (WaitForCliHandler, ShellWaitForHandler):
        assert handler.run_timeout_field == "max_wait_seconds"
        assert handler.run_timeout_margin_seconds == netcli_waiting.RUN_TIMEOUT_MARGIN_SECONDS
