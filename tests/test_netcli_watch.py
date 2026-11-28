# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``netcli.watch``: follow what network devices print for a set time."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any, cast

import asyncssh
import pytest

from hegemony_step_sdk import DeviceConnectionSpec, HandlerContext, HandlerServices
from hegemony_steps_netcli.watch import WatchCliHandler
from hegemony_transport_netmiko.transport import SSHTransport
from tests.ssh_fakes import MONITOR_MESSAGES, PASSWORD, USERNAME, Servers, checks_off, ssh_servers

R1 = {"id": "d1", "name": "r1", "mgmt_host": "192.0.2.1", "platform": "ios-xe"}
R2 = {"id": "d2", "name": "r2", "mgmt_host": "192.0.2.2", "platform": "ios-xe"}

LOG = (
    "\r\n%LINK-3-UPDOWN: Interface Gi1, changed state to down\r\n"
    "\r\n%LINK-3-UPDOWN: Interface Gi1, changed state to up\r\n"
)


@dataclass
class Result:
    command: str
    output: str
    exit_code: int = 0
    error: str | None = None
    latency_ms: float = 0.0


@dataclass
class Watched:
    setup: list[Result] = field(default_factory=list)
    output: str = ""
    disconnected: bool = False
    cancelled: bool = False
    error: str | None = None
    elapsed_seconds: float = 0.0


class FakeTransport:
    supports_cli_watch = True

    def __init__(self, watched: Watched | Exception, streams: bool = False) -> None:
        self.watched = watched
        self.calls: list[tuple[list[str], float, float]] = []
        self.streams_watch_output = streams
        self.legacy: bool | None = None

    def configure_ssh_security(self, *, allow_legacy: bool = False) -> None:
        self.legacy = allow_legacy

    async def watch_output(self, commands, *, duration_seconds, keepalive_seconds=0):
        self.calls.append((list(commands), duration_seconds, keepalive_seconds))
        await asyncio.sleep(0)
        if isinstance(self.watched, Exception):
            raise self.watched
        return self.watched


class NoWatchTransport:
    def configure_ssh_security(self, *, allow_legacy: bool = False) -> None:
        return None


class Services:
    """``transports`` maps a device's name to its transport, or an exception ``connect`` raises."""

    def __init__(self, transports: dict[str, Any]) -> None:
        self.transports = transports
        self.connected: list[dict[str, Any]] = []

    def connect(self, device, **kwargs):
        self.connected.append(kwargs)
        item = self.transports[device["name"]]
        if isinstance(item, Exception):
            raise item
        return item


def _ctx(config, services, events, devices=None, timeout=None) -> HandlerContext:
    async def _record(message, device_id, attrs):
        events.append((message, attrs))
        return True

    duration = config.get("duration_seconds", 300)
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        target_roles=["primary"],
        target_devices_by_role={"primary": devices or [R1]},
        services=cast(HandlerServices, services),
        timeout_seconds=timeout or duration + WatchCliHandler.run_timeout_margin_seconds,
        _emit_progress=_record,
    )


def _log(events: list) -> str:
    return "".join(message for message, _ in events)


def _watched(output: str = LOG, **kwargs: Any) -> Watched:
    kwargs.setdefault("setup", [Result("terminal monitor", "")])
    kwargs.setdefault("elapsed_seconds", 60.2)
    return Watched(output=output, **kwargs)


async def _run(transports, events=None, devices=None, timeout=None, **config):
    events = [] if events is None else events
    services = Services(transports)
    base: dict[str, Any] = {"duration_seconds": 60}
    base.update(config)
    result = await WatchCliHandler().execute(
        _ctx(base, services, events, devices=devices, timeout=timeout)
    )
    return result, services, events


async def test_a_watch_that_runs_to_the_end_passes():
    transport = FakeTransport(_watched())

    result, services, events = await _run({"r1": transport})

    assert result.success is True
    assert transport.calls == [(["terminal monitor"], 60.0, 300.0)]
    assert services.connected[0]["connect_timeout"] == 10.0
    assert services.connected[0]["command_timeout"] == 30.0
    assert services.connected[0]["step_run_id"] == "sr"
    assert transport.legacy is False
    assert result.output["devices"]["r1"] == {
        "ended": "duration",
        "elapsed_seconds": 60,
        "lines": 2,
        "fail_matches": [],
        "expect_matched": None,
        "error": None,
    }
    assert result.output["passed"] is True
    assert "changed state to up" in result.output["stdout"]
    [evidence] = result.evidence
    assert evidence["name"] == "Watch"
    assert evidence["content_text"].startswith("$ terminal monitor\n")
    assert evidence["content_json"]["ended"] == "duration"
    log = _log(events)
    assert "watching for 60 s\n" in log
    assert "$ terminal monitor\n" in log
    assert LOG in log


async def test_streamed_output_is_not_written_twice():
    result, _, events = await _run({"r1": FakeTransport(_watched(), streams=True)})

    assert result.success is True
    assert LOG not in _log(events)


async def test_a_line_that_matches_fail_pattern_fails_the_device():
    result, _, _ = await _run(
        {"r1": FakeTransport(_watched())}, fail_pattern=r"%LINK-3-UPDOWN: .*down"
    )

    assert result.success is False
    device = result.output["devices"]["r1"]
    assert device["fail_matches"] == ["%LINK-3-UPDOWN: Interface Gi1, changed state to down"]
    assert device["error"] == "1 line(s) matched fail_pattern"


async def test_expect_pattern_must_match_a_line():
    seen, _, _ = await _run({"r1": FakeTransport(_watched())}, expect_pattern="state to up$")
    missing, _, _ = await _run({"r1": FakeTransport(_watched())}, expect_pattern="BGP.*Up")

    assert seen.success is True
    assert seen.output["devices"]["r1"]["expect_matched"] is True
    assert missing.success is False
    assert missing.output["devices"]["r1"]["error"] == "no line matched expect_pattern"


async def test_a_device_that_closes_the_session_fails():
    watched = _watched(disconnected=True, elapsed_seconds=12.4)

    result, _, _ = await _run({"r1": FakeTransport(watched)})

    assert result.success is False
    device = result.output["devices"]["r1"]
    assert device["ended"] == "disconnected"
    assert device["error"] == "the device closed the session after 12 s"


async def test_a_failed_setup_command_fails_the_device():
    watched = Watched(
        setup=[Result("terminal monitr", "% Invalid input", 1, "% Invalid input detected")]
    )

    result, _, events = await _run({"r1": FakeTransport(watched)}, commands=["terminal monitr"])

    assert result.success is False
    device = result.output["devices"]["r1"]
    assert device["ended"] == "failed"
    assert device["error"] == "setup command 'terminal monitr' failed: % Invalid input detected"
    assert "$ terminal monitr\n% Invalid input\n" in _log(events)


async def test_a_refused_login_fails_the_device():
    watched = Watched(error="Authentication failed: bad password")

    result, _, _ = await _run({"r1": FakeTransport(watched)})

    assert result.success is False
    assert result.error == "r1: Authentication failed: bad password"


async def test_a_cancelled_watch_says_so():
    result, _, _ = await _run({"r1": FakeTransport(_watched(cancelled=True))})

    assert result.success is False
    assert result.output["devices"]["r1"]["ended"] == "cancelled"


async def test_a_transport_that_cannot_watch_fails_plainly():
    result, _, _ = await _run({"r1": NoWatchTransport()})

    assert result.success is False
    assert "needs the netmiko or scrapli transport" in result.error


async def test_one_failing_device_keeps_the_others_results():
    transports = {"r1": FakeTransport(_watched()), "r2": ValueError("Device has no password")}

    result, _, _ = await _run(transports, devices=[R1, R2])

    assert result.success is False
    assert result.output["devices"]["r1"]["error"] is None
    assert result.output["devices"]["r2"]["error"] == "Device has no password"
    assert [item["name"] for item in result.evidence] == ["Watch (r1)"]


async def test_a_watch_that_raises_fails_the_device():
    result, _, events = await _run({"r1": FakeTransport(OSError("socket closed"))})

    assert result.success is False
    assert result.output["devices"]["r1"]["error"] == "the watch failed (OSError)"
    assert "socket closed" in _log(events)


async def test_more_devices_than_can_be_watched_at_once_are_refused():
    devices = [{"id": f"d{n}", "name": f"r{n}", "mgmt_host": f"192.0.2.{n}"} for n in range(33)]

    result, services, _ = await _run({}, devices=devices)

    assert result.success is False
    assert "at most 32 devices" in result.error
    assert services.connected == []


async def test_a_short_step_timeout_shortens_the_watch():
    transport = FakeTransport(_watched())
    margin = WatchCliHandler.run_timeout_margin_seconds

    result, _, _ = await _run({"r1": transport}, duration_seconds=600, timeout=margin + 90)

    assert result.success is True
    assert transport.calls[0][1] == 90.0
    assert result.metrics["duration_seconds"] == 90


async def test_settings_reach_the_transport():
    transport = FakeTransport(_watched())

    await _run(
        {"r1": transport},
        commands=["terminal monitor", "", "terminal length 0"],
        keepalive_seconds=0,
        allow_legacy_ssh=True,
    )

    assert transport.calls == [(["terminal monitor", "terminal length 0"], 60.0, 0.0)]
    assert transport.legacy is True


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"fail_pattern": "("}, "fail_pattern is not a valid regular expression"),
        ({"expect_pattern": "[a-"}, "expect_pattern is not a valid regular expression"),
        ({"commands": [f"terminal x{n}" for n in range(11)]}, "at most 10 setup commands"),
        ({"duration_seconds": 0}, "duration_seconds"),
        ({"keepalive_seconds": -1}, "keepalive_seconds"),
    ],
)
async def test_invalid_settings_are_refused(overrides, message):
    result, services, _ = await _run({"r1": FakeTransport(_watched())}, **overrides)

    assert result.success is False
    assert message in (result.error or "")
    assert services.connected == []


def test_run_timeout_covers_the_duration():
    assert WatchCliHandler.run_timeout_field == "duration_seconds"


# --- against the in-process SSH device, through the netmiko transport ------------------------


@pytest.fixture
async def servers() -> AsyncIterator[Servers]:
    async with ssh_servers() as started:
        yield started


class RealServices:
    def __init__(self, port: int) -> None:
        self.port = port

    def connect(self, device, **kwargs):
        spec = DeviceConnectionSpec(
            host="127.0.0.1",
            port=self.port,
            username=USERNAME,
            password=PASSWORD,
            platform="ios-xe",
            connect_timeout=5.0,
            command_timeout=5.0,
        )
        return SSHTransport(spec, host_key_verifier=checks_off())


async def test_the_step_watches_a_real_session(servers):
    port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
    events: list = []
    config = {"duration_seconds": 1, "expect_pattern": "changed state to up"}

    result = await WatchCliHandler().execute(_ctx(config, RealServices(port), events))

    assert result.success is True, result.error
    device = result.output["devices"]["r1"]
    assert device["ended"] == "duration"
    assert device["expect_matched"] is True
    for message in MONITOR_MESSAGES:
        assert message in _log(events)
