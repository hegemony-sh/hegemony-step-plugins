# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The install step returns only once a reloading device has gone down.

The install step used to return as soon as the device accepted the install
or the reload. A device that has not gone down yet keeps answering from its
old image for a while, so the verify step that follows could read the old
version: pass without a target version, or fail an upgrade that is about to
succeed. Now the step checks with a new session every few seconds until the
device stops answering, for up to Reload Wait, and fails a device that never
goes down.
"""

from __future__ import annotations

from typing import Any

import pytest

from hegemony_steps_cisco_iosxe.upgrade.handlers import install as install_module
from hegemony_steps_cisco_iosxe.upgrade.handlers.install import (
    UpgradeInstallConfig,
    UpgradeInstallHandler,
)
from tests.iosxe_fakes import (
    UNREACHABLE,
    FakeServices,
    InstantClock,
    Result,
    ScriptedTransport,
    make_ctx,
)

BOOT_OK = Result("BOOT variable = flash:packages.conf;\nCONFIG_FILE variable = \n")
RELOADING = Result(
    "Activate: Passed on [1]\nFinished Activate\n"
    "Install will reload the system now!\n"
    "SUCCESS: install_add_activate_commit\n"
)
UP = Result("10:00:00.000 UTC Mon Oct 5 2026")

# Bundle mode: the boot change, the save, and a reload whose session closes.
OLD = "bootflash:isr4300.16.09.04.SPA.bin"
NEW = "bootflash:isr4300.17.03.08a.SPA.bin"
BUNDLE = {
    "show boot": [
        Result(f"BOOT variable = {OLD},12;\n"),
        Result(f"BOOT variable = {NEW},12;{OLD},12;\n"),
    ],
    "write memory": Result("Building configuration...\n[OK]\n"),
    "reload": Result("Proceed with reload? [confirm]y\n", exit_code=-1, error="Socket is closed"),
}


@pytest.fixture
def clock(monkeypatch) -> InstantClock:
    instant = InstantClock()
    monkeypatch.setattr(install_module, "asyncio", instant)
    return instant


def _probes(ssh: ScriptedTransport) -> int:
    return ssh.commands.count("show clock")


async def _run(ssh: ScriptedTransport, **config: Any):
    config = {"image_name": "img.bin", **config}
    return await UpgradeInstallHandler().execute(make_ctx(config, FakeServices(lambda: ssh)))


async def test_install_waits_until_the_device_goes_down(clock):
    ssh = ScriptedTransport(
        {"show boot": BOOT_OK, "install add": RELOADING, "show clock": [UP, UP, UNREACHABLE]}
    )
    result = await _run(ssh)
    assert result.success is True, result.error
    assert _probes(ssh) == 3
    evidence = result.evidence[0]["content_json"]
    assert evidence["went_down"] is True
    assert evidence["down_elapsed_sec"] == 10
    assert "Went Down: True" in result.evidence[0]["content_text"]
    assert clock.now == 10


async def test_a_device_that_never_goes_down_fails(clock):
    ssh = ScriptedTransport({"show boot": BOOT_OK, "install add": RELOADING, "show clock": UP})
    result = await _run(ssh, reload_wait_seconds=60)
    assert result.success is False
    assert result.metrics["failure_count"] == 1
    evidence = result.evidence[0]["content_json"]
    assert evidence["success"] is False
    assert evidence["reboot_triggered"] is True
    assert evidence["went_down"] is False
    assert evidence["error"] == (
        "The device reported its reload but still answered 60s later: "
        "it did not go down within Reload Wait (60s)"
    )
    # One check at once, then one every 5 seconds until the limit.
    assert _probes(ssh) == 12
    assert clock.now == 60


class _SlowCheckTransport(ScriptedTransport):
    """Its ``show clock`` takes ``seconds`` on the clock, then answers ``reply``."""

    def __init__(self, clock: InstantClock, seconds: float, reply: Result) -> None:
        super().__init__({"show boot": BOOT_OK, "install add": RELOADING, "show clock": reply})
        self.clock = clock
        self.seconds = seconds

    async def execute_commands(self, commands: list[str]) -> list[Result]:
        if commands == ["show clock"]:
            self.clock.now += self.seconds
        return await super().execute_commands(commands)


async def test_a_check_still_waiting_when_reload_wait_runs_out_fails(clock):
    """A failure seen after Reload Wait does not count as the device going down."""
    ssh = _SlowCheckTransport(clock, 90, UNREACHABLE)
    result = await _run(ssh, reload_wait_seconds=1)
    assert result.success is False
    evidence = result.evidence[0]["content_json"]
    assert evidence["went_down"] is False
    assert evidence["down_elapsed_sec"] == 1
    assert evidence["error"] == (
        "The device reported its reload, but a check for it was still waiting for an "
        "answer when Reload Wait (1s) ran out: it was not seen to go down"
    )
    assert clock.now == 1


async def test_a_check_without_an_answer_in_its_time_counts_as_down(clock):
    ssh = _SlowCheckTransport(clock, 40, UP)
    result = await _run(ssh)
    assert result.success is True, result.error
    evidence = result.evidence[0]["content_json"]
    assert evidence["went_down"] is True
    assert evidence["down_elapsed_sec"] == 30


@pytest.mark.parametrize(("reload_wait", "timeout"), [(300, 30), (10, 10)])
async def test_each_check_session_ends_by_the_end_of_reload_wait(clock, reload_wait, timeout):
    ssh = ScriptedTransport(
        {"show boot": BOOT_OK, "install add": RELOADING, "show clock": UNREACHABLE}
    )
    services = FakeServices(lambda: ssh)
    config = {"image_name": "img.bin", "reload_wait_seconds": reload_wait}
    result = await UpgradeInstallHandler().execute(make_ctx(config, services))
    assert result.success is True, result.error
    check = services.connect_calls[-1]
    assert (check["connect_timeout"], check["command_timeout"]) == (timeout, timeout)


async def test_a_cli_error_is_still_an_answer(clock):
    rejected = Result("% Invalid input detected", exit_code=1, error="% Invalid input")
    ssh = ScriptedTransport(
        {"show boot": BOOT_OK, "install add": RELOADING, "show clock": [rejected, UNREACHABLE]}
    )
    result = await _run(ssh)
    assert result.success is True, result.error
    assert _probes(ssh) == 2


async def test_a_probe_that_raises_counts_as_down(clock):
    ssh = ScriptedTransport({"show boot": BOOT_OK, "install add": RELOADING})

    class _Services(FakeServices):
        def connect(self, device, *, platform=None, **kwargs):
            # The install's own session, then the down check.
            if self.connect_calls:
                raise OSError("No route to host")
            return super().connect(device, platform=platform, **kwargs)

    services = _Services(lambda: ssh)
    result = await UpgradeInstallHandler().execute(make_ctx({"image_name": "img.bin"}, services))
    assert result.success is True, result.error
    assert result.evidence[0]["content_json"]["went_down"] is True


async def test_bundle_mode_waits_after_the_reload_too(clock):
    ssh = ScriptedTransport({**BUNDLE, "show clock": [UP, UNREACHABLE]})
    result = await _run(
        ssh, upgrade_mode="bundle", image_name="isr4300.17.03.08a.SPA.bin", dest_fs="bootflash:"
    )
    assert result.success is True, result.error
    assert ssh.commands.index("reload") < ssh.commands.index("show clock")
    assert _probes(ssh) == 2
    assert result.evidence[0]["content_json"]["went_down"] is True


@pytest.mark.parametrize(
    ("replies", "config"),
    [
        ({"install add": Result("SUCCESS: install_add\n")}, {"activate": False}),
        (
            {
                "show boot": BOOT_OK,
                "install add": Result("Same Image File-No Change\nSUCCESS: install_add\n"),
            },
            {},
        ),
        ({"show boot": BOOT_OK, "install add": RELOADING}, {"reload_wait_seconds": 0}),
        (
            {"show boot": BOOT_OK, "install add": Result("FAILED: install_add : no space\n")},
            {},
        ),
    ],
    ids=["not-activated", "no-change", "wait-off", "install-failed"],
)
async def test_no_down_check_without_a_reload_to_wait_for(clock, replies, config):
    ssh = ScriptedTransport({**replies, "show clock": UP})
    result = await _run(ssh, **config)
    assert _probes(ssh) == 0
    assert result.evidence[0]["content_json"]["went_down"] is None


def test_reload_wait_defaults_to_five_minutes():
    assert UpgradeInstallConfig.model_fields["reload_wait_seconds"].default == 300
    parsed = UpgradeInstallConfig.model_validate({"image_name": "i", "reload_wait_seconds": "0"})
    assert parsed.reload_wait_seconds == 0
