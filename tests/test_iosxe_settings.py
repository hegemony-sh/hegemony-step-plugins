# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The IOS-XE upgrade steps run with their config model's values.

The platform renders a step's ``{{ }}`` templates to text before the step
runs, so a switch set by a template arrives as "False". Read raw, that text
counted as on: install activated (a reload) and committed, rewrote the boot
setting and saved the configuration, stage re-transferred, cleanup removed
packages. Preflight without Min Free Space skipped the disk check its model
default promises. The steps now read their settings through the model.
"""

from __future__ import annotations

from typing import Any

import pytest

from hegemony_steps_cisco_iosxe.upgrade.driver import (
    CleanupResult,
    InstallResult,
    PreflightResult,
    StageResult,
    VerifyResult,
)
from hegemony_steps_cisco_iosxe.upgrade.handlers import (
    cleanup as cleanup_module,
    install as install_module,
    preflight as preflight_module,
    stage as stage_module,
    verify as verify_module,
)
from hegemony_steps_cisco_iosxe.upgrade.handlers.cleanup import UpgradeCleanupHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.install import UpgradeInstallHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.preflight import UpgradePreflightHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.stage import (
    UpgradeStageConfig,
    UpgradeStageHandler,
)
from hegemony_steps_cisco_iosxe.upgrade.handlers.verify import UpgradeVerifyHandler
from tests.iosxe_fakes import FakeServices, InstantClock, Result, ScriptedTransport, make_ctx

STAGE = {"source_url": "https://repo.example/img.bin", "dest_filename": "img.bin"}


class _RecordingDriver:
    """An upgrade driver that records the settings each operation got."""

    def __init__(self) -> None:
        self.calls: dict[str, dict[str, Any]] = {}
        self.platforms: list[str] = []

    async def preflight(self, ssh, **kwargs) -> PreflightResult:
        self.calls["preflight"] = kwargs
        return PreflightResult(success=True)

    async def stage(self, ssh, **kwargs) -> StageResult:
        self.calls["stage"] = kwargs
        return StageResult(success=True, staged=True)

    async def install(self, ssh, **kwargs) -> InstallResult:
        self.calls["install"] = kwargs
        return InstallResult(success=True)

    async def verify(self, ssh, **kwargs) -> VerifyResult:
        self.calls["verify"] = kwargs
        return VerifyResult(success=True)

    async def cleanup(self, ssh, **kwargs) -> CleanupResult:
        self.calls["cleanup"] = kwargs
        return CleanupResult(success=True)


@pytest.fixture
def driver(monkeypatch) -> _RecordingDriver:
    recording = _RecordingDriver()

    def _get_driver(platform, mode):
        recording.platforms.append(platform)
        return recording

    for module in (preflight_module, stage_module, install_module, verify_module, cleanup_module):
        monkeypatch.setattr(module, "get_driver", _get_driver)
    monkeypatch.setattr(verify_module, "asyncio", InstantClock())
    return recording


def _services() -> FakeServices:
    return FakeServices(lambda: ScriptedTransport({"show clock": Result("10:00:00 UTC")}))


@pytest.mark.parametrize("rendered", ["False", "false", "0"])
@pytest.mark.parametrize("name", ["activate", "commit", "fix_boot_config"])
async def test_install_reads_a_rendered_false_as_off(driver, name, rendered):
    config = {"image_name": "img.bin", "activate": True, "commit": True, name: rendered}
    result = await UpgradeInstallHandler().execute(make_ctx(config, _services()))
    assert result.success is True, result.error
    assert driver.calls["install"][name] is False


async def test_install_reads_a_rendered_true_as_on(driver):
    config = {"image_name": "img.bin", "fix_boot_config": "True"}
    await UpgradeInstallHandler().execute(make_ctx(config, _services()))
    assert driver.calls["install"]["fix_boot_config"] is True


async def test_rendered_false_activate_never_reloads_the_device():
    """End to end: no boot check, no activate keyword, no reload."""
    ssh = ScriptedTransport({"install add": Result("SUCCESS: install_add  Mon Oct  5\n")})
    config = {"image_name": "img.bin", "activate": "False", "commit": "False"}
    result = await UpgradeInstallHandler().execute(make_ctx(config, FakeServices(lambda: ssh)))
    assert result.success is True, result.error
    assert ssh.commands == ["install add file flash:img.bin"]
    assert result.evidence[0]["content_json"]["reboot_triggered"] is False


async def test_rendered_false_fix_boot_config_never_rewrites_the_boot_setting():
    ssh = ScriptedTransport(
        {"show boot": Result("BOOT variable = flash:old.bin;\n"), "write memory": Result("[OK]")}
    )
    config = {"image_name": "img.bin", "fix_boot_config": "False"}
    result = await UpgradeInstallHandler().execute(make_ctx(config, FakeServices(lambda: ssh)))
    assert result.success is False
    assert "turn on fix_boot_config" in result.evidence[0]["content_json"]["error"]
    assert ssh.commands == ["show boot"]


async def test_install_without_an_image_name_fails_before_connecting(driver):
    services = _services()
    result = await UpgradeInstallHandler().execute(make_ctx({"image_name": ""}, services))
    assert result.success is False
    assert (result.error or "").startswith("Invalid cisco.iosxe.upgrade.install config:")
    assert services.connect_calls == []


@pytest.mark.parametrize(("rendered", "expected"), [("False", False), ("true", True)])
async def test_stage_reads_a_rendered_overwrite(driver, rendered, expected):
    config = {**STAGE, "overwrite": rendered}
    result = await UpgradeStageHandler().execute(make_ctx(config, _services()))
    assert result.success is True, result.error
    assert driver.calls["stage"]["overwrite"] is expected


async def test_stage_reads_a_rendered_expected_size_as_a_number(driver):
    config = {**STAGE, "expected_size": "987654321"}
    await UpgradeStageHandler().execute(make_ctx(config, _services()))
    assert driver.calls["stage"]["expected_size"] == 987654321


async def test_stage_refuses_a_legacy_transfer_method_before_connecting(driver):
    services = _services()
    config = {**STAGE, "transfer_method": "tftp"}
    result = await UpgradeStageHandler().execute(make_ctx(config, services))
    assert result.success is False
    assert "transfer_method" in (result.error or "")
    assert services.connect_calls == []


def test_stage_takes_one_file_id_given_as_text():
    assert UpgradeStageConfig.model_validate({"file_ids": "abc"}).file_ids == ["abc"]


@pytest.mark.parametrize("rendered", ["False", "false"])
async def test_cleanup_reads_a_rendered_false_as_skip(driver, rendered):
    services = _services()
    result = await UpgradeCleanupHandler().execute(
        make_ctx({"remove_inactive": rendered}, services)
    )
    assert result.success is True
    assert "skipped" in result.summary
    assert services.connect_calls == []
    assert "cleanup" not in driver.calls


async def test_cleanup_reads_rendered_numbers(driver):
    config = {"upgrade_mode": "bundle", "remove_inactive": "True", "keep_versions": "2"}
    await UpgradeCleanupHandler().execute(make_ctx(config, _services()))
    assert driver.calls["cleanup"] == {"remove_inactive": True, "keep_versions": 2}


async def test_preflight_without_min_free_bytes_checks_the_model_default(driver):
    await UpgradePreflightHandler().execute(make_ctx({}, _services()))
    assert driver.calls["preflight"]["min_free_bytes"] == 1073741824


async def test_preflight_without_min_free_bytes_fails_a_device_short_of_space():
    ssh = ScriptedTransport(
        {
            "show version": Result("Cisco IOS XE Software, Version 17.06.05"),
            "dir": Result("1000 bytes total (500000000 bytes free)"),
            "show install summary": Result("IMG   C    17.06.05.0.6\n"),
        }
    )
    result = await UpgradePreflightHandler().execute(make_ctx({}, FakeServices(lambda: ssh)))
    assert result.success is False
    assert "Insufficient disk space" in result.evidence[0]["content_json"]["error"]


async def test_preflight_reads_a_rendered_min_free_bytes(driver):
    await UpgradePreflightHandler().execute(make_ctx({"min_free_bytes": "200000000"}, _services()))
    assert driver.calls["preflight"]["min_free_bytes"] == 200000000


async def test_verify_reads_the_pre_upgrade_version_setting(driver):
    config = {"preflight_version": "17.06.05", "max_wait_seconds": 60}
    await UpgradeVerifyHandler().execute(make_ctx(config, _services()))
    assert driver.calls["verify"]["preflight_version"] == "17.06.05"


async def test_verify_without_a_pre_upgrade_version_passes_none(driver):
    await UpgradeVerifyHandler().execute(make_ctx({"max_wait_seconds": 60}, _services()))
    assert driver.calls["verify"]["preflight_version"] is None


@pytest.mark.parametrize(
    ("handler", "config"),
    [
        (UpgradePreflightHandler, {}),
        (UpgradeStageHandler, STAGE),
        (UpgradeInstallHandler, {"image_name": "img.bin"}),
        (UpgradeVerifyHandler, {"max_wait_seconds": 60}),
        (UpgradeCleanupHandler, {}),
    ],
    ids=["preflight", "stage", "install", "verify", "cleanup"],
)
async def test_a_step_that_names_its_platform_keeps_it(driver, handler, config):
    services = _services()
    await handler().execute(make_ctx({**config, "platform": "cisco-ios-xe"}, services))
    assert driver.platforms == ["cisco-ios-xe"]
    assert {call["platform"] for call in services.connect_calls} == {"cisco-ios-xe"}
