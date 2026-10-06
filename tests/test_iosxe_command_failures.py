# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Every IOS-XE upgrade step checks what its commands returned.

No transport raises when a command fails: netmiko and scrapli return exit
code -1, no output and an ``error`` for a connection that failed, and exit
code 1 for a CLI error. A device that cannot be reached must therefore fail
every step, not pass on empty output; and cleanup must not delete images
when it cannot tell which one the device boots.
"""

from __future__ import annotations

from typing import Any

import pytest

from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_bundle import IOSXEBundleDriver
from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_common import stage_image
from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_install import IOSXEInstallDriver
from hegemony_steps_cisco_iosxe.upgrade.handlers import verify as verify_module
from hegemony_steps_cisco_iosxe.upgrade.handlers.cleanup import UpgradeCleanupHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.install import UpgradeInstallHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.preflight import UpgradePreflightHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.stage import UpgradeStageHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.verify import UpgradeVerifyHandler
from tests.iosxe_fakes import (
    UNREACHABLE,
    FakeServices,
    InstantClock,
    Result,
    ScriptedTransport,
    make_ctx,
)

STAGE = {"source_url": "https://repo.example/img.bin", "dest_filename": "img.bin"}
# Verify retries until the device answers, on an instant clock (see below).
VERIFY_WAIT = {"max_wait_seconds": 60, "poll_interval_seconds": 5}


@pytest.fixture(autouse=True)
def _instant_verify_wait(monkeypatch):
    monkeypatch.setattr(verify_module, "asyncio", InstantClock())


STEPS = [
    ("preflight-install", UpgradePreflightHandler, {"upgrade_mode": "install"}),
    ("preflight-bundle", UpgradePreflightHandler, {"upgrade_mode": "bundle"}),
    ("stage", UpgradeStageHandler, STAGE),
    ("install-install", UpgradeInstallHandler, {"image_name": "img.bin"}),
    ("install-bundle", UpgradeInstallHandler, {"image_name": "img.bin", "upgrade_mode": "bundle"}),
    ("verify-install", UpgradeVerifyHandler, {"upgrade_mode": "install", **VERIFY_WAIT}),
    ("verify-bundle", UpgradeVerifyHandler, {"upgrade_mode": "bundle", **VERIFY_WAIT}),
    ("cleanup-install", UpgradeCleanupHandler, {"upgrade_mode": "install"}),
    ("cleanup-bundle", UpgradeCleanupHandler, {"upgrade_mode": "bundle"}),
]


@pytest.mark.parametrize(("handler", "config"), [s[1:] for s in STEPS], ids=[s[0] for s in STEPS])
async def test_unreachable_device_fails_every_step(handler, config):
    ssh = ScriptedTransport(default=UNREACHABLE, transferred=False)
    result = await handler().execute(make_ctx(config, FakeServices(lambda: ssh)))
    assert result.success is False
    assert result.metrics["failure_count"] == 1
    evidence = result.evidence[0]["content_json"]
    assert evidence["success"] is False
    assert "Connection timeout" in (evidence["error"] or "")
    # Nothing that changes the device was attempted on a device never reached.
    assert not any(c.startswith(("configure", "delete", "reload", "write")) for c in ssh.commands)


@pytest.mark.parametrize(
    "mode,driver", [("install", IOSXEInstallDriver()), ("bundle", IOSXEBundleDriver())]
)
async def test_verify_fails_when_show_version_fails(mode, driver):
    """The device answers "show clock" but the verification commands fail."""
    ssh = ScriptedTransport(
        {"show clock": Result("10:00:00.000 UTC Mon Oct 5 2026")}, default=UNREACHABLE
    )
    result = await UpgradeVerifyHandler().execute(
        make_ctx({"upgrade_mode": mode, "target_version": "17.09.04a"}, FakeServices(lambda: ssh))
    )
    assert result.success is False
    assert "show version failed" in result.evidence[0]["content_json"]["error"]


@pytest.mark.parametrize(("handler", "config"), [s[1:] for s in STEPS], ids=[s[0] for s in STEPS])
async def test_connect_raising_fails_every_step(handler, config):
    class _Services(FakeServices):
        def connect(self, device, *, platform=None, **kwargs):
            raise ValueError("Device access_config has no username")

    result = await handler().execute(make_ctx(config, _Services(ScriptedTransport)))
    assert result.success is False
    assert result.metrics["failure_count"] == 1


# --- preflight ---------------------------------------------------------------


async def test_install_summary_cli_error_means_no_install_mode():
    ssh = ScriptedTransport(
        {
            "show version": Result("Cisco IOS XE Software, Version 16.09.04"),
            "dir": Result("1000 bytes total (2000000000 bytes free)"),
            "show install summary": Result(
                "% Invalid input detected at '^' marker.", exit_code=1, error="% Invalid input"
            ),
        }
    )
    result = await IOSXEInstallDriver().preflight(ssh)
    assert result.success is False
    assert result.install_mode_supported is False
    assert "does not support install mode" in (result.error or "")


async def test_install_summary_that_did_not_run_is_a_command_error():
    ssh = ScriptedTransport(
        {
            "show version": Result("Cisco IOS XE Software, Version 17.09.04a"),
            "dir": Result("1000 bytes total (2000000000 bytes free)"),
            "show install summary": UNREACHABLE,
        }
    )
    result = await IOSXEInstallDriver().preflight(ssh)
    assert result.success is False
    assert "show install summary failed: Connection timeout" in (result.error or "")


async def test_preflight_dir_error_fails():
    ssh = ScriptedTransport(
        {
            "show version": Result("Cisco IOS XE Software, Version 17.09.04a"),
            "dir": Result("%Error opening usbflash0: (No such device)"),
        }
    )
    result = await IOSXEBundleDriver().preflight(ssh, dest_fs="usbflash0:")
    assert result.success is False
    assert "dir usbflash0: failed: %Error opening usbflash0:" in (result.error or "")


# --- stage -------------------------------------------------------------------


async def test_stage_fails_when_the_file_is_missing_after_the_transfer():
    missing = Result("%Error opening flash:img.bin (No such file or directory)")
    ssh = ScriptedTransport({"dir": missing})
    result = await stage_image(
        ssh,
        source_url="https://repo.example/img.bin",
        dest_fs="flash:",
        dest_filename="img.bin",
        transfer_method="auto",
        expected_md5=None,
        expected_size=None,
        overwrite=False,
        select_transfer_method_fn=lambda **_: "https",
    )
    assert result.success is False
    assert ssh.transfers == ["flash:img.bin"]
    assert "dir flash:img.bin failed" in (result.error or "")


# --- install-mode cleanup ----------------------------------------------------

REMOVED = (
    "install_remove: START Mon Oct  5 10:00:00 UTC 2026\n"
    "Do you want to remove the above files? [y/n]y\n"
    "Deleting file flash:cat9k-rpbase.16.12.04.SPA.pkg ... done.\n"
    "Deleting file flash:cat9k-srdriver.16.12.04.SPA.pkg ... done.\n"
    "SUCCESS: Files deleted.\n"
    "SUCCESS: install_remove  Mon Oct  5 10:01:00 UTC 2026\n"
)
INSTALL_CLEANUP = [
    ("removed", Result(REMOVED), True),
    ("nothing-to-remove", Result("install_remove: START\nNothing to clean\n"), True),
    ("empty-output", Result(""), False),
    ("cut-off", Result("install_remove: START\nScanning boot directory ...\n"), False),
    ("failed", Result("install_remove: START\nFAILED: install_remove : busy\n"), False),
    ("cli-error", Result("% Invalid input detected", exit_code=1, error="% Invalid input"), False),
    ("unreachable", UNREACHABLE, False),
]


@pytest.mark.parametrize(
    ("reply", "success"),
    [case[1:] for case in INSTALL_CLEANUP],
    ids=[case[0] for case in INSTALL_CLEANUP],
)
async def test_install_mode_cleanup_needs_the_device_to_confirm(reply, success):
    ssh = ScriptedTransport({"install remove inactive": reply})
    result = await IOSXEInstallDriver().cleanup(ssh)
    assert result.success is success, result.error
    if not success:
        assert result.error


async def test_install_mode_cleanup_lists_the_deleted_files():
    ssh = ScriptedTransport({"install remove inactive": Result(REMOVED)})
    result = await IOSXEInstallDriver().cleanup(ssh)
    assert result.removed_packages == [
        "flash:cat9k-rpbase.16.12.04.SPA.pkg",
        "flash:cat9k-srdriver.16.12.04.SPA.pkg",
    ]


# --- bundle-mode cleanup -----------------------------------------------------

LISTING = Result(
    "Directory of flash:/*.bin\n"
    "   12  -rw-   400000000  Jan 1 2025 00:00:00 +00:00  isr4300.16.09.04.SPA.bin\n"
    "   13  -rw-   400000000  Jan 1 2026 00:00:00 +00:00  isr4300.16.12.05.SPA.bin\n"
    "   14  -rw-   400000000  Jan 1 2026 00:00:00 +00:00  isr4300.17.03.08a.SPA.bin\n"
)


def _bundle_device(boot: str, **replies: Any) -> ScriptedTransport:
    return ScriptedTransport(
        {"show boot": Result(f"BOOT variable = {boot}\n"), "dir": LISTING, **replies}
    )


def _deleted(ssh: ScriptedTransport) -> list[str]:
    return [c.rsplit(":", 1)[1] for c in ssh.commands if c.startswith("delete")]


@pytest.mark.parametrize("boot", ["", "not set"])
async def test_bundle_cleanup_with_no_boot_image_deletes_nothing(boot):
    ssh = _bundle_device(boot)
    result = await IOSXEBundleDriver().cleanup(ssh, keep_versions=0)
    assert result.success is False
    assert "names no image" in (result.error or "")
    assert _deleted(ssh) == []
    assert result.removed_packages == []


async def test_bundle_cleanup_keeps_the_boot_image_and_the_newest_old_ones():
    ssh = _bundle_device("bootflash:isr4300.17.03.08a.SPA.bin,12;")
    result = await IOSXEBundleDriver().cleanup(ssh, keep_versions=1)
    assert result.success is True
    assert _deleted(ssh) == ["isr4300.16.09.04.SPA.bin"]
    assert result.removed_packages == ["isr4300.16.09.04.SPA.bin"]


async def test_bundle_cleanup_keeps_old_images_up_to_keep_versions():
    """With as many old images as Versions to Keep, nothing is deleted."""
    ssh = _bundle_device("bootflash:isr4300.17.03.08a.SPA.bin;")
    result = await IOSXEBundleDriver().cleanup(ssh, keep_versions=2)
    assert result.success is True
    assert _deleted(ssh) == []


async def test_bundle_cleanup_failed_delete_fails_and_is_not_reported_removed():
    ssh = _bundle_device(
        "bootflash:isr4300.17.03.08a.SPA.bin;",
        **{"delete /force flash:isr4300.16.09.04": UNREACHABLE},
    )
    result = await IOSXEBundleDriver().cleanup(ssh, keep_versions=0)
    assert result.success is False
    assert _deleted(ssh) == ["isr4300.16.09.04.SPA.bin", "isr4300.16.12.05.SPA.bin"]
    assert result.removed_packages == ["isr4300.16.12.05.SPA.bin"]
    assert "isr4300.16.09.04.SPA.bin failed: Connection timeout" in (result.error or "")


async def test_bundle_cleanup_with_no_bin_files_deletes_nothing():
    ssh = _bundle_device(
        "bootflash:isr4300.17.03.08a.SPA.bin;",
        dir=Result("%Error opening flash:/*.bin (No such file or directory)"),
    )
    result = await IOSXEBundleDriver().cleanup(ssh, keep_versions=0)
    assert result.success is True
    assert _deleted(ssh) == []


# --- install-mode verify -----------------------------------------------------


async def test_verify_reports_an_uncommitted_install():
    ssh = ScriptedTransport(
        {
            "show version": Result("Cisco IOS XE Software, Version 17.09.04a"),
            "show install summary": Result("IMG   U    17.09.04a.0.6\n"),
        }
    )
    result = await IOSXEInstallDriver().verify(ssh, target_version="17.09.04a", auto_commit=False)
    assert result.success is False
    assert result.error == "The new software is not committed"


async def test_verify_fails_when_install_commit_fails(monkeypatch):
    async def _no_sleep(_seconds):
        return None

    monkeypatch.setattr(
        "hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_install.asyncio.sleep", _no_sleep
    )
    ssh = ScriptedTransport(
        {
            "show version": Result("Cisco IOS XE Software, Version 17.09.04a"),
            "show install summary": Result("IMG   U    17.09.04a.0.6\n"),
            "install commit": Result("%Error: commit failed\n"),
        }
    )
    result = await IOSXEInstallDriver().verify(ssh, target_version="17.09.04a")
    assert result.success is False
    assert "install commit failed: %Error: commit failed" in (result.error or "")
