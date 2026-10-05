# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""An install counts as done only when the device says so.

The transports never raise: a CLI error comes back as output (exit code 1,
or 0 for "%Error ..."), a dead session as exit code -1. The install driver
reads errors first, needs positive proof of success, and treats a dropped
session as the reload only once activation finished. Exceptions, from the
driver or from ``services.connect()``, are failures, never "rebooting".
"""

from __future__ import annotations

import pytest

from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_bundle import IOSXEBundleDriver
from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_install import IOSXEInstallDriver
from hegemony_steps_cisco_iosxe.upgrade.handlers.install import UpgradeInstallHandler
from tests.iosxe_fakes import UNREACHABLE, FakeServices, Result, ScriptedTransport, make_ctx

BOOT_OK = Result("BOOT variable = flash:packages.conf;\nCONFIG_FILE variable = \n")

ACTIVATED = (
    "install_add_activate_commit: START Mon Oct  5 10:00:00 UTC 2026\n"
    "install_add_activate_commit: Adding PACKAGE\n"
    "Add: Passed on [1]\nFinished Add\n"
    "install_add_activate_commit: Activating PACKAGE\n"
    "This operation may require a reload of the system. Do you want to proceed? [y/n]y\n"
    "Activate: Passed on [1]\nFinished Activate\n"
)
DONE = ACTIVATED + (
    "Commit: Passed on [1]\nFinished Commit\n"
    "Install will reload the system now!\n"
    "SUCCESS: install_add_activate_commit  Mon Oct  5 10:12:00 UTC 2026\n"
)
STARTED = (
    "install_add_activate_commit: START Mon Oct  5 10:00:00 UTC 2026\n"
    "install_add_activate_commit: Adding PACKAGE\n"
)
INVALID = (
    "install add file flash:img.bin activate commit\n"
    "                          ^\n"
    "% Invalid input detected at '^' marker.\n"
)

CASES = [
    # id, output, exit_code, error, success, reboot_triggered
    ("completed-and-reloading", DONE, 0, None, True, True),
    ("invalid-input", INVALID, 1, "% Invalid input detected at '^' marker.", False, False),
    (
        "error-line",
        "%Error opening flash:img.bin (No such file or directory)\n",
        0,
        None,
        False,
        False,
    ),
    ("incomplete", "% Incomplete command.\n", 1, "% Incomplete command", False, False),
    ("ambiguous", '% Ambiguous command:  "install a"\n', 1, "% Ambiguous command", False, False),
    (
        "install-failed",
        STARTED + "FAILED: install_add_activate_commit : no space\n",
        0,
        None,
        False,
        False,
    ),
    ("unreachable", "", -1, "Connection timeout: TCP connection failed", False, False),
    ("dropped-after-activation", ACTIVATED, -1, "Socket is closed", True, True),
    ("dropped-before-activation", STARTED, -1, "Socket is closed", False, False),
    ("no-completion", STARTED, 0, None, False, False),
    ("only-the-reload-prompt", ACTIVATED.split("Activate: Passed")[0], 0, None, False, False),
    ("success-with-an-error-string", DONE, 0, "unexpected prompt", False, True),
    (
        "already-at-target",
        STARTED + "Same Image File-No Change\nSUCCESS: install_add_activate_commit\n",
        0,
        None,
        True,
        False,
    ),
    (
        "same-image-but-failed",
        STARTED + "Same Image File-No Change\nFAILED: install_add_activate_commit : nothing\n",
        0,
        None,
        False,
        False,
    ),
]


@pytest.mark.parametrize(
    ("output", "exit_code", "error", "success", "reboot"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
async def test_install_mode_outcome(output, exit_code, error, success, reboot):
    ssh = ScriptedTransport(
        {
            "show boot": BOOT_OK,
            "install add": Result(output, exit_code=exit_code, error=error),
        }
    )
    result = await IOSXEInstallDriver().install(ssh, image_name="img.bin", dest_fs="flash:")
    assert result.success is success, result.error
    assert result.reboot_triggered is reboot
    if not success:
        assert result.error


async def test_no_completion_names_the_reason():
    ssh = ScriptedTransport({"show boot": BOOT_OK, "install add": Result(STARTED)})
    result = await IOSXEInstallDriver().install(ssh, image_name="img.bin", dest_fs="flash:")
    assert result.error == "Install did not report completion"


async def test_failure_names_the_device_line():
    ssh = ScriptedTransport({"show boot": BOOT_OK, "install add": Result(INVALID, exit_code=1)})
    result = await IOSXEInstallDriver().install(ssh, image_name="img.bin", dest_fs="flash:")
    assert result.error == "Install failed: % Invalid input detected at '^' marker."


async def test_without_activate_sends_neither_activate_nor_commit():
    ssh = ScriptedTransport({"install add": Result("SUCCESS: install_add  Mon Oct  5\n")})
    result = await IOSXEInstallDriver().install(
        ssh, image_name="img.bin", dest_fs="flash:", activate=False, commit=True
    )
    assert result.success is True
    assert result.reboot_triggered is False
    assert result.activated is False and result.committed is False
    assert "install add file flash:img.bin" in ssh.commands


class _RaisingTransport(ScriptedTransport):
    async def execute_commands(self, commands):
        raise RuntimeError("SSH connection lost")

    async def execute_command_timing(self, command, **kwargs):
        raise RuntimeError("SSH connection lost")


@pytest.mark.parametrize(
    "driver", [IOSXEInstallDriver(), IOSXEBundleDriver()], ids=["install", "bundle"]
)
async def test_an_exception_is_a_failure_not_a_reload(driver):
    result = await driver.install(_RaisingTransport(), image_name="img.bin", dest_fs="flash:")
    assert result.success is False
    assert result.reboot_triggered is False
    assert "SSH connection lost" in (result.error or "")


async def test_handler_fails_when_connect_raises():
    """connect() does not dial: an exception from it is config or credentials."""

    class _Services(FakeServices):
        def connect(self, device, *, platform=None, **kwargs):
            raise ValueError("Device access_config has no username: SSH connection impossible")

    result = await UpgradeInstallHandler().execute(
        make_ctx({"image_name": "img.bin"}, _Services(ScriptedTransport))
    )
    assert result.success is False
    assert result.evidence[0]["name"] == "Install Error: sw1"
    assert result.evidence[0]["content_json"]["success"] is False
    assert result.metrics["output_context"] == {}


async def test_handler_fails_for_an_unreachable_device():
    result = await UpgradeInstallHandler().execute(
        make_ctx(
            {"image_name": "img.bin"},
            FakeServices(lambda: ScriptedTransport(default=UNREACHABLE)),
        )
    )
    assert result.success is False
    assert result.evidence[0]["content_json"]["reboot_triggered"] is False
