# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bundle mode really points the device at the new image.

The transports send a command list as configuration only when it starts
with "configure terminal". Bundle install sent each line on its own, in a
new session each, so "no boot system" and "boot system ..." ran in exec mode
and were rejected, and the results were never read. These tests drive the
real netmiko transport against a small emulated IOS-XE device.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

import hegemony_transport_netmiko.transport as netmiko_transport
from hegemony_step_sdk import DeviceConnectionSpec
from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_bundle import IOSXEBundleDriver
from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_common import (
    all_boot_images,
    parse_boot_statements,
)
from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_install import IOSXEInstallDriver
from tests.iosxe_fakes import UNREACHABLE, Result, ScriptedTransport

INVALID = "                 ^\n% Invalid input detected at '^' marker.\n"
OLD = "bootflash:isr4300-universalk9.16.09.04.SPA.bin"
NEW_NAME = "isr4300-universalk9.17.03.08a.SPA.bin"
NEW = f"bootflash:{NEW_NAME}"


class EmulatedIOS:
    """A minimal IOS-XE device. Each connection is a new session in exec mode.

    It keeps the boot variable, accepts boot commands only in configuration
    mode, saves on "write memory" and walks through the reload prompts.
    """

    def __init__(self, boot: list[str]) -> None:
        self.boot = list(boot)
        self.saved = False
        self.reloaded = False
        self.sessions = 0
        self.config_sessions: list[list[str]] = []
        self.exec_commands: list[str] = []
        self.answers: list[str] = []
        self.installed: list[str] = []

    def show_boot(self) -> str:
        value = "".join(f"{image},12;" for image in self.boot)
        return (
            f"BOOT variable = {value}\nCONFIG_FILE variable does not exist\n"
            "BAUD variable = 9600\nConfiguration register is 0x2102\n"
        )

    def connect(self, **params: Any):
        self.sessions += 1
        device = self

        class Connection:
            remote_conn_pre = None
            remote_conn = None

            def enable(self) -> None:
                pass

            def send_command(self, command: str, **kwargs: Any) -> str:
                device.exec_commands.append(command)
                if command == "show boot":
                    return device.show_boot()
                if command.startswith(("show ", "dir ")):
                    return ""
                return INVALID  # configuration commands typed in exec mode

            def send_config_set(self, commands: list[str], **kwargs: Any) -> str:
                device.config_sessions.append(list(commands))
                for command in commands:
                    if command == "no boot system":
                        device.boot = []
                    elif command.startswith("boot system "):
                        device.boot.append(command.split(" ", 2)[2])
                return "configure terminal\n" + "\n".join(commands) + "\nend\n"

            def send_command_timing(self, command: str, **kwargs: Any) -> str:
                if command == "write memory":
                    device.saved = True
                    return "Building configuration...\n[OK]\n"
                if command.startswith("install add file"):
                    device.installed.append(command)
                    return (
                        "Install will reload the system now!\n"
                        "SUCCESS: install_add_activate_commit\n"
                    )
                if command == "reload":
                    return "System configuration has been modified. Save? [yes/no]: "
                device.answers.append(command)
                if command == "no":
                    return "Proceed with reload? [confirm]"
                if command == "y":
                    device.reloaded = True
                    raise OSError("Socket is closed")
                return ""

            def read_channel(self) -> str:
                return ""

            def write_channel(self, data: str) -> None:
                pass

        return Connection()


def _netmiko(device: EmulatedIOS):
    """The real netmiko transport, talking to ``device``."""
    return patch.object(netmiko_transport, "ConnectHandler", side_effect=device.connect)


def _transport():
    spec = DeviceConnectionSpec(host="192.0.2.10", username="admin", password="pw")
    return netmiko_transport.SSHTransport(spec)


async def test_bundle_install_against_the_emulator():
    device = EmulatedIOS(boot=[OLD])
    with _netmiko(device):
        result = await IOSXEBundleDriver().install(
            _transport(), image_name=NEW_NAME, dest_fs="bootflash:"
        )
    assert result.success is True, result.error
    assert result.reboot_triggered is True
    # One configuration session, nothing typed in exec mode by mistake.
    assert device.config_sessions == [
        ["no boot system", f"boot system {NEW}", f"boot system {OLD}"]
    ]
    assert device.exec_commands == ["show boot", "show boot"]
    # The new image boots first, the old one is the fallback.
    assert device.boot == [NEW, OLD]
    assert device.saved is True
    assert device.answers == ["no", "y"] and device.reloaded is True
    assert result.boot_config_changed is True
    assert result.previous_boot == [OLD]
    assert f"boot system {NEW}" in result.cli_output


async def test_bundle_install_without_activate_saves_and_does_not_reload():
    device = EmulatedIOS(boot=[OLD])
    with _netmiko(device):
        result = await IOSXEBundleDriver().install(
            _transport(), image_name=NEW_NAME, dest_fs="bootflash:", activate=False
        )
    assert result.success is True
    assert result.reboot_triggered is False
    assert device.boot == [NEW, OLD] and device.saved is True
    assert device.reloaded is False


async def test_install_mode_boot_fix_against_the_emulator():
    device = EmulatedIOS(boot=[OLD])
    with _netmiko(device):
        default = await IOSXEInstallDriver().install(
            _transport(), image_name="img.bin", dest_fs="bootflash:"
        )
    assert default.success is False
    assert device.config_sessions == [] and device.saved is False

    with _netmiko(device):
        fixed = await IOSXEInstallDriver().install(
            _transport(), image_name="img.bin", dest_fs="bootflash:", fix_boot_config=True
        )
    assert fixed.success is True, fixed.error
    assert fixed.boot_config_changed is True
    assert device.config_sessions == [["no boot system", "boot system bootflash:packages.conf"]]
    assert device.boot == ["bootflash:packages.conf"] and device.saved is True
    assert device.installed == ["install add file bootflash:img.bin activate commit"]


# --- bundle install outcomes -------------------------------------------------

SAVED = Result("Building configuration...\n[OK]\n")
CONFIRM = Result(
    "System configuration has been modified. Save? [yes/no]: no\nProceed with reload? [confirm]y\n",
    exit_code=-1,
    error="Socket is closed",
)


def _boot(*images: str) -> Result:
    return Result("BOOT variable = " + "".join(f"{i},12;" for i in images) + "\n")


def _device(**replies: Result | list[Result]) -> ScriptedTransport:
    script: dict[str, Result | list[Result]] = {
        "show boot": [_boot(OLD), _boot(NEW, OLD)],
        "write memory": SAVED,
        "reload": CONFIRM,
    }
    script.update(replies)
    return ScriptedTransport(script)


async def _install(ssh: ScriptedTransport, **kwargs: Any):
    return await IOSXEBundleDriver().install(
        ssh, image_name=NEW_NAME, dest_fs="bootflash:", **kwargs
    )


async def test_rerun_keeps_one_fallback_and_no_duplicate():
    ssh = _device(**{"show boot": _boot(NEW, OLD)})
    result = await _install(ssh)
    assert result.success is True
    assert [
        "configure terminal",
        "no boot system",
        f"boot system {NEW}",
        f"boot system {OLD}",
        "end",
    ] in ssh.calls


@pytest.mark.parametrize(
    ("replies", "error"),
    [
        ({"boot system": Result(INVALID, exit_code=1, error="% Invalid input")}, "failed"),
        ({"write memory": Result("Building configuration...\n")}, "did not confirm the save"),
        ({"show boot": [_boot(OLD), _boot(OLD, NEW)]}, f"expected {NEW} first"),
        ({"show boot": UNREACHABLE}, "show boot failed: Connection timeout"),
        ({"show boot": Result("")}, "Could not read the boot variable"),
    ],
    ids=["config-rejected", "save-unconfirmed", "wrong-first-entry", "unreachable", "no-boot-line"],
)
async def test_a_failed_boot_change_never_reloads(replies, error):
    ssh = _device(**replies)
    result = await _install(ssh)
    assert result.success is False
    assert error in (result.error or "")
    assert "reload" not in ssh.commands


@pytest.mark.parametrize(
    ("reply", "success"),
    [
        (CONFIRM, True),
        (Result("Proceed with reload? [confirm]y\n"), True),
        (UNREACHABLE, False),
        (Result(INVALID, exit_code=1, error="% Invalid input"), False),
        (Result(""), False),
    ],
    ids=["session-closed-after-confirm", "confirmed", "unreachable", "rejected", "no-output"],
)
async def test_reload_outcome(reply, success):
    result = await _install(_device(reload=reply))
    assert result.success is success, result.error
    assert result.reboot_triggered is success
    assert result.boot_config_changed is True


async def test_reload_prompts_have_one_answer_each():
    ssh = _device()
    await _install(ssh)
    assert ssh.timing_kwargs["reload"]["answers"] == {"Save?": "no", "Proceed with reload": "y"}


async def test_bundle_preflight_refuses_an_install_mode_device():
    ssh = ScriptedTransport(
        {
            "show version": Result("Cisco IOS XE Software, Version 17.09.04a"),
            "dir": Result("1000 bytes total (2000000000 bytes free)"),
            "show boot": Result("BOOT variable = flash:packages.conf;\n"),
        }
    )
    result = await IOSXEBundleDriver().preflight(ssh)
    assert result.success is False
    assert "install mode" in (result.error or "")


# --- boot variable parsing ---------------------------------------------------


def test_boot_attempt_count_is_not_an_image():
    assert parse_boot_statements(f"BOOT variable = {OLD},12;\n") == [OLD]
    assert parse_boot_statements(f"BOOT variable = {NEW},12;{OLD},12;\n") == [NEW, OLD]


def test_empty_boot_variable_does_not_take_the_next_line():
    show_boot = "BOOT variable = \nCONFIG_FILE variable = \nBAUD variable = 9600\n"
    assert parse_boot_statements(show_boot) == []
    assert all_boot_images(show_boot) == []


def test_next_reload_boot_variable_wins():
    show_boot = (
        "Current Boot Variables:\nBOOT variable = flash:old.bin;\n\n"
        "Boot Variables on next reload:\nBOOT variable = flash:packages.conf;\nManual Boot = no\n"
    )
    assert parse_boot_statements(show_boot) == ["flash:packages.conf"]
    assert all_boot_images(show_boot) == ["flash:old.bin", "flash:packages.conf"]


async def test_bundle_cleanup_with_an_empty_boot_variable_deletes_nothing():
    """Real "show boot" output: the empty BOOT line is followed by others."""
    ssh = ScriptedTransport(
        {
            "show boot": Result(
                "BOOT variable = \nCONFIG_FILE variable = \nBAUD variable = 9600\n"
            ),
            "dir": Result("  12  -rw-  400000000  Jan 1 2026 00:00:00 +00:00  old.bin\n"),
        }
    )
    result = await IOSXEBundleDriver().cleanup(ssh, keep_versions=0)
    assert result.success is False
    assert not any(c.startswith("delete") for c in ssh.commands)


async def test_partly_applied_bundle_boot_change_is_undone():
    ssh = _device(**{f"boot system {NEW}": Result(INVALID, exit_code=1, error="% Invalid input")})
    result = await _install(ssh)
    assert result.success is False
    assert ssh.calls[-1] == ["configure terminal", "no boot system", f"boot system {OLD}", "end"]
    assert result.boot_config_changed is False
    assert "% Invalid input detected" in result.cli_output
    assert "reload" not in ssh.commands


async def test_partly_applied_bundle_boot_change_that_cannot_be_undone_is_reported():
    ssh = _device(
        **{
            f"boot system {NEW}": Result(INVALID, exit_code=1, error="% Invalid input"),
            f"boot system {OLD}": UNREACHABLE,
        }
    )
    result = await _install(ssh)
    assert result.success is False
    assert result.boot_config_changed is True
    assert "check the device's boot setting" in (result.error or "")


RESTORE = ["configure terminal", "no boot system", f"boot system {OLD}", "end"]


async def test_boot_config_changed_does_not_mean_saved():
    """The save failed and so did the undo: the flag says changed."""
    ssh = _device(
        **{
            "write memory": Result("Building configuration...\n"),
            # The fallback line of the change works; the undo's does not.
            f"boot system {OLD}": [Result(), UNREACHABLE],
        }
    )
    result = await _install(ssh)
    assert result.success is False
    assert ssh.calls[-1] == RESTORE
    assert result.boot_config_changed is True
    assert "did not confirm the save" in (result.error or "")
    assert "check the device's boot setting" in (result.error or "")


@pytest.mark.parametrize(
    ("replies", "error"),
    [
        ({"write memory": Result("Building configuration...\n")}, "did not confirm the save"),
        ({"write memory": UNREACHABLE}, "write memory failed: Connection timeout"),
        ({"show boot": [_boot(OLD), _boot(OLD, NEW)]}, f"expected {NEW} first"),
        ({"show boot": [_boot(OLD), UNREACHABLE]}, "show boot failed: Connection timeout"),
    ],
    ids=["save-unconfirmed", "save-failed", "wrong-first-entry", "read-back-failed"],
)
async def test_a_failed_save_or_read_back_is_undone(replies, error):
    ssh = _device(**replies)
    result = await _install(ssh)
    assert result.success is False
    assert error in (result.error or "")
    assert (result.error or "").endswith(
        "the previous boot entries were restored in the running configuration, "
        "but the saved configuration may still hold the change"
    )
    assert ssh.calls[-1] == RESTORE
    assert result.boot_config_changed is False
    assert "reload" not in ssh.commands
