# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Install mode changes the boot setting only when the flow asks for it.

Activation boots packages.conf. When the boot variable points elsewhere the
install step used to rewrite it to flash:packages.conf and save the whole
running configuration, silently, even when "show boot" had failed. Now the
device fails unless fix_boot_config is on; with it on, the change uses the
destination filesystem, every command is checked, and the evidence shows it.
"""

from __future__ import annotations

from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_install import IOSXEInstallDriver
from hegemony_steps_cisco_iosxe.upgrade.handlers.install import (
    UpgradeInstallConfig,
    UpgradeInstallHandler,
)
from tests.iosxe_fakes import UNREACHABLE, FakeServices, Result, ScriptedTransport, make_ctx

OLD_IMAGE = "flash:cat9k_iosxe.16.12.04.SPA.bin"
BOOT_OLD = Result(f"BOOT variable = {OLD_IMAGE};\nCONFIG_FILE variable = \n")
DONE = Result(
    "Activate: Passed on [1]\nInstall will reload the system now!\n"
    "SUCCESS: install_add_activate_commit\n"
)
SAVED = Result("Building configuration...\n[OK]\n")
CONFIG_LINES = [
    "configure terminal",
    "no boot system",
    "boot system bootflash:packages.conf",
    "end",
]


def _boot(path: str) -> Result:
    return Result(f"BOOT variable = {path};\nCONFIG_FILE variable = \n")


def _fixing_device(**overrides: Result | list[Result]) -> ScriptedTransport:
    replies: dict[str, Result | list[Result]] = {
        "show boot": [BOOT_OLD, _boot("bootflash:packages.conf")],
        "write memory": SAVED,
        "install add": DONE,
    }
    replies.update(overrides)
    return ScriptedTransport(replies)


async def _install(ssh: ScriptedTransport, **kwargs):
    kwargs.setdefault("dest_fs", "bootflash:")
    return await IOSXEInstallDriver().install(ssh, image_name="img.bin", **kwargs)


async def test_wrong_boot_variable_fails_by_default_and_changes_nothing():
    ssh = ScriptedTransport({"show boot": BOOT_OLD, "install add": DONE})
    result = await _install(ssh, dest_fs="flash:")
    assert result.success is False
    assert result.error == (
        f"Boot variable is {OLD_IMAGE}, expected flash:packages.conf "
        "(turn on fix_boot_config to set it)"
    )
    assert ssh.commands == ["show boot"]
    assert result.boot_config_changed is False
    assert result.previous_boot == [OLD_IMAGE]


async def test_packages_conf_on_bootflash_counts_for_flash():
    ssh = ScriptedTransport({"show boot": _boot("bootflash:packages.conf"), "install add": DONE})
    result = await _install(ssh, dest_fs="flash:")
    assert result.success is True
    assert result.boot_config_changed is False
    assert ssh.commands == ["show boot", "install add file flash:img.bin activate commit"]


async def test_opt_in_sets_the_destination_filesystem_and_records_it():
    ssh = _fixing_device()
    result = await _install(ssh, fix_boot_config=True)
    assert result.success is True, result.error
    assert CONFIG_LINES in ssh.calls  # one configuration session
    assert ssh.commands == [
        "show boot",
        *CONFIG_LINES,
        "write memory",
        "show boot",
        "install add file bootflash:img.bin activate commit",
    ]
    assert result.boot_config_changed is True
    assert result.previous_boot == [OLD_IMAGE]
    for text in ("boot system bootflash:packages.conf", "write memory", "[OK]", OLD_IMAGE):
        assert text in result.cli_output
    assert "show boot (after)" in result.cli_output


async def test_failed_show_boot_fails_and_never_rewrites():
    ssh = ScriptedTransport({"show boot": UNREACHABLE, "install add": DONE})
    result = await _install(ssh, fix_boot_config=True)
    assert result.success is False
    assert "show boot failed: Connection timeout" in (result.error or "")
    assert ssh.commands == ["show boot"]


async def test_show_boot_without_a_boot_variable_fails_and_never_rewrites():
    ssh = ScriptedTransport({"show boot": Result(""), "install add": DONE})
    result = await _install(ssh, fix_boot_config=True)
    assert result.success is False
    assert "Could not read the boot variable" in (result.error or "")
    assert ssh.commands == ["show boot"]


async def test_rejected_config_line_stops_before_saving():
    ssh = _fixing_device(
        **{"boot system": Result("% Invalid input detected", exit_code=1, error="% Invalid input")}
    )
    result = await _install(ssh, fix_boot_config=True)
    assert result.success is False
    assert "boot system bootflash:packages.conf failed" in (result.error or "")
    assert "write memory" not in ssh.commands
    assert not any(c.startswith("install") for c in ssh.commands)


async def test_unconfirmed_save_stops_before_installing():
    ssh = _fixing_device(**{"write memory": Result("Building configuration...\n")})
    result = await _install(ssh, fix_boot_config=True)
    assert result.success is False
    assert "write memory did not confirm the save" in (result.error or "")
    assert result.boot_config_changed is True
    assert not any(c.startswith("install") for c in ssh.commands)


async def test_boot_variable_not_changed_after_save_stops_before_installing():
    ssh = _fixing_device(**{"show boot": BOOT_OLD})
    result = await _install(ssh, fix_boot_config=True)
    assert result.success is False
    assert "after the change, expected bootflash:packages.conf" in (result.error or "")
    assert not any(c.startswith("install") for c in ssh.commands)


async def test_without_activate_the_boot_variable_is_not_read():
    ssh = ScriptedTransport({"install add": Result("SUCCESS: install_add\n")})
    result = await _install(ssh, activate=False)
    assert result.success is True
    assert ssh.commands == ["install add file bootflash:img.bin"]


def test_fix_boot_config_is_off_by_default():
    assert UpgradeInstallConfig.model_fields["fix_boot_config"].default is False
    assert UpgradeInstallHandler.default_config["fix_boot_config"] is False


async def test_handler_passes_the_option_and_reports_the_change():
    ssh = _fixing_device()
    result = await UpgradeInstallHandler().execute(
        make_ctx(
            {"image_name": "img.bin", "dest_fs": "bootflash:", "fix_boot_config": True},
            FakeServices(lambda: ssh),
        )
    )
    assert result.success is True
    evidence = result.evidence[0]
    assert evidence["content_json"]["boot_config_changed"] is True
    assert evidence["content_json"]["previous_boot"] == [OLD_IMAGE]
    assert "boot system bootflash:packages.conf" in evidence["content_text"]
    context = result.metrics["output_context"]["11111111-1111-1111-1111-111111111111"]
    assert context["boot_config_changed"] is True
    assert context["previous_boot"] == [OLD_IMAGE]


async def test_handler_default_fails_a_device_with_the_wrong_boot_variable():
    ssh = ScriptedTransport({"show boot": BOOT_OLD, "install add": DONE})
    result = await UpgradeInstallHandler().execute(
        make_ctx({"image_name": "img.bin"}, FakeServices(lambda: ssh))
    )
    assert result.success is False
    assert "expected flash:packages.conf" in result.evidence[0]["content_json"]["error"]
    assert not any(c.startswith(("configure", "install")) for c in ssh.commands)


# --- a boot change that fails part-way ---------------------------------------

RESTORE_LINES = ["configure terminal", "no boot system", f"boot system {OLD_IMAGE}", "end"]


def _partly_applied(**replies: Result | list[Result]) -> ScriptedTransport:
    """'no boot system' is applied, then the new boot line is rejected."""
    return _fixing_device(
        **{
            "boot system bootflash:packages.conf": Result(
                "% Invalid input detected at '^' marker.", exit_code=1, error="% Invalid input"
            ),
            **replies,
        }
    )


async def test_partly_applied_boot_change_is_undone_and_kept_in_the_transcript():
    ssh = _partly_applied()
    result = await _install(ssh, fix_boot_config=True)
    assert result.success is False
    # The previous entries are put back in a second session.
    assert ssh.calls[-1] == RESTORE_LINES
    assert result.boot_config_changed is False
    assert "previous boot entries were restored" in (result.error or "")
    # The failed session's own output stays in the evidence.
    assert "% Invalid input detected" in result.cli_output
    assert "write memory" not in ssh.commands


async def test_partly_applied_boot_change_that_cannot_be_undone_is_reported():
    ssh = _partly_applied(**{f"boot system {OLD_IMAGE}": UNREACHABLE})
    result = await _install(ssh, fix_boot_config=True)
    assert result.success is False
    assert ssh.calls[-1] == RESTORE_LINES
    assert result.boot_config_changed is True
    assert "check the device's boot setting" in (result.error or "")
