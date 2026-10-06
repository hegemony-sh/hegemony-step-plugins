# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""IOS-XE versions are compared as releases, never as substrings.

A target of 17.09.04 used to match a device running 17.09.04a, and an
upgrade from 17.09.04 to 17.09.04a read as "Version unchanged". Versions
now compare by their numbers and letter suffix: 17.9.4a is 17.09.04a, and
17.09.04 is not.
"""

from __future__ import annotations

import pytest

from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_bundle import IOSXEBundleDriver
from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_common import (
    parse_iosxe_version,
    same_version,
)
from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_install import IOSXEInstallDriver
from tests.iosxe_fakes import Result, ScriptedTransport


@pytest.mark.parametrize(
    ("text", "release"),
    [
        ("17.09.04a", (17, 9, 4, "a")),
        ("17.9.4a", (17, 9, 4, "a")),
        ("17.09.04A", (17, 9, 4, "a")),
        ("17.09.04", (17, 9, 4, "")),
        ("16.12.10a", (16, 12, 10, "a")),
        # "show install summary" adds build numbers; an old train adds ".S".
        ("17.09.04a.0.6", (17, 9, 4, "a")),
        ("03.16.07b.S", (3, 16, 7, "b")),
        ("17.09", None),
        ("17.09.04a1", None),
        ("15.2(4)E10", None),
        ("", None),
    ],
)
def test_parse_iosxe_version(text, release):
    assert parse_iosxe_version(text) == release


@pytest.mark.parametrize(
    ("first", "second", "same"),
    [
        ("17.9.4a", "17.09.04a", True),
        ("17.09.04a", "17.09.04A", True),
        ("17.09.04a.0.6", "17.09.04a", True),
        ("17.09.04", "17.09.04a", False),
        ("17.09.04a", "17.09.04", False),
        ("17.09.04a", "17.09.4b", False),
        ("17.09.04a", "7.09.04a", False),
        ("17.09.04a", "17.09", False),
        # Not versions: compared as written, ignoring case and space.
        ("17.09", "17.09 ", True),
        ("Fuji", "fuji", True),
        ("", "17.09.04a", False),
    ],
)
def test_same_version(first, second, same):
    assert same_version(first, second) is same


def _show_version(version: str) -> Result:
    return Result(f"Cisco IOS XE Software, Version {version}\n")


COMMITTED = Result("IMG   C    17.09.04a.0.6\n")


@pytest.mark.parametrize(
    ("target", "match"),
    [("17.09.04a", True), ("17.9.4a", True), ("17.09.04", False), ("17.09", False)],
)
@pytest.mark.parametrize(
    "driver", [IOSXEInstallDriver(), IOSXEBundleDriver()], ids=["install", "bundle"]
)
async def test_verify_matches_the_target_exactly(driver, target, match):
    ssh = ScriptedTransport(
        {"show version": _show_version("17.09.04a"), "show install summary": COMMITTED}
    )
    result = await driver.verify(ssh, target_version=target)
    assert result.version_match is match
    assert result.success is match
    if not match:
        assert result.error == f"Running version 17.09.04a is not {target}"


@pytest.mark.parametrize(
    "driver", [IOSXEInstallDriver(), IOSXEBundleDriver()], ids=["install", "bundle"]
)
async def test_an_upgrade_to_a_lettered_rebuild_is_a_version_change(driver):
    ssh = ScriptedTransport(
        {"show version": _show_version("17.09.04a"), "show install summary": COMMITTED}
    )
    result = await driver.verify(ssh, target_version="17.09.04a", preflight_version="17.09.04")
    assert result.success is True, result.error
    assert result.version_changed is True


@pytest.mark.parametrize(
    "driver", [IOSXEInstallDriver(), IOSXEBundleDriver()], ids=["install", "bundle"]
)
async def test_the_same_release_written_differently_is_unchanged(driver):
    ssh = ScriptedTransport({"show version": _show_version("17.09.04a")})
    result = await driver.verify(ssh, preflight_version="17.9.4a")
    assert result.success is False
    assert result.version_changed is False
    assert result.error == "Version unchanged: still running 17.09.04a"


INSTALL_PREFLIGHT: dict[str, Result | list[Result]] = {
    "show version": _show_version("17.06.05"),
    "dir": Result("1000 bytes total (2000000000 bytes free)"),
    "show install summary": Result(
        "State (St): I - Inactive, U - Activated & Uncommitted,\n"
        "            C - Activated & Committed, D - Deactivated & Uncommitted\n"
        "Type  St   Filename/Version\n"
        "IMG   C    17.09.04a.0.6\n"
        "IMG   I    17.06.05.0.4459\n"
    ),
}


@pytest.mark.parametrize(
    ("target", "installed"),
    [("17.09.04a", True), ("17.9.4a", True), ("17.09.04", False), ("17.06.05", False)],
)
async def test_install_preflight_finds_the_committed_target_exactly(target, installed):
    ssh = ScriptedTransport(INSTALL_PREFLIGHT)
    result = await IOSXEInstallDriver().preflight(ssh, target_version=target)
    assert result.success is True, result.error
    assert result.target_version_installed is installed


@pytest.mark.parametrize(
    ("target", "installed"), [("17.09.04a", True), ("17.9.4a", True), ("17.09.04", False)]
)
async def test_bundle_preflight_finds_the_running_target_exactly(target, installed):
    ssh = ScriptedTransport(
        {
            "show version": _show_version("17.09.04a"),
            "dir": Result("1000 bytes total (2000000000 bytes free)"),
            "show boot": Result("BOOT variable = flash:isr4300.17.09.04a.SPA.bin;\n"),
        }
    )
    result = await IOSXEBundleDriver().preflight(ssh, target_version=target)
    assert result.success is True, result.error
    assert result.target_version_installed is installed
