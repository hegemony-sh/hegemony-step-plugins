# SPDX-FileCopyrightText: 2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""A rejected password fails the install step, on every transport.

The transports never raise for a login the device refuses: every command
comes back with exit code -1, no output and an error. The install step must
read that as a failure - not as an install that finished without a reload.
Each test dials a real SSH server in this process (``tests/ssh_fakes.py``)
that refuses the password, so what is under test is the transport's own
handling of the SSH library's authentication error.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import asyncssh
import pytest

from hegemony_step_sdk import DeviceConnectionSpec
from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_install import IOSXEInstallDriver
from hegemony_steps_cisco_iosxe.upgrade.handlers.install import UpgradeInstallHandler
from hegemony_transport_asyncssh.transport import AsyncSSHTransport
from hegemony_transport_netmiko import transport as netmiko_transport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests.iosxe_fakes import FakeServices, Result, ScriptedTransport, make_ctx
from tests.ssh_fakes import PASSWORD, USERNAME, Servers, checks_off, ssh_servers

HOST = "127.0.0.1"
WRONG_PASSWORD = "not-the-device-pw"
INSTALL = "install add file flash:img.bin activate commit"

TRANSPORTS: dict[str, tuple[type, str]] = {
    "asyncssh": (AsyncSSHTransport, "linux"),
    "scrapli": (ScrapliTransport, "ios-xe"),
    "netmiko": (netmiko_transport.SSHTransport, "ios-xe"),
}


@pytest.fixture(params=sorted(TRANSPORTS))
def transport_id(request) -> str:
    return request.param


@pytest.fixture
async def servers() -> AsyncIterator[Servers]:
    async with ssh_servers() as started:
        yield started


@pytest.fixture
async def refusing(servers: Servers, transport_id: str) -> Callable[[], Any]:
    """Build the transport under test for a device that refuses its password."""
    port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
    transport_class, platform = TRANSPORTS[transport_id]

    def build() -> Any:
        spec = DeviceConnectionSpec(
            host=HOST,
            port=port,
            username=USERNAME,
            password=WRONG_PASSWORD,
            platform=platform,
            connect_timeout=5.0,
            command_timeout=5.0,
        )
        return transport_class(spec, host_key_verifier=checks_off())

    return build


class _LoginRefusedAtInstall(ScriptedTransport):
    """``show boot`` answers; the install session's login is refused.

    The session before the install logs in, the install's own does not: the
    install command is the one the rejected password must not turn into a
    finished install.
    """

    def __init__(self, transport: Any) -> None:
        super().__init__({"show boot": Result("BOOT variable = flash:packages.conf;\n")})
        self.transport = transport

    async def execute_command_timing(self, command: str, **kwargs: Any) -> Any:
        self.calls.append([command])
        return await self.transport.execute_command_timing(command, **kwargs)


def _assert_login_refused(servers: Servers) -> None:
    assert servers.seen.passwords, "the device never saw a login"
    assert set(servers.seen.passwords) == {WRONG_PASSWORD}
    assert PASSWORD not in servers.seen.passwords


async def test_execute_commands_reports_a_refused_login_as_a_failure(servers, refusing):
    [result] = await refusing().execute_commands(["show boot"])

    assert result.exit_code == -1
    assert result.output == ""
    assert (result.error or "").startswith("Authentication failed: ")
    _assert_login_refused(servers)


async def test_timing_mode_reports_a_refused_login_as_a_failure(servers, refusing):
    result = await refusing().execute_command_timing(
        INSTALL, read_timeout=10, answers={"[y/n]": "y"}, wait_for_patterns=["SUCCESS: install_"]
    )

    assert result.exit_code == -1
    assert result.output == ""
    assert result.error
    _assert_login_refused(servers)


@pytest.mark.parametrize("activate", [True, False], ids=["activate", "add-only"])
async def test_the_driver_fails_when_the_install_session_login_is_refused(
    servers, refusing, activate
):
    ssh = _LoginRefusedAtInstall(refusing())

    result = await IOSXEInstallDriver().install(
        ssh, image_name="img.bin", dest_fs="flash:", activate=activate
    )

    assert result.success is False
    assert result.reboot_triggered is False
    assert result.activated is False
    assert result.committed is False
    assert (result.error or "").startswith("Install session failed: ")
    assert ssh.commands[-1].startswith("install add file flash:img.bin")
    _assert_login_refused(servers)


async def test_the_step_fails_when_the_install_session_login_is_refused(servers, refusing):
    services = FakeServices(lambda: _LoginRefusedAtInstall(refusing()))

    result = await UpgradeInstallHandler().execute(make_ctx({"image_name": "img.bin"}, services))

    assert result.success is False
    assert result.summary == "Install failed on 1 device(s): sw1"
    assert result.metrics["success_count"] == 0
    assert result.metrics["failure_count"] == 1
    [context] = result.metrics["output_context"].values()
    assert context["reboot_triggered"] is False
    assert context["activated"] is False
    [evidence] = result.evidence
    assert evidence["name"] == "Install: sw1"
    status = evidence["content_json"]
    assert status["success"] is False
    assert status["reboot_triggered"] is False
    assert status["went_down"] is None
    assert status["error"].startswith("Install session failed: ")
    assert "Success: False" in evidence["content_text"]
    assert "Reboot Triggered: False" in evidence["content_text"]
    _assert_login_refused(servers)


async def test_the_step_fails_when_every_login_is_refused(servers, refusing):
    """No session logs in, so the boot variable check fails before the install."""
    services = FakeServices(refusing)

    result = await UpgradeInstallHandler().execute(make_ctx({"image_name": "img.bin"}, services))

    assert result.success is False
    [evidence] = result.evidence
    status = evidence["content_json"]
    assert status["success"] is False
    assert status["reboot_triggered"] is False
    assert status["error"].startswith("show boot failed: Authentication failed: ")
    _assert_login_refused(servers)
