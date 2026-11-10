# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The inventory's per-hop legacy SSH flag opens one hop only, and reports weak host keys."""

from typing import Any

import asyncssh
import pytest

from hegemony_step_sdk import DeviceConnectionSpec, JumpHostSpec, SshAlgorithms
from hegemony_step_sdk.ssh import hop_allows_legacy, is_weak_ssh_public_key
from hegemony_transport_asyncssh.transport import AsyncSSHTransport
from hegemony_transport_netmiko.transport import SSHTransport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests.ssh_fakes import (
    JUMP_PASSWORD,
    JUMP_USERNAME,
    PASSWORD,
    USERNAME,
    FakeVerifier,
    key_line,
    ssh_servers,
)

TRANSPORTS = [(AsyncSSHTransport, "linux"), (SSHTransport, "ios-xe"), (ScrapliTransport, "ios-xe")]


class Recorder:
    """Keeps what each hop agreed on, by port."""

    def __init__(self) -> None:
        self.hops: dict[int, SshAlgorithms] = {}

    def record(self, host: str, port: int, algorithms: SshAlgorithms) -> None:
        self.hops[port] = algorithms


def build(cls, platform, port, *, jump_port=None, device_legacy=False, jump_legacy=False):
    """A transport whose hops carry the inventory's legacy flags."""
    recorder = Recorder()
    transport = cls(
        DeviceConnectionSpec(
            host="127.0.0.1",
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform=platform,
            connect_timeout=3,
            command_timeout=3,
            jump_host=JumpHostSpec(
                "127.0.0.1", jump_port, JUMP_USERNAME, JUMP_PASSWORD, allow_legacy_ssh=jump_legacy
            )
            if jump_port
            else None,
            allow_legacy_ssh=device_legacy,
        ),
        host_key_verifier=FakeVerifier(),
        ssh_algorithm_recorder=recorder,
    )
    return transport, recorder


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
@pytest.mark.parametrize("weak_hop", ["device", "jump"])
@pytest.mark.parametrize("flagged_hop", ["device", "jump", "none"])
async def test_inventory_flag_opens_only_its_own_hop(cls, platform, weak_hop, flagged_hop):
    """A legacy-only hop connects when its own flag is set, never through the other hop's."""
    key = asyncssh.generate_private_key("ssh-ed25519")
    weak: dict[str, Any] = {"encryption_algs": ["aes128-cbc"]}
    async with ssh_servers() as servers:
        jump_port = await servers.bastion(key, **(weak if weak_hop == "jump" else {}))
        port = await servers.device(key, **(weak if weak_hop == "device" else {}))
        transport, recorder = build(
            cls,
            platform,
            port,
            jump_port=jump_port,
            device_legacy=flagged_hop == "device",
            jump_legacy=flagged_hop == "jump",
        )
        [result] = await transport.execute_commands(["show version"])
        if weak_hop == flagged_hop:
            assert result.exit_code == 0, result.error
            weak_port = port if weak_hop == "device" else jump_port
            other_port = jump_port if weak_hop == "device" else port
            assert recorder.hops[weak_port].cipher == "aes128-cbc"
            assert recorder.hops[other_port].cipher != "aes128-cbc"
        else:
            assert result.exit_code != 0
            assert PASSWORD not in servers.seen.passwords


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
@pytest.mark.parametrize("small", [False, True])
async def test_recorded_hop_says_whether_the_host_key_is_weak(cls, platform, small):
    """A small RSA host key is reported as weak although its signature algorithm is not."""
    key = (
        asyncssh.generate_private_key("ssh-rsa", key_size=1024)
        if small
        else asyncssh.generate_private_key("ssh-ed25519")
    )
    async with ssh_servers() as servers:
        port = await servers.device(key)
        transport, recorder = build(cls, platform, port, device_legacy=True)
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code == 0, result.error
        assert recorder.hops[port].weak_host_key is small
        assert is_weak_ssh_public_key(key_line(key)) is small


def test_step_setting_allows_legacy_on_both_hops():
    """The step setting covers both hops; without it each hop follows its own flag."""
    spec = DeviceConnectionSpec(
        host="device",
        port=22,
        jump_host=JumpHostSpec("bastion", 2222),
        allow_legacy_ssh=True,
    )
    assert hop_allows_legacy(spec, "device", 22)
    assert not hop_allows_legacy(spec, "bastion", 2222)
    assert hop_allows_legacy(spec, "bastion", 2222, step_setting=True)
    plain = DeviceConnectionSpec(host="device", port=22)
    assert not hop_allows_legacy(plain, "device", 22)
    assert hop_allows_legacy(plain, "device", 22, step_setting=True)
