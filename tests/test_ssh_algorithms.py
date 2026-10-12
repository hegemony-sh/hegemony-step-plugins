# SPDX-FileCopyrightText: 2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The device transports report what each SSH hop's key exchange agreed on.

The first tests check the agreement rule on hand-built KEXINIT messages. The
rest dial real SSH servers in this process (``tests/ssh_fakes.py``), so the
algorithms reported are the ones asyncssh (asyncssh and scrapli transports)
and paramiko (netmiko) actually agreed on with the server.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

import asyncssh
import pytest

from hegemony_step_sdk import DeviceConnectionSpec, JumpHostSpec, SshAlgorithms
from hegemony_transport_asyncssh.transport import AsyncSSHTransport
from hegemony_transport_netmiko import transport as netmiko_transport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests.ssh_fakes import (
    JUMP_PASSWORD,
    JUMP_USERNAME,
    PASSWORD,
    USERNAME,
    Servers,
    checks_off,
    ssh_servers,
)

HOST = "127.0.0.1"

TRANSPORTS: dict[str, tuple[type, str]] = {
    "asyncssh": (AsyncSSHTransport, "linux"),
    "scrapli": (ScrapliTransport, "ios-xe"),
    "netmiko": (netmiko_transport.SSHTransport, "ios-xe"),
}


def kexinit(
    kex: tuple[str, ...],
    host_key: tuple[str, ...] = ("ssh-ed25519",),
    cipher: tuple[str, ...] = ("aes128-ctr",),
    mac: tuple[str, ...] = ("hmac-sha2-256",),
) -> bytes:
    """A KEXINIT message (RFC 4253 §7.1) offering these algorithms in both directions."""
    lists = (kex, host_key, cipher, cipher, mac, mac, ("none",), ("none",), (), ())
    body = b"".join(
        len(names).to_bytes(4, "big") + names for names in (",".join(x).encode() for x in lists)
    )
    return bytes([20]) + bytes(16) + body + b"\x00" + bytes(4)


def test_each_algorithm_is_the_first_of_the_clients_list_the_server_offers():
    client = kexinit(
        ("mlkem768x25519-sha256", "curve25519-sha256", "ext-info-c"),
        host_key=("ssh-ed25519", "rsa-sha2-512"),
        cipher=("aes256-ctr", "aes128-ctr"),
        mac=("hmac-sha2-512", "hmac-sha2-256"),
    )
    server = kexinit(
        ("ecdh-sha2-nistp256", "curve25519-sha256", "kex-strict-s-v00@openssh.com"),
        host_key=("rsa-sha2-512", "ssh-ed25519"),
        cipher=("aes128-ctr", "aes256-ctr"),
        mac=("hmac-sha2-256", "hmac-sha2-512"),
    )

    assert SshAlgorithms.from_kexinit(client, server) == SshAlgorithms(
        kex="curve25519-sha256",
        host_key="ssh-ed25519",
        cipher="aes256-ctr",
        mac="hmac-sha2-512",
    )


def test_a_cipher_with_integrity_built_in_has_no_mac():
    offer = kexinit(("curve25519-sha256",), cipher=("chacha20-poly1305@openssh.com",))

    assert SshAlgorithms.from_kexinit(offer, offer).mac == ""


def test_nothing_in_common_is_left_empty():
    algorithms = SshAlgorithms.from_kexinit(
        kexinit(("mlkem768x25519-sha256",)), kexinit(("diffie-hellman-group14-sha1",))
    )

    assert algorithms.kex == ""
    assert algorithms.cipher == "aes128-ctr"


@pytest.mark.parametrize(
    "message",
    [b"", bytes([21]) + bytes(40), kexinit(("curve25519-sha256",))[:30]],
    ids=["empty", "another message", "truncated"],
)
def test_a_message_that_is_not_a_whole_kexinit_is_refused(message: bytes):
    with pytest.raises(ValueError):
        SshAlgorithms.from_kexinit(message, kexinit(("curve25519-sha256",)))


# --- the transports, against real SSH servers -----------------------------------------------


class Recorder:
    """The host's recorder, in memory."""

    def __init__(self) -> None:
        self.records: list[tuple[str, int, SshAlgorithms]] = []

    def record(self, host: str, port: int, algorithms: SshAlgorithms) -> None:
        self.records.append((host, port, algorithms))


class FailingRecorder:
    def record(self, host: str, port: int, algorithms: SshAlgorithms) -> None:
        raise RuntimeError("the host could not keep the record")


@pytest.fixture(params=sorted(TRANSPORTS))
def transport_id(request) -> str:
    return request.param


@pytest.fixture
async def servers() -> AsyncIterator[Servers]:
    async with ssh_servers() as started:
        yield started


@pytest.fixture
def make(transport_id: str) -> Callable[..., Any]:
    """Build the transport under test for a device on ``port``."""
    transport_class, platform = TRANSPORTS[transport_id]

    def build(port: int, recorder: Any, *, jump_port: int | None = None) -> Any:
        jump = (
            JumpHostSpec(host=HOST, port=jump_port, username=JUMP_USERNAME, password=JUMP_PASSWORD)
            if jump_port is not None
            else None
        )
        spec = DeviceConnectionSpec(
            host=HOST,
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform=platform,
            connect_timeout=5.0,
            command_timeout=5.0,
            jump_host=jump,
        )
        return transport_class(
            spec, host_key_verifier=checks_off(), ssh_algorithm_recorder=recorder
        )

    return build


def _ed25519() -> asyncssh.SSHKey:
    return asyncssh.generate_private_key("ssh-ed25519")


async def _run(transport: Any) -> None:
    [result] = await transport.execute_commands(["show version"])
    assert result.exit_code == 0, result.error


def test_every_transport_advertises_the_recorder():
    for transport_class, _ in TRANSPORTS.values():
        assert getattr(transport_class, "supports_ssh_algorithm_recorder", False) is True


@pytest.mark.asyncio
async def test_the_device_hop_records_what_its_key_exchange_agreed_on(servers, make, transport_id):
    port = await servers.device(_ed25519())
    recorder = Recorder()

    await _run(make(port, recorder))

    [(host, recorded_port, algorithms)] = recorder.records
    assert (host, recorded_port) == (HOST, port)
    if transport_id == "netmiko":
        # paramiko has no post-quantum key exchange.
        assert algorithms.kex in ("curve25519-sha256", "curve25519-sha256@libssh.org")
    else:
        assert algorithms.kex == "mlkem768x25519-sha256"
    assert algorithms.host_key == "ssh-ed25519"
    assert algorithms.cipher


@pytest.mark.asyncio
async def test_the_key_exchange_recorded_is_the_one_the_device_allows(servers, make):
    port = await servers.device(_ed25519(), kex_algs=["ecdh-sha2-nistp256"])
    recorder = Recorder()

    await _run(make(port, recorder))

    [(_, _, algorithms)] = recorder.records
    assert algorithms.kex == "ecdh-sha2-nistp256"


@pytest.mark.asyncio
async def test_both_hops_are_recorded_jump_host_first(servers, make):
    jump_port = await servers.bastion(_ed25519(), kex_algs=["ecdh-sha2-nistp384"])
    device_port = await servers.device(_ed25519(), kex_algs=["ecdh-sha2-nistp256"])
    recorder = Recorder()

    await _run(make(device_port, recorder, jump_port=jump_port))

    assert [(port, algorithms.kex) for _, port, algorithms in recorder.records] == [
        (jump_port, "ecdh-sha2-nistp384"),
        (device_port, "ecdh-sha2-nistp256"),
    ]


@pytest.mark.asyncio
async def test_a_recorder_that_fails_does_not_fail_the_step(servers, make):
    port = await servers.device(_ed25519())

    await _run(make(port, FailingRecorder()))


@pytest.mark.asyncio
async def test_without_a_recorder_the_transports_connect_as_before(servers, make):
    port = await servers.device(_ed25519())

    await _run(make(port, None))
