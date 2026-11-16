# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
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
from hegemony_step_sdk.ssh import negotiation_failure_detail
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


@pytest.mark.parametrize(
    "cipher",
    [
        "chacha20-poly1305@openssh.com",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "AEAD_AES_128_GCM",
        "AEAD_AES_256_GCM",
    ],
)
def test_a_cipher_with_integrity_built_in_has_no_mac(cipher: str):
    offer = kexinit(("curve25519-sha256",), cipher=(cipher,))

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


# --- what an error names when the two sides agree on nothing --------------------------------

CLIENT = kexinit(
    ("mlkem768x25519-sha256", "curve25519-sha256", "ext-info-c", "kex-strict-c-v00@openssh.com"),
    host_key=("ssh-ed25519", "rsa-sha2-256"),
    cipher=("aes128-ctr",),
    mac=("hmac-sha2-256",),
)
OLD_DEVICE = kexinit(
    ("diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"),
    host_key=("ssh-rsa",),
    cipher=("aes128-ctr", "aes128-cbc"),
    mac=("hmac-sha1",),
)


def test_the_detail_names_what_each_side_offers_for_each_kind_without_a_match():
    detail = negotiation_failure_detail(CLIENT, OLD_DEVICE)

    assert detail == (
        "no key exchange (kex) algorithm in common; the device offers: "
        "diffie-hellman-group14-sha1, diffie-hellman-group1-sha1; this connection offers: "
        "mlkem768x25519-sha256, curve25519-sha256. "
        "no host key algorithm in common; the device offers: ssh-rsa; "
        "this connection offers: ssh-ed25519, rsa-sha2-256. "
        "no MAC (message authentication code) algorithm in common; the device offers: "
        "hmac-sha1; this connection offers: hmac-sha2-256"
    )


def test_the_detail_says_which_names_the_legacy_opt_in_would_add():
    with_legacy = {"kex": ("diffie-hellman-group14-sha1",), "host_key": (), "mac": ("hmac-sha1",)}

    detail = negotiation_failure_detail(CLIENT, OLD_DEVICE, with_legacy=with_legacy)

    assert "allowing legacy SSH (allow_legacy_ssh) would add: diffie-hellman-group14-sha1" in detail
    assert "would add: hmac-sha1" in detail
    assert (
        detail.count(
            "would not help: this transport implements none of the device's; "
            "choose another SSH transport for this device"
        )
        == 1
    )


def test_the_detail_says_when_legacy_ssh_is_already_allowed():
    detail = negotiation_failure_detail(CLIENT, OLD_DEVICE, legacy_allowed=True)

    assert (
        detail.count(
            "legacy SSH is already allowed, so this transport implements none of the device's; "
            "choose another SSH transport for this device"
        )
        == 3
    )


def test_a_mac_is_not_needed_beside_a_cipher_with_integrity_built_in():
    client = kexinit(("curve25519-sha256",), cipher=("aes256-gcm@openssh.com",))
    device = kexinit(("curve25519-sha256",), cipher=("aes256-gcm@openssh.com",), mac=("hmac-sha1",))

    assert negotiation_failure_detail(client, device) == ""


def test_a_mac_mismatch_is_reported_when_only_the_other_direction_has_integrity_built_in():
    lists = (
        ("curve25519-sha256",),
        ("ssh-ed25519",),
        ("aes256-gcm@openssh.com",),
        ("aes128-ctr",),
        ("hmac-sha2-256",),
        ("hmac-sha2-256",),
        ("none",),
        ("none",),
        (),
        (),
    )
    body = b"".join(
        len(names).to_bytes(4, "big") + names for names in (",".join(x).encode() for x in lists)
    )
    client = bytes([20]) + bytes(16) + body + b"\x00" + bytes(4)
    device = kexinit(
        ("curve25519-sha256",),
        cipher=("aes256-gcm@openssh.com", "aes128-ctr"),
        mac=("hmac-sha1",),
    )

    detail = negotiation_failure_detail(client, device)

    assert detail.startswith("no MAC (message authentication code, device to client) algorithm")
    assert "the device offers: hmac-sha1; this connection offers: hmac-sha2-256" in detail


@pytest.mark.parametrize("message", [b"", bytes([21]) + bytes(40)], ids=["empty", "not kexinit"])
def test_no_detail_without_both_whole_messages(message: bytes):
    assert negotiation_failure_detail(CLIENT, message) == ""
    assert negotiation_failure_detail(message, OLD_DEVICE) == ""


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
async def test_the_device_hop_records_what_its_key_exchange_agreed_on(servers, make):
    port = await servers.device(_ed25519())
    recorder = Recorder()

    await _run(make(port, recorder))

    [(host, recorded_port, algorithms)] = recorder.records
    assert (host, recorded_port) == (HOST, port)
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


@pytest.mark.asyncio
async def test_netmiko_names_the_algorithms_when_the_device_offers_none_it_accepts(servers):
    port = await servers.device(_ed25519(), kex_algs=["diffie-hellman-group14-sha1"])
    transport = TRANSPORTS["netmiko"][0](
        DeviceConnectionSpec(
            host=HOST,
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform="ios-xe",
            connect_timeout=5.0,
            command_timeout=5.0,
        ),
        host_key_verifier=checks_off(),
    )

    [result] = await transport.execute_commands(["show flash"])

    assert result.exit_code == -1
    # netmiko calls the mismatch a timeout; the transport reports it as what it is.
    assert result.error.startswith(
        "SSH connection failed: Incompatible ssh peer (no acceptable kex"
    )
    assert "the device offers: diffie-hellman-group14-sha1;" in result.error
    assert "this connection offers: mlkem768x25519-sha256," in result.error
    assert "ext-info-c" not in result.error
    assert "allow_legacy_ssh" in result.error


#: An old Cisco IOS router: only SHA-1 group 1 key exchange, ssh-rsa host-key
#: signatures, CBC encryption and an SHA-1 MAC.
OLD_IOS = {
    "kex_algs": ["diffie-hellman-group1-sha1"],
    "signature_algs": ["ssh-rsa"],
    "encryption_algs": ["aes256-cbc"],
    "mac_algs": ["hmac-sha1"],
}


@pytest.mark.asyncio
async def test_an_old_ios_router_needs_legacy_ssh_and_a_transport_that_implements_it(
    servers, make, transport_id
):
    port = await servers.device(asyncssh.generate_private_key("ssh-rsa", key_size=2048), **OLD_IOS)
    transport = make(port, None)
    transport.configure_ssh_security(allow_legacy=True)

    [result] = await transport.execute_commands(["show version"])

    if transport_id == "netmiko":
        # paramiko 5 implements none of these key exchanges or signatures.
        assert result.exit_code == -1
        assert "the device offers: diffie-hellman-group1-sha1;" in result.error
        assert "choose another SSH transport for this device" in result.error
    else:
        assert result.exit_code == 0, result.error


@pytest.mark.asyncio
async def test_an_old_ios_router_takes_a_download_over_scrapli_with_legacy_ssh(servers, make):
    """The device pulls a download link: the staging path an old router needs."""
    port = await servers.device(asyncssh.generate_private_key("ssh-rsa", key_size=2048), **OLD_IOS)
    transport = TRANSPORTS["scrapli"][0](
        DeviceConnectionSpec(
            host=HOST,
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform="ios-xe",
            connect_timeout=5.0,
            command_timeout=5.0,
        ),
        host_key_verifier=checks_off(),
    )
    transport.configure_ssh_security(allow_legacy=True)

    result = await transport.http_transfer(
        url="http://10.0.0.9:8080/api/dl/tok/image.bin",
        dest_fs="flash:",
        dest_filename="image.bin",
        timeout_seconds=30,
    )

    assert result["transferred"] is True, result["output"]
    assert "4096 bytes copied" in result["output"]


@pytest.mark.asyncio
@pytest.mark.parametrize("cli_transport", ["netmiko", "scrapli"])
async def test_netmiko_and_scrapli_run_the_same_download_dialogue(servers, cli_transport):
    """The asyncssh transport downloads with curl on a host instead, so it is not here."""
    port = await servers.device(_ed25519())
    transport_class, platform = TRANSPORTS[cli_transport]
    transport = transport_class(
        DeviceConnectionSpec(
            host=HOST,
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform=platform,
            connect_timeout=5.0,
            command_timeout=5.0,
        ),
        host_key_verifier=checks_off(),
    )

    result = await transport.http_transfer(
        url="http://10.0.0.9:8080/api/dl/tok/image.bin",
        dest_fs="flash:",
        dest_filename="image.bin",
        timeout_seconds=30,
    )

    assert result["transferred"] is True, result["output"]


@pytest.mark.asyncio
async def test_scrapli_waits_through_a_silent_copy(servers, monkeypatch):
    """IOS prints nothing while it fetches; a quiet poll must not end the session."""
    from hegemony_transport_scrapli import transport as scrapli_transport

    # Polls much shorter than the router's silence, as in production (2.5 s
    # polls against a fetch that takes as long as the file needs).
    monkeypatch.setattr(scrapli_transport, "_TIMING_POLL_SECONDS", 0.2)
    port = await servers.device(_ed25519())
    transport = TRANSPORTS["scrapli"][0](
        DeviceConnectionSpec(
            host=HOST,
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform="ios-xe",
            connect_timeout=5.0,
            command_timeout=5.0,
        ),
        host_key_verifier=checks_off(),
    )

    result = await transport.http_transfer(
        url="http://10.0.0.9:8080/api/dl/slow/image.bin",
        dest_fs="flash:",
        dest_filename="image.bin",
        timeout_seconds=30,
    )

    assert result["transferred"] is True, result["output"]


@pytest.mark.asyncio
async def test_scrapli_timing_mode_waits_through_a_silent_command(servers, monkeypatch):
    """A long command that goes quiet (an install, a copy) keeps its session in timing mode."""
    from hegemony_transport_scrapli import transport as scrapli_transport

    monkeypatch.setattr(scrapli_transport, "_TIMING_POLL_SECONDS", 0.2)
    port = await servers.device(_ed25519())
    transport = TRANSPORTS["scrapli"][0](
        DeviceConnectionSpec(
            host=HOST,
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform="ios-xe",
            connect_timeout=5.0,
            command_timeout=5.0,
        ),
        host_key_verifier=checks_off(),
    )

    result = await transport.execute_command_timing(
        "copy http://10.0.0.9:8080/api/dl/slow/image.bin flash:image.bin",
        read_timeout=30.0,
        answers={"Destination filename": ""},
        wait_for_patterns=["bytes copied"],
    )

    assert result.exit_code == 0, result.error
    assert "4096 bytes copied" in result.output
