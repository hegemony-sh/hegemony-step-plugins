# SPDX-FileCopyrightText: 2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The device transports check SSH host keys through the host's verifier.

Each test dials real SSH servers in this process (``tests/ssh_fakes.py``), so
the key exchange and the SSH library's own check (asyncssh for the asyncssh
and scrapli transports, paramiko for netmiko) are what is under test. Both
hops are covered: a device dialled directly, and a device behind a jump host.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Callable
from typing import Any

import asyncssh
import pytest

from hegemony_step_sdk import DeviceConnectionSpec, JumpHostSpec
from hegemony_transport_asyncssh.transport import AsyncSSHTransport
from hegemony_transport_netmiko import transport as netmiko_transport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests.ssh_fakes import (
    JUMP_PASSWORD,
    JUMP_USERNAME,
    PASSWORD,
    USERNAME,
    FakeVerifier,
    Servers,
    key_line,
    ssh_servers,
)

HOST = "127.0.0.1"

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
def make(transport_id: str) -> Callable[..., Any]:
    """Build the transport under test for a device on ``port``."""
    transport_class, platform = TRANSPORTS[transport_id]

    def build(port: int, verifier: FakeVerifier | None, *, jump_port: int | None = None) -> Any:
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
        return transport_class(spec, host_key_verifier=verifier)

    return build


def _ed25519() -> asyncssh.SSHKey:
    return asyncssh.generate_private_key("ssh-ed25519")


async def _run(transport: Any) -> Any:
    [result] = await transport.execute_commands(["show version"])
    return result


def test_every_transport_advertises_the_verifier():
    for transport_class, _ in TRANSPORTS.values():
        assert getattr(transport_class, "supports_host_key_verifier", False) is True


# --- one hop -----------------------------------------------------------------------------


async def test_first_contact_records_the_key_before_logging_in(servers, make):
    key = _ed25519()
    port = await servers.device(key)
    verifier = FakeVerifier()

    result = await _run(make(port, verifier))

    assert result.exit_code == 0, result.error
    assert "show version" in result.output
    assert verifier.keys[(HOST, port)] == [key_line(key)]
    assert verifier.operations() == ["trusted_keys", "learn"]
    assert servers.seen.passwords == [PASSWORD]


async def test_a_changed_host_key_fails_the_step_before_the_password_is_sent(servers, make):
    trusted, presented = _ed25519(), _ed25519()
    port = await servers.device(presented)
    verifier = FakeVerifier()
    verifier.trust(HOST, port, trusted)

    result = await _run(make(port, verifier))

    assert result.exit_code != 0
    assert f"The SSH host key of {HOST}:{port} does not match" in (result.error or "")
    assert servers.seen.passwords == []
    assert verifier.calls[-1] == ("rejected", HOST, port, key_line(presented))
    assert verifier.keys[(HOST, port)] == [key_line(trusted)]


async def test_the_login_after_first_contact_accepts_only_the_key_just_recorded(servers, make):
    # The host answers the key fetch with one key, then the login with another
    # (a machine in the path that steps in between): the login is refused.
    recorded, swapped = _ed25519(), _ed25519()
    port = await servers.device(recorded)
    verifier = FakeVerifier()

    async def swap() -> None:
        await servers.restart(port, swapped)

    verifier.after_learn = swap

    result = await _run(make(port, verifier))

    assert "does not match" in (result.error or "")
    assert servers.seen.passwords == []
    assert verifier.keys[(HOST, port)] == [key_line(recorded)]
    assert verifier.calls[-1] == ("rejected", HOST, port, key_line(swapped))


async def test_a_host_that_now_offers_only_another_key_type_is_refused(servers, make):
    trusted = _ed25519()
    presented = asyncssh.generate_private_key("ecdsa-sha2-nistp256")
    port = await servers.device(presented)
    verifier = FakeVerifier()
    verifier.trust(HOST, port, trusted)

    result = await _run(make(port, verifier))

    assert "does not match" in (result.error or "")
    assert servers.seen.passwords == []
    assert verifier.calls[-1] == ("rejected", HOST, port, key_line(presented))


async def test_a_trusted_key_logs_in_without_learning(servers, make):
    key = _ed25519()
    port = await servers.device(key)
    verifier = FakeVerifier(mode="strict")
    verifier.trust(HOST, port, key)

    result = await _run(make(port, verifier))

    assert result.exit_code == 0, result.error
    assert verifier.operations() == ["trusted_keys"]


async def test_a_host_with_several_trusted_keys_may_present_any_of_them(servers, make):
    key = _ed25519()
    port = await servers.device(key)
    verifier = FakeVerifier()
    verifier.trust(HOST, port, asyncssh.generate_private_key("ecdsa-sha2-nistp256"), key)

    result = await _run(make(port, verifier))

    assert result.exit_code == 0, result.error


async def test_strict_without_a_trusted_key_does_not_dial(servers, make):
    port = await servers.device(_ed25519())
    verifier = FakeVerifier(mode="strict")

    result = await _run(make(port, verifier))

    assert "is trusted (strict)" in (result.error or "")
    assert servers.seen.connections == []


async def test_checks_switched_off_connect_unchecked(servers, make):
    port = await servers.device(_ed25519())
    verifier = FakeVerifier(mode="off")

    result = await _run(make(port, verifier))

    assert result.exit_code == 0, result.error
    assert verifier.operations() == ["trusted_keys"]
    assert verifier.keys == {}


async def test_without_a_verifier_the_transport_refuses_to_connect(servers, make):
    port = await servers.device(_ed25519())

    result = await _run(make(port, None))

    assert result.exit_code != 0
    assert f"refusing to connect to {HOST}:{port}: no SSH host-key verifier" in (result.error or "")
    assert servers.seen.connections == []


async def test_without_a_verifier_the_jump_host_is_not_dialled_either(servers, make):
    jump_port = await servers.bastion(_ed25519())
    port = await servers.device(_ed25519())

    result = await _run(make(port, None, jump_port=jump_port))

    assert f"refusing to connect to {HOST}:{jump_port}" in (result.error or "")
    assert servers.seen.connections == []


# --- a device behind a jump host ---------------------------------------------------------


async def test_both_hops_learn_their_keys_on_first_contact(servers, make):
    bastion_key, device_key = _ed25519(), _ed25519()
    jump_port = await servers.bastion(bastion_key)
    port = await servers.device(device_key)
    verifier = FakeVerifier()

    result = await _run(make(port, verifier, jump_port=jump_port))

    assert result.exit_code == 0, result.error
    assert verifier.keys == {
        (HOST, jump_port): [key_line(bastion_key)],
        (HOST, port): [key_line(device_key)],
    }
    # The jump host first; the device's key was fetched through it.
    assert [call[:3] for call in verifier.calls] == [
        ("trusted_keys", HOST, jump_port),
        ("learn", HOST, jump_port),
        ("trusted_keys", HOST, port),
        ("learn", HOST, port),
    ]
    assert servers.seen.passwords == [JUMP_PASSWORD, PASSWORD]
    assert (HOST, port) in servers.seen.forwards


async def test_a_changed_jump_host_key_fails_before_the_jump_password_is_sent(servers, make):
    trusted, presented = _ed25519(), _ed25519()
    jump_port = await servers.bastion(presented)
    port = await servers.device(_ed25519())
    verifier = FakeVerifier()
    verifier.trust(HOST, jump_port, trusted)

    result = await _run(make(port, verifier, jump_port=jump_port))

    assert f"The SSH host key of {HOST}:{jump_port} does not match" in (result.error or "")
    assert servers.seen.passwords == []
    assert servers.seen.forwards == []
    assert verifier.calls[-1] == ("rejected", HOST, jump_port, key_line(presented))


async def test_a_changed_device_key_behind_the_jump_host_fails_before_the_device_password(
    servers, make
):
    bastion_key, trusted, presented = _ed25519(), _ed25519(), _ed25519()
    jump_port = await servers.bastion(bastion_key)
    port = await servers.device(presented)
    verifier = FakeVerifier()
    verifier.trust(HOST, jump_port, bastion_key)
    verifier.trust(HOST, port, trusted)

    result = await _run(make(port, verifier, jump_port=jump_port))

    assert f"The SSH host key of {HOST}:{port} does not match" in (result.error or "")
    # The jump host was trusted and logged in to; the device saw no password.
    assert servers.seen.passwords == [JUMP_PASSWORD]
    assert verifier.calls[-1] == ("rejected", HOST, port, key_line(presented))


# --- netmiko specifics -------------------------------------------------------------------


async def test_netmiko_removes_its_known_hosts_file(servers, monkeypatch):
    written: list[str] = []
    write = netmiko_transport._write_known_hosts

    def recording_write(host: str, port: int, keys: tuple[str, ...]) -> str:
        path = write(host, port, keys)
        with open(path, encoding="ascii") as handle:
            assert handle.read() == f"[{host}]:{port} {keys[0]}\n"
        written.append(path)
        return path

    monkeypatch.setattr(netmiko_transport, "_write_known_hosts", recording_write)
    key = _ed25519()
    port = await servers.device(key)
    verifier = FakeVerifier()
    verifier.trust(HOST, port, key)
    transport_class, platform = TRANSPORTS["netmiko"]
    spec = DeviceConnectionSpec(
        host=HOST, port=port, username=USERNAME, password=PASSWORD, platform=platform
    )

    result = await _run(transport_class(spec, host_key_verifier=verifier))

    assert result.exit_code == 0, result.error
    assert len(written) == 1
    assert not os.path.exists(written[0])


def _netmiko_with(verifier: FakeVerifier) -> Any:
    transport_class, platform = TRANSPORTS["netmiko"]
    spec = DeviceConnectionSpec(host=HOST, port=22, username=USERNAME, platform=platform)
    return transport_class(spec, host_key_verifier=verifier)


def test_netmiko_runs_the_verifier_on_a_loop_of_its_own_outside_its_async_methods():
    # Called directly (no async method recorded a loop), the blocking side
    # still asks the verifier.
    verifier = FakeVerifier()
    verifier.trust(HOST, 22, _ed25519())

    keys = _netmiko_with(verifier)._from_loop(verifier.trusted_keys(HOST, 22))

    assert keys == tuple(verifier.keys[(HOST, 22)])


async def test_netmiko_refuses_to_wait_for_the_verifier_on_its_own_loop():
    # Waiting in the loop's own thread would block the loop the verifier needs.
    verifier = FakeVerifier()
    transport = _netmiko_with(verifier)
    transport._loop = asyncio.get_running_loop()

    with pytest.raises(RuntimeError, match="cannot wait for the verifier"):
        transport._from_loop(verifier.trusted_keys(HOST, 22))
