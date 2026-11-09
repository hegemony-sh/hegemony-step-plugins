# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What each transport offers with and without the legacy opt-in, and what it let through."""

from typing import Any

import asyncssh
import pytest

from hegemony_step_sdk import SshAlgorithms
from hegemony_step_sdk.ssh import (
    LEGACY_SSH_HELP_TOPIC,
    SSH_ALGORITHM_KINDS,
    SshSecurityConfig,
    asyncssh_algorithm_lists,
    asyncssh_algorithms,
    is_weak_algorithm,
    legacy_algorithms,
)
from hegemony_transport_asyncssh.transport import AsyncSSHTransport
from hegemony_transport_netmiko.transport import SSHTransport
from hegemony_transport_scrapli.transport import ScrapliTransport

TRANSPORTS = (AsyncSSHTransport, ScrapliTransport, SSHTransport)
KIND_FOR_WEAKNESS = {"kex": "kex", "host_key": "signature", "cipher": "cipher", "mac": "mac"}


@pytest.mark.parametrize("transport", TRANSPORTS, ids=lambda t: t.__name__)
def test_legacy_only_adds_and_the_secure_lists_hold_nothing_weak(transport: Any) -> None:
    secure = transport.ssh_algorithm_lists()
    legacy = transport.ssh_algorithm_lists(allow_legacy=True)
    assert tuple(secure) == SSH_ALGORITHM_KINDS == tuple(legacy)
    for kind in SSH_ALGORITHM_KINDS:
        assert secure[kind], kind
        assert set(secure[kind]) <= set(legacy[kind]), kind
        assert not [n for n in secure[kind] if is_weak_algorithm(KIND_FOR_WEAKNESS[kind], n)]
    # The opt-in adds something weak: that is what the help page lists. What
    # it adds differs per library: Paramiko 5 no longer implements SHA-1 key
    # exchange or host keys at all, so for netmiko it adds ciphers and MACs only.
    # Legacy offers every secure algorithm before any it adds, so a peer that
    # supports a secure one agrees on it even with the opt-in on. (With the
    # opt-in netmiko's group exchange no longer checks the group size, so it
    # moves behind the exchanges that need no such check.)
    for kind in SSH_ALGORITHM_KINDS:
        order = list(legacy[kind])
        added_at = [order.index(n) for n in order if n not in secure[kind]]
        secure_at = [order.index(n) for n in secure[kind] if n in order]
        assert not added_at or max(secure_at) < min(added_at), kind
    added = {k: set(legacy[k]) - set(secure[k]) for k in SSH_ALGORITHM_KINDS}
    assert any(is_weak_algorithm(KIND_FOR_WEAKNESS[k], n) for k in added for n in added[k])


def test_asyncssh_legacy_adds_sha1_key_exchange_and_host_keys() -> None:
    secure = AsyncSSHTransport.ssh_algorithm_lists()
    legacy = AsyncSSHTransport.ssh_algorithm_lists(allow_legacy=True)
    assert "diffie-hellman-group14-sha1" in set(legacy["kex"]) - set(secure["kex"])
    assert "ssh-rsa" in set(legacy["host_key"]) - set(secure["host_key"])


def test_the_asyncssh_lists_are_the_ones_a_connection_uses() -> None:
    for allow_legacy in (False, True):
        lists = asyncssh_algorithm_lists(asyncssh, allow_legacy)
        options = asyncssh_algorithms(asyncssh, allow_legacy)
        assert lists["kex"] == tuple(options["kex_algs"])
        assert lists["host_key"] == tuple(options["server_host_key_algs"])
        assert lists["cipher"] == tuple(options["encryption_algs"])
        assert lists["mac"] == tuple(options["mac_algs"])
        assert AsyncSSHTransport.ssh_algorithm_lists(allow_legacy) == lists


def test_netmiko_keeps_the_bounded_group_exchange_in_secure_mode() -> None:
    # Paramiko's group exchange refuses a server group under 2048 bits here,
    # so it stays offered without the opt-in; asyncssh's cannot, so it does not.
    netmiko = SSHTransport.ssh_algorithm_lists()
    assert "diffie-hellman-group-exchange-sha256" in netmiko["kex"]
    asyncssh_lists = AsyncSSHTransport.ssh_algorithm_lists()
    assert not [n for n in asyncssh_lists["kex"] if n.startswith("diffie-hellman-group-exchange-")]


def test_legacy_algorithms_names_what_only_the_opt_in_allows() -> None:
    secure = AsyncSSHTransport.ssh_algorithm_lists()
    with_legacy = AsyncSSHTransport.ssh_algorithm_lists(allow_legacy=True)
    modern = SshAlgorithms(
        kex="mlkem768x25519-sha256",
        host_key="ssh-ed25519",
        cipher="chacha20-poly1305@openssh.com",
        mac="",
    )
    assert legacy_algorithms(modern, secure, with_legacy) == {}
    old = SshAlgorithms(
        kex="diffie-hellman-group14-sha1",
        host_key="ssh-rsa",
        cipher="aes128-cbc",
        mac="hmac-sha1",
    )
    assert legacy_algorithms(old, secure, with_legacy) == {
        "kex": "diffie-hellman-group14-sha1",
        "host_key": "ssh-rsa",
        "cipher": "aes128-cbc",
        "mac": "hmac-sha1",
    }
    # An unknown field is not reported as legacy.
    assert legacy_algorithms(
        SshAlgorithms(kex="diffie-hellman-group1-sha1"), secure, with_legacy
    ) == {"kex": "diffie-hellman-group1-sha1"}
    # Nor is a name the transport does not offer at all: it says nothing of the opt-in.
    netmiko_secure = SSHTransport.ssh_algorithm_lists()
    netmiko_legacy = SSHTransport.ssh_algorithm_lists(allow_legacy=True)
    assert legacy_algorithms(modern, netmiko_secure, netmiko_legacy) == {}
    # And a cipher only netmiko's opt-in adds is reported.
    cbc = SshAlgorithms(
        kex="curve25519-sha256@libssh.org",
        host_key="ssh-ed25519",
        cipher="aes128-cbc",
        mac="hmac-sha1",
    )
    assert legacy_algorithms(cbc, netmiko_secure, netmiko_legacy) == {
        "cipher": "aes128-cbc",
        "mac": "hmac-sha1",
    }


def test_the_opt_in_is_off_by_default_and_names_its_help_page() -> None:
    assert SshSecurityConfig().allow_legacy_ssh is False
    field = SshSecurityConfig.model_json_schema()["properties"]["allow_legacy_ssh"]
    assert field["default"] is False
    assert field["x_help"] == LEGACY_SSH_HELP_TOPIC == "legacy-ssh-algorithms"
