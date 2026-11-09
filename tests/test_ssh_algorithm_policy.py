# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Library defaults are filtered for weak algorithms and unbounded group exchanges."""

import base64
import socket
from typing import Any

import asyncssh
import paramiko
import paramiko.kex_gex
import pytest

from hegemony_step_sdk.ssh import (
    algorithm_policy,
    asyncssh_algorithms,
    configure_paramiko,
    is_weak_algorithm,
    validate_ssh_public_key,
)
from hegemony_transport_asyncssh.transport import AsyncSSHTransport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests.ssh_fakes import PASSWORD, FakeVerifier, key_line, ssh_servers
from tests.test_ssh_security_policy import build

#: AsyncSSH implements UMAC only when the nettle library is installed.
UMAC_AVAILABLE = (
    b"umac-128-etm@openssh.com"
    in asyncssh.SSHClientConnectionOptions(config=None, mac_algs="*").mac_algs
)

ASYNCSSH_KINDS = {
    "kex_algs": "kex",
    "encryption_algs": "cipher",
    "mac_algs": "mac",
    "signature_algs": "signature",
    "server_host_key_algs": "signature",
}


@pytest.mark.parametrize(
    ("kind", "name"),
    [
        ("kex", "diffie-hellman-group14-sha1"),
        ("kex", "diffie-hellman-group1-sha1"),
        ("kex", "diffie-hellman-group-exchange-sha1"),
        ("kex", "gss-group14-sha1"),
        ("kex", "rsa1024-sha1"),
        ("cipher", "aes128-cbc"),
        ("cipher", "3des-cbc"),
        ("cipher", "blowfish-cbc"),
        ("cipher", "seed-cbc@ssh.com"),
        ("cipher", "arcfour"),
        ("cipher", "arcfour256"),
        ("cipher", "none"),
        ("mac", "hmac-sha1"),
        ("mac", "hmac-sha1-etm@openssh.com"),
        ("mac", "hmac-md5-96"),
        ("mac", "hmac-sha2-256-96"),
        ("signature", "ssh-rsa"),
        ("signature", "ssh-rsa-cert-v01@openssh.com"),
        ("signature", "ssh-dss"),
        ("signature", "x509v3-ssh-rsa"),
        ("signature", "x509v3-sign-dss"),
    ],
)
def test_weak_algorithms_are_recognised(kind, name):
    """Each weak family is caught, including suffix variants such as -etm."""
    assert is_weak_algorithm(kind, name)


@pytest.mark.parametrize(
    ("kind", "name"),
    [
        ("kex", "sntrup761x25519-sha512"),
        ("kex", "mlkem1024nistp384-sha384"),
        ("kex", "curve448-sha512"),
        ("kex", "diffie-hellman-group-exchange-sha256"),
        ("cipher", "chacha20-poly1305@openssh.com"),
        ("cipher", "aes256-gcm@openssh.com"),
        ("mac", "umac-128-etm@openssh.com"),
        ("mac", "hmac-sha2-512-etm@openssh.com"),
        ("signature", "rsa-sha2-512"),
        ("signature", "rsa-sha2-512-cert-v01@openssh.com"),
        ("signature", "ssh-ed448"),
        ("signature", "sk-ssh-ed25519@openssh.com"),
    ],
)
def test_strong_algorithms_are_not_weak(kind, name):
    """Strong primitives are not mislabeled weak; exchange-size policy is separate."""
    assert not is_weak_algorithm(kind, name)


def test_policy_keeps_library_order_and_adds_everything_for_legacy():
    """Secure mode filters the defaults; legacy adds what the library implements."""
    defaults = ["new-strong-cipher", "aes128-ctr", "aes128-cbc"]
    implemented = ["new-strong-cipher", "aes128-ctr", "aes128-cbc", "arcfour", "3des-cbc"]
    assert algorithm_policy("cipher", defaults, implemented) == ("new-strong-cipher", "aes128-ctr")
    assert algorithm_policy("cipher", defaults, implemented, allow_legacy=True) == tuple(
        implemented
    )


def test_legacy_offers_every_secure_algorithm_before_any_weak_one():
    """A library default order that puts a weak algorithm early does not lead with it."""
    defaults = ["aes128-cbc", "chacha20-poly1305@openssh.com", "3des-cbc", "aes128-ctr"]
    implemented = [*defaults, "arcfour"]
    assert algorithm_policy("cipher", defaults, implemented, allow_legacy=True) == (
        "chacha20-poly1305@openssh.com",
        "aes128-ctr",
        "aes128-cbc",
        "3des-cbc",
        "arcfour",
    )
    # A default the library does not implement is never offered.
    assert algorithm_policy("cipher", ["missing"], implemented) == ()


@pytest.mark.parametrize("legacy", [False, True])
def test_asyncssh_policy_follows_the_library(legacy):
    """No weak name in secure mode; every implemented name with the legacy override."""
    policy = asyncssh_algorithms(asyncssh, legacy)
    implemented = asyncssh.SSHClientConnectionOptions(
        config=None, kex_algs="*", encryption_algs="*", mac_algs="*", signature_algs="*"
    )
    for name, kind in ASYNCSSH_KINDS.items():
        weak = [alg for alg in policy[name] if is_weak_algorithm(kind, alg)]
        assert bool(weak) is legacy, (name, weak)
    for name in ("kex_algs", "encryption_algs", "mac_algs", "signature_algs"):
        # X.509 signatures need X.509 trust anchors, which the transports never set.
        every = {
            alg.decode() for alg in getattr(implemented, name) if not alg.startswith(b"x509v3-")
        }
        assert (set(policy[name]) == every) is legacy
    # Strong algorithms the earlier fixed lists left out are now offered.
    assert "curve448-sha512" in policy["kex_algs"]
    if UMAC_AVAILABLE:
        assert "umac-128-etm@openssh.com" in policy["mac_algs"]
    assert "ssh-ed448" in policy["server_host_key_algs"]
    assert not any(alg.startswith(("sk-", "webauthn-")) for alg in policy["server_host_key_algs"])
    assert not any(alg.startswith("x509v3-") for alg in policy["signature_algs"])


@pytest.mark.parametrize("legacy", [False, True])
def test_paramiko_policy_follows_the_library(legacy):
    """Paramiko keeps its own defaults minus weak names, or everything with legacy."""
    left, right = socket.socketpair()
    transport = paramiko.Transport(left)
    try:
        configure_paramiko(transport, legacy)
        options = transport.get_security_options()
        for name, kind, registry in (
            ("kex", "kex", paramiko.Transport._kex_info),
            ("ciphers", "cipher", paramiko.Transport._cipher_info),
            ("digests", "mac", paramiko.Transport._mac_info),
        ):
            chosen = tuple(getattr(options, name))
            assert chosen
            assert not any(is_weak_algorithm(kind, alg) for alg in chosen) or legacy
            if legacy:
                assert set(chosen) == set(registry)
        assert not any(alg.endswith("-cert-v01@openssh.com") for alg in options.key_types)
        assert ("hmac-sha1" in options.digests) is legacy
    finally:
        transport.close()
        right.close()


@pytest.mark.parametrize(
    ("cls", "platform"), [(AsyncSSHTransport, "linux"), (ScrapliTransport, "ios-xe")]
)
@pytest.mark.parametrize(
    ("option", "value"),
    [
        ("kex_algs", "curve448-sha512"),
        pytest.param(
            "mac_algs",
            "umac-128-etm@openssh.com",
            marks=pytest.mark.skipif(not UMAC_AVAILABLE, reason="AsyncSSH UMAC needs nettle"),
        ),
    ],
)
async def test_strong_algorithm_outside_old_lists_connects_securely(cls, platform, option, value):
    """A device offering only a strong algorithm the old allowlist omitted still connects."""
    options: dict[str, Any] = {option: [value], "encryption_algs": ["aes128-ctr"]}
    async with ssh_servers() as servers:
        port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"), **options)
        transport = build(cls, platform, port, FakeVerifier())
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code == 0, result.error
        assert PASSWORD in servers.seen.passwords


@pytest.mark.parametrize(
    ("cls", "platform"), [(AsyncSSHTransport, "linux"), (ScrapliTransport, "ios-xe")]
)
async def test_ed448_host_key_connects_securely(cls, platform):
    """Ed448 host keys are strong and accepted without the legacy override."""
    async with ssh_servers() as servers:
        port = await servers.device(asyncssh.generate_private_key("ssh-ed448"))
        transport = build(cls, platform, port, FakeVerifier())
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code == 0, result.error


@pytest.mark.parametrize(
    ("cls", "platform"), [(AsyncSSHTransport, "linux"), (ScrapliTransport, "ios-xe")]
)
@pytest.mark.parametrize("legacy", [False, True])
async def test_legacy_override_offers_every_implemented_cipher(cls, platform, legacy):
    """Legacy keeps very old devices reachable, even with ciphers the old list never named."""
    async with ssh_servers() as servers:
        port = await servers.device(
            asyncssh.generate_private_key("ssh-ed25519"), encryption_algs=["arcfour256"]
        )
        transport = build(cls, platform, port, FakeVerifier())
        transport.configure_ssh_security(allow_legacy=legacy)
        [result] = await transport.execute_commands(["show version"])
        assert (result.exit_code == 0) is legacy, result.error
        assert (PASSWORD in servers.seen.passwords) is legacy


def test_ed448_keys_are_validated():
    """Accept well-formed Ed448 keys and reject a wrong length."""
    key = asyncssh.generate_private_key("ssh-ed448")
    validate_ssh_public_key(key_line(key))
    blob = b"".join(len(part).to_bytes(4, "big") + part for part in (b"ssh-ed448", bytes(32)))
    with pytest.raises(ValueError, match="Ed448"):
        validate_ssh_public_key("ssh-ed448 " + base64.b64encode(blob).decode())


def test_dsa_keys_are_rejected():
    """DSA is weak whatever its encoding."""
    blob = b"".join(len(part).to_bytes(4, "big") + part for part in (b"ssh-dss", b"\x01"))
    with pytest.raises(ValueError, match="DSA"):
        validate_ssh_public_key("ssh-dss " + base64.b64encode(blob).decode())


def test_unknown_key_types_are_not_rejected():
    """A future key type is not refused only because the policy does not list it."""
    blob = b"".join(len(part).to_bytes(4, "big") + part for part in (b"ssh-future", b"key"))
    validate_ssh_public_key("ssh-future " + base64.b64encode(blob).decode())


@pytest.mark.parametrize("kind", ["ssh-ed25519-cert-v01@openssh.com", "x509v3-ssh-ed25519"])
def test_certificates_are_not_validated_as_plain_keys(kind):
    """Certificates must be checked through their keys, never accepted as unknown."""
    blob = len(kind).to_bytes(4, "big") + kind.encode()
    with pytest.raises(ValueError, match="certificates"):
        validate_ssh_public_key(kind + " " + base64.b64encode(blob).decode())


@pytest.mark.parametrize(
    "name",
    [
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group-exchange-sha256@vendor.example",
        "gss-gex-sha256",
        "gss-gex-sha256-example-mechanism",
    ],
)
def test_unbounded_group_exchange_requires_legacy(name):
    """A strong exchange hash does not establish the negotiated DH group's size."""
    defaults = [name, "diffie-hellman-group14-sha256", "curve25519-sha256"]
    assert algorithm_policy("kex", defaults, defaults) == tuple(defaults[1:])
    # Legacy still offers it, after the exchanges whose group size is known.
    assert algorithm_policy("kex", defaults, defaults, allow_legacy=True) == (
        *defaults[1:],
        name,
    )


def test_bounded_group_exchange_stays_in_secure_mode():
    """An exchange whose group size the adapter enforces is kept; a weak hash is not."""
    gex = "diffie-hellman-group-exchange-sha256"
    defaults = [gex, "diffie-hellman-group-exchange-sha1", "gss-gex-sha256", "curve25519-sha256"]
    assert algorithm_policy("kex", defaults, defaults, bounded=[gex]) == (gex, "curve25519-sha256")
    assert algorithm_policy("kex", defaults, defaults) == ("curve25519-sha256",)


def test_paramiko_bounded_group_exchange_is_per_connection():
    """The bounded handler replaces Paramiko's on this connection only, in secure mode only."""

    class Bounded(paramiko.kex_gex.KexGexSHA256):
        pass

    gex = paramiko.kex_gex.KexGexSHA256.name
    sockets = [socket.socketpair() for _ in range(3)]
    secure, legacy, other = (paramiko.Transport(left) for left, _ in sockets)
    try:
        configure_paramiko(secure, False, {gex: Bounded})
        configure_paramiko(legacy, True, {gex: Bounded})
        configure_paramiko(other, False)
        assert secure._kex_info[gex] is Bounded
        assert gex in secure.get_security_options().kex
        assert legacy._kex_info[gex] is paramiko.kex_gex.KexGexSHA256
        assert gex in legacy.get_security_options().kex
        assert gex not in other.get_security_options().kex
        assert paramiko.Transport._kex_info[gex] is paramiko.kex_gex.KexGexSHA256
    finally:
        for transport in (secure, legacy, other):
            transport.close()
        for _, right in sockets:
            right.close()
