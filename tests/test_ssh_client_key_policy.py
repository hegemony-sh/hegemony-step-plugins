# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Reject weak discovered identities before real SSH servers see a key offer."""

import base64
from unittest.mock import AsyncMock

import asyncssh
import pytest

from hegemony_step_sdk.ssh import asyncssh_security_options, validate_asyncssh_client_key
from hegemony_transport_asyncssh.transport import AsyncSSHTransport
from hegemony_transport_scrapli.transport import ScrapliTransport
from tests import ssh_fakes
from tests.ssh_fakes import JUMP_PASSWORD, PASSWORD, FakeVerifier, key_line, ssh_servers
from tests.test_ssh_security_policy import build


@pytest.mark.parametrize(
    ("cls", "platform"), [(AsyncSSHTransport, "linux"), (ScrapliTransport, "ios-xe")]
)
@pytest.mark.parametrize("hop", ["device", "jump"])
@pytest.mark.parametrize("source", ["default", "agent"])
@pytest.mark.parametrize("fallback", ["strong_key", "password", "none"])
@pytest.mark.parametrize("legacy", [False, True])
async def test_discovered_key_strength_before_offer(
    monkeypatch, cls, platform, hop, source, fallback, legacy
):
    """Skip weak identities while retaining later strong keys, passwords, and legacy opt-in."""
    if source == "agent" and hop == "device" and cls is ScrapliTransport:
        pytest.skip("Scrapli disables device-hop agent discovery")
    weak = asyncssh.generate_private_key("ssh-rsa", key_size=1024)
    strong = asyncssh.generate_private_key("ssh-ed25519")
    test_identities = [weak, strong] if fallback == "strong_key" else [weak]
    offered = []
    affected = JUMP_PASSWORD if hop == "jump" else PASSWORD

    def validate_key(server, username, key):
        offered.append((server._password, key_line(key)))
        return True

    monkeypatch.setattr(ssh_fakes._Device, "public_key_auth_supported", lambda self: True)
    monkeypatch.setattr(ssh_fakes._Device, "validate_public_key", validate_key)
    if fallback == "none":
        # Only remove fallback on the hop under test; the other hop may need it.
        monkeypatch.setattr(
            ssh_fakes._Device,
            "password_auth_supported",
            lambda self: self._password != affected,
        )
    monkeypatch.setattr(
        asyncssh.connection,
        "load_default_keypairs",
        lambda *args: asyncssh.load_keypairs(test_identities) if source == "default" else [],
    )

    class Agent(asyncssh.agent.SSHAgentClient):
        """Use AsyncSSH's real agent-key wrapper and signature encoding."""

        def __init__(self, path):
            pass

        async def get_keys(self, identities=None):
            return (
                [
                    asyncssh.agent.SSHAgentKeyPair(self, key.algorithm, key.public_data, b"test")
                    for key in test_identities
                ]
                if source == "agent"
                else []
            )

        async def sign(self, key_blob, data, flags=0):
            key = next(key for key in test_identities if key.public_data == key_blob)
            algorithm = (
                b"rsa-sha2-512" if flags == 4 else b"rsa-sha2-256" if flags == 2 else key.algorithm
            )
            return key.sign(data, algorithm)

        def close(self):
            pass

        async def wait_closed(self):
            pass

    monkeypatch.setattr(asyncssh.connection, "SSHAgentClient", Agent)
    monkeypatch.setenv("SSH_AUTH_SOCK", "/test-agent")
    async with ssh_servers() as servers:
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        jump = await servers.bastion(host_key) if hop == "jump" else None
        port = await servers.device(host_key)
        transport = build(cls, platform, port, FakeVerifier(), jump)
        transport.configure_ssh_security(allow_legacy=legacy)
        [result] = await transport.execute_commands(["show version"])
        expected_success = legacy or fallback != "none"
        assert (result.exit_code == 0) is expected_success, result.error
        affected_keys = [key for password, key in offered if password == affected]
        if legacy:
            assert key_line(weak) in affected_keys
        else:
            assert key_line(weak) not in affected_keys
            if fallback == "strong_key":
                assert key_line(strong) in affected_keys
            elif fallback == "password":
                assert affected in servers.seen.passwords
            else:
                assert affected_keys == []
                assert servers.seen.passwords == []


@pytest.mark.parametrize("user_bits", [1024, 2048])
@pytest.mark.parametrize("ca_bits", [1024, 2048])
@pytest.mark.parametrize("source", ["local", "agent"])
def test_certificate_subject_and_signing_key_strength(user_bits, ca_bits, source):
    """Certificates must not hide a weak user key or certificate-authority key."""
    user = asyncssh.generate_private_key("ssh-rsa", key_size=user_bits)
    ca = asyncssh.generate_private_key("ssh-rsa", key_size=ca_bits)
    cert = ca.generate_user_certificate(user, "test", principals=["admin"])
    pair = (
        asyncssh.load_keypairs([(user, cert)])[0]
        if source == "local"
        else asyncssh.agent.SSHAgentKeyPair(
            asyncssh.agent.SSHAgentClient("/unused"), cert.algorithm, cert.public_data, b"test"
        )
    )
    if min(user_bits, ca_bits) < 2048:
        with pytest.raises(ValueError, match="2048"):
            validate_asyncssh_client_key(asyncssh, pair)
    else:
        validate_asyncssh_client_key(asyncssh, pair)


@pytest.mark.parametrize(
    "kind", ["sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"]
)
def test_hardware_backed_public_identity_remains_usable(kind):
    """Validate hardware-backed public keys without requiring attached hardware."""
    import struct
    from types import SimpleNamespace

    underlying = asyncssh.generate_private_key(
        "ssh-ed25519" if "ed25519" in kind else "ecdsa-sha2-nistp256"
    )
    original = underlying.public_data
    size = int.from_bytes(original[:4], "big")

    def string(value):
        return struct.pack(">I", len(value)) + value

    data = string(kind.encode()) + original[4 + size :] + string(b"ssh:")
    line = kind + " " + base64.b64encode(data).decode()
    asyncssh.import_public_key(line)
    validate_asyncssh_client_key(asyncssh, SimpleNamespace(public_data=data))


def test_missing_asyncssh_selection_hook_fails_closed():
    """Unsupported library changes must not silently disable the key-strength policy."""
    client = asyncssh_security_options(asyncssh, None)["client_factory"]()
    with pytest.raises(RuntimeError, match="cannot enforce"):
        client.connection_made(object())


async def test_empty_key_selection_preserves_password_fallback():
    """A connection with no discovered identities should simply move to password auth."""
    from types import SimpleNamespace

    connection = SimpleNamespace(public_key_auth_requested=AsyncMock(return_value=None))
    client = asyncssh_security_options(asyncssh, None)["client_factory"]()
    client.connection_made(connection)
    result = await connection.public_key_auth_requested()
    assert result is None


@pytest.mark.parametrize(
    ("cls", "platform"), [(AsyncSSHTransport, "linux"), (ScrapliTransport, "ios-xe")]
)
@pytest.mark.parametrize("legacy", [False, True])
async def test_real_default_identity_file_is_checked(
    tmp_path, monkeypatch, caplog, cls, platform, legacy
):
    """Exercise the unmocked default-file loader with a weak ~/.ssh/id_rsa."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    directory = tmp_path / ".ssh"
    directory.mkdir()
    weak = asyncssh.generate_private_key("ssh-rsa", key_size=1024)
    weak.write_private_key(directory / "id_rsa")
    offered = []

    def validate_key(server, username, key):
        offered.append(key_line(key))
        return True

    monkeypatch.setattr(ssh_fakes._Device, "public_key_auth_supported", lambda self: True)
    monkeypatch.setattr(ssh_fakes._Device, "validate_public_key", validate_key)
    async with ssh_servers() as servers:
        port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
        transport = build(cls, platform, port, FakeVerifier())
        transport.configure_ssh_security(allow_legacy=legacy)
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code == 0, result.error
        assert (key_line(weak) in offered) is legacy
        skipped = [r.getMessage() for r in caplog.records if "Skipping SSH login" in r.getMessage()]
        if legacy:
            assert skipped == []
        else:
            assert PASSWORD in servers.seen.passwords
            # The operator can see which identity was skipped and why.
            assert any("ssh-rsa" in message and "2048" in message for message in skipped)


@pytest.mark.parametrize(
    ("cls", "platform"), [(AsyncSSHTransport, "linux"), (ScrapliTransport, "ios-xe")]
)
async def test_default_ed448_identity_is_offered(tmp_path, monkeypatch, cls, platform):
    """A strong ~/.ssh/id_ed448 is offered in secure mode, not skipped."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    directory = tmp_path / ".ssh"
    directory.mkdir()
    key = asyncssh.generate_private_key("ssh-ed448")
    key.write_private_key(directory / "id_ed448")
    offered = []

    def validate_key(server, username, key):
        offered.append(key_line(key))
        return True

    monkeypatch.setattr(ssh_fakes._Device, "public_key_auth_supported", lambda self: True)
    monkeypatch.setattr(ssh_fakes._Device, "validate_public_key", validate_key)
    monkeypatch.setattr(ssh_fakes._Device, "password_auth_supported", lambda self: False)
    async with ssh_servers() as servers:
        port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
        transport = build(cls, platform, port, FakeVerifier())
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code == 0, result.error
        assert key_line(key) in offered


@pytest.mark.parametrize("subject", ["weak_rsa", "strong_rsa", "ed25519"])
def test_x509_identity_subject_key_strength(subject):
    """X.509 identities are checked through their subject key, not skipped by type."""
    from types import SimpleNamespace

    key = (
        asyncssh.generate_private_key("ssh-rsa", key_size=1024)
        if subject == "weak_rsa"
        else asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        if subject == "strong_rsa"
        else asyncssh.generate_private_key("ssh-ed25519")
    )
    algorithm = b"x509v3-" + key.algorithm
    pair = SimpleNamespace(public_data=len(algorithm).to_bytes(4, "big") + algorithm + b"chain")
    imported = []

    def import_certificate(line):
        imported.append(line.split()[0])
        # An X.509 chain exposes its subject key and has no OpenSSH signing key.
        return SimpleNamespace(key=key)

    library = SimpleNamespace(import_certificate=import_certificate)
    if subject == "weak_rsa":
        with pytest.raises(ValueError, match="2048"):
            validate_asyncssh_client_key(library, pair)
    else:
        validate_asyncssh_client_key(library, pair)
    assert imported == [algorithm.decode()]


@pytest.mark.parametrize("bits", [1024, 2048])
def test_real_x509_identity_subject_key_strength(bits):
    """With PyOpenSSL installed, a real X.509 identity is validated by its subject key."""
    pytest.importorskip("OpenSSL")
    key = asyncssh.generate_private_key("ssh-rsa", key_size=bits)
    cert = key.generate_x509_user_certificate(key, "OU=test", "OU=test")
    pair = asyncssh.load_keypairs([(key, cert)])[0]
    if bits < 2048:
        with pytest.raises(ValueError, match="2048"):
            validate_asyncssh_client_key(asyncssh, pair)
    else:
        validate_asyncssh_client_key(asyncssh, pair)
