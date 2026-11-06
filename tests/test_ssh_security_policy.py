# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Real handshakes prove legacy negotiation is explicit and never bypasses trust."""

from types import SimpleNamespace
from typing import Any

import asyncssh
import paramiko
import pytest

from hegemony_step_sdk import DeviceConnectionSpec, HandlerContext, JumpHostSpec
from hegemony_step_sdk.ssh import configure_ssh_security, validate_ssh_public_key
from hegemony_steps_netcli.collect_evidence import CollectEvidenceHandler
from hegemony_steps_netcli.execute import ExecuteCLIActionHandler
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


def build(cls, platform, port, verifier, jump_port=None):
    """Build a device transport with optional bastion access and explicit trust."""
    return cls(
        DeviceConnectionSpec(
            host="127.0.0.1",
            port=port,
            username=USERNAME,
            password=PASSWORD,
            platform=platform,
            connect_timeout=3,
            command_timeout=3,
            jump_host=JumpHostSpec("127.0.0.1", jump_port, JUMP_USERNAME, JUMP_PASSWORD)
            if jump_port
            else None,
        ),
        host_key_verifier=verifier,
    )


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
@pytest.mark.parametrize("hop", ["device", "jump"])
@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("weakness", ["cbc", "sha1", "small_rsa"])
@pytest.mark.parametrize("trust_mode", ["accept_new", "off"])
async def test_weak_peer_requires_explicit_opt_in(cls, platform, hop, legacy, weakness, trust_mode):
    """Require legacy opt-in before weak peers receive credentials on either hop."""
    strong = asyncssh.generate_private_key("ssh-ed25519")
    weak = (
        asyncssh.generate_private_key("ssh-rsa", key_size=1024)
        if weakness == "small_rsa"
        else strong
    )
    options: dict[str, Any] = {
        "cbc": {"encryption_algs": ["aes128-cbc"]},
        "sha1": {"kex_algs": ["diffie-hellman-group14-sha1"]},
        "small_rsa": {},
    }[weakness]
    async with ssh_servers() as servers:
        if hop == "jump":
            jump = await servers.bastion(weak, **options)
            port = await servers.device(strong)
        else:
            jump = None
            port = await servers.device(weak, **options)
        verifier = FakeVerifier(mode=trust_mode)
        transport = build(cls, platform, port, verifier, jump)
        transport.configure_ssh_security(allow_legacy=legacy)
        [result] = await transport.execute_commands(["show version"])
        supported = (
            cls is not SSHTransport
            or weakness != "sha1"
            or "diffie-hellman-group14-sha1" in paramiko.Transport._kex_info
        )
        if legacy and supported:
            assert result.exit_code == 0, result.error
            assert PASSWORD in servers.seen.passwords
        else:
            assert result.exit_code != 0
            assert servers.seen.passwords == []
            assert not any(call[0] == "learn" for call in verifier.calls)


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
async def test_legacy_opt_in_keeps_host_identity_verification(cls, platform):
    """Reject a changed host identity even when weak algorithms are allowed."""
    async with ssh_servers() as servers:
        port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
        verifier = FakeVerifier("strict")
        verifier.trust("127.0.0.1", port, asyncssh.generate_private_key("ssh-ed25519"))
        transport = build(cls, platform, port, verifier)
        transport.configure_ssh_security(allow_legacy=True)
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code != 0
        assert "does not match" in result.error
        assert servers.seen.passwords == []


@pytest.mark.parametrize("bits", [1024, 2048, 3072])
def test_rsa_minimum(bits):
    """Accept RSA keys only at or above the secure minimum size."""
    key = asyncssh.generate_private_key("ssh-rsa", key_size=bits)
    if bits < 2048:
        with pytest.raises(ValueError, match="2048"):
            validate_ssh_public_key(key_line(key))
    else:
        validate_ssh_public_key(key_line(key))


@pytest.mark.parametrize("value", [False, "false", True, "true"])
@pytest.mark.parametrize("handler_class", [ExecuteCLIActionHandler, CollectEvidenceHandler])
async def test_step_setting_reaches_transport_before_commands(handler_class, value):
    """Apply the parsed step policy before any command can connect."""
    calls = []

    class Transport:
        def configure_ssh_security(self, *, allow_legacy=False):
            """Record the policy configured by the step handler."""
            calls.append(("policy", allow_legacy))

        async def execute_commands(self, commands):
            """Record execution order and return one successful command result."""
            calls.append(("commands", commands))
            return [
                SimpleNamespace(
                    command=commands[0], output="ok", exit_code=0, error=None, latency_ms=0
                )
            ]

    services: Any = SimpleNamespace(connect=lambda *args, **kwargs: Transport())
    ctx = HandlerContext(
        run_id="run",
        flow_id="flow",
        step_run_id="step-run",
        step_id="step",
        target_roles=["router"],
        target_devices_by_role={
            "router": [{"id": "device", "name": "router", "mgmt_host": "127.0.0.1"}]
        },
        config={"commands": ["show version"], "allow_legacy_ssh": value},
        services=services,
    )
    result = await handler_class().execute(ctx)
    assert result.success, result.error
    assert calls == [("policy", value in (True, "true")), ("commands", ["show version"])]


def test_unsupported_legacy_override_is_not_silently_ignored():
    """Refuse a legacy request when the selected transport cannot enforce it."""
    with pytest.raises(ValueError, match="does not support"):
        configure_ssh_security(object(), True)
    configure_ssh_security(object(), False)


def test_legacy_setting_rejects_arbitrary_truthy_strings():
    """Reject ambiguous configuration values instead of enabling legacy mode."""
    with pytest.raises(ValueError):
        configure_ssh_security(object(), "definitely")


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
@pytest.mark.parametrize("hop", ["device", "jump"])
@pytest.mark.parametrize("legacy", [False, True])
async def test_trusted_rsa_cannot_restore_sha1_signatures(cls, platform, hop, legacy):
    """Keep trusted RSA keys from restoring forbidden SHA-1 host signatures."""
    key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    weak = asyncssh.import_private_key(key.export_private_key())
    weak.sig_algorithms = (b"ssh-rsa",)
    async with ssh_servers() as servers:
        jump = await servers.bastion(weak) if hop == "jump" else None
        port = await servers.device(weak if hop == "device" else key)
        verifier = FakeVerifier("strict")
        verifier.trust("127.0.0.1", port, key)
        if jump:
            verifier.trust("127.0.0.1", jump, key)
        transport = build(cls, platform, port, verifier, jump)
        transport.configure_ssh_security(allow_legacy=legacy)
        [result] = await transport.execute_commands(["show version"])
        supported = cls is not SSHTransport or "ssh-rsa" in paramiko.Transport._key_info
        assert (result.exit_code == 0) is (legacy and supported), result.error
        if not (legacy and supported):
            assert servers.seen.passwords == []


@pytest.mark.parametrize("adapter", ["asyncssh", "scrapli"])
async def test_diagnostic_signature_request_cannot_override_policy(adapter):
    """Constrain diagnostic signature requests to the selected policy."""
    from importlib import import_module

    presented = import_module(f"hegemony_transport_{adapter}.transport")._presented_key
    key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    key.sig_algorithms = (b"ssh-rsa",)
    async with ssh_servers() as servers:
        port = await servers.device(key)
        with pytest.raises(ValueError, match="excluded"):
            await presented("127.0.0.1", port, tunnel=None, timeout=3, algorithms=["ssh-rsa"])
        result = await presented(
            "127.0.0.1", port, tunnel=None, timeout=3, algorithms=["ssh-rsa"], allow_legacy=True
        )
        assert result == key_line(key)
        assert servers.seen.passwords == []


async def test_installed_asyncssh_without_mlkem_can_discover_and_login(monkeypatch):
    """Connect securely when the installed library lacks a newer exchange."""
    import asyncssh.kex

    # Model an older permitted AsyncSSH installation without this implementation.
    monkeypatch.setattr(
        asyncssh.kex,
        "_kex_algs",
        [alg for alg in asyncssh.kex._kex_algs if alg != b"mlkem768x25519-sha256"],
    )
    async with ssh_servers() as servers:
        port = await servers.device(asyncssh.generate_private_key("ssh-ed25519"))
        transport = build(AsyncSSHTransport, "linux", port, FakeVerifier())
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code == 0, result.error


@pytest.mark.parametrize("trust_mode", ["strict", "off"])
async def test_rejected_netmiko_key_closes_started_transport(monkeypatch, trust_mode):
    """Close sockets and stop transport activity after a host-key rejection."""
    from hegemony_transport_netmiko.transport import _KexinitKeepingTransport

    started = []
    original = _KexinitKeepingTransport.start_client

    def record(self, *args, **kwargs):
        """Record the attempted operation before delegating to the real transport."""
        started.append(self)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(_KexinitKeepingTransport, "start_client", record)
    async with ssh_servers() as servers:
        key = asyncssh.generate_private_key("ssh-rsa", key_size=1024)
        port = await servers.device(key)
        verifier = FakeVerifier(trust_mode)
        verifier.trust("127.0.0.1", port, key)
        transport = build(SSHTransport, "ios-xe", port, verifier)
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code != 0
        assert started
        assert all(not connection.is_active() and connection.sock._closed for connection in started)
        assert servers.seen.passwords == []


@pytest.mark.parametrize("exponent", [b"", b"\x00", b"\x02", b"\x80", b"\x00\x03"])
def test_malformed_rsa_exponent_is_rejected(exponent):
    """Reject empty, invalid, or noncanonical RSA exponent encodings."""
    import base64

    parts = [b"ssh-rsa", exponent, b"\x00\x80" + b"\x00" * 254 + b"\x01"]
    blob = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
    with pytest.raises(ValueError, match="RSA"):
        validate_ssh_public_key("ssh-rsa " + base64.b64encode(blob).decode())


@pytest.mark.parametrize("point", [b"", b"\x04", b"\x04" + bytes(63), b"\x02" + bytes(64)])
def test_malformed_ecdsa_point_is_rejected(point):
    """Reject empty, truncated, or incorrectly encoded curve points."""
    import base64

    parts = [b"ecdsa-sha2-nistp256", b"nistp256", point]
    blob = b"".join(len(part).to_bytes(4, "big") + part for part in parts)
    with pytest.raises(ValueError, match="ECDSA"):
        validate_ssh_public_key("ecdsa-sha2-nistp256 " + base64.b64encode(blob).decode())


@pytest.mark.parametrize("curve", ["nistp256", "nistp384", "nistp521"])
def test_valid_ecdsa_key_is_accepted(curve):
    """Keep valid keys on all supported NIST curves usable."""
    validate_ssh_public_key(key_line(asyncssh.generate_private_key("ecdsa-sha2-" + curve)))


@pytest.mark.parametrize("legacy", [False, True])
def test_security_key_authentication_is_allowed_without_widening_host_policy(legacy):
    """Enable hardware-backed client signatures without trusting new host types."""
    from hegemony_step_sdk.ssh import asyncssh_algorithms

    policy = asyncssh_algorithms(asyncssh, legacy)
    options = asyncssh.SSHClientConnectionOptions(**policy)
    for algorithm in (
        b"sk-ssh-ed25519@openssh.com",
        b"sk-ecdsa-sha2-nistp256@openssh.com",
        b"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
    ):
        assert algorithm in options.signature_algs
        assert algorithm.decode() not in policy["server_host_key_algs"]
    assert (b"ssh-rsa" in options.signature_algs) is legacy


@pytest.mark.parametrize(("cls", "platform"), [TRANSPORTS[0], TRANSPORTS[2]])
async def test_legacy_mismatch_report_keeps_presented_identity(cls, platform):
    """Include the replacement identity in a legacy host-key rejection report."""
    key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
    key.sig_algorithms = (b"ssh-rsa",)
    async with ssh_servers() as servers:
        port = await servers.device(key)
        verifier = FakeVerifier("strict")
        verifier.trust("127.0.0.1", port, asyncssh.generate_private_key("ssh-rsa", key_size=2048))
        transport = build(cls, platform, port, verifier)
        transport.configure_ssh_security(allow_legacy=True)
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code != 0
        assert ("rejected", "127.0.0.1", port, key_line(key)) in verifier.calls
        assert servers.seen.passwords == []


@pytest.mark.parametrize("explicit", [False, True])
async def test_weak_bastion_identity_is_never_offered_and_only_discovered_keys_are_skipped(
    monkeypatch, explicit
):
    """Skip weak discovered identities but reject weak explicit credentials."""
    import io
    from dataclasses import replace
    from unittest.mock import MagicMock

    weak = paramiko.RSAKey.generate(1024)
    agent = MagicMock()
    agent.get_keys.return_value = [weak]
    monkeypatch.setattr(paramiko.client, "Agent", lambda: agent)
    offered = []
    original = paramiko.Transport.auth_publickey

    def record(self, username, key, *args, **kwargs):
        """Record the attempted operation before delegating to the real transport."""
        offered.append(key)
        return original(self, username, key, *args, **kwargs)

    monkeypatch.setattr(paramiko.Transport, "auth_publickey", record)
    async with ssh_servers() as servers:
        key = asyncssh.generate_private_key("ssh-ed25519")
        jump = await servers.bastion(key)
        port = await servers.device(key)
        transport = build(SSHTransport, "ios-xe", port, FakeVerifier(), jump)
        if explicit:
            pem = io.StringIO()
            weak.write_private_key(pem)
            transport.jump_host = replace(transport.jump_host, private_key=pem.getvalue())
        [result] = await transport.execute_commands(["show version"])
        assert weak not in offered
        if explicit:
            assert result.exit_code != 0
            assert servers.seen.passwords == []
        else:
            assert result.exit_code == 0, result.error
            assert JUMP_PASSWORD in servers.seen.passwords


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
@pytest.mark.parametrize("hop", ["device", "jump"])
async def test_legacy_only_peer_mismatch_rejects_before_affected_hop_credentials(
    cls, platform, hop
):
    """Legacy encryption never permits a changed device or bastion identity."""
    key = asyncssh.generate_private_key("ssh-rsa", key_size=1024)
    other = asyncssh.generate_private_key("ssh-rsa", key_size=1024)
    async with ssh_servers() as servers:
        jump = await servers.bastion(key, encryption_algs=["aes128-cbc"]) if hop == "jump" else None
        port = await servers.device(key, encryption_algs=["aes128-cbc"])
        verifier = FakeVerifier("strict")
        verifier.trust("127.0.0.1", port, other if hop == "device" else key)
        if jump:
            verifier.trust("127.0.0.1", jump, other)
        transport = build(cls, platform, port, verifier, jump)
        transport.configure_ssh_security(allow_legacy=True)
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code != 0
        assert "does not match" in result.error
        assert (JUMP_PASSWORD if hop == "jump" else PASSWORD) not in servers.seen.passwords
