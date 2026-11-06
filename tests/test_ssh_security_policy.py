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
        supported = not (cls is SSHTransport and weakness == "sha1")
        if legacy and supported:
            assert result.exit_code == 0, result.error
            assert PASSWORD in servers.seen.passwords
        else:
            assert result.exit_code != 0
            assert servers.seen.passwords == []
            assert not any(call[0] == "learn" for call in verifier.calls)


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
async def test_legacy_opt_in_keeps_host_identity_verification(cls, platform):
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
    key = asyncssh.generate_private_key("ssh-rsa", key_size=bits)
    if bits < 2048:
        with pytest.raises(ValueError, match="2048"):
            validate_ssh_public_key(key_line(key))
    else:
        validate_ssh_public_key(key_line(key))


@pytest.mark.parametrize("value", [False, "false", True, "true"])
@pytest.mark.parametrize("handler_class", [ExecuteCLIActionHandler, CollectEvidenceHandler])
async def test_step_setting_reaches_transport_before_commands(handler_class, value):
    calls = []

    class Transport:
        def configure_ssh_security(self, *, allow_legacy=False):
            calls.append(("policy", allow_legacy))

        async def execute_commands(self, commands):
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
    with pytest.raises(ValueError, match="does not support"):
        configure_ssh_security(object(), True)
    configure_ssh_security(object(), False)


def test_legacy_setting_rejects_arbitrary_truthy_strings():
    with pytest.raises(ValueError):
        configure_ssh_security(object(), "definitely")


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
@pytest.mark.parametrize("hop", ["device", "jump"])
@pytest.mark.parametrize("legacy", [False, True])
async def test_trusted_rsa_cannot_restore_sha1_signatures(cls, platform, hop, legacy):
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
    from hegemony_transport_netmiko.transport import _KexinitKeepingTransport

    started = []
    original = _KexinitKeepingTransport.start_client

    def record(self, *args, **kwargs):
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
