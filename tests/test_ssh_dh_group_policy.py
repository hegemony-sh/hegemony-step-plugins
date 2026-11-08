# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Server-selected DH groups cannot bypass the secure policy's size requirement."""

from typing import Any

import asyncssh
import asyncssh.kex_dh
import pytest

from tests.ssh_fakes import JUMP_PASSWORD, PASSWORD, FakeVerifier, ssh_servers
from tests.test_ssh_security_policy import TRANSPORTS, build


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
@pytest.mark.parametrize("hop", ["device", "jump"])
@pytest.mark.parametrize("trust_mode", ["accept_new", "strict"])
@pytest.mark.parametrize("bits", [1024, 2048])
@pytest.mark.parametrize("legacy", [False, True])
async def test_group_exchange_needs_explicit_legacy(
    monkeypatch, cls, platform, hop, trust_mode, bits, legacy
):
    """Reject variable groups before credentials on discovery and trusted-key logins."""
    # Only alter the local server's group catalogue. Client policy and protocol
    # validation remain untouched; a 1024-bit group reproduces the original gap.
    groups = tuple(group for group in asyncssh.kex_dh._dh_gex_groups if group[0] == bits)
    assert groups
    monkeypatch.setattr(asyncssh.kex_dh, "_dh_gex_groups", groups)
    key = asyncssh.generate_private_key("ssh-ed25519")
    options: dict[str, Any] = {"kex_algs": ["diffie-hellman-group-exchange-sha256"]}
    async with ssh_servers() as servers:
        jump = await servers.bastion(key, **options) if hop == "jump" else None
        port = await servers.device(key, **(options if hop == "device" else {}))
        verifier = FakeVerifier(trust_mode)
        if trust_mode == "strict":
            verifier.trust("127.0.0.1", port, key)
            if jump:
                verifier.trust("127.0.0.1", jump, key)
        transport = build(cls, platform, port, verifier, jump)
        transport.configure_ssh_security(allow_legacy=legacy)
        [result] = await transport.execute_commands(["show version"])
        assert (result.exit_code == 0) is legacy, result.error
        if legacy:
            assert PASSWORD in servers.seen.passwords
            if jump:
                assert JUMP_PASSWORD in servers.seen.passwords
        else:
            assert servers.seen.passwords == []
            assert not any(call[0] == "learn" for call in verifier.calls)


@pytest.mark.parametrize(("cls", "platform"), TRANSPORTS)
@pytest.mark.parametrize("hop", ["device", "jump"])
async def test_fixed_2048_bit_group_remains_available(cls, platform, hop):
    """Secure mode still authenticates peers with a fixed, sufficiently large DH group."""
    key = asyncssh.generate_private_key("ssh-ed25519")
    options: dict[str, Any] = {"kex_algs": ["diffie-hellman-group14-sha256"]}
    async with ssh_servers() as servers:
        jump = await servers.bastion(key, **options) if hop == "jump" else None
        port = await servers.device(key, **(options if hop == "device" else {}))
        transport = build(cls, platform, port, FakeVerifier(), jump)
        [result] = await transport.execute_commands(["show version"])
        assert result.exit_code == 0, result.error
        assert PASSWORD in servers.seen.passwords
