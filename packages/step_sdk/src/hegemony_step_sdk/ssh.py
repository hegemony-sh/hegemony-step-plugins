# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Per-connection SSH policy shared by the built-in device transports.

No SSH library is imported by the SDK. Adapters supply their library objects.
Legacy negotiation is explicit; a failed secure handshake never retries weakly.
"""

from __future__ import annotations

import base64
from typing import Any

from pydantic import BaseModel, Field

KEX = (
    "mlkem768x25519-sha256",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
)
CIPHERS = (
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
)
MACS = (
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512",
    "hmac-sha2-256",
)
HOST_KEYS = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
)
CLIENT_SIGNATURES = HOST_KEYS + (
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
)
LEGACY_KEX = ("diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1")
LEGACY_CIPHERS = ("aes256-cbc", "aes192-cbc", "aes128-cbc", "3des-cbc")
LEGACY_MACS = ("hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96")
LEGACY_HOST_KEYS = ("ssh-rsa",)


class SshSecurityConfig(BaseModel):
    """Step setting shared by netcli handlers."""

    allow_legacy_ssh: bool = Field(
        default=False,
        title="Allow legacy SSH algorithms",
        description=(
            "Enable weak SSH algorithms and small host keys for older devices, "
            "including the jump host. Host-key verification remains enabled. "
            "Use only on trusted networks while upgrading the device."
        ),
    )


def configure_ssh_security(transport: Any, value: Any = False) -> None:
    """Configure a transport before I/O; never silently ignore a legacy request."""
    legacy = SshSecurityConfig(allow_legacy_ssh=value).allow_legacy_ssh
    setter = getattr(transport, "configure_ssh_security", None)
    if callable(setter):
        setter(allow_legacy=legacy)
    elif legacy:
        raise ValueError("this transport does not support the allow_legacy_ssh step setting")


def validate_ssh_public_key(line: str) -> None:
    """Reject weak/malformed OpenSSH host keys without depending on an SSH library."""
    try:
        fields = line.split()
        data = base64.b64decode(fields[1], validate=True)
        offset = 0

        def part() -> bytes:
            """Consume one complete SSH length-prefixed field."""
            nonlocal offset
            if offset + 4 > len(data):
                raise ValueError("truncated key")
            size = int.from_bytes(data[offset : offset + 4], "big")
            offset += 4
            end = offset + size
            if end > len(data):
                raise ValueError("truncated key")
            value = data[offset:end]
            offset = end
            return value

        kind = part().decode("ascii")
        if kind != fields[0]:
            raise ValueError("key type mismatch")
        if kind == "ssh-rsa":
            exponent = part()
            modulus = part()
            for component in (exponent, modulus):
                if not component or component[0] & 0x80:
                    raise ValueError("invalid positive RSA integer")
                if len(component) > 1 and component[0] == 0 and not component[1] & 0x80:
                    raise ValueError("non-canonical RSA integer")
            e = int.from_bytes(exponent, "big")
            n = int.from_bytes(modulus, "big")
            if e < 3 or e % 2 == 0 or e >= n or n % 2 == 0:
                raise ValueError("invalid RSA exponent or modulus")
            if n.bit_length() < 2048:
                raise ValueError("RSA key is smaller than 2048 bits")
        elif kind == "ssh-ed25519":
            if len(part()) != 32:
                raise ValueError("invalid Ed25519 key")
        elif kind in {"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"}:
            if part().decode("ascii") != kind.removeprefix("ecdsa-sha2-"):
                raise ValueError("curve mismatch")
            point = part()
            size = {
                "ecdsa-sha2-nistp256": 32,
                "ecdsa-sha2-nistp384": 48,
                "ecdsa-sha2-nistp521": 66,
            }[kind]
            if len(point) != 1 + 2 * size or point[0] != 4:
                raise ValueError("invalid uncompressed ECDSA point")
        else:
            raise ValueError("host-key type is not in the secure SSH policy")
        if offset != len(data):
            raise ValueError("trailing key data")
    except (ValueError, IndexError, UnicodeError) as exc:
        raise ValueError(
            f"SSH key rejected by secure policy: {exc}. "
            "Upgrade the key or explicitly enable allow_legacy_ssh for this step."
        ) from None


def asyncssh_algorithms(library: Any, allow_legacy: bool = False) -> dict[str, Any]:
    """Explicit algorithm lists, with weak choices only after an opt-in."""
    policy = {
        "kex_algs": KEX + (LEGACY_KEX if allow_legacy else ()),
        "encryption_algs": CIPHERS + (LEGACY_CIPHERS if allow_legacy else ()),
        "mac_algs": MACS + (LEGACY_MACS if allow_legacy else ()),
        "server_host_key_algs": HOST_KEYS + (LEGACY_HOST_KEYS if allow_legacy else ()),
        "signature_algs": CLIENT_SIGNATURES + (LEGACY_HOST_KEYS if allow_legacy else ()),
    }

    # Wildcards enumerate installed capabilities without requiring newer algorithms.
    # This options object is only used for discovery, never for a connection.
    available = library.SSHClientConnectionOptions(
        config=None, kex_algs="*", encryption_algs="*", mac_algs="*", signature_algs="*"
    )
    for name, algorithms in policy.items():
        attribute = "signature_algs" if name == "server_host_key_algs" else name
        supported = {alg.decode("ascii") for alg in getattr(available, attribute)}
        policy[name] = tuple(alg for alg in algorithms if alg in supported)
        if not policy[name]:
            raise ValueError(f"the SSH library has no supported {name} for this policy")
    return policy


def asyncssh_security_options(
    library: Any, keys: tuple[str, ...] | None, allow_legacy: bool = False
) -> dict[str, Any]:
    """Check strength before authentication, even when host identity checks are off."""
    options = asyncssh_algorithms(library, allow_legacy)
    parsed = [library.import_public_key(line) for line in keys] if keys is not None else None
    if parsed is not None:
        accepted = {alg.decode("ascii") for key in parsed for alg in key.sig_algorithms}
        options["server_host_key_algs"] = tuple(
            alg for alg in options["server_host_key_algs"] if alg in accepted
        )
        if not options["server_host_key_algs"]:
            raise ValueError("trusted SSH keys require allow_legacy_ssh or a host-key upgrade")

    class PolicyClient(library.SSHClient):
        def validate_host_public_key(self, host: str, addr: str, port: int, key: Any) -> bool:
            """Check key strength before matching the host's trusted identities."""
            if not allow_legacy:
                validate_ssh_public_key(key.export_public_key("openssh").decode("ascii"))
            return parsed is None or key in parsed

    # An empty known_hosts list delegates to the callback; None would bypass it.
    options.update(known_hosts=([], [], []), client_factory=PolicyClient)
    return options


def configure_paramiko(transport: Any, allow_legacy: bool = False) -> None:
    """Set per-connection lists via Paramiko's public SecurityOptions interface."""
    options = transport.get_security_options()
    for name, secure, legacy in (
        ("kex", KEX, LEGACY_KEX),
        ("ciphers", CIPHERS, LEGACY_CIPHERS),
        ("digests", MACS, LEGACY_MACS),
        ("key_types", HOST_KEYS, LEGACY_HOST_KEYS),
    ):
        supported = []
        for algorithm in secure + (legacy if allow_legacy else ()):
            try:
                setattr(options, name, (algorithm,))
            except ValueError:  # This installed library does not implement the algorithm.
                continue
            supported.append(algorithm)
        if not supported:
            raise ValueError(f"the SSH library has no supported {name} for this policy")
        setattr(options, name, tuple(supported))
