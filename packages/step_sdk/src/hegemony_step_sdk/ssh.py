# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Per-connection SSH policy shared by the built-in device transports.

No SSH library is imported by the SDK. This module is the contract and policy;
the built-in transports map it onto Paramiko and AsyncSSH through the internal
``hegemony_transport_support.ssh`` package, which depends on this one and never
the other way round. Legacy negotiation is explicit; a failed secure handshake
never retries weakly.

The policy names weak algorithms and exchanges whose minimum size cannot be
enforced. Secure mode starts from the installed library's own defaults and
removes those choices, so algorithms a library adds later are used without a
policy change. The explicit legacy
override offers every algorithm the library still implements, weak included.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Collection, Iterable, Mapping
from typing import Any

from pydantic import BaseModel, Field

#: Name parts (split on ``-`` and ``@``) that make an algorithm weak, per kind.
#: ``kex`` key exchange, ``cipher`` encryption, ``mac`` integrity,
#: ``signature`` host-key and login signatures.
WEAK_ALGORITHM_PARTS: dict[str, frozenset[str]] = {
    # SHA-1 exchange hashes and 1024-bit RSA key exchange.
    "kex": frozenset({"sha1", "rsa1024"}),
    # CBC mode, 64-bit block ciphers, RC4, and no encryption.
    "cipher": frozenset(
        {"cbc", "3des", "des", "blowfish", "cast128", "arcfour", "arcfour128", "arcfour256", "none"}
    ),
    # SHA-1 and MD5 MACs, truncated (96-bit) MACs, and no integrity.
    "mac": frozenset({"sha1", "md5", "96", "none"}),
    # DSA and SHA-1 signatures.
    "signature": frozenset({"dss", "sha1"}),
}
#: Whole names that are weak although none of their parts is: the RSA
#: signatures (plain, OpenSSH-certificate and X.509) that use SHA-1.
WEAK_ALGORITHM_NAMES: dict[str, frozenset[str]] = {
    "signature": frozenset(
        {"ssh-rsa", "ssh-rsa-cert-v01@openssh.com", "x509v3-ssh-rsa", "x509v3-sign-rsa"}
    ),
}

#: These exchanges let the server choose a DH group. Supported libraries can
#: accept a group below 2048 bits even with a SHA-256 exchange hash. They stay
#: behind the explicit legacy opt-in, GSS variants included, unless the adapter
#: enforces ``MIN_DH_GROUP_BITS`` on the server's group for that connection
#: (``algorithm_policy``'s ``bounded``; the Paramiko adapter does, see
#: ``hegemony_transport_support.ssh.configure_paramiko``).
UNBOUNDED_DH_EXCHANGE_PREFIXES = ("diffie-hellman-group-exchange-", "gss-gex-")

#: Smallest Diffie-Hellman group, in bits, a bounded group exchange accepts.
MIN_DH_GROUP_BITS = 2048

#: Smallest RSA modulus, in bits, accepted for host and login keys.
MIN_RSA_BITS = 2048

#: The help topic that explains, with the exact lists, what the legacy opt-in
#: allows. Hosts read it from the ``x_help`` key of the field's JSON
#: schema and link the setting to that page.
LEGACY_SSH_HELP_TOPIC = "legacy-ssh-algorithms"

#: The algorithm kinds a policy list and an agreed connection are reported by,
#: in the order of an SSH key exchange.
SSH_ALGORITHM_KINDS = ("kex", "host_key", "cipher", "mac")


def is_weak_algorithm(kind: str, name: str) -> bool:
    """True when ``name`` is a weak ``kind`` algorithm (see ``WEAK_ALGORITHM_PARTS``)."""
    if name in WEAK_ALGORITHM_NAMES.get(kind, frozenset()):
        return True
    return not WEAK_ALGORITHM_PARTS[kind].isdisjoint(re.split(r"[-@]", name))


def algorithm_policy(
    kind: str,
    defaults: Iterable[str],
    implemented: Iterable[str],
    allow_legacy: bool = False,
    bounded: Collection[str] = (),
) -> tuple[str, ...]:
    """Filter weak or unbounded exchanges; legacy adds everything implemented after them.

    Secure mode offers the library's defaults in its order, without weak
    algorithms or unbounded group exchanges. Legacy offers exactly those first,
    in the same order, then the other secure algorithms the library implements
    but does not enable by default, and only then the weak ones and the
    unbounded group exchanges: the library's other defaults, then the rest it
    implements. So a peer that supports any secure algorithm agrees on one even
    with legacy allowed; only a peer that supports none falls back. A default
    the library does not implement is dropped. ``bounded`` names group
    exchanges for which the adapter refuses a server group below
    ``MIN_DH_GROUP_BITS``; those stay in secure mode unless their exchange hash
    is weak.
    """
    implemented = tuple(implemented)
    defaults = [name for name in defaults if name in implemented]

    def acceptable(name: str) -> bool:
        return not is_weak_algorithm(kind, name) and not (
            kind == "kex"
            and name.startswith(UNBOUNDED_DH_EXCHANGE_PREFIXES)
            and name not in bounded
        )

    secure = tuple(dict.fromkeys(name for name in defaults if acceptable(name)))
    if allow_legacy:
        other_secure = [name for name in implemented if acceptable(name)]
        return tuple(dict.fromkeys([*secure, *other_secure, *defaults, *implemented]))
    return secure


class SshSecurityConfig(BaseModel):
    """Step setting shared by netcli handlers."""

    allow_legacy_ssh: bool = Field(
        default=False,
        title="Allow legacy SSH algorithms",
        description=(
            "Enable weak SSH algorithms and small host or login keys for older devices, "
            "including the jump host, for every device this step connects to. "
            "To allow them for one old device only, set allow_legacy_ssh in that "
            "device's SSH access configuration instead. Host-key verification "
            "remains enabled. Use only on trusted networks while upgrading the device."
        ),
        json_schema_extra={"x_help": LEGACY_SSH_HELP_TOPIC},
    )


def configure_ssh_security(transport: Any, value: Any = False) -> None:
    """Configure a transport before I/O; never silently ignore a legacy request."""
    legacy = SshSecurityConfig(allow_legacy_ssh=value).allow_legacy_ssh
    setter = getattr(transport, "configure_ssh_security", None)
    if callable(setter):
        setter(allow_legacy=legacy)
    elif legacy:
        raise ValueError("this transport does not support the allow_legacy_ssh step setting")


#: Uncompressed point coordinate size, in bytes, for the ECDSA curves SSH names.
_ECDSA_COORDINATE_BYTES = {"nistp256": 32, "nistp384": 48, "nistp521": 66, "1.3.132.0.10": 32}


def validate_ssh_public_key(line: str, *, allow_security_keys: bool = False) -> None:
    """Reject weak or malformed OpenSSH host or login keys without an SSH library.

    Only weak keys are refused: DSA and RSA under ``MIN_RSA_BITS``. Known key
    types are also checked for a well-formed encoding. A type this function
    does not know is accepted, so stronger key types the SSH library adds
    later keep working. Certificates are not plain keys: validate their
    keys separately (the AsyncSSH adapter does, in
    ``hegemony_transport_support.ssh.validate_asyncssh_client_key``).
    """
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
        if kind.endswith("-cert-v01@openssh.com") or kind.startswith("x509v3-"):
            raise ValueError("certificates must be validated through their keys")
        security_key = kind.startswith("sk-")
        if security_key:
            if not allow_security_keys:
                raise ValueError(
                    "security-key identities are only allowed for client authentication"
                )
            kind = kind.removeprefix("sk-").removesuffix("@openssh.com")
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
            if n.bit_length() < MIN_RSA_BITS:
                raise ValueError(f"RSA key is smaller than {MIN_RSA_BITS} bits")
        elif kind == "ssh-dss":
            raise ValueError("DSA keys are weak")
        elif kind in {"ssh-ed25519", "ssh-ed448"}:
            if len(part()) != (32 if kind == "ssh-ed25519" else 57):
                raise ValueError(f"invalid {kind.removeprefix('ssh-').capitalize()} key")
        elif kind.startswith("ecdsa-sha2-"):
            curve = kind.removeprefix("ecdsa-sha2-")
            if part().decode("ascii") != curve:
                raise ValueError("curve mismatch")
            point = part()
            size = _ECDSA_COORDINATE_BYTES.get(curve)
            valid = len(point) == 1 + 2 * size if size else len(point) > 1 and len(point) % 2
            if not valid or point[0] != 4:
                raise ValueError("invalid uncompressed ECDSA point")
        else:
            # A type the library negotiated but this policy does not know: no
            # weakness is known, and its layout cannot be checked here.
            return
        if security_key and not part():
            raise ValueError("security-key application is empty")
        if offset != len(data):
            raise ValueError("trailing key data")
    except (ValueError, IndexError, UnicodeError) as exc:
        raise ValueError(
            f"SSH key rejected by secure policy: {exc}. "
            "Upgrade the key or explicitly enable allow_legacy_ssh for this step "
            "or for this host in the inventory."
        ) from None


def is_weak_ssh_public_key(line: str) -> bool:
    """True when the secure policy refuses OpenSSH key ``line`` (``validate_ssh_public_key``)."""
    try:
        validate_ssh_public_key(line)
    except ValueError:
        return True
    return False


def hop_allows_legacy(spec: Any, *, jump_host: bool, step_setting: bool = False) -> bool:
    """Whether one hop of connection ``spec`` may use legacy SSH.

    ``jump_host`` says which hop: the jump host, or the device. The caller
    names it, because the two endpoints can be equal (``127.0.0.1:22`` is a
    forwarded bastion on the first hop and the bastion's own loopback on the
    second), so the address does not tell the hops apart.

    The step's ``allow_legacy_ssh`` setting allows it on both hops. Otherwise
    each hop follows its own inventory flag: ``spec.allow_legacy_ssh`` for the
    device (a ``DeviceConnectionSpec``) and ``spec.jump_host.allow_legacy_ssh``
    for the jump host, so an old device does not weaken its bastion.
    """
    if step_setting:
        return True
    hop = getattr(spec, "jump_host", None) if jump_host else spec
    return bool(getattr(hop, "allow_legacy_ssh", False))


def legacy_algorithms(
    agreed: Any,
    secure: Mapping[str, Collection[str]],
    with_legacy: Mapping[str, Collection[str]],
) -> dict[str, str]:
    """The algorithms a connection agreed on that only the legacy opt-in allowed.

    ``agreed`` is an ``SshAlgorithms``; ``secure`` and ``with_legacy`` are what
    the transport offers without and with the opt-in
    (``ssh_algorithm_lists(False)`` and ``(True)``). A name counts only when the
    opt-in adds it, so an unknown (empty) field or a name the transport does
    not offer at all is not reported. The result maps each kind to the
    algorithm's name, so a step's evidence can say exactly what the opt-in let
    through.
    """
    found: dict[str, str] = {}
    for kind in SSH_ALGORITHM_KINDS:
        name = getattr(agreed, kind, "")
        if name and name in with_legacy.get(kind, ()) and name not in secure.get(kind, ()):
            found[kind] = name
    return found


#: Where each kind's name-list sits in a KEXINIT message (RFC 4253 §7.1), with
#: the label an error names it by. Ciphers and MACs are listed per direction.
_NEGOTIATED_LISTS: tuple[tuple[str, int, str], ...] = (
    ("kex", 0, "key exchange (kex)"),
    ("host_key", 1, "host key"),
    ("cipher", 2, "cipher"),
    ("cipher", 3, "cipher (device to client)"),
    ("mac", 4, "MAC (message authentication code)"),
    ("mac", 5, "MAC (message authentication code, device to client)"),
)


#: Names a KEXINIT lists among key exchanges that only signal an extension
#: (RFC 8308 ext-info, OpenSSH strict key exchange); no exchange runs by them.
_KEX_MARKER_PREFIXES = ("ext-info-", "kex-strict-")


#: What a hop is told when no setting can make its transport agree with the device.
_UNSUPPORTED = (
    "this transport implements none of the device's; choose another SSH transport for this device"
)


def _name_list(names: list[str]) -> str:
    """Algorithm names for an error, without key-exchange extension markers."""
    shown = [name for name in names if not name.startswith(_KEX_MARKER_PREFIXES)]
    return ", ".join(shown) or "(none)"


def negotiation_failure_detail(
    client_kexinit: bytes,
    server_kexinit: bytes,
    *,
    with_legacy: Mapping[str, Collection[str]] | None = None,
    legacy_allowed: bool = False,
) -> str:
    """Why two KEXINIT messages agree on nothing, naming both sides' algorithms.

    For each kind the two lists share no name in, the text gives what the
    device offers and what this connection offers. ``with_legacy`` is what the
    transport would offer with the legacy opt-in (``ssh_algorithm_lists(True)``);
    pass it only for a hop that does not already allow legacy SSH, and the text
    says whether the opt-in would add a name the device offers;
    ``legacy_allowed`` says the hop already allows it. Returns ``""``
    when a message is missing or malformed, or every kind has a match, so a
    caller keeps its library's own message then.
    """
    from .transports import _AEAD_CIPHERS, _first_match, _kexinit_lists

    try:
        client = _kexinit_lists(client_kexinit)
        server = _kexinit_lists(server_kexinit)
    except (ValueError, UnicodeDecodeError):
        return ""
    ciphers = (_first_match(client[2], server[2]), _first_match(client[3], server[3]))
    parts: list[str] = []
    reported: set[int] = set()
    for kind, index, label in _NEGOTIATED_LISTS:
        ours, theirs = client[index], server[index]
        if _first_match(ours, theirs):
            continue
        # A cipher with integrity built in uses no MAC, so no MAC match is needed.
        if kind == "mac" and ciphers[index - 4] in _AEAD_CIPHERS:
            continue
        # The device-to-client list is reported only when it says something new.
        if (
            index in (3, 5)
            and index - 1 in reported
            and (ours, theirs) == (client[index - 1], server[index - 1])
        ):
            continue
        reported.add(index)
        text = (
            f"no {label} algorithm in common; the device offers: "
            f"{_name_list(theirs)}; this connection offers: {_name_list(ours)}"
        )
        if legacy_allowed:
            text += f"; legacy SSH is already allowed, so {_UNSUPPORTED}"
        elif with_legacy is not None:
            added = [
                name for name in theirs if name in with_legacy.get(kind, ()) and name not in ours
            ]
            if added:
                text += f"; allowing legacy SSH (allow_legacy_ssh) would add: {', '.join(added)}"
            else:
                text += f"; allowing legacy SSH (allow_legacy_ssh) would not help: {_UNSUPPORTED}"
        parts.append(text)
    return ". ".join(parts)
