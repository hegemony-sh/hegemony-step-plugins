# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Per-connection SSH policy shared by the built-in device transports.

No SSH library is imported by the SDK. Adapters supply their library objects.
Legacy negotiation is explicit; a failed secure handshake never retries weakly.

The policy names weak algorithms and exchanges whose minimum size cannot be
enforced. Secure mode starts from the installed library's own defaults and
removes those choices, so algorithms a library adds later are used without a
policy change. The explicit legacy
override offers every algorithm the library still implements, weak included.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
from collections.abc import Collection, Iterable, Mapping
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

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
#: (``algorithm_policy``'s ``bounded``; Paramiko does, see ``configure_paramiko``).
UNBOUNDED_DH_EXCHANGE_PREFIXES = ("diffie-hellman-group-exchange-", "gss-gex-")

#: Smallest Diffie-Hellman group, in bits, a bounded group exchange accepts.
MIN_DH_GROUP_BITS = 2048

#: Smallest RSA modulus, in bits, accepted for host and login keys.
MIN_RSA_BITS = 2048

#: The help topic that explains, with the exact lists, what the legacy opt-in
#: allows. Hosts read it from the ``x-hegemony-help`` key of the field's JSON
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
    """Filter weak or unbounded exchanges; legacy offers everything implemented.

    Order is the library's: its defaults first, then (legacy only) the
    algorithms it implements but does not enable by default. A default the
    library does not implement is dropped. ``bounded`` names group exchanges
    for which the adapter refuses a server group below ``MIN_DH_GROUP_BITS``;
    those stay in secure mode unless their exchange hash is weak.
    """
    implemented = tuple(implemented)
    defaults = [name for name in defaults if name in implemented]
    if allow_legacy:
        return tuple(dict.fromkeys([*defaults, *implemented]))
    return tuple(
        dict.fromkeys(
            name
            for name in defaults
            if not is_weak_algorithm(kind, name)
            and not (
                kind == "kex"
                and name.startswith(UNBOUNDED_DH_EXCHANGE_PREFIXES)
                and name not in bounded
            )
        )
    )


def _plain_host_key_algorithm(name: str) -> bool:
    """Host trust stores plain keys: no certificates, X.509 or security-key types."""
    return not (
        name.endswith("-cert-v01@openssh.com") or name.startswith(("x509v3-", "sk-", "webauthn-"))
    )


class SshSecurityConfig(BaseModel):
    """Step setting shared by netcli handlers."""

    allow_legacy_ssh: bool = Field(
        default=False,
        title="Allow legacy SSH algorithms",
        description=(
            "Enable weak SSH algorithms and small host or login keys for older devices, "
            "including the jump host. Host-key verification remains enabled. "
            "Use only on trusted networks while upgrading the device."
        ),
        json_schema_extra={"x-hegemony-help": LEGACY_SSH_HELP_TOPIC},
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
    keys separately (``validate_asyncssh_client_key``).
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
            "Upgrade the key or explicitly enable allow_legacy_ssh for this step."
        ) from None


def validate_asyncssh_client_key(library: Any, keypair: Any) -> None:
    """Validate a login identity's keys, including certificate subject and signing keys.

    OpenSSH certificates are checked for both the user key and the signing
    (certificate authority) key; X.509 identities for the key of every
    certificate in the chain they present.
    """
    data = keypair.public_data
    size = int.from_bytes(data[:4], "big")
    algorithm = data[4 : 4 + size].decode("ascii")
    if algorithm.startswith("x509v3-"):
        keys = [library.import_certificate(der).key for der in _x509_chain(data, 4 + size)]
    elif algorithm.endswith("-cert-v01@openssh.com"):
        certificate = library.import_certificate(
            algorithm + " " + base64.b64encode(data).decode("ascii")
        )
        keys = [certificate.key, certificate.signing_key]
    else:
        keys = [library.import_public_key(algorithm + " " + base64.b64encode(data).decode())]
    for key in keys:
        validate_ssh_public_key(
            key.export_public_key("openssh").decode("ascii"), allow_security_keys=True
        )


def _x509_chain(data: bytes, offset: int) -> list[bytes]:
    """DER certificates of an X.509 public key blob (RFC 6187), after its algorithm name."""
    if offset + 4 > len(data):
        raise ValueError("truncated X.509 certificate chain")
    count = int.from_bytes(data[offset : offset + 4], "big")
    offset += 4
    certificates = []
    for _ in range(count):
        size = int.from_bytes(data[offset : offset + 4], "big")
        certificate = data[offset + 4 : offset + 4 + size]
        if offset + 4 > len(data) or len(certificate) != size:
            raise ValueError("truncated X.509 certificate chain")
        certificates.append(certificate)
        offset += 4 + size
    if not certificates:
        raise ValueError("empty X.509 certificate chain")
    return certificates


def _identity_label(keypair: Any) -> str:
    """Algorithm, SHA-256 fingerprint and comment of a login identity, for logs."""
    data = keypair.public_data
    kind = data[4 : 4 + int.from_bytes(data[:4], "big")].decode("ascii", "replace")
    digest = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
    label = f"{kind} SHA256:{digest}"
    get_comment = getattr(keypair, "get_comment", None)
    comment = get_comment() if callable(get_comment) else None
    return f"{label} ({comment})" if comment else label


def asyncssh_algorithms(library: Any, allow_legacy: bool = False) -> dict[str, Any]:
    """AsyncSSH's own algorithm lists, without weak ones unless legacy is allowed."""
    # These options objects only enumerate the library's lists; they never connect.
    defaults = library.SSHClientConnectionOptions(config=None)
    implemented = library.SSHClientConnectionOptions(
        config=None, kex_algs="*", encryption_algs="*", mac_algs="*", signature_algs="*"
    )
    policy: dict[str, Any] = {}
    for name, kind in (
        ("kex_algs", "kex"),
        ("encryption_algs", "cipher"),
        ("mac_algs", "mac"),
        ("signature_algs", "signature"),
    ):
        policy[name] = algorithm_policy(
            kind,
            (alg.decode("ascii") for alg in getattr(defaults, name)),
            (alg.decode("ascii") for alg in getattr(implemented, name)),
            allow_legacy,
        )
    # AsyncSSH accepts X.509 signatures only with X.509 trust anchors, which
    # these transports never configure (host trust uses plain keys). With
    # PyOpenSSL installed its defaults still list them, so drop them here.
    policy["signature_algs"] = tuple(
        alg for alg in policy["signature_algs"] if not alg.startswith("x509v3-")
    )
    policy["server_host_key_algs"] = tuple(
        alg for alg in policy["signature_algs"] if _plain_host_key_algorithm(alg)
    )
    for name, algorithms in policy.items():
        if not algorithms:
            raise ValueError(f"the SSH library has no supported {name} for this policy")
    return policy


def asyncssh_algorithm_lists(
    library: Any, allow_legacy: bool = False
) -> dict[str, tuple[str, ...]]:
    """What an asyncssh connection offers, by kind (``SSH_ALGORITHM_KINDS``), in order.

    The same lists ``asyncssh_algorithms`` gives a connection, named the way
    ``SshAlgorithms`` names what a connection agreed on, so a host can show the
    exact effect of the legacy opt-in.
    """
    policy = asyncssh_algorithms(library, allow_legacy)
    return {
        "kex": tuple(policy["kex_algs"]),
        "host_key": tuple(policy["server_host_key_algs"]),
        "cipher": tuple(policy["encryption_algs"]),
        "mac": tuple(policy["mac_algs"]),
    }


def paramiko_algorithm_lists(transport: Any) -> dict[str, tuple[str, ...]]:
    """What a Paramiko transport configured by ``configure_paramiko`` offers, by kind."""
    options = transport.get_security_options()
    return {
        "kex": tuple(options.kex),
        "host_key": tuple(options.key_types),
        "cipher": tuple(options.ciphers),
        "mac": tuple(options.digests),
    }


def legacy_algorithms(agreed: Any, secure: Mapping[str, Collection[str]]) -> dict[str, str]:
    """The algorithms a connection agreed on that its transport offers only with legacy allowed.

    ``agreed`` is an ``SshAlgorithms``; ``secure`` is what the transport offers
    without the opt-in (``asyncssh_algorithm_lists(library)`` and the like).
    An unknown (empty) field is not reported. The result maps each kind to
    the algorithm's name, so a step's evidence can say exactly what the
    opt-in let through.
    """
    found: dict[str, str] = {}
    for kind in SSH_ALGORITHM_KINDS:
        name = getattr(agreed, kind, "")
        if name and name not in secure.get(kind, ()):
            found[kind] = name
    return found


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
        def connection_made(self, connection: Any) -> None:
            """Filter each selected identity before AsyncSSH can send a key offer.

            AsyncSSH's owner callback runs only after agent/default identities.
            Wrap the per-connection selection method to cover those identities,
            PKCS#11 keys, and certificate retries without changing global state.
            Integration tests cover the supported AsyncSSH versions and both hops.
            """
            if allow_legacy:
                return
            select_key = getattr(connection, "public_key_auth_requested", None)
            if not callable(select_key):
                raise RuntimeError("this AsyncSSH version cannot enforce client-key strength")

            async def select_secure_key() -> Any:
                """Skip rejected identities and let other keys or passwords proceed."""
                while (keypair := await select_key()) is not None:
                    try:
                        validate_asyncssh_client_key(library, keypair)
                    except ValueError as exc:
                        logger.warning(
                            "Skipping SSH login identity %s: %s", _identity_label(keypair), exc
                        )
                        continue
                    return keypair
                return None

            connection.public_key_auth_requested = select_secure_key

        def validate_host_public_key(self, host: str, addr: str, port: int, key: Any) -> bool:
            """Check key strength before matching the host's trusted identities."""
            if not allow_legacy:
                validate_ssh_public_key(key.export_public_key("openssh").decode("ascii"))
            return parsed is None or key in parsed

    # An empty known_hosts list delegates to the callback; None would bypass it.
    options.update(known_hosts=([], [], []), client_factory=PolicyClient)
    return options


def configure_paramiko(
    transport: Any,
    allow_legacy: bool = False,
    group_exchange: Mapping[str, Any] | None = None,
) -> None:
    """Apply the policy to Paramiko's per-connection ``SecurityOptions`` lists.

    Paramiko's defaults are the starting point. With legacy, every algorithm
    in its registries (``Transport._kex_info`` and so on) is offered too.

    ``group_exchange`` maps group-exchange names to the adapter's handlers that
    refuse a server group below ``MIN_DH_GROUP_BITS``. In secure mode they
    replace Paramiko's handlers on this connection only (an instance attribute
    over the class registry), and those exchanges are offered again.
    """
    bounded: tuple[str, ...] = ()
    if group_exchange and not allow_legacy:
        transport._kex_info = {**transport._kex_info, **group_exchange}
        bounded = tuple(group_exchange)
    options = transport.get_security_options()
    for name, kind, registry in (
        ("kex", "kex", "_kex_info"),
        ("ciphers", "cipher", "_cipher_info"),
        ("digests", "mac", "_mac_info"),
        ("key_types", "signature", "_key_info"),
    ):
        implemented = tuple(getattr(transport, registry, None) or ())
        algorithms = algorithm_policy(
            kind,
            getattr(options, name),
            implemented,
            allow_legacy,
            bounded if kind == "kex" else (),
        )
        if name == "key_types":
            algorithms = tuple(alg for alg in algorithms if _plain_host_key_algorithm(alg))
        if not algorithms:
            raise ValueError(f"the SSH library has no supported {name} for this policy")
        setattr(options, name, algorithms)
