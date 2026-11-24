# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Apply the SDK's SSH policy (``hegemony_step_sdk.ssh``) to Paramiko and AsyncSSH.

Internal to the built-in transports, with no stability promise; see the
package docstring. The policy itself (which algorithms and keys are weak, the
legacy opt-in) lives in the SDK. This module only maps it onto each SSH
library's own options, so every transport that uses the same library applies
it the same way. No SSH library is imported here either: callers pass their
library module or objects in.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from collections.abc import Mapping
from typing import Any

from hegemony_step_sdk.ssh import algorithm_policy, validate_ssh_public_key

logger = logging.getLogger(__name__)


def _plain_host_key_algorithm(name: str) -> bool:
    """Host trust stores plain keys: no certificates, X.509 or security-key types."""
    return not (
        name.endswith("-cert-v01@openssh.com") or name.startswith(("x509v3-", "sk-", "webauthn-"))
    )


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
