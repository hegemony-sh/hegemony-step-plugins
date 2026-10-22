# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Trust for TLS checks: the system store plus the run organization's trusted CAs.

A handler that verifies a TLS server trusts, by default, the worker's system
store and the CA certificates the run organization's administrators added
(:meth:`HandlerServices.trusted_ca_certificates`). A ``ca_bundle`` the step
sets keeps its meaning: only those CAs, which pins them.

On a host without the service every helper here behaves as if the
organization trusted no extra CA, so a handler behaves exactly as before.
"""

from __future__ import annotations

import os
import ssl
from typing import Any

#: Where ``container.run`` places the bundles inside a step container.
CONTAINER_CA_DIR = "/hegemony/ca"
#: The system store plus the organization's trusted CAs.
CONTAINER_CA_BUNDLE = f"{CONTAINER_CA_DIR}/ca-bundle.pem"
#: The organization's trusted CAs alone (for ``NODE_EXTRA_CA_CERTS``).
CONTAINER_ORG_CAS = f"{CONTAINER_CA_DIR}/org-cas.pem"

_PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
_MAX_SYSTEM_STORE_BYTES = 16 * 1024 * 1024


async def org_trusted_ca_pem(services: Any) -> str | None:
    """The run organization's trusted CAs as PEM text, or None when it has none.

    None also when ``services`` is None or the host predates the service
    (no ``trusted_ca_certificates`` attribute, or ``NotImplementedError``).
    A host that has the service but cannot load the list raises
    ``RuntimeError``; that propagates, so a step does not silently verify
    against less than its organization trusts.
    """
    method = getattr(services, "trusted_ca_certificates", None) if services is not None else None
    if not callable(method):
        return None
    try:
        text = await method()
    except NotImplementedError:
        return None
    if not isinstance(text, str) or _PEM_BEGIN not in text:
        return None
    return text.strip() + "\n"


def add_trusted_cas(context: ssl.SSLContext, pem: str | None) -> ssl.SSLContext:
    """Add ``pem``'s certificates to ``context``'s trust store; returns ``context``.

    ``context`` keeps what it already trusts (the system store for a context
    from :func:`ssl.create_default_context`). Raises ``ssl.SSLError`` when
    ``pem`` holds a certificate ``ssl`` cannot load.
    """
    if pem:
        context.load_verify_locations(cadata=pem)
    return context


def verifying_context(org_pem: str | None, *, cafile: str | None = None) -> ssl.SSLContext:
    """A default client context trusting the system store (or ``cafile``) plus ``org_pem``."""
    return add_trusted_cas(ssl.create_default_context(cafile=cafile), org_pem)


def system_ca_pem() -> str:
    """The worker's system trust store as PEM text ("" when it cannot be read).

    Reads the bundle file :func:`ssl.get_default_verify_paths` reports,
    falling back to ``certifi``'s bundle when that package is installed.
    """
    candidates: list[str] = []
    paths = ssl.get_default_verify_paths()
    for path in (paths.cafile, paths.openssl_cafile):
        if path and path not in candidates:
            candidates.append(path)
    try:
        import certifi

        candidates.append(certifi.where())
    except ImportError:
        # No certifi: the files the ssl module reports are the only candidates.
        pass
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="ascii", errors="ignore") as handle:
                text = handle.read(_MAX_SYSTEM_STORE_BYTES)
        except OSError:
            continue
        if _PEM_BEGIN in text:
            return text
    return ""


def combined_ca_pem(org_pem: str | None, system_pem: str | None = None) -> str:
    """The system store followed by ``org_pem``, as one PEM bundle."""
    system = system_ca_pem() if system_pem is None else system_pem
    parts = [part.strip() for part in (system, org_pem or "") if part and part.strip()]
    return "\n".join(parts) + "\n" if parts else ""
