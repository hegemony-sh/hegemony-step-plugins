# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Certificate helpers for ``probe.tls``: parsing, matching, and offline checks.

Everything here is pure (no sockets, no event loop), so the rules the step
applies - endpoint syntax, hostname matching, fingerprint normalisation,
chain validation of a supplied certificate, the OCSP request/response
handling, and the CRL checks - are unit-testable on their own. The handler
in ``tls_check`` does the network work and calls into this module.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
import ssl
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    CRLEntryExtensionOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    SignatureAlgorithmOID,
)

#: Most endpoints one step may check (targets and listed endpoints together).
MAX_ENDPOINTS = 500

#: Longest issuer chain the offline validator walks before giving up.
MAX_CHAIN_DEPTH = 10

#: Clock skew tolerated on OCSP ``thisUpdate``/``nextUpdate``.
OCSP_CLOCK_SKEW = timedelta(minutes=5)

#: Clock skew tolerated on CRL ``thisUpdate``/``nextUpdate``.
CRL_CLOCK_SKEW = OCSP_CLOCK_SKEW

#: What reading an unusual or malformed certificate, OCSP response or CRL can
#: raise: an unknown algorithm, key type or name form, or a bad encoding.
_UNREADABLE = (
    ValueError,
    TypeError,
    UnsupportedAlgorithm,
    x509.DuplicateExtension,
    x509.UnsupportedGeneralNameType,
)

_ENTRY_SPLIT_RE = re.compile(r"[\r\n,]+")
_HOST_RE = re.compile(r"^[^\s/@\[\]:]+$")
_PEM_BLOCK_RE = re.compile(rb"-----BEGIN CERTIFICATE-----\s.*?-----END CERTIFICATE-----", re.DOTALL)
_FINGERPRINT_PREFIX_RE = re.compile(r"^\s*sha-?256\s*(?:fingerprint)?\s*[=:]\s*", re.IGNORECASE)
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


# --- Endpoints ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EndpointSpec:
    """One ``host:port[:sni]`` entry; ``sni`` is None unless written."""

    host: str
    port: int
    sni: str | None = None


def is_ip_literal(value: str) -> bool:
    """Whether ``value`` is an IPv4/IPv6 address (brackets and a zone id allowed)."""
    return parse_ip(value) is not None


def parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """``value`` as an address, or None when it is a name."""
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    text = text.split("%", 1)[0]
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def normalize_host(host: str) -> str:
    """Comparable form of a host: compressed address, or lowercase name without a trailing dot.

    An IPv6 zone (``fe80::1%eth0``) is kept, since the same link-local
    address on another interface is another endpoint.
    """
    address = parse_ip(host)
    if address is not None:
        text = host.strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        _, _, zone = text.partition("%")
        return f"{address.compressed}%{zone}" if zone else address.compressed
    return host.strip().rstrip(".").lower()


def endpoint_label(host: str, port: int) -> str:
    """``host:port`` with an IPv6 literal bracketed."""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def split_endpoint_entries(value: Any) -> list[str]:
    """Endpoint entries from a list of strings or one string.

    Templates render to strings, so a single string is split on newlines and
    commas; list items are split the same way (a templated item may hold
    several). Blank entries are dropped.
    """
    if value is None:
        return []
    if isinstance(value, str):
        items: list[Any] = [value]
    elif isinstance(value, list | tuple):
        items = list(value)
    else:
        raise ValueError("endpoints must be a list of strings or one string")
    entries: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError(f"endpoint {item!r} must be a string")
        entries.extend(part.strip() for part in _ENTRY_SPLIT_RE.split(item) if part.strip())
    return entries


def _parse_port(entry: str, text: str | None, default_port: int) -> int:
    """The port written in ``entry``, or ``default_port`` when none is given. Raises ``ValueError``."""
    if text is None or not text.strip():
        return default_port
    try:
        port = int(text.strip())
    except ValueError:
        raise ValueError(f"{entry!r}: port {text!r} is not a number") from None
    if not 1 <= port <= 65535:
        raise ValueError(f"{entry!r}: port {port} is outside 1-65535")
    return port


def parse_endpoint(entry: str, *, default_port: int = 443) -> EndpointSpec:
    """Parse ``host``, ``host:port`` or ``host:port:sni``.

    IPv6 literals go in brackets (``[2001:db8::1]:443``, or ``[2001:db8::1]``
    for the default port); a bare one is refused, since ``2001:db8::1:443``
    could be read either way. A missing port takes ``default_port``. Raises
    ``ValueError`` with the offending entry named.
    """
    text = entry.strip()
    if not text:
        raise ValueError("empty endpoint")
    if "://" in text:
        raise ValueError(f"{entry!r}: write host:port, not a URL")
    port_text: str | None
    sni: str | None
    if text.startswith("["):
        close = text.find("]")
        if close < 0:
            raise ValueError(f"{entry!r}: unclosed '[' around an IPv6 literal")
        host = text[1:close]
        if not isinstance(parse_ip(host), ipaddress.IPv6Address):
            raise ValueError(f"{entry!r}: [{host}] is not an IPv6 address")
        rest = text[close + 1 :]
        if not rest:
            port_text, sni = None, None
        elif rest.startswith(":"):
            port_text, _, sni_text = rest[1:].partition(":")
            sni = sni_text
        else:
            raise ValueError(f"{entry!r}: expected ':port' after ']'")
    elif text.count(":") > 2 or isinstance(parse_ip(text), ipaddress.IPv6Address):
        raise ValueError(f"{entry!r}: write an IPv6 address in brackets, e.g. [2001:db8::1]:443")
    else:
        parts = text.split(":")
        host = parts[0]
        port_text = parts[1] if len(parts) > 1 else None
        sni = parts[2] if len(parts) > 2 else None
        if not host or not _HOST_RE.match(host):
            raise ValueError(f"{entry!r}: {host!r} is not a host name or address")
    port = _parse_port(entry, port_text, default_port)
    sni = (sni or "").strip() or None
    if sni is not None and not _HOST_RE.match(sni):
        raise ValueError(f"{entry!r}: SNI {sni!r} is not a host name")
    return EndpointSpec(host=host.strip(), port=port, sni=sni)


def parse_endpoints(value: Any, *, default_port: int = 443) -> list[EndpointSpec]:
    """Every entry of :func:`split_endpoint_entries`, parsed."""
    return [
        parse_endpoint(entry, default_port=default_port) for entry in split_endpoint_entries(value)
    ]


def endpoint_key(host: str, port: int) -> tuple[str, int]:
    """Lookup key for per-endpoint settings (normalised host, port)."""
    return normalize_host(host), port


# --- Fingerprints ------------------------------------------------------------


def normalize_fingerprint(value: str) -> str:
    """Lowercase hex SHA-256 fingerprint without separators.

    Colons, whitespace and case are ignored, as is a leading ``sha256:`` or
    ``SHA256 Fingerprint=`` label (the form ``openssl x509 -fingerprint``
    prints). Raises ``ValueError`` for anything that is not 64 hex digits.
    """
    text = _FINGERPRINT_PREFIX_RE.sub("", value)
    text = re.sub(r"[\s:]", "", text).lower()
    if not _FINGERPRINT_RE.match(text):
        raise ValueError(
            f"{value.strip()!r} is not a SHA-256 fingerprint (64 hex digits, colons optional)"
        )
    return text


def fingerprint_sha256(cert: x509.Certificate) -> str:
    """Lowercase hex SHA-256 of the certificate's DER encoding."""
    return cert.fingerprint(hashes.SHA256()).hex()


# --- Hostname matching (RFC 6125) -------------------------------------------


def _to_ascii(name: str) -> str:
    """``name`` in its IDNA (punycode) form, or unchanged when it cannot be encoded."""
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def dns_name_matches(pattern: str, hostname: str) -> bool:
    """Whether a DNS-ID ``pattern`` from a certificate matches ``hostname``.

    Case-insensitive, trailing dots ignored. A wildcard is honoured only as
    the entire left-most label (``*.example.com``), matches exactly one
    non-empty label, and needs at least two labels after it, so
    ``*.example.com`` matches ``www.example.com`` but neither
    ``example.com`` nor ``a.b.example.com``; partial-label wildcards
    (``w*.example.com``) and wildcards elsewhere never match. A DNS-ID never
    matches an IP address.
    """
    pattern = pattern.strip().rstrip(".").lower()
    host = _to_ascii(hostname.strip().rstrip(".")).lower()
    if not pattern or not host or is_ip_literal(host):
        return False
    if "*" not in pattern:
        return pattern == host
    pattern_labels = pattern.split(".")
    host_labels = host.split(".")
    if pattern_labels[0] != "*" or any("*" in label for label in pattern_labels[1:]):
        return False
    if len(pattern_labels) < 3 or len(host_labels) != len(pattern_labels):
        return False
    if not host_labels[0]:
        return False
    return pattern_labels[1:] == host_labels[1:]


def hostname_matches(
    hostname: str,
    dns_names: Sequence[str],
    ip_addresses: Sequence[str],
    common_name: str | None,
) -> bool:
    """Whether a certificate with these identities is valid for ``hostname``.

    An IP-address host matches only IP SANs; a name matches only DNS SANs
    (with :func:`dns_name_matches`). The subject common name is consulted
    only when the certificate carries no DNS or IP SANs at all.
    """
    address = parse_ip(hostname)
    has_sans = bool(dns_names or ip_addresses)
    if address is not None:
        if has_sans:
            return any(parse_ip(value) == address for value in ip_addresses)
        return common_name is not None and parse_ip(common_name) == address
    if has_sans:
        return any(dns_name_matches(pattern, hostname) for pattern in dns_names)
    return common_name is not None and dns_name_matches(common_name, hostname)


# --- Loading -----------------------------------------------------------------


def load_pem_certificates(data: str | bytes) -> list[x509.Certificate]:
    """Every parsable ``CERTIFICATE`` block in ``data``, in order.

    Text around the blocks is ignored, and a malformed block raises
    ``ValueError`` naming its position, so a pasted bundle with comments or
    an explanatory header still loads.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else data
    certs: list[x509.Certificate] = []
    for index, block in enumerate(_PEM_BLOCK_RE.findall(raw), start=1):
        try:
            certs.append(x509.load_pem_x509_certificate(block))
        except ValueError as exc:
            raise ValueError(f"certificate #{index} cannot be parsed: {exc}") from exc
    return certs


def load_certificates_any(data: bytes) -> list[x509.Certificate]:
    """Certificates from a downloaded issuer file: PEM, DER, or PKCS#7 (DER or PEM)."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        try:
            return load_pem_certificates(data)
        except ValueError:
            return []
    try:
        return [x509.load_der_x509_certificate(data)]
    except ValueError:
        pass
    for loader in (pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
        try:
            return list(loader(data))
        except (ValueError, UnsupportedAlgorithm):
            continue
    return []


def certificates_to_pem(certs: Iterable[x509.Certificate]) -> str:
    """PEM text for ``certs`` (as ``ssl`` accepts for ``cadata``)."""
    return "".join(cert.public_bytes(serialization.Encoding.PEM).decode("ascii") for cert in certs)


def load_system_anchors() -> list[x509.Certificate]:
    """The worker's default trust store, as ``ssl`` would load it.

    Reads the PEM bundle file and hashed directory ``ssl`` reports in
    :func:`ssl.get_default_verify_paths`. Returns an empty list when neither
    exists or nothing in them parses; unreadable entries are skipped.
    """
    paths = ssl.get_default_verify_paths()
    sources: list[str] = []
    if paths.cafile and os.path.isfile(paths.cafile):
        sources.append(paths.cafile)
    if paths.capath and os.path.isdir(paths.capath):
        try:
            entries = sorted(os.scandir(paths.capath), key=lambda entry: entry.name)
        except OSError:
            entries = []
        sources.extend(
            entry.path for entry in entries if entry.is_file() and not entry.name.startswith(".")
        )
    anchors: dict[bytes, x509.Certificate] = {}
    for path in sources:
        try:
            with open(path, "rb") as handle:
                data = handle.read(16 * 1024 * 1024)
        except OSError:
            continue
        for block in _PEM_BLOCK_RE.findall(data):
            try:
                cert = x509.load_pem_x509_certificate(block)
            except ValueError:
                continue
            anchors.setdefault(cert.fingerprint(hashes.SHA256()), cert)
    return list(anchors.values())


# --- Certificate fields ------------------------------------------------------


def _iso_z(moment: datetime) -> str:
    """``moment`` as an ISO 8601 UTC timestamp ending in ``Z``."""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _first_attribute(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    """The first value of ``oid`` in ``name`` as text, or None when absent."""
    try:
        attributes = name.get_attributes_for_oid(oid)
    except ValueError:
        return None
    if not attributes:
        return None
    value = attributes[0].value
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _extension_value(
    cert: x509.Certificate | x509.CertificateRevocationList, ext_type: type[Any]
) -> Any:
    """The value of a certificate's or CRL's ``ext_type`` extension; None when absent or malformed."""
    try:
        return cert.extensions.get_extension_for_class(ext_type).value
    except (x509.ExtensionNotFound, x509.DuplicateExtension, ValueError):
        return None


def san_names(cert: x509.Certificate) -> tuple[list[str], list[str]]:
    """The certificate's DNS and IP subject alternative names, as strings."""
    sans = _extension_value(cert, x509.SubjectAlternativeName)
    if sans is None:
        return [], []
    dns_names = [str(value) for value in sans.get_values_for_type(x509.DNSName)]
    ip_addresses = [value.compressed for value in sans.get_values_for_type(x509.IPAddress)]
    return dns_names, ip_addresses


def common_name(cert: x509.Certificate) -> str | None:
    """The subject's first common name."""
    return _first_attribute(cert.subject, NameOID.COMMON_NAME)


def is_ca(cert: x509.Certificate) -> bool:
    """Whether basicConstraints marks the certificate as a CA."""
    constraints = _extension_value(cert, x509.BasicConstraints)
    return bool(constraints is not None and constraints.ca)


def _key_details(cert: x509.Certificate) -> tuple[str | None, int | None, str | None]:
    """``(key_type, key_bits, curve_name)`` of the certificate's public key; Nones when unknown."""
    try:
        key = cert.public_key()
    except (ValueError, UnsupportedAlgorithm):
        return None, None, None
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size, None
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ec", key.curve.key_size, key.curve.name
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519", 256, None
    if isinstance(key, ed448.Ed448PublicKey):
        return "ed448", 448, None
    if isinstance(key, dsa.DSAPublicKey):
        return "dsa", key.key_size, None
    return None, None, None


def _signature_algorithm(cert: x509.Certificate) -> str:
    """The signature algorithm's name, or its dotted OID when the name is unknown."""
    oid = cert.signature_algorithm_oid
    name = getattr(oid, "_name", "") or ""
    return name if name and name != "Unknown OID" else oid.dotted_string


def days_left(cert: x509.Certificate, now: datetime) -> int:
    """Whole days until ``notAfter`` (floored, so negative once expired)."""
    return math.floor((cert.not_valid_after_utc - now).total_seconds() / 86400)


#: Certificate keys every endpoint record carries (None when no certificate).
CERTIFICATE_FIELDS = (
    "subject_cn",
    "sans",
    "issuer_cn",
    "issuer",
    "serial",
    "fingerprint_sha256",
    "not_before",
    "not_after",
    "days_left",
    "expired",
    "key_type",
    "key_bits",
    "key_curve",
    "signature_algorithm",
    "is_ca",
)


def empty_certificate_fields() -> dict[str, Any]:
    """Every certificate key, unset - the shape of an endpoint without a certificate."""
    return dict.fromkeys(CERTIFICATE_FIELDS)


def certificate_fields(cert: x509.Certificate, *, now: datetime) -> dict[str, Any]:
    """The reported description of one certificate (see ``CERTIFICATE_FIELDS``)."""
    dns_names, ip_addresses = san_names(cert)
    key_type, key_bits, key_curve = _key_details(cert)
    return {
        "subject_cn": common_name(cert),
        "sans": dns_names + ip_addresses,
        "issuer_cn": _first_attribute(cert.issuer, NameOID.COMMON_NAME),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "fingerprint_sha256": fingerprint_sha256(cert),
        "not_before": _iso_z(cert.not_valid_before_utc),
        "not_after": _iso_z(cert.not_valid_after_utc),
        "days_left": days_left(cert, now),
        "expired": now > cert.not_valid_after_utc,
        "key_type": key_type,
        "key_bits": key_bits,
        "key_curve": key_curve,
        "signature_algorithm": _signature_algorithm(cert),
        "is_ca": is_ca(cert),
    }


def certificate_pem(cert: x509.Certificate) -> str:
    """The certificate as PEM text."""
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


# --- Offline chain validation ------------------------------------------------


def _signed_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Whether ``issuer``'s name and key issued ``cert``."""
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False
    return True


def _may_issue(cert: x509.Certificate) -> bool:
    """CA check as OpenSSL applies it.

    Key usage, when present, must allow certificate signing, and
    basicConstraints must mark a CA (or the certificate be version 1).
    """
    usage = _extension_value(cert, x509.KeyUsage)
    if usage is not None and not usage.key_cert_sign:
        return False
    constraints = _extension_value(cert, x509.BasicConstraints)
    if constraints is not None:
        return bool(constraints.ca)
    return cert.version == x509.Version.v1


def _time_error(cert: x509.Certificate, now: datetime) -> str | None:
    """Why the certificate is outside its validity period at ``now``, or None."""
    if now < cert.not_valid_before_utc:
        return "certificate is not yet valid"
    if now > cert.not_valid_after_utc:
        return "certificate has expired"
    return None


#: Extended key usages that let a certificate serve TLS (OpenSSL's ``ssl_server``
#: purpose: server authentication, or the legacy Netscape and Microsoft
#: server-gated cryptography usages).
_SERVER_USAGES = frozenset(
    {
        ExtendedKeyUsageOID.SERVER_AUTH,
        x509.ObjectIdentifier("2.16.840.1.113730.4.1"),  # Netscape SGC
        x509.ObjectIdentifier("1.3.6.1.4.1.311.10.3.3"),  # Microsoft SGC
    }
)

#: Extensions OpenSSL's verifier understands; any other extension marked
#: critical makes it reject the certificate ("unhandled critical extension").
_HANDLED_CRITICAL_EXTENSIONS = frozenset(
    {
        "2.16.840.1.113730.1.1",  # Netscape certificate type
        ExtensionOID.KEY_USAGE.dotted_string,
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string,
        ExtensionOID.BASIC_CONSTRAINTS.dotted_string,
        ExtensionOID.CERTIFICATE_POLICIES.dotted_string,
        ExtensionOID.CRL_DISTRIBUTION_POINTS.dotted_string,
        ExtensionOID.EXTENDED_KEY_USAGE.dotted_string,
        "1.3.6.1.5.5.7.1.7",  # RFC 3779 IP address blocks
        "1.3.6.1.5.5.7.1.8",  # RFC 3779 AS identifiers
        ExtensionOID.OCSP_NO_CHECK.dotted_string,
        ExtensionOID.POLICY_CONSTRAINTS.dotted_string,
        "1.3.6.1.5.5.7.1.14",  # proxy certificate information
        ExtensionOID.NAME_CONSTRAINTS.dotted_string,
        ExtensionOID.POLICY_MAPPINGS.dotted_string,
        ExtensionOID.INHIBIT_ANY_POLICY.dotted_string,
    }
)

#: OpenSSL 3's wording when a certificate's purpose rules out a TLS server.
_PURPOSE_ERROR = "unsuitable certificate purpose"

#: A subject common name OpenSSL treats as a DNS name for name constraints.
_CN_DNS_RE = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def _key_usage(cert: x509.Certificate) -> x509.KeyUsage | None:
    """The certificate's key usage extension, or None when it has none."""
    return _extension_value(cert, x509.KeyUsage)


def _eku_error(cert: x509.Certificate) -> str | None:
    """Why the certificate's extended key usage rules out TLS servers, or None."""
    usages = _extension_value(cert, x509.ExtendedKeyUsage)
    if usages is not None and _SERVER_USAGES.isdisjoint(set(usages)):
        return _PURPOSE_ERROR
    return None


def _purpose_error(leaf: x509.Certificate) -> str | None:
    """Why the leaf cannot serve TLS, as OpenSSL's ``ssl_server`` purpose judges it, or None.

    Its extended key usage, when present, must allow server authentication,
    and its key usage, when present, must allow a digital signature, key
    encipherment or key agreement.
    """
    error = _eku_error(leaf)
    if error is not None:
        return error
    usage = _key_usage(leaf)
    if usage is not None and not (
        usage.digital_signature or usage.key_encipherment or usage.key_agreement
    ):
        return _PURPOSE_ERROR
    return None


def _critical_extension_error(cert: x509.Certificate) -> str | None:
    """Why the certificate carries a critical extension the verifier cannot handle, or None."""
    try:
        extensions = list(cert.extensions)
    except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        return "unhandled critical extension"
    for extension in extensions:
        if extension.critical and extension.oid.dotted_string not in _HANDLED_CRITICAL_EXTENSIONS:
            return "unhandled critical extension"
    return None


def verify_chain_offline(
    leaf: x509.Certificate,
    intermediates: Sequence[x509.Certificate],
    anchors: Sequence[x509.Certificate],
    *,
    now: datetime,
) -> tuple[bool, str | None]:
    """Validate ``leaf`` up to one of ``anchors`` without any network access.

    The checks OpenSSL's verifier makes for a TLS server, minus the host
    name (checked on its own): every certificate on the path is within its
    validity period, carries no critical extension the verifier does not
    handle, and is signed by the next; every issuer may act as a CA
    (basicConstraints, key usage, path length) and, when untrusted, allows
    server authentication in its extended key usage; the leaf may serve TLS
    (extended key usage and key usage); every name below a CA with name
    constraints satisfies them; and the path ends at a trust anchor.
    ``intermediates`` are untrusted candidates. A leaf that is itself an
    anchor (a pinned self-signed certificate) needs only to be current,
    usable for TLS and free of unhandled critical extensions. Errors use
    OpenSSL's wording, so a supplied certificate and a served one read the
    same.
    """
    anchor_fingerprints = {fingerprint_sha256(anchor) for anchor in anchors}
    if fingerprint_sha256(leaf) in anchor_fingerprints:
        error = _critical_extension_error(leaf) or _purpose_error(leaf) or _time_error(leaf, now)
        return (error is None, error)
    error = _critical_extension_error(leaf) or _purpose_error(leaf)
    if error is not None:
        return False, error
    error = _walk(
        leaf, list(intermediates), list(anchors), now, depth=0, used=frozenset(), path=(leaf,)
    )
    return (error is None, error)


def _walk(
    cert: x509.Certificate,
    intermediates: list[x509.Certificate],
    anchors: list[x509.Certificate],
    now: datetime,
    *,
    depth: int,
    used: frozenset[str],
    path: tuple[x509.Certificate, ...],
) -> str | None:
    """Depth-first issuer search; None when a valid path to an anchor exists, else why not.

    ``path`` holds the certificates from the leaf up to ``cert``.
    """
    error = _time_error(cert, now)
    if error is not None:
        return error
    if depth >= MAX_CHAIN_DEPTH:
        return "certificate chain too long"
    first_error: str | None = None
    for anchor in anchors:
        if anchor.subject != cert.issuer or not _signed_by(cert, anchor):
            continue
        problem = _issuer_problem(anchor, depth, now, trusted=True) or _name_constraints_error(
            (*path, anchor)
        )
        if problem is None:
            return None
        first_error = first_error or problem
    for candidate in intermediates:
        fingerprint = fingerprint_sha256(candidate)
        if fingerprint in used or candidate.subject != cert.issuer:
            continue
        if not _signed_by(cert, candidate):
            first_error = first_error or "certificate signature failure"
            continue
        problem = _issuer_problem(candidate, depth, now, trusted=False)
        if problem is None:
            problem = _walk(
                candidate,
                intermediates,
                anchors,
                now,
                depth=depth + 1,
                used=used | {fingerprint},
                path=(*path, candidate),
            )
        if problem is None:
            return None
        first_error = first_error or problem
    if first_error is not None:
        return first_error
    if cert.issuer == cert.subject and _signed_by(cert, cert):
        return "self-signed certificate" if depth == 0 else "self-signed certificate in chain"
    return "unable to get local issuer certificate"


def _issuer_problem(
    issuer: x509.Certificate, depth: int, now: datetime, *, trusted: bool
) -> str | None:
    """Why ``issuer`` cannot sign at this depth (``depth`` intermediates below it)."""
    error = _time_error(issuer, now) or _critical_extension_error(issuer)
    if error is not None:
        return error
    if not _may_issue(issuer):
        return "invalid CA certificate"
    if not trusted and _eku_error(issuer) is not None:
        return _PURPOSE_ERROR
    constraints = _extension_value(issuer, x509.BasicConstraints)
    path_length = constraints.path_length if constraints is not None else None
    if path_length is not None and depth > path_length:
        return "path length constraint exceeded"
    return None


# --- Name constraints ---------------------------------------------------------


#: Name types the name-constraint check understands; others are refused.
_SUPPORTED_NAME_TYPES = (
    x509.DNSName,
    x509.IPAddress,
    x509.RFC822Name,
    x509.UniformResourceIdentifier,
    x509.DirectoryName,
)


def _name_constraints_error(path: Sequence[x509.Certificate]) -> str | None:
    """Why a certificate in ``path`` (leaf first) breaks a CA's name constraints, or None.

    Each CA's constraints apply to every certificate below it, except
    self-issued intermediates (RFC 5280, 6.1.4).
    """
    for index in range(1, len(path)):
        constraints = _extension_value(path[index], x509.NameConstraints)
        if constraints is None:
            continue
        for position, cert in enumerate(path[:index]):
            if position > 0 and cert.subject == cert.issuer:
                continue
            error = _names_error(cert, constraints, leaf=position == 0)
            if error is not None:
                return error
    return None


def _subject_names(cert: x509.Certificate, *, leaf: bool) -> list[x509.GeneralName]:
    """Every name name constraints apply to: the subject, its e-mail addresses, the SANs.

    A leaf without DNS SANs also has its host-name-like common names
    checked as DNS names, as OpenSSL does.
    """
    names: list[x509.GeneralName] = []
    if len(cert.subject) > 0:
        names.append(x509.DirectoryName(cert.subject))
    for attribute in cert.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS):
        if isinstance(attribute.value, str):
            names.append(x509.RFC822Name(attribute.value))
    sans = _extension_value(cert, x509.SubjectAlternativeName)
    if sans is not None:
        names.extend(sans)
    if leaf and not any(isinstance(name, x509.DNSName) for name in names):
        for attribute in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            value = attribute.value
            if isinstance(value, str) and _CN_DNS_RE.match(value):
                names.append(x509.DNSName(value))
    return names


def _names_error(
    cert: x509.Certificate, constraints: x509.NameConstraints, *, leaf: bool
) -> str | None:
    """Why one certificate's names break ``constraints``, or None."""
    permitted = list(constraints.permitted_subtrees or [])
    excluded = list(constraints.excluded_subtrees or [])
    try:
        names = _subject_names(cert, leaf=leaf)
    except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        return "unsupported name constraint type"
    for name in names:
        same_type = [base for base in permitted + excluded if type(base) is type(name)]
        if not same_type:
            continue
        if not isinstance(name, _SUPPORTED_NAME_TYPES):
            return "unsupported name constraint type"
        if any(_name_within(name, base) for base in excluded if type(base) is type(name)):
            return "excluded subtree violation"
        allowed = [base for base in permitted if type(base) is type(name)]
        if allowed and not any(_name_within(name, base) for base in allowed):
            return "permitted subtree violation"
    return None


def _name_within(name: x509.GeneralName, base: x509.GeneralName) -> bool:
    """Whether ``name`` falls inside the subtree ``base`` (both of the same type)."""
    if isinstance(name, x509.DNSName) and isinstance(base, x509.DNSName):
        return _dns_within(name.value, base.value)
    if isinstance(name, x509.IPAddress) and isinstance(base, x509.IPAddress):
        network = base.value
        address = name.value
        if not isinstance(network, ipaddress.IPv4Network | ipaddress.IPv6Network):
            return False
        if not isinstance(address, ipaddress.IPv4Address | ipaddress.IPv6Address):
            return False
        return address.version == network.version and address in network
    if isinstance(name, x509.RFC822Name) and isinstance(base, x509.RFC822Name):
        return _email_within(name.value, base.value)
    if isinstance(name, x509.UniformResourceIdentifier) and isinstance(
        base, x509.UniformResourceIdentifier
    ):
        return _uri_within(name.value, base.value)
    if isinstance(name, x509.DirectoryName) and isinstance(base, x509.DirectoryName):
        rdns, prefix = list(name.value.rdns), list(base.value.rdns)
        return rdns[: len(prefix)] == prefix
    return False


def _dns_within(name: str, base: str) -> bool:
    """DNS subtree match as OpenSSL does it: equal, or a subdomain of ``base``."""
    name, base = name.lower(), base.lower()
    if not base:
        return True
    if len(name) > len(base):
        if not base.startswith(".") and name[-len(base) - 1] != ".":
            return False
        return name.endswith(base)
    return name == base


def _email_within(address: str, base: str) -> bool:
    """E-mail subtree match: one mailbox, every address at a host, or at its subdomains."""
    local, at, domain = address.rpartition("@")
    if not at:
        return False
    if "@" in base:
        base_local, _, base_domain = base.rpartition("@")
        return local == base_local and domain.lower() == base_domain.lower()
    if base.startswith("."):
        return domain.lower().endswith(base.lower())
    return domain.lower() == base.lower()


def _uri_within(uri: str, base: str) -> bool:
    """URI subtree match on the URI's host: equal, or (``.domain``) a subdomain."""
    _, separator, rest = uri.partition("://")
    if not separator:
        return False
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = host.rsplit("@", 1)[-1]
    if host.startswith("["):
        return False
    host = host.split(":", 1)[0].lower()
    if not host:
        return False
    if base.startswith("."):
        return host.endswith(base.lower())
    return host == base.lower()


# --- Issuers and OCSP --------------------------------------------------------


def find_issuer(
    cert: x509.Certificate, candidates: Iterable[x509.Certificate]
) -> x509.Certificate | None:
    """The first candidate whose name and key issued ``cert``."""
    for candidate in candidates:
        if candidate.subject == cert.issuer and _signed_by(cert, candidate):
            return candidate
    return None


def _access_urls(cert: x509.Certificate, method: x509.ObjectIdentifier) -> list[str]:
    """HTTP(S) URLs of the Authority Information Access entries using ``method``."""
    access = _extension_value(cert, x509.AuthorityInformationAccess)
    if access is None:
        return []
    return [
        description.access_location.value
        for description in access
        if description.access_method == method
        and isinstance(description.access_location, x509.UniformResourceIdentifier)
        and description.access_location.value.lower().startswith(("http://", "https://"))
    ]


def ocsp_responder_urls(cert: x509.Certificate) -> list[str]:
    """HTTP(S) OCSP responder URLs from the Authority Information Access extension."""
    return _access_urls(cert, AuthorityInformationAccessOID.OCSP)


def ca_issuer_urls(cert: x509.Certificate) -> list[str]:
    """HTTP(S) caIssuers URLs from the Authority Information Access extension."""
    return _access_urls(cert, AuthorityInformationAccessOID.CA_ISSUERS)


def build_ocsp_request(cert: x509.Certificate, issuer: x509.Certificate) -> bytes:
    """DER OCSP request for ``cert`` (SHA-1 CertID, as responders universally accept)."""
    request = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA1()).build()
    return request.public_bytes(serialization.Encoding.DER)


def _responder_is(response: ocsp.OCSPResponse, candidate: x509.Certificate) -> bool:
    """Whether ``candidate`` is the responder the OCSP response names, by name or key hash."""
    if response.responder_name is not None:
        return response.responder_name == candidate.subject
    if response.responder_key_hash is not None:
        key_id = x509.SubjectKeyIdentifier.from_public_key(candidate.public_key())
        return response.responder_key_hash == key_id.digest
    return False


def _delegated_signer(cert: x509.Certificate) -> bool:
    """Whether the certificate carries the OCSP-signing extended key usage."""
    usages = _extension_value(cert, x509.ExtendedKeyUsage)
    return usages is not None and ExtendedKeyUsageOID.OCSP_SIGNING in set(usages)


def _verify_signature(
    key: Any,
    signature: bytes,
    data: bytes,
    hash_algorithm: hashes.HashAlgorithm | None,
    signature_oid: x509.ObjectIdentifier,
) -> bool:
    """Whether ``signature`` over ``data`` verifies with ``key``; False for unsupported keys."""
    try:
        if isinstance(key, rsa.RSAPublicKey) and hash_algorithm is not None:
            if signature_oid == SignatureAlgorithmOID.RSASSA_PSS:
                pss = padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=padding.PSS.AUTO)
                key.verify(signature, data, pss, hash_algorithm)
            else:
                key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey) and hash_algorithm is not None:
            key.verify(signature, data, ec.ECDSA(hash_algorithm))
        elif isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
            key.verify(signature, data)
        elif isinstance(key, dsa.DSAPublicKey) and hash_algorithm is not None:
            key.verify(signature, data, hash_algorithm)
        else:
            return False
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm):
        return False
    return True


def ocsp_outcome(
    status: str, detail: str | None, revocation_time: str | None = None
) -> dict[str, Any]:
    """The three OCSP keys every endpoint record carries."""
    return {"ocsp": status, "ocsp_detail": detail, "revocation_time": revocation_time}


def evaluate_ocsp_response(
    data: bytes,
    cert: x509.Certificate,
    issuer: x509.Certificate,
    *,
    now: datetime,
) -> dict[str, Any]:
    """Judge a DER OCSP response for ``cert``: good, revoked, unknown, or error.

    The response must come from the issuer itself or from a responder the
    issuer delegated (its certificate in the response, issued by the issuer,
    with the OCSP-signing purpose, and within its validity period), its
    signature must verify, it must be about this certificate (serial number,
    issuer name hash and issuer key hash), and it must be current. Never
    raises: a response the checks cannot read (an unknown signature
    algorithm, an unsupported responder key) is an error for this
    certificate alone.
    """
    try:
        return _judge_ocsp_response(data, cert, issuer, now=now)
    except _UNREADABLE as exc:
        return ocsp_outcome("error", f"response cannot be checked: {exc}")


def _judge_ocsp_response(
    data: bytes,
    cert: x509.Certificate,
    issuer: x509.Certificate,
    *,
    now: datetime,
) -> dict[str, Any]:
    """:func:`evaluate_ocsp_response` without the guard against unreadable responses."""
    try:
        response = ocsp.load_der_ocsp_response(data)
    except ValueError as exc:
        return ocsp_outcome("error", f"malformed OCSP response: {exc}")
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return ocsp_outcome("error", f"responder answered {response.response_status.name.lower()}")

    signer: x509.Certificate | None = issuer if _responder_is(response, issuer) else None
    if signer is None:
        for candidate in response.certificates:
            if (
                _responder_is(response, candidate)
                and _delegated_signer(candidate)
                and _signed_by(candidate, issuer)
                and _time_error(candidate, now) is None
            ):
                signer = candidate
                break
    if signer is None:
        return ocsp_outcome(
            "error", "response is not signed by the issuer or a responder it authorised"
        )
    if not _verify_signature(
        signer.public_key(),
        response.signature,
        response.tbs_response_bytes,
        response.signature_hash_algorithm,
        response.signature_algorithm_oid,
    ):
        return ocsp_outcome("error", "response signature does not verify")

    singles: Iterable[Any] = getattr(response, "responses", None) or [response]
    for single in singles:
        if single.serial_number != cert.serial_number:
            continue
        try:
            expected = (
                ocsp.OCSPRequestBuilder()
                .add_certificate(cert, issuer, single.hash_algorithm)
                .build()
            )
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
        if (
            single.issuer_key_hash != expected.issuer_key_hash
            or single.issuer_name_hash != expected.issuer_name_hash
        ):
            continue
        return _single_outcome(single, now)
    return ocsp_outcome("error", "response does not cover this certificate")


def _single_outcome(single: Any, now: datetime) -> dict[str, Any]:
    """The OCSP outcome of one single response at ``now``, after its freshness check."""
    this_update: datetime = single.this_update_utc
    next_update: datetime | None = single.next_update_utc
    if this_update - OCSP_CLOCK_SKEW > now:
        return ocsp_outcome("error", f"response is not valid until {_iso_z(this_update)}")
    if next_update is not None and next_update + OCSP_CLOCK_SKEW < now:
        return ocsp_outcome("error", f"response is stale (next update was {_iso_z(next_update)})")
    status = single.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        return ocsp_outcome("good", "responder reports the certificate good")
    if status == ocsp.OCSPCertStatus.REVOKED:
        revoked_at: datetime | None = single.revocation_time_utc
        reason = single.revocation_reason
        detail = "certificate is revoked"
        if reason is not None:
            detail += f" (reason: {reason.name})"
        return ocsp_outcome("revoked", detail, _iso_z(revoked_at) if revoked_at else None)
    return ocsp_outcome("unknown", "responder does not know this certificate")


# --- CRLs -----------------------------------------------------------------------


#: Extensions a CRL may mark critical and still be used: the issuing
#: distribution point, whose scope :func:`crl_status` checks.
_HANDLED_CRITICAL_CRL_EXTENSIONS = frozenset({ExtensionOID.ISSUING_DISTRIBUTION_POINT})

#: Entry extensions a CRL entry may mark critical and still be read. The
#: certificate issuer extension belongs to indirect CRLs, which are refused.
_HANDLED_CRITICAL_ENTRY_EXTENSIONS = frozenset(
    {CRLEntryExtensionOID.CRL_REASON, CRLEntryExtensionOID.INVALIDITY_DATE}
)


#: Public key types that can sign a CRL.
_SIGNING_KEY_TYPES = (
    rsa.RSAPublicKey,
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    ed448.Ed448PublicKey,
    dsa.DSAPublicKey,
)


@dataclass(frozen=True, slots=True)
class CrlLocation:
    """One HTTP(S) address a certificate's CRL is published at.

    ``names`` holds every name of the distribution point the address came
    from, for the scope check against the CRL's issuing distribution point.
    """

    url: str
    names: frozenset[x509.GeneralName]


def crl_locations(cert: x509.Certificate) -> tuple[list[CrlLocation], str | None]:
    """The certificate's HTTP(S) CRL addresses in order, or none and why.

    Only distribution points the issuer publishes directly and for every
    revocation reason count: one naming a separate CRL issuer (an indirect
    CRL), covering only some reasons, or named relative to the issuer is
    skipped. Other URL schemes (``ldap://``) are skipped too.
    """
    points = _extension_value(cert, x509.CRLDistributionPoints)
    if points is None:
        return [], "the certificate names no CRL distribution point"
    locations: list[CrlLocation] = []
    seen: set[str] = set()
    unsupported = False
    for point in points:
        if point.full_name is None or point.crl_issuer is not None or point.reasons is not None:
            unsupported = True
            continue
        names = frozenset(point.full_name)
        for name in point.full_name:
            if not isinstance(name, x509.UniformResourceIdentifier):
                continue
            url = name.value
            if url.lower().startswith(("http://", "https://")) and url not in seen:
                seen.add(url)
                locations.append(CrlLocation(url, names))
    if locations:
        return locations, None
    if unsupported:
        return [], (
            "the certificate's CRL distribution points need an indirect CRL, partial "
            "reasons or a relative name, which this check does not support"
        )
    return [], "the certificate's CRL distribution points name no HTTP address"


def load_crl(data: bytes) -> x509.CertificateRevocationList:
    """A downloaded CRL, DER or PEM. Raises ``ValueError`` when it is neither."""
    if b"-----BEGIN X509 CRL-----" in data:
        return x509.load_pem_x509_crl(data)
    return x509.load_der_x509_crl(data)


def crl_outcome(
    status: str,
    detail: str | None,
    *,
    url: str | None = None,
    next_update: str | None = None,
    revocation_time: str | None = None,
) -> dict[str, Any]:
    """The five CRL keys every endpoint record carries."""
    return {
        "crl": status,
        "crl_detail": detail,
        "crl_url": url,
        "crl_next_update": next_update,
        "crl_revocation_time": revocation_time,
    }


def crl_signature_problem(
    crl: x509.CertificateRevocationList, issuer: x509.Certificate
) -> str | None:
    """Why ``crl`` is not a complete list ``issuer`` signed, or None.

    The CRL must name the issuer, the issuer's key usage (when present) must
    allow signing CRLs, the signature must verify with the issuer's key, and
    the CRL must be a complete one (not a delta) without a critical extension
    the check does not handle. None of this depends on the certificate looked
    up, so the handler checks it once per list and issuer. Never raises: a
    list the checks cannot read is a problem like any other.
    """
    try:
        return _crl_list_problem(crl, issuer)
    except _UNREADABLE as exc:
        return f"CRL cannot be checked: {exc}"


def _crl_list_problem(crl: x509.CertificateRevocationList, issuer: x509.Certificate) -> str | None:
    """:func:`crl_signature_problem` without the guard against unreadable lists."""
    if crl.issuer != issuer.subject:
        return "CRL is not issued by the certificate's issuer"
    usage = _key_usage(issuer)
    if usage is not None and not usage.crl_sign:
        return "the issuer's key usage does not allow signing CRLs"
    try:
        key = issuer.public_key()
        valid = isinstance(key, _SIGNING_KEY_TYPES) and crl.is_signature_valid(key)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        valid = False
    if not valid:
        return "CRL signature does not verify with the issuer's key"
    try:
        extensions = list(crl.extensions)
    except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        return "CRL extensions cannot be parsed"
    for extension in extensions:
        if extension.oid == ExtensionOID.DELTA_CRL_INDICATOR:
            return "the address serves a delta CRL, not a complete one"
        if extension.critical and extension.oid not in _HANDLED_CRITICAL_CRL_EXTENSIONS:
            return "CRL has an unhandled critical extension"
    return None


def _crl_scope_problem(
    crl: x509.CertificateRevocationList,
    cert: x509.Certificate,
    names: frozenset[x509.GeneralName],
) -> str | None:
    """Why the CRL's issuing distribution point leaves ``cert`` out of scope, or None."""
    scope = _extension_value(crl, x509.IssuingDistributionPoint)
    if scope is None:
        return None
    if scope.indirect_crl:
        return "CRL is an indirect CRL, which this check does not support"
    if scope.only_some_reasons is not None:
        return "CRL covers only some revocation reasons"
    if scope.only_contains_attribute_certs:
        return "CRL does not cover this certificate (it lists attribute certificates only)"
    if scope.only_contains_ca_certs and not is_ca(cert):
        return "CRL does not cover this certificate (it lists CA certificates only)"
    if scope.only_contains_user_certs and is_ca(cert):
        return "CRL does not cover this certificate (it lists end-entity certificates only)"
    if scope.relative_name is not None:
        return (
            "CRL scope uses a relative distribution point name, which this check does not support"
        )
    if scope.full_name is not None and names.isdisjoint(scope.full_name):
        return "CRL does not cover this certificate (it is for another distribution point)"
    return None


def crl_status(
    crl: x509.CertificateRevocationList,
    cert: x509.Certificate,
    *,
    url: str,
    names: frozenset[x509.GeneralName],
    now: datetime,
) -> dict[str, Any]:
    """Look ``cert`` up in a ``crl`` that already passed :func:`crl_signature_problem`.

    The list must be current (``thisUpdate`` not in the future, ``nextUpdate``
    not past) and cover the certificate (its issuing distribution point, when
    present, names the distribution point it was fetched from and does not
    leave this kind of certificate out). Good means the certificate is not
    listed; revoked carries the reason and time the CRL gives. Never raises:
    a list the checks cannot read is an error for this certificate.
    """
    try:
        return _crl_lookup(crl, cert, url=url, names=names, now=now)
    except _UNREADABLE as exc:
        return crl_outcome("error", f"CRL cannot be read: {exc}", url=url)


def _crl_lookup(
    crl: x509.CertificateRevocationList,
    cert: x509.Certificate,
    *,
    url: str,
    names: frozenset[x509.GeneralName],
    now: datetime,
) -> dict[str, Any]:
    """:func:`crl_status` without the guard against unreadable lists."""
    next_update: datetime | None = crl.next_update_utc
    found = {"url": url, "next_update": _iso_z(next_update) if next_update else None}
    this_update: datetime = crl.last_update_utc
    if this_update - CRL_CLOCK_SKEW > now:
        return crl_outcome("error", f"CRL is not valid until {_iso_z(this_update)}", **found)
    if next_update is not None and next_update + CRL_CLOCK_SKEW < now:
        return crl_outcome(
            "error", f"CRL is stale (next update was {_iso_z(next_update)})", **found
        )
    problem = _crl_scope_problem(crl, cert, names)
    if problem is not None:
        return crl_outcome("error", problem, **found)
    try:
        entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        extensions = list(entry.extensions) if entry is not None else []
    except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
        return crl_outcome("error", "the CRL entry for this certificate cannot be parsed", **found)
    if entry is None:
        return crl_outcome("good", "certificate is not on the CRL", **found)
    reason: x509.ReasonFlags | None = None
    for extension in extensions:
        if isinstance(extension.value, x509.CRLReason):
            reason = extension.value.reason
        elif extension.critical and extension.oid not in _HANDLED_CRITICAL_ENTRY_EXTENSIONS:
            return crl_outcome(
                "error",
                "the CRL entry for this certificate has an unhandled critical extension",
                **found,
            )
    if reason == x509.ReasonFlags.remove_from_crl:
        return crl_outcome("good", "certificate was removed from the CRL", **found)
    detail = "certificate is revoked"
    if reason is not None:
        detail += f" (reason: {reason.name})"
    return crl_outcome(
        "revoked", detail, revocation_time=_iso_z(entry.revocation_date_utc), **found
    )


def evaluate_crl(
    crl: x509.CertificateRevocationList,
    cert: x509.Certificate,
    issuer: x509.Certificate,
    *,
    url: str,
    names: frozenset[x509.GeneralName],
    now: datetime,
) -> dict[str, Any]:
    """Judge ``cert`` against a downloaded ``crl``: good, revoked, or error.

    :func:`crl_signature_problem` and then :func:`crl_status`.
    """
    problem = crl_signature_problem(crl, issuer)
    if problem is not None:
        return crl_outcome("error", problem, url=url)
    return crl_status(crl, cert, url=url, names=names, now=now)
