# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``probe.tls``: endpoint parsing, certificate rules, and the handler end to end.

The PKI is generated here (a root, an intermediate, and leaves for each
case), served by local TLS servers on 127.0.0.1, with a local OCSP responder
answering for them and publishing the intermediate's CRL. Nothing leaves the
machine.
"""

from __future__ import annotations

import asyncio
import contextlib
import gzip
import ipaddress
import socket
import ssl
import threading
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
)
from httpx import _decoders

from hegemony_step_sdk import MAX_PARALLEL_DEVICES_LIMIT, HandlerContext, HandlerServices
from hegemony_step_sdk.docs import check_page, load_docs_bundle
from hegemony_steps_probe import tls_certs, tls_check
from hegemony_steps_probe.tls_certs import (
    EndpointSpec,
    dns_name_matches,
    evaluate_ocsp_response,
    hostname_matches,
    load_certificates_any,
    load_pem_certificates,
    normalize_fingerprint,
    parse_endpoint,
    split_endpoint_entries,
    verify_chain_offline,
)
from hegemony_steps_probe.tls_check import TlsProbeConfig, TlsProbeHandler

NOW = datetime.now(UTC)

SigningKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


# --- PKI ----------------------------------------------------------------------


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _san(value: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(value))
    except ValueError:
        return x509.DNSName(value)


def issue(
    common_name: str,
    key: SigningKey,
    *,
    issuer: x509.Certificate | None = None,
    issuer_key: SigningKey | None = None,
    ca: bool = False,
    path_length: int | None = None,
    sans: tuple[str, ...] = (),
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    ocsp_url: str | None = None,
    issuer_url: str | None = None,
    crl_url: str | None = None,
    eku: tuple[x509.ObjectIdentifier, ...] | None = (ExtendedKeyUsageOID.SERVER_AUTH,),
    basic_constraints: bool = True,
    extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    subject: x509.Name | None = None,
) -> x509.Certificate:
    """A certificate for ``key``, self-signed unless an issuer is given.

    ``extensions`` adds ``(extension, critical)`` pairs; ``subject`` replaces
    the plain common-name subject.
    """
    signer = issuer_key or key
    subject_name = subject if subject is not None else _name(common_name)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer.subject if issuer is not None else subject_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(days=1))
        .not_valid_after(not_after or NOW + timedelta(days=60))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True
        )
    if issuer is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            critical=False,
        )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([_san(value) for value in sans]), critical=False
        )
    if eku and not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
    access: list[x509.AccessDescription] = []
    if ocsp_url:
        access.append(
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(ocsp_url)
            )
        )
    if issuer_url:
        access.append(
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(issuer_url),
            )
        )
    if access:
        builder = builder.add_extension(x509.AuthorityInformationAccess(access), critical=False)
    if crl_url:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        [x509.UniformResourceIdentifier(crl_url)], None, None, None
                    )
                ]
            ),
            critical=False,
        )
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    algorithm = None if isinstance(signer, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(signer, algorithm)


def pem_of(*certs: x509.Certificate) -> str:
    return "".join(cert.public_bytes(serialization.Encoding.PEM).decode() for cert in certs)


def fingerprint_of(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


@dataclass
class _OcspEntry:
    cert: x509.Certificate
    issuer: x509.Certificate
    issuer_key: SigningKey
    status: ocsp.OCSPCertStatus
    revoked_at: datetime | None = None


@dataclass
class OcspResponder:
    """A local OCSP responder plus the caIssuers and CRL downloads it serves."""

    port: int
    entries: dict[int, _OcspEntry] = field(default_factory=dict)
    issuer_der: bytes = b""
    crl_der: bytes = b""
    requests: list[str] = field(default_factory=list)

    @property
    def crl_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/inter.crl"

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/ocsp"

    @property
    def issuer_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/issuer.der"

    def answer(self, body: bytes) -> bytes:
        request = ocsp.load_der_ocsp_request(body)
        entry = self.entries.get(request.serial_number)
        if entry is None:
            return ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.UNAUTHORIZED
            ).public_bytes(serialization.Encoding.DER)
        response = (
            ocsp.OCSPResponseBuilder()
            .add_response(
                cert=entry.cert,
                issuer=entry.issuer,
                algorithm=hashes.SHA1(),
                cert_status=entry.status,
                this_update=NOW - timedelta(hours=1),
                next_update=NOW + timedelta(days=1),
                revocation_time=entry.revoked_at,
                revocation_reason=(
                    x509.ReasonFlags.key_compromise if entry.revoked_at is not None else None
                ),
            )
            .responder_id(ocsp.OCSPResponderEncoding.HASH, entry.issuer)
            .sign(entry.issuer_key, hashes.SHA256())
        )
        return response.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="module")
def responder() -> Iterator[OcspResponder]:
    state = OcspResponder(port=0)

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            state.requests.append(f"POST {self.path}")
            payload = state.answer(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/ocsp-response")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            state.requests.append(f"GET {self.path}")
            downloads = {
                "/issuer.der": ("application/pkix-cert", state.issuer_der),
                "/inter.crl": ("application/pkix-crl", state.crl_der),
            }
            if self.path not in downloads:
                self.send_error(404)
                return
            content_type, body = downloads[self.path]
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    state.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


@dataclass
class Leaf:
    cert: x509.Certificate
    key: SigningKey
    chain: tuple[x509.Certificate, ...]


@dataclass
class Pki:
    root: x509.Certificate
    root_key: SigningKey
    inter: x509.Certificate
    inter_key: SigningKey
    leaves: dict[str, Leaf]

    @property
    def root_pem(self) -> str:
        return pem_of(self.root)


@pytest.fixture(scope="module")
def pki(responder: OcspResponder) -> Pki:
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = issue("Probe Test Root", root_key, ca=True, not_after=NOW + timedelta(days=3650))
    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter = issue(
        "Probe Test Intermediate",
        inter_key,
        issuer=root,
        issuer_key=root_key,
        ca=True,
        path_length=0,
        not_after=NOW + timedelta(days=1825),
    )
    responder.issuer_der = inter.public_bytes(serialization.Encoding.DER)
    leaves: dict[str, Leaf] = {}

    def leaf(
        name: str,
        key: SigningKey,
        *,
        status: ocsp.OCSPCertStatus | None = None,
        revoked_at: datetime | None = None,
        signed_by_root: bool = False,
        **kwargs: Any,
    ) -> None:
        issuer, issuer_key = (root, root_key) if signed_by_root else (inter, inter_key)
        cert = issue(f"{name}.example.test", key, issuer=issuer, issuer_key=issuer_key, **kwargs)
        leaves[name] = Leaf(cert, key, () if signed_by_root else (inter,))
        if status is not None:
            responder.entries[cert.serial_number] = _OcspEntry(
                cert, issuer, issuer_key, status, revoked_at
            )

    with_aia: dict[str, Any] = {"ocsp_url": responder.url, "issuer_url": responder.issuer_url}
    leaf(
        "rsa",
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        sans=("leaf.example.test", "127.0.0.1"),
        not_after=NOW + timedelta(days=41, hours=1),
        status=ocsp.OCSPCertStatus.GOOD,
        **with_aia,
    )
    leaf(
        "ec",
        ec.generate_private_key(ec.SECP384R1()),
        sans=("ec.example.test", "127.0.0.1"),
        not_after=NOW + timedelta(days=90, hours=1),
        status=ocsp.OCSPCertStatus.GOOD,
        **with_aia,
    )
    leaf(
        "expired",
        ec.generate_private_key(ec.SECP256R1()),
        sans=("leaf.example.test", "127.0.0.1"),
        not_before=NOW - timedelta(days=30),
        not_after=NOW - timedelta(days=2, hours=12),
    )
    leaf("wrong_host", ec.generate_private_key(ec.SECP256R1()), sans=("other.example.test",))
    leaf("wildcard", ec.generate_private_key(ec.SECP256R1()), sans=("*.example.test",))
    leaf(
        "revoked",
        ec.generate_private_key(ec.SECP256R1()),
        sans=("leaf.example.test", "127.0.0.1"),
        status=ocsp.OCSPCertStatus.REVOKED,
        revoked_at=(NOW - timedelta(days=1)).replace(microsecond=0),
        **with_aia,
    )
    leaf("no_aia", ec.generate_private_key(ec.SECP256R1()), sans=("127.0.0.1",))
    leaf(
        "direct",
        ec.generate_private_key(ec.SECP256R1()),
        sans=("127.0.0.1",),
        signed_by_root=True,
        status=ocsp.OCSPCertStatus.GOOD,
        ocsp_url=responder.url,
    )
    with_crl: dict[str, Any] = {"crl_url": responder.crl_url, "issuer_url": responder.issuer_url}
    leaf("crl_good", ec.generate_private_key(ec.SECP256R1()), sans=("127.0.0.1",), **with_crl)
    leaf("crl_revoked", ec.generate_private_key(ec.SECP256R1()), sans=("127.0.0.1",), **with_crl)
    responder.crl_der = make_crl(
        inter,
        inter_key,
        revoked={leaves["crl_revoked"].cert.serial_number: x509.ReasonFlags.key_compromise},
    ).public_bytes(serialization.Encoding.DER)
    return Pki(root, root_key, inter, inter_key, leaves)


#: When the test CRLs list a certificate as revoked.
CRL_REVOKED_AT = (NOW - timedelta(days=1)).replace(microsecond=0)


def make_crl(
    issuer: x509.Certificate,
    issuer_key: SigningKey,
    *,
    revoked: dict[int, x509.ReasonFlags | None] | None = None,
    this_update: datetime | None = None,
    next_update: datetime | None = None,
    issuer_name: x509.Name | None = None,
    extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    entry_extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
) -> x509.CertificateRevocationList:
    """A CRL ``issuer`` signs, listing ``revoked`` serial numbers with their reasons.

    ``entry_extensions`` are added to every entry; ``issuer_name`` replaces
    the issuer's subject as the CRL's issuer.
    """
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_name or issuer.subject)
        .last_update(this_update or NOW - timedelta(hours=1))
        .next_update(next_update or NOW + timedelta(days=7))
    )
    for serial, reason in (revoked or {}).items():
        entry = (
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(CRL_REVOKED_AT)
        )
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        for extension, critical in entry_extensions:
            entry = entry.add_extension(extension, critical=critical)
        builder = builder.add_revoked_certificate(entry.build())
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical=critical)
    algorithm = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(issuer_key, algorithm)


@contextlib.asynccontextmanager
async def tls_server(tmp_path: Path, leaf: Leaf, *, with_chain: bool = True) -> AsyncIterator[int]:
    """Serve ``leaf`` (and its chain) on 127.0.0.1; yields the port."""
    serial = format(leaf.cert.serial_number, "x")
    cert_file = tmp_path / f"{serial}-chain.pem"
    key_file = tmp_path / f"{serial}-key.pem"
    chain = leaf.chain if with_chain else ()
    cert_file.write_text(pem_of(leaf.cert, *chain))
    key_file.write_bytes(
        leaf.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            await reader.read()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), 2)


@contextlib.asynccontextmanager
async def alternating_tls_server(tmp_path: Path, first: Leaf, second: Leaf) -> AsyncIterator[int]:
    """Serve ``first`` and ``second`` to alternate handshakes (chosen by SNI); yields the port."""
    contexts = []
    for leaf in (first, second):
        serial = format(leaf.cert.serial_number, "x")
        cert_file, key_file = tmp_path / f"{serial}-alt.pem", tmp_path / f"{serial}-alt-key.pem"
        cert_file.write_text(pem_of(leaf.cert, *leaf.chain))
        key_file.write_bytes(
            leaf.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        contexts.append(context)
    handshakes = 0

    def choose(ssl_object: ssl.SSLObject, server_name: str | None, _: ssl.SSLContext) -> None:
        nonlocal handshakes
        ssl_object.context = contexts[handshakes % 2]
        handshakes += 1

    front = contexts[0]
    front.sni_callback = choose

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            await reader.read()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=front)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), 2)


@contextlib.asynccontextmanager
async def trickling_http_server(seconds: float) -> AsyncIterator[int]:
    """An HTTP server answering 200 with a 20-byte body sent one byte at a time over ``seconds``."""

    async def trickle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n")
            await writer.drain()
            for _ in range(20):
                await asyncio.sleep(seconds / 20)
                writer.write(b"x")
                await writer.drain()
        writer.close()

    server = await asyncio.start_server(trickle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), 2)


@dataclass
class FixedHttpServer:
    """A running :func:`fixed_http_server`: its port and each request's headers, lower-cased."""

    port: int
    requests: list[dict[str, str]] = field(default_factory=list)


@contextlib.asynccontextmanager
async def fixed_http_server(headers: dict[str, str], body: bytes) -> AsyncIterator[FixedHttpServer]:
    """An HTTP server answering every request 200 with ``headers`` and ``body``, whatever it asked."""
    state = FixedHttpServer(port=0)

    async def answer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            head = await reader.readuntil(b"\r\n\r\n")
            seen: dict[str, str] = {}
            for line in head.decode("latin-1").split("\r\n")[1:]:
                name, sep, value = line.partition(":")
                if sep:
                    seen[name.strip().lower()] = value.strip()
            state.requests.append(seen)
            await reader.readexactly(int(seen.get("content-length") or 0))
            extra = "".join(f"{name}: {value}\r\n" for name, value in headers.items())
            writer.write(
                f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n{extra}"
                "Connection: close\r\n\r\n".encode()
            )
            writer.write(body)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(answer, "127.0.0.1", 0)
    state.port = server.sockets[0].getsockname()[1]
    try:
        yield state
    finally:
        server.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(server.wait_closed(), 2)


def closed_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Denied(Exception):
    """Stands in for the host's egress-denial error."""


class FakeServices:
    """The two services ``probe.tls`` uses: the egress gate and secret resolution."""

    def __init__(
        self, *, secrets: dict[str, str] | None = None, deny: tuple[str, ...] = ()
    ) -> None:
        self.secrets = secrets or {}
        self.deny = deny
        self.egress: list[tuple[str, int | None, str | None, str]] = []
        self.secret_calls: list[tuple[str | None, str]] = []

    async def enforce_egress(
        self,
        host: str,
        port: int | None = None,
        *,
        proto: str | None = None,
        kind: str = "connection",
    ) -> None:
        self.egress.append((host, port, proto, kind))
        if host in self.deny:
            raise Denied(f"{kind} to {host} refused by the flow egress policy")

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        self.secret_calls.append((ref, source))
        return self.secrets.get(ref or "")


def make_ctx(
    config: dict[str, Any],
    *,
    devices: list[dict[str, Any]] | None = None,
    ips: list[str] | None = None,
    services: Any = None,
) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        target_roles=["edge"] if devices else [],
        target_devices_by_role={"edge": devices} if devices else {},
        step_target_ips=ips or [],
        services=cast(HandlerServices, services) if services is not None else None,
    )


async def run_step(config: dict[str, Any], **kwargs: Any):
    kwargs.setdefault("services", FakeServices())
    config = {"attempt_timeout_seconds": 5, **config}
    return await TlsProbeHandler().execute(make_ctx(config, **kwargs))


# --- Endpoint parsing ---------------------------------------------------------


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("portal.example.com", EndpointSpec("portal.example.com", 443)),
        ("portal.example.com:8443", EndpointSpec("portal.example.com", 8443)),
        (
            "192.0.2.10:8443:device.example.com",
            EndpointSpec("192.0.2.10", 8443, "device.example.com"),
        ),
        ("192.0.2.10::device.example.com", EndpointSpec("192.0.2.10", 443, "device.example.com")),
        ("  host.example:444:  ", EndpointSpec("host.example", 444)),
        ("[2001:db8::1]:443", EndpointSpec("2001:db8::1", 443)),
        ("[2001:db8::1]", EndpointSpec("2001:db8::1", 443)),
        ("[2001:db8::1]:8443:name.example", EndpointSpec("2001:db8::1", 8443, "name.example")),
        ("[::1]:10443", EndpointSpec("::1", 10443)),
    ],
)
def test_parse_endpoint_accepts_every_documented_form(entry, expected):
    assert parse_endpoint(entry, default_port=443) == expected


@pytest.mark.parametrize(
    ("entry", "fragment"),
    [
        ("2001:db8::1", "brackets"),
        ("2001:db8::1:443", "brackets"),
        ("[2001:db8::1", "unclosed"),
        ("[192.0.2.1]:443", "not an IPv6 address"),
        ("[2001:db8::1]443", "expected ':port'"),
        ("host.example:0", "outside 1-65535"),
        ("host.example:70000", "outside 1-65535"),
        ("host.example:https", "not a number"),
        ("https://host.example", "not a URL"),
        ("host.example:443:bad/name", "SNI"),
        (":443", "not a host name"),
    ],
)
def test_parse_endpoint_rejects_malformed_entries(entry, fragment):
    with pytest.raises(ValueError, match=fragment):
        parse_endpoint(entry, default_port=443)


def test_split_endpoint_entries_takes_newlines_commas_and_lists():
    assert split_endpoint_entries("a:1\nb:2, c:3,,\n\n  d  ") == ["a:1", "b:2", "c:3", "d"]
    assert split_endpoint_entries(["a:1", "b:2,c:3", "  ", "d\ne"]) == [
        "a:1",
        "b:2",
        "c:3",
        "d",
        "e",
    ]
    assert split_endpoint_entries(None) == []
    assert split_endpoint_entries("") == []
    with pytest.raises(ValueError, match="must be a string"):
        split_endpoint_entries(["a:1", 443])
    with pytest.raises(ValueError, match="list of strings"):
        split_endpoint_entries(443)


# --- Hostname matching --------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "host", "matches"),
    [
        ("www.example.com", "www.example.com", True),
        ("WWW.Example.COM", "www.example.com", True),
        ("www.example.com.", "www.example.com", True),
        ("www.example.com", "WWW.EXAMPLE.COM.", True),
        ("www.example.com", "example.com", False),
        ("*.example.com", "www.example.com", True),
        ("*.example.com", "WWW.example.com", True),
        ("*.example.com", "example.com", False),
        ("*.example.com", "a.b.example.com", False),
        ("*.example.com", ".example.com", False),
        ("*.com", "example.com", False),
        ("*", "localhost", False),
        ("w*.example.com", "www.example.com", False),
        ("*w.example.com", "www.example.com", False),
        ("www.*.example.com", "www.a.example.com", False),
        ("*.*.example.com", "a.b.example.com", False),
        ("*.example.com", "192.0.2.1", False),
        ("192.0.2.1", "192.0.2.1", False),
        ("xn--bcher-kva.example", "bücher.example", True),
        ("", "example.com", False),
    ],
)
def test_dns_name_matches_follows_rfc_6125(pattern, host, matches):
    assert dns_name_matches(pattern, host) is matches


@pytest.mark.parametrize(
    ("host", "dns_names", "ips", "cn", "matches"),
    [
        # IP hosts match IP SANs only, never DNS SANs.
        ("127.0.0.1", ["localhost"], ["127.0.0.1"], None, True),
        ("127.0.0.1", ["127.0.0.1"], [], None, False),
        ("2001:db8::1", [], ["2001:db8:0:0:0:0:0:1"], None, True),
        ("[2001:db8::1]", [], ["2001:db8::1"], None, True),
        ("192.0.2.2", [], ["192.0.2.1"], None, False),
        # Names match DNS SANs, wildcards included.
        ("www.example.com", ["*.example.com"], [], None, True),
        ("www.example.com", [], ["192.0.2.1"], "www.example.com", False),
        # CN only without any SAN.
        ("www.example.com", [], [], "www.example.com", True),
        ("www.example.com", [], [], "*.example.com", True),
        ("www.example.com", ["other.example.com"], [], "www.example.com", False),
        ("192.0.2.1", [], [], "192.0.2.1", True),
        ("192.0.2.1", ["x.example"], [], "192.0.2.1", False),
        ("www.example.com", [], [], None, False),
    ],
)
def test_hostname_matches_prefers_sans_and_keeps_ips_apart(host, dns_names, ips, cn, matches):
    assert hostname_matches(host, dns_names, ips, cn) is matches


# --- Fingerprints and loading -------------------------------------------------


def test_normalize_fingerprint_ignores_colons_case_and_labels():
    plain = "ab" * 32
    colon = ":".join(["AB"] * 32)
    assert normalize_fingerprint(plain) == plain
    assert normalize_fingerprint(colon) == plain
    assert normalize_fingerprint(f"SHA256 Fingerprint={colon}") == plain
    assert normalize_fingerprint(f"sha256:{plain}") == plain
    assert normalize_fingerprint(f"  {plain[:32]} {plain[32:]}\n") == plain
    for bad in ("", "ab" * 31, "zz" * 32, "ab" * 33):
        with pytest.raises(ValueError, match="SHA-256"):
            normalize_fingerprint(bad)


def test_load_pem_certificates_skips_surrounding_text(pki):
    text = "Leaf:\n" + pem_of(pki.leaves["rsa"].cert) + "\nIntermediate:\n" + pem_of(pki.inter)
    certs = load_pem_certificates(text)
    assert [cert.subject for cert in certs] == [pki.leaves["rsa"].cert.subject, pki.inter.subject]
    assert load_pem_certificates("no certificates here") == []
    broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
    with pytest.raises(ValueError, match="#1"):
        load_pem_certificates(broken)


def test_load_pem_certificates_accepts_every_layout_the_parser_reads(pki):
    pem = pem_of(pki.inter)
    begin, _, rest = pem.partition("\n")
    layouts = {
        "str": pem,
        "crlf": pem.replace("\n", "\r\n"),
        "header": f"{begin}\nProc-Type: 4,CLEAR\n\n{rest}",
        "one line": "".join(pem.splitlines()),
        "after an unclosed block": "-----BEGIN CERTIFICATE-----\nAAAA\n" + pem,
    }
    for name, text in layouts.items():
        assert load_pem_certificates(text) == [pki.inter], name
        assert load_pem_certificates(text.encode()) == [pki.inter], name


def test_loading_pem_text_takes_linear_time_on_unclosed_blocks():
    """An unclosed BEGIN line must not make the parser rescan the rest of the text."""
    begins = "-----BEGIN CERTIFICATE-----\n" * (1024 * 1024 // 28)
    unclosed_bodies = ("-----BEGIN CERTIFICATE-----\n" + "QUFB" * 64 + "\n") * 3800
    for text in (begins, unclosed_bodies):
        assert len(text) > 1000 * 1024
        started = time.perf_counter()
        assert load_pem_certificates(text) == []
        assert load_pem_certificates(text.encode()) == []
        assert load_certificates_any(text.encode()) == []
        assert TlsProbeHandler().validate_config({"pem": text}) == ["pem: no PEM certificate found"]
        assert time.perf_counter() - started < 1.0


def test_load_certificates_any_reads_der_pem_and_pkcs7(pki):
    der = pki.inter.public_bytes(serialization.Encoding.DER)
    assert load_certificates_any(der) == [pki.inter]
    assert load_certificates_any(pem_of(pki.inter).encode()) == [pki.inter]
    bundle = pkcs7.serialize_certificates([pki.inter, pki.root], serialization.Encoding.DER)
    # A PKCS#7 bundle is a DER SET: the order is the encoding's, not ours.
    assert set(load_certificates_any(bundle)) == {pki.inter, pki.root}
    assert load_certificates_any(b"garbage") == []


def test_certificate_fields_describe_the_leaf(pki):
    cert = pki.leaves["ec"].cert
    fields = tls_certs.certificate_fields(cert, now=NOW)
    assert fields["subject_cn"] == "ec.example.test"
    assert fields["sans"] == ["ec.example.test", "127.0.0.1"]
    assert fields["issuer_cn"] == "Probe Test Intermediate"
    assert fields["issuer"] == "CN=Probe Test Intermediate"
    assert fields["serial"] == format(cert.serial_number, "x")
    assert fields["fingerprint_sha256"] == fingerprint_of(cert)
    assert fields["not_after"].endswith("Z") and "T" in fields["not_after"]
    assert fields["days_left"] == 90
    assert fields["expired"] is False
    assert (fields["key_type"], fields["key_bits"], fields["key_curve"]) == ("ec", 384, "secp384r1")
    assert fields["signature_algorithm"] == "sha256WithRSAEncryption"
    assert fields["is_ca"] is False
    assert tls_certs.certificate_fields(pki.root, now=NOW)["is_ca"] is True


def test_days_left_floors_and_goes_negative(pki):
    expired = pki.leaves["expired"].cert
    assert tls_certs.days_left(expired, NOW) == -3
    assert tls_certs.days_left(pki.leaves["rsa"].cert, NOW) == 41


# --- Offline chain validation -------------------------------------------------


def test_offline_chain_ok_with_intermediate_and_root(pki):
    leaf = pki.leaves["rsa"].cert
    assert verify_chain_offline(leaf, [pki.inter], [pki.root], now=NOW) == (True, None)


def test_offline_chain_missing_intermediate(pki):
    leaf = pki.leaves["rsa"].cert
    assert verify_chain_offline(leaf, [], [pki.root], now=NOW) == (
        False,
        "unable to get local issuer certificate",
    )


def test_offline_chain_untrusted_root(pki):
    other_key = ec.generate_private_key(ec.SECP256R1())
    other_root = issue("Other Root", other_key, ca=True)
    ok, error = verify_chain_offline(
        pki.leaves["rsa"].cert, [pki.inter, pki.root], [other_root], now=NOW
    )
    assert ok is False
    assert error == "self-signed certificate in certificate chain"


def test_offline_chain_expired_leaf(pki):
    ok, error = verify_chain_offline(pki.leaves["expired"].cert, [pki.inter], [pki.root], now=NOW)
    assert (ok, error) == (False, "certificate has expired")


def test_offline_chain_trusts_a_pinned_self_signed_leaf_and_an_intermediate_anchor(pki):
    key = ec.generate_private_key(ec.SECP256R1())
    self_signed = issue("device.example.test", key, sans=("device.example.test",))
    assert verify_chain_offline(self_signed, [], [self_signed], now=NOW) == (True, None)
    assert verify_chain_offline(self_signed, [], [pki.root], now=NOW) == (
        False,
        "self-signed certificate",
    )
    # Every anchor is trusted as given, an intermediate included.
    assert verify_chain_offline(pki.leaves["rsa"].cert, [], [pki.inter], now=NOW) == (True, None)


def test_offline_chain_refuses_a_non_ca_issuer_and_path_length(pki):
    not_ca_key = ec.generate_private_key(ec.SECP256R1())
    not_ca = issue("Not A CA", not_ca_key, issuer=pki.root, issuer_key=pki.root_key, eku=None)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = issue("x.example.test", leaf_key, issuer=not_ca, issuer_key=not_ca_key)
    assert verify_chain_offline(leaf, [not_ca], [pki.root], now=NOW) == (
        False,
        "invalid CA certificate",
    )
    # The intermediate allows no further CA below it (pathlen 0).
    sub_key = ec.generate_private_key(ec.SECP256R1())
    sub = issue("Sub CA", sub_key, issuer=pki.inter, issuer_key=pki.inter_key, ca=True)
    deep = issue("deep.example.test", leaf_key, issuer=sub, issuer_key=sub_key)
    assert verify_chain_offline(deep, [sub, pki.inter], [pki.root], now=NOW) == (
        False,
        "path length constraint exceeded",
    )


def test_offline_chain_checks_the_leaf_purpose(pki):
    key = ec.generate_private_key(ec.SECP256R1())
    client_only = issue(
        "client.example.test",
        key,
        issuer=pki.inter,
        issuer_key=pki.inter_key,
        eku=(ExtendedKeyUsageOID.CLIENT_AUTH,),
    )
    assert verify_chain_offline(client_only, [pki.inter], [pki.root], now=NOW) == (
        False,
        "unsuitable certificate purpose",
    )


def _cross_signed(count: int) -> tuple[x509.Certificate, list[x509.Certificate]]:
    """A leaf under ``count`` CAs named A and ``count`` named B that each issue the other.

    Every A certificate is signed with B's key and every B certificate with
    A's, so the untrusted certificates chain in every possible order.
    """
    a_key = ec.generate_private_key(ec.SECP256R1())
    b_key = ec.generate_private_key(ec.SECP256R1())
    b_name = issue("Cross B", b_key, ca=True)
    a_certs = [
        issue("Cross A", a_key, issuer=b_name, issuer_key=b_key, ca=True) for _ in range(count)
    ]
    b_certs = [
        issue("Cross B", b_key, issuer=a_certs[0], issuer_key=a_key, ca=True) for _ in range(count)
    ]
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = issue("leaf.example.test", leaf_key, issuer=a_certs[0], issuer_key=a_key)
    return leaf, a_certs + b_certs


def test_offline_chain_stops_at_a_self_signed_untrusted_certificate(pki):
    """Copies of one self-signed CA verify each other; no ordering of them is tried."""
    key = ec.generate_private_key(ec.SECP256R1())
    copies = [issue("Loop CA", key, ca=True) for _ in range(12)]
    leaf = issue(
        "leaf.example.test",
        ec.generate_private_key(ec.SECP256R1()),
        issuer=copies[0],
        issuer_key=key,
    )
    started = time.perf_counter()
    assert verify_chain_offline(leaf, copies, [pki.root], now=NOW) == (
        False,
        "self-signed certificate in certificate chain",
    )
    assert time.perf_counter() - started < 1.0


def test_offline_chain_search_remembers_what_cannot_succeed(pki, monkeypatch):
    # Without remembering failed searches this takes over 2000 signature checks.
    monkeypatch.setattr(tls_certs, "MAX_CHAIN_SIGNATURE_CHECKS", 1000)
    leaf, cross = _cross_signed(4)
    assert verify_chain_offline(leaf, cross, [pki.root], now=NOW) == (
        False,
        "unable to get local issuer certificate",
    )


async def test_offline_chain_search_gives_up_after_its_signature_checks(pki):
    leaf, cross = _cross_signed(9)
    assert len(cross) + 1 <= tls_certs.MAX_PEM_CERTIFICATES
    reason = (
        "the certificates offer too many issuer paths to check "
        f"(stopped after {tls_certs.MAX_CHAIN_SIGNATURE_CHECKS} signature checks)"
    )
    started = time.perf_counter()
    assert verify_chain_offline(leaf, cross, [pki.root], now=NOW) == (None, reason)
    assert time.perf_counter() - started < 2.0

    result = await run_step(
        {"pem": pem_of(leaf, *cross), "ca_bundle": pki.root_pem, "require_valid_chain": True}
    )
    [record] = result.output["endpoints"]
    assert (record["chain_ok"], record["chain_error"]) == (None, reason)
    assert result.success is False
    assert f"chain not verified: {reason}" in (result.error or "")


async def test_a_pasted_chain_is_checked_off_the_event_loop(pki, monkeypatch):
    real_verify = tls_certs.verify_chain_offline
    threads: list[threading.Thread] = []

    def verify(*args: Any, **kwargs: Any) -> tuple[bool | None, str | None]:
        threads.append(threading.current_thread())
        return real_verify(*args, **kwargs)

    monkeypatch.setattr(tls_certs, "verify_chain_offline", verify)
    result = await run_step(
        {"pem": pem_of(pki.leaves["rsa"].cert, pki.inter), "ca_bundle": pki.root_pem}
    )
    assert result.output["endpoints"][0]["chain_ok"] is True
    assert threads and threading.main_thread() not in threads


async def test_a_pasted_chain_holds_at_most_twenty_certificates(pki):
    too_many = pem_of(*([pki.leaves["rsa"].cert] + [pki.inter] * 20))
    assert TlsProbeHandler().validate_config({"pem": too_many}) == [
        "pem: at most 20 certificates are allowed"
    ]
    assert TlsProbeHandler().validate_config({"pem": pem_of(pki.inter)}) == []
    refused = await run_step({"pem": too_many})
    assert refused.error == "Invalid probe.tls config: pem: at most 20 certificates are allowed"
    # Text the editor cannot check (it still looks like a template) is checked at run time.
    unchecked = await run_step({"pem": too_many + "\n# {{ placeholder }}\n"})
    assert unchecked.error == "Invalid certificate PEM: 21 certificates (at most 20)"


# --- OCSP response evaluation -------------------------------------------------


def _ocsp_response(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    signer: x509.Certificate,
    signer_key: SigningKey,
    *,
    status: ocsp.OCSPCertStatus = ocsp.OCSPCertStatus.GOOD,
    next_update: datetime | None = None,
    certificates: list[x509.Certificate] | None = None,
) -> bytes:
    builder = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert,
            issuer=issuer,
            algorithm=hashes.SHA256(),
            cert_status=status,
            this_update=NOW - timedelta(hours=2),
            next_update=next_update or NOW + timedelta(days=1),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, signer)
    )
    if certificates:
        builder = builder.certificates(certificates)
    algorithm = None if isinstance(signer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(signer_key, algorithm).public_bytes(serialization.Encoding.DER)


def test_ocsp_response_signed_by_the_issuer_or_a_delegate(pki):
    leaf = pki.leaves["rsa"].cert
    good = _ocsp_response(leaf, pki.inter, pki.inter, pki.inter_key)
    assert evaluate_ocsp_response(good, leaf, pki.inter, now=NOW)["ocsp"] == "good"
    unknown = _ocsp_response(
        leaf, pki.inter, pki.inter, pki.inter_key, status=ocsp.OCSPCertStatus.UNKNOWN
    )
    assert evaluate_ocsp_response(unknown, leaf, pki.inter, now=NOW)["ocsp"] == "unknown"

    delegate_key = ed25519.Ed25519PrivateKey.generate()
    delegate = issue(
        "OCSP Signer",
        delegate_key,
        issuer=pki.inter,
        issuer_key=pki.inter_key,
        eku=(ExtendedKeyUsageOID.OCSP_SIGNING,),
    )
    delegated = _ocsp_response(leaf, pki.inter, delegate, delegate_key, certificates=[delegate])
    assert evaluate_ocsp_response(delegated, leaf, pki.inter, now=NOW)["ocsp"] == "good"


def test_ocsp_response_problems_are_errors(pki):
    leaf = pki.leaves["rsa"].cert
    stranger_key = ec.generate_private_key(ec.SECP256R1())
    stranger = issue("Stranger", stranger_key, eku=(ExtendedKeyUsageOID.OCSP_SIGNING,))
    forged = _ocsp_response(leaf, pki.inter, stranger, stranger_key, certificates=[stranger])
    outcome = evaluate_ocsp_response(forged, leaf, pki.inter, now=NOW)
    assert outcome["ocsp"] == "error"
    assert "not signed by the issuer" in outcome["ocsp_detail"]

    stale = _ocsp_response(
        leaf, pki.inter, pki.inter, pki.inter_key, next_update=NOW - timedelta(hours=1)
    )
    outcome = evaluate_ocsp_response(stale, leaf, pki.inter, now=NOW)
    assert (outcome["ocsp"], "stale" in outcome["ocsp_detail"]) == ("error", True)

    other = _ocsp_response(pki.leaves["ec"].cert, pki.inter, pki.inter, pki.inter_key)
    outcome = evaluate_ocsp_response(other, leaf, pki.inter, now=NOW)
    assert outcome["ocsp_detail"] == "response does not cover this certificate"

    refused = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.TRY_LATER
    ).public_bytes(serialization.Encoding.DER)
    outcome = evaluate_ocsp_response(refused, leaf, pki.inter, now=NOW)
    assert outcome == {
        "ocsp": "error",
        "ocsp_detail": "responder answered try_later",
        "revocation_time": None,
    }
    assert evaluate_ocsp_response(b"junk", leaf, pki.inter, now=NOW)["ocsp"] == "error"


# --- The handler: sources ----------------------------------------------------


async def test_device_target_reports_the_served_certificate(pki, tmp_path):
    leaf = pki.leaves["rsa"]
    async with tls_server(tmp_path, leaf) as port:
        result = await run_step(
            {"port": port, "ca_bundle": pki.root_pem},
            devices=[{"id": "d1", "name": "edge1", "mgmt_host": "127.0.0.1"}],
        )
    assert result.success is True, result.error
    output = result.output
    assert set(output) == {"endpoints", "summary", "all_ok", "min_days_left"}
    assert output["all_ok"] is True
    assert output["min_days_left"] == 41
    [record] = output["endpoints"]
    assert record["source"] == "target"
    assert (record["host"], record["port"], record["sni"]) == ("127.0.0.1", port, None)
    assert (record["device_id"], record["device_name"]) == ("d1", "edge1")
    assert record["reachable"] is True and record["error"] is None
    assert record["tls_version"].startswith("TLS")
    assert record["cipher"]
    assert (record["chain_ok"], record["chain_error"]) == (True, None)
    assert record["hostname_ok"] is True  # IP SAN 127.0.0.1
    assert record["matches_expected"] is None
    assert record["ocsp"] is None
    assert record["crl"] is None and record["crl_url"] is None
    assert record["subject_cn"] == "rsa.example.test"
    assert record["sans"] == ["leaf.example.test", "127.0.0.1"]
    assert record["issuer_cn"] == "Probe Test Intermediate"
    assert record["fingerprint_sha256"] == fingerprint_of(leaf.cert)
    assert record["serial"] == format(leaf.cert.serial_number, "x")
    assert (record["key_type"], record["key_bits"], record["key_curve"]) == ("rsa", 2048, None)
    assert record["days_left"] == 41 and record["expired"] is False
    assert "certificate_pem" not in record
    assert record["ok"] is True and record["failures"] == []

    assert output["summary"] == {
        "total": 1,
        "reachable": 1,
        "unreachable": 0,
        "expired": 0,
        "chain_failures": 0,
        "hostname_failures": 0,
        "mismatches": 0,
        "ocsp_revoked": 0,
        "crl_revoked": 0,
        "failed": 0,
        "warn_30": 0,
        "warn_14": 0,
        "warn_7": 0,
        "min_days_left": 41,
    }
    assert result.summary == "tls: 1 endpoint, 1 reachable, min 41 days left"
    assert result.metrics == {"endpoints": 1, "unreachable": 0, "min_days_left": 41}
    [evidence] = result.evidence
    assert evidence["kind"] == "transport_meta"
    assert evidence["name"] == f"tls_127.0.0.1_{port}"
    assert evidence["device_id"] == "d1"
    assert evidence["content_json"]["fingerprint_sha256"] == record["fingerprint_sha256"]


@pytest.mark.parametrize("form", ["newlines", "commas", "list"])
async def test_endpoints_string_and_list_forms(pki, tmp_path, form):
    async with (
        tls_server(tmp_path, pki.leaves["rsa"]) as first,
        tls_server(tmp_path, pki.leaves["ec"]) as second,
    ):
        entries = [f"127.0.0.1:{first}:leaf.example.test", f"127.0.0.1:{second}"]
        endpoints: Any = {
            "newlines": "\n".join(entries) + "\n\n",
            "commas": ", ".join(entries),
            "list": entries,
        }[form]
        result = await run_step({"endpoints": endpoints, "ca_bundle": pki.root_pem})
    assert result.success is True, result.error
    records = result.output["endpoints"]
    assert [(r["source"], r["port"], r["sni"]) for r in records] == [
        ("endpoint", first, "leaf.example.test"),
        ("endpoint", second, None),
    ]
    assert [r["hostname_ok"] for r in records] == [True, True]
    assert [r["subject_cn"] for r in records] == ["rsa.example.test", "ec.example.test"]
    assert result.summary == "tls: 2 endpoints, 2 reachable, min 41 days left"
    assert [e["device_id"] for e in result.evidence] == [None, None]


async def test_evidence_names_tell_server_names_apart(pki, tmp_path):
    async with tls_server(tmp_path, pki.leaves["wildcard"]) as port:
        result = await run_step(
            {
                "endpoints": [
                    f"127.0.0.1:{port}:a.example.test",
                    f"127.0.0.1:{port}:b.example.test",
                    f"127.0.0.1:{port}",
                ]
            }
        )
    assert [evidence["name"] for evidence in result.evidence] == [
        f"tls_127.0.0.1_{port}_a.example.test",
        f"tls_127.0.0.1_{port}_b.example.test",
        f"tls_127.0.0.1_{port}",
    ]


async def test_targets_and_endpoints_combine_without_duplicates(pki, tmp_path):
    async with tls_server(tmp_path, pki.leaves["rsa"]) as port:
        result = await run_step(
            {"port": port, "endpoints": [f"127.0.0.1:{port}"], "ca_bundle": pki.root_pem},
            ips=["127.0.0.1"],
        )
    assert result.success is True, result.error
    assert [r["source"] for r in result.output["endpoints"]] == ["target"]


async def test_pem_mode_never_connects(pki, monkeypatch):
    async def no_dial(*args, **kwargs):
        raise AssertionError("pem mode must not connect")

    monkeypatch.setattr(tls_check, "tls_handshake", no_dial)
    leaf = pki.leaves["rsa"].cert
    # No services bound: a pasted certificate needs neither the network nor secrets.
    result = await TlsProbeHandler().execute(
        make_ctx(
            {
                "pem": pem_of(leaf, pki.inter),
                "ca_bundle": pki.root_pem,
                "sni": "leaf.example.test",
                "include_pem": True,
            }
        )
    )
    assert result.success is True, result.error
    [record] = result.output["endpoints"]
    assert record["source"] == "pem"
    assert (record["host"], record["port"], record["sni"]) == (None, None, "leaf.example.test")
    assert record["reachable"] is None and record["tls_version"] is None
    assert (record["chain_ok"], record["hostname_ok"]) == (True, True)
    assert record["certificate_pem"] == pem_of(leaf)
    assert result.summary == "tls: pem certificate, min 41 days left"
    assert result.evidence[0]["name"] == "tls_pem"
    assert result.output["summary"]["reachable"] == 0


async def test_pem_mode_chain_failures(pki, monkeypatch):
    leaf = pki.leaves["rsa"].cert
    # Missing intermediate.
    result = await run_step({"pem": pem_of(leaf), "ca_bundle": pki.root_pem})
    [record] = result.output["endpoints"]
    assert (record["chain_ok"], record["chain_error"]) == (
        False,
        "unable to get local issuer certificate",
    )
    assert result.success is True  # chain validity is not required by default

    # No CA bundle: the worker's trust store, which does not know the test root.
    unrelated = issue("Unrelated Root", ec.generate_private_key(ec.SECP256R1()), ca=True)
    monkeypatch.setattr(tls_certs, "load_system_anchors", lambda: [unrelated])
    result = await run_step({"pem": pem_of(leaf, pki.inter), "require_valid_chain": True})
    assert result.success is False
    [record] = result.output["endpoints"]
    assert record["chain_ok"] is False
    assert "chain not valid" in (result.error or "")

    # No loadable trust store at all: unknown, explained.
    monkeypatch.setattr(tls_certs, "load_system_anchors", lambda: [])
    result = await run_step({"pem": pem_of(leaf, pki.inter), "require_valid_chain": True})
    [record] = result.output["endpoints"]
    assert record["chain_ok"] is None
    assert "set a CA bundle" in record["chain_error"]
    assert "chain not verified" in (result.error or "")


# --- The handler: chain, host name, expiry, fingerprints ----------------------


async def test_live_chain_without_ca_bundle_and_missing_intermediate(pki, tmp_path):
    leaf = pki.leaves["rsa"]
    async with tls_server(tmp_path, leaf) as port:
        system = await run_step({"endpoints": f"127.0.0.1:{port}"})
    [record] = system.output["endpoints"]
    assert record["chain_ok"] is False
    assert "unable to get local issuer certificate" in record["chain_error"]
    assert system.success is True
    assert system.output["summary"]["chain_failures"] == 1

    async with tls_server(tmp_path, leaf, with_chain=False) as port:
        missing = await run_step({"endpoints": f"127.0.0.1:{port}", "ca_bundle": pki.root_pem})
    [record] = missing.output["endpoints"]
    assert record["chain_ok"] is False
    assert "unable to get local issuer certificate" in record["chain_error"]


async def test_a_chain_verdict_for_another_certificate_is_not_reported(pki, tmp_path):
    """A server that presents a self-signed certificate to the first handshake and a valid
    one to the second must not have the self-signed one reported as verified."""
    key = ec.generate_private_key(ec.SECP256R1())
    rogue = Leaf(issue("leaf.example.test", key, sans=("leaf.example.test",)), key, ())
    async with alternating_tls_server(tmp_path, rogue, pki.leaves["rsa"]) as port:
        result = await run_step(
            {
                "endpoints": f"127.0.0.1:{port}:leaf.example.test",
                "ca_bundle": pki.root_pem,
                "require_valid_chain": True,
            }
        )
    [record] = result.output["endpoints"]
    assert record["fingerprint_sha256"] == fingerprint_of(rogue.cert)
    assert record["chain_ok"] is None
    assert "presented a different certificate to the verifying handshake" in record["chain_error"]
    assert result.success is False
    assert "chain not verified: the server presented a different certificate" in (
        result.error or ""
    )


async def test_wildcard_and_wrong_host_name(pki, tmp_path):
    async with (
        tls_server(tmp_path, pki.leaves["wildcard"]) as wildcard,
        tls_server(tmp_path, pki.leaves["wrong_host"]) as wrong,
    ):
        result = await run_step(
            {
                "endpoints": [
                    f"127.0.0.1:{wildcard}:www.example.test",
                    f"127.0.0.1:{wildcard}:example.test",
                    f"127.0.0.1:{wrong}:leaf.example.test",
                ],
                "require_hostname_match": True,
                "ca_bundle": pki.root_pem,
            }
        )
    records = result.output["endpoints"]
    assert [r["hostname_ok"] for r in records] == [True, False, False]
    assert [r["chain_ok"] for r in records] == [True, True, True]
    assert result.success is False
    assert result.output["summary"]["hostname_failures"] == 2
    assert "certificate is not valid for example.test" in (result.error or "")
    assert "certificate is not valid for leaf.example.test" in (result.error or "")


async def test_expired_certificate(pki, tmp_path):
    async with tls_server(tmp_path, pki.leaves["expired"]) as port:
        relaxed = await run_step({"endpoints": f"127.0.0.1:{port}"})
        strict = await run_step({"endpoints": f"127.0.0.1:{port}", "min_days_left": 0})
    [record] = relaxed.output["endpoints"]
    assert (record["days_left"], record["expired"]) == (-3, True)
    assert relaxed.success is True
    summary = relaxed.output["summary"]
    assert (summary["expired"], summary["warn_30"], summary["warn_7"]) == (1, 1, 1)
    assert relaxed.metrics["min_days_left"] == -3
    assert strict.success is False
    assert f"expired on {record['not_after']}" in (strict.error or "")


async def test_expected_fingerprints_normalise_and_override(pki, tmp_path):
    rsa_fp = fingerprint_of(pki.leaves["rsa"].cert)
    colon_upper = ":".join(rsa_fp[i : i + 2] for i in range(0, 64, 2)).upper()
    async with (
        tls_server(tmp_path, pki.leaves["rsa"]) as first,
        tls_server(tmp_path, pki.leaves["ec"]) as second,
    ):
        endpoints = [f"127.0.0.1:{first}", f"127.0.0.1:{second}"]
        everywhere = await run_step({"endpoints": endpoints, "expected_fingerprint": colon_upper})
        per_endpoint = await run_step(
            {
                "endpoints": endpoints,
                "expected_fingerprint": colon_upper,
                "expected_fingerprints": {
                    f"127.0.0.1:{second}": fingerprint_of(pki.leaves["ec"].cert).upper()
                },
            }
        )
    assert [r["matches_expected"] for r in everywhere.output["endpoints"]] == [True, False]
    assert everywhere.success is False
    assert everywhere.output["summary"]["mismatches"] == 1
    assert f"127.0.0.1:{second} (fingerprint does not match" in (everywhere.error or "")
    assert [r["matches_expected"] for r in per_endpoint.output["endpoints"]] == [True, True]
    assert per_endpoint.success is True, per_endpoint.error


@pytest.mark.parametrize(
    ("leaf_name", "config", "reason"),
    [
        ("rsa", {"min_days_left": 60}, "41 days left (minimum 60)"),
        ("rsa", {"require_valid_chain": True, "ca_bundle": ""}, "chain not valid"),
        ("rsa", {"require_hostname_match": True, "sni": "nope.example.test"}, "not valid for"),
        ("rsa", {"expected_fingerprint": "00" * 32}, "fingerprint does not match"),
        ("revoked", {"check_ocsp": True, "require_ocsp_good": True}, "OCSP revoked"),
    ],
    ids=["min-days", "chain", "hostname", "fingerprint", "ocsp"],
)
async def test_each_assertion_fails_the_step_with_output_populated(
    pki, tmp_path, leaf_name, config, reason
):
    leaf = pki.leaves[leaf_name]
    async with tls_server(tmp_path, leaf) as port:
        result = await run_step(
            {"port": port, "ca_bundle": pki.root_pem, **config}, ips=["127.0.0.1"]
        )
    assert result.success is False
    assert reason in (result.error or "")
    assert result.error.startswith("TLS check failed for 1 of 1 endpoint: 127.0.0.1:")
    output = result.output
    assert output["all_ok"] is False
    [record] = output["endpoints"]
    assert record["ok"] is False and record["failures"]
    assert record["fingerprint_sha256"] == fingerprint_of(leaf.cert)
    assert record["reachable"] is True
    assert output["summary"]["failed"] == 1
    assert result.summary.endswith(", 1 failing")
    assert len(result.evidence) == 1


# --- The handler: reachability, egress, secrets, parallelism ------------------


async def test_unreachable_endpoint_follows_require_reachable():
    port = closed_port()
    strict = await run_step({"endpoints": f"127.0.0.1:{port}"})
    assert strict.success is False
    assert f"127.0.0.1:{port} (unreachable: connection refused)" in (strict.error or "")
    [record] = strict.output["endpoints"]
    assert (record["reachable"], record["error"]) == (False, "connection refused")
    assert record["fingerprint_sha256"] is None and "days_left" in record

    relaxed = await run_step(
        {"endpoints": f"127.0.0.1:{port}", "require_reachable": False, "min_days_left": 30}
    )
    assert relaxed.success is True, relaxed.error
    assert relaxed.output["all_ok"] is True
    assert relaxed.output["summary"]["unreachable"] == 1
    assert relaxed.output["min_days_left"] is None
    assert relaxed.summary == "tls: 1 endpoint, 0 reachable"
    assert relaxed.metrics == {"endpoints": 1, "unreachable": 1}


async def test_a_target_without_an_address_always_fails():
    result = await run_step({"require_reachable": False}, devices=[{"id": "d9", "name": "ghost"}])
    assert result.success is False
    assert "ghost (target has no management address)" in (result.error or "")


async def test_egress_denial_is_the_step_error(pki, tmp_path):
    services = FakeServices(deny=("127.0.0.1",))
    async with tls_server(tmp_path, pki.leaves["rsa"]) as port:
        with pytest.raises(Denied, match="tls probe"):
            await run_step({"endpoints": f"127.0.0.1:{port}"}, services=services)
    assert services.egress == [("127.0.0.1", port, "tcp", "tls probe")]


async def test_ca_bundle_as_a_bare_secret_reference(pki, tmp_path):
    reference = "vault://orgs/acme/secrets/tls/internal-ca"
    template = "{{ secret('" + reference + "') }}"
    services = FakeServices(secrets={template: pki.root_pem})
    async with tls_server(tmp_path, pki.leaves["rsa"]) as port:
        result = await run_step(
            {"endpoints": f"127.0.0.1:{port}", "ca_bundle": reference, "require_valid_chain": True},
            services=services,
        )
        templated = await run_step(
            {"endpoints": f"127.0.0.1:{port}", "ca_bundle": template, "require_valid_chain": True},
            services=services,
        )
    assert result.success is True, result.error
    assert templated.success is True, templated.error
    assert services.secret_calls == [
        (template, "probe.tls.ca_bundle"),
        (template, "probe.tls.ca_bundle"),
    ]
    assert "ca_bundle" in TlsProbeHandler.raw_config_keys

    empty = await run_step(
        {"endpoints": "127.0.0.1:1", "ca_bundle": "vault://orgs/acme/missing"},
        services=FakeServices(),
    )
    assert empty.success is False
    assert "resolved to an empty value" in (empty.error or "")


async def test_parallelism_is_bounded_and_results_keep_their_order(monkeypatch):
    active = 0
    peak = 0

    async def fake_handshake(host, port, server_name, context, timeout):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.02)
        finally:
            active -= 1
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(tls_check, "tls_handshake", fake_handshake)
    endpoints = [f"192.0.2.{index}:443" for index in range(1, 13)]
    result = await run_step(
        {"endpoints": endpoints, "max_parallel_devices": 3, "require_reachable": False}
    )
    assert peak == 3
    assert [r["host"] for r in result.output["endpoints"]] == [
        f"192.0.2.{index}" for index in range(1, 13)
    ]
    assert result.output["summary"]["unreachable"] == 12


# --- The handler: OCSP --------------------------------------------------------


async def test_ocsp_good_through_the_issuer_download(pki, tmp_path, responder):
    services = FakeServices()
    async with tls_server(tmp_path, pki.leaves["rsa"]) as port:
        result = await run_step(
            {
                "endpoints": f"127.0.0.1:{port}",
                "ca_bundle": pki.root_pem,
                "check_ocsp": True,
                "require_ocsp_good": True,
            },
            services=services,
        )
    assert result.success is True, result.error
    [record] = result.output["endpoints"]
    assert record["ocsp"] == "good"
    assert record["revocation_time"] is None
    gated = [entry for entry in services.egress if entry[3] == "ocsp check"]
    assert gated and all(entry[:3] == ("127.0.0.1", responder.port, "tcp") for entry in gated)


async def test_a_downloaded_issuer_is_parsed_off_the_event_loop(pki, responder, monkeypatch):
    real_load = tls_certs.load_certificates_any
    threads: list[threading.Thread] = []

    def load(data: bytes) -> list[x509.Certificate]:
        threads.append(threading.current_thread())
        return real_load(data)

    monkeypatch.setattr(tls_certs, "load_certificates_any", load)
    result = await run_step(
        {"pem": pem_of(pki.leaves["rsa"].cert), "ca_bundle": pki.root_pem, "check_ocsp": True}
    )
    [record] = result.output["endpoints"]
    assert record["ocsp"] == "good", record["ocsp_detail"]
    assert threads and threading.main_thread() not in threads


async def test_ocsp_good_with_the_issuer_in_the_ca_bundle(pki, tmp_path, responder):
    before = len(responder.requests)
    async with tls_server(tmp_path, pki.leaves["direct"]) as port:
        result = await run_step(
            {"endpoints": f"127.0.0.1:{port}", "ca_bundle": pki.root_pem, "check_ocsp": True}
        )
    [record] = result.output["endpoints"]
    assert record["ocsp"] == "good", record["ocsp_detail"]
    assert responder.requests[before:] == ["POST /ocsp"]


async def test_ocsp_revoked_and_unavailable(pki, tmp_path):
    async with (
        tls_server(tmp_path, pki.leaves["revoked"]) as revoked,
        tls_server(tmp_path, pki.leaves["no_aia"]) as no_aia,
    ):
        result = await run_step(
            {
                "endpoints": [f"127.0.0.1:{revoked}", f"127.0.0.1:{no_aia}"],
                "ca_bundle": pki.root_pem,
                "check_ocsp": True,
            }
        )
    assert result.success is True, result.error  # nothing requires a good answer
    revoked_record, unavailable = result.output["endpoints"]
    assert revoked_record["ocsp"] == "revoked"
    assert revoked_record["ocsp_detail"] == "certificate is revoked (reason: key_compromise)"
    expected_time = (NOW - timedelta(days=1)).replace(microsecond=0)
    assert revoked_record["revocation_time"] == expected_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert unavailable["ocsp"] == "unavailable"
    assert unavailable["ocsp_detail"] == "the certificate names no OCSP responder"
    assert result.output["summary"]["ocsp_revoked"] == 1


async def test_ocsp_responder_down_is_an_error(pki, monkeypatch):
    leaf = pki.leaves["rsa"].cert
    dead = f"http://127.0.0.1:{closed_port()}/ocsp"
    monkeypatch.setattr(tls_certs, "ocsp_responder_urls", lambda cert: [dead])
    result = await run_step(
        {"pem": pem_of(leaf, pki.inter), "ca_bundle": pki.root_pem, "check_ocsp": True}
    )
    [record] = result.output["endpoints"]
    assert record["ocsp"] == "error"
    assert record["ocsp_detail"].startswith(f"OCSP request to {dead} failed: ConnectError")


async def test_the_attempt_timeout_bounds_each_revocation_request_as_a_whole(pki):
    """A responder that sends its answer a byte at a time never trips a read timeout."""
    async with trickling_http_server(6.0) as port:
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = issue(
            "slow.example.test",
            key,
            issuer=pki.inter,
            issuer_key=pki.inter_key,
            ocsp_url=f"http://127.0.0.1:{port}/ocsp",
            crl_url=f"http://127.0.0.1:{port}/inter.crl",
        )
        started = time.perf_counter()
        result = await run_step(
            {
                "pem": pem_of(leaf, pki.inter),
                "ca_bundle": pki.root_pem,
                "check_ocsp": True,
                "check_crl": True,
                "attempt_timeout_seconds": 1,
            }
        )
        elapsed = time.perf_counter() - started
    [record] = result.output["endpoints"]
    assert (record["ocsp"], record["ocsp_detail"]) == (
        "error",
        f"OCSP request to http://127.0.0.1:{port}/ocsp failed: timed out after 1s",
    )
    assert (record["crl"], record["crl_detail"]) == (
        "error",
        "downloading the CRL failed: timed out after 1s",
    )
    assert elapsed < 4.0


async def _revocation_record(pki: Pki, server: FixedHttpServer) -> dict[str, Any]:
    """The record of a pasted leaf whose OCSP responder and CRL are both on ``server``."""
    leaf = issue(
        "fetched.example.test",
        ec.generate_private_key(ec.SECP256R1()),
        issuer=pki.inter,
        issuer_key=pki.inter_key,
        ocsp_url=f"http://127.0.0.1:{server.port}/ocsp",
        crl_url=f"http://127.0.0.1:{server.port}/inter.crl",
    )
    async with asyncio.timeout(30):
        result = await run_step(
            {
                "pem": pem_of(leaf, pki.inter),
                "ca_bundle": pki.root_pem,
                "check_ocsp": True,
                "check_crl": True,
            }
        )
    [record] = result.output["endpoints"]
    return record


async def test_a_compressed_revocation_response_is_refused_without_decoding(pki, monkeypatch):
    """A small gzip body that expands far past the limits is never expanded."""
    decoded: list[int] = []
    real_decode = _decoders.GZipDecoder.decode

    def decode(self: _decoders.GZipDecoder, data: bytes) -> bytes:
        output = real_decode(self, data)
        decoded.append(len(output))
        return output

    monkeypatch.setattr(_decoders.GZipDecoder, "decode", decode)
    body = gzip.compress(bytes(32 * 1024 * 1024))
    assert len(body) < tls_check.MAX_FETCH_BYTES
    async with fixed_http_server({"Content-Encoding": "gzip"}, body) as server:
        record = await _revocation_record(pki, server)
    refused = "the server sent a gzip-compressed response; only uncompressed responses are read"
    assert (record["ocsp"], record["ocsp_detail"]) == (
        "error",
        f"OCSP request to http://127.0.0.1:{server.port}/ocsp failed: {refused}",
    )
    assert (record["crl"], record["crl_detail"]) == (
        "error",
        f"downloading the CRL failed: {refused}",
    )
    assert decoded == []
    # Both requests asked for an uncompressed answer; the server ignored that.
    assert [request.get("accept-encoding") for request in server.requests] == ["identity"] * 2


@pytest.mark.parametrize("headers", [{}, {"Content-Encoding": "identity"}])
async def test_an_uncompressed_revocation_response_past_its_limit_is_an_error(pki, headers):
    body = bytes(tls_check.MAX_FETCH_BYTES + 1)
    async with fixed_http_server(headers, body) as server:
        record = await _revocation_record(pki, server)
    url = f"http://127.0.0.1:{server.port}/ocsp"
    assert (record["ocsp"], record["ocsp_detail"]) == (
        "error",
        f"OCSP request to {url} failed: response from {url} exceeds "
        f"{tls_check.MAX_FETCH_BYTES} bytes",
    )
    # The same body fits a CRL's larger limit, so it is read and fails to parse.
    assert record["crl"] == "error"
    assert record["crl_detail"].startswith("the CRL cannot be parsed")


# --- Configuration -------------------------------------------------------------


async def test_configuration_errors_stop_before_any_connection(pki):
    handler = TlsProbeHandler()
    no_source = await run_step({})
    assert no_source.success is False
    assert no_source.error == "No target devices, IPs, endpoints, or certificate PEM configured"

    mixed = await run_step({"pem": pki.root_pem, "endpoints": "a.example:443"})
    assert "cannot be combined" in (mixed.error or "")

    too_many = await run_step({"endpoints": [f"h{index}.example" for index in range(501)]})
    assert too_many.error == "Invalid probe.tls config: endpoints: at most 500 are allowed"
    assert too_many.summary == "Config validation failed"

    # Targets count towards the limit too, which only the run can see.
    with_targets = await run_step(
        {"endpoints": [f"h{index}.example" for index in range(500)]}, ips=["192.0.2.1"]
    )
    assert "Too many endpoints: 501" in (with_targets.error or "")

    bad_fp = await run_step({"endpoints": "a.example", "expected_fingerprint": "abc"})
    assert "SHA-256" in (bad_fp.error or "")

    bad_endpoint = await run_step({"endpoints": "a.example:99999"})
    assert "outside 1-65535" in (bad_endpoint.error or "")

    assert handler.validate_config({"endpoints": "a.example:443"}) == []
    assert handler.validate_config({"endpoints": "{{ steps.inventory.output.hosts }}"}) == []
    assert handler.validate_config({"endpoints": "a.example:x"}) == [
        "endpoints: 'a.example:x': port 'x' is not a number"
    ]
    assert handler.validate_config({"pem": "nothing"}) == ["pem: no PEM certificate found"]
    assert handler.validate_config({"ca_bundle": "vault://orgs/acme/ca"}) == []
    assert handler.validate_config({"ca_bundle": "not pem"}) == [
        "ca_bundle: no PEM certificate found"
    ]
    assert handler.validate_config({"expected_fingerprints": {"a.example:443": "zz"}})
    # The same parallelism setting and bounds as every other handler that runs per target.
    assert "max_parallel" not in TlsProbeConfig.model_fields
    limit = MAX_PARALLEL_DEVICES_LIMIT
    assert handler.validate_config({"max_parallel_devices": limit}) == []
    assert handler.validate_config({"max_parallel_devices": limit + 1})
    assert handler.validate_config({"max_parallel_devices": 0})
    assert handler.validate_config({"warn_days": [30, -1]})


def test_every_config_field_is_documented_and_the_page_meets_the_contract():
    for name, model_field in TlsProbeConfig.model_fields.items():
        assert (model_field.title or "").strip(), name
        assert (model_field.description or "").strip(), name
    bundle = load_docs_bundle("hegemony_steps_probe")
    assert "probe.tls" in bundle
    assert check_page("probe.tls", bundle["probe.tls"]) == []
    page = bundle["probe.tls"]
    for key in (
        "chain_ok",
        "hostname_ok",
        "matches_expected",
        "min_days_left",
        "warn_30",
        "crl_next_update",
        "crl_revoked",
    ):
        assert key in page, key


async def test_ocsp_takes_the_issuer_from_the_served_chain(pki, responder, monkeypatch):
    """With the issuer in the served chain, nothing is downloaded."""
    leaf = pki.leaves["rsa"].cert
    served = [
        leaf.public_bytes(serialization.Encoding.DER),
        pki.inter.public_bytes(serialization.Encoding.DER),
    ]

    async def fake_handshake(host, port, server_name, context, timeout):
        return tls_check._Handshake(
            der=served[0], version="TLSv1.3", cipher="TLS_AES_128_GCM_SHA256", chain_der=served
        )

    monkeypatch.setattr(tls_check, "tls_handshake", fake_handshake)
    before = len(responder.requests)
    result = await run_step({"endpoints": "192.0.2.80:443", "check_ocsp": True})
    [record] = result.output["endpoints"]
    assert record["ocsp"] == "good", record["ocsp_detail"]
    assert (record["tls_version"], record["cipher"]) == ("TLSv1.3", "TLS_AES_128_GCM_SHA256")
    assert record["chain_ok"] is True
    assert responder.requests[before:] == ["POST /ocsp"]


async def test_the_served_chain_is_read_on_this_python(pki, tmp_path, responder):
    """The issuer comes from the chain the server sent, not from a download."""
    before = len(responder.requests)
    async with tls_server(tmp_path, pki.leaves["rsa"]) as port:
        result = await run_step(
            {"endpoints": f"127.0.0.1:{port}", "ca_bundle": pki.root_pem, "check_ocsp": True}
        )
    [record] = result.output["endpoints"]
    assert record["ocsp"] == "good", record["ocsp_detail"]
    assert responder.requests[before:] == ["POST /ocsp"]


class _PublicChain:
    """An SSL object with the public chain call (Python 3.13+): DER bytes."""

    def __init__(self, chain: list[bytes]) -> None:
        self.chain = chain

    def get_unverified_chain(self) -> list[bytes]:
        return self.chain


class _LibraryCertificate:
    """A certificate as the TLS library returns it before Python 3.13."""

    def __init__(self, cert: x509.Certificate) -> None:
        self.cert = cert

    def public_bytes(self) -> str:
        return pem_of(self.cert)


class _PrivateChain:
    """An SSL object with the chain call only on its private ``_sslobj`` (Python 3.10-3.12)."""

    def __init__(self, chain: list[x509.Certificate]) -> None:
        self._sslobj = _PublicChain(cast(list[bytes], [_LibraryCertificate(c) for c in chain]))


def test_served_chain_reads_every_form_of_the_tls_library(pki):
    leaf = pki.leaves["rsa"].cert
    der = [cert.public_bytes(serialization.Encoding.DER) for cert in (leaf, pki.inter)]
    assert tls_check.served_chain(_PublicChain(der)) == der
    assert tls_check.served_chain(_PrivateChain([leaf, pki.inter])) == der
    assert tls_check.served_chain(_PublicChain(cast(list[bytes], None))) == []
    assert tls_check.served_chain(object()) == []


async def test_an_ocsp_request_the_egress_policy_denies_is_the_step_error(pki):
    services = FakeServices(deny=("127.0.0.1",))
    leaf = pki.leaves["rsa"].cert
    with pytest.raises(Denied, match="ocsp check"):
        await run_step(
            {"pem": pem_of(leaf, pki.inter), "ca_bundle": pki.root_pem, "check_ocsp": True},
            services=services,
        )
    assert [entry[3] for entry in services.egress] == ["ocsp check"]


async def test_the_step_error_names_the_first_twenty_failing_endpoints(monkeypatch):
    async def refused(host, port, server_name, context, timeout):
        raise ConnectionRefusedError(111, "Connection refused")

    monkeypatch.setattr(tls_check, "tls_handshake", refused)
    endpoints = [f"192.0.2.{index}:443" for index in range(1, 24)]
    result = await run_step({"endpoints": endpoints})
    error = result.error or ""
    assert error.startswith("TLS check failed for 23 of 23 endpoints: 192.0.2.1:443 (")
    assert "192.0.2.20:443" in error and "192.0.2.21:443" not in error
    assert error.endswith(", and 3 more")
    assert len(result.output["endpoints"]) == 23


# --- Offline validation matches the live verifier ------------------------------

_UNKNOWN_CRITICAL = (
    x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.4.1.55555.1.1"), b"\x05\x00"),
    True,
)


def _key_usage(**flags: bool) -> tuple[x509.KeyUsage, bool]:
    names = (
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    )
    return x509.KeyUsage(**{name: flags.get(name, False) for name in names}), True


_CA_USAGE = _key_usage(key_cert_sign=True, crl_sign=True)


def _constraints(
    permitted: list[x509.GeneralName] | None = None,
    excluded: list[x509.GeneralName] | None = None,
) -> tuple[x509.NameConstraints, bool]:
    return x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=excluded), True


def _chain_case(
    pki: Pki,
    *,
    inter_extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (_CA_USAGE,),
    leaf_extensions: tuple[tuple[x509.ExtensionType, bool], ...] = (),
    leaf_sans: tuple[str, ...] = ("leaf.example.test",),
    leaf_eku: tuple[x509.ObjectIdentifier, ...] | None = (ExtendedKeyUsageOID.SERVER_AUTH,),
    leaf_subject: x509.Name | None = None,
) -> tuple[Leaf, str]:
    """A root -> intermediate -> leaf chain; returns the served leaf and the anchor PEM."""
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = issue(
        "Case Intermediate",
        inter_key,
        issuer=pki.root,
        issuer_key=pki.root_key,
        ca=True,
        extensions=inter_extensions,
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = issue(
        "leaf.example.test",
        leaf_key,
        issuer=inter,
        issuer_key=inter_key,
        sans=leaf_sans,
        eku=leaf_eku,
        extensions=leaf_extensions,
        subject=leaf_subject,
    )
    return Leaf(leaf, leaf_key, (inter,)), pki.root_pem


def _der_element(data: bytes, offset: int) -> tuple[int, int, int]:
    """``(tag, content start, end)`` of the DER element at ``offset``."""
    tag, length, start = data[offset], data[offset + 1], offset + 2
    if length & 0x80:
        size = length & 0x7F
        length = int.from_bytes(data[start : start + size], "big")
        start += size
    return tag, start, start + length


def _der(tag: int, content: bytes) -> bytes:
    """One DER element."""
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + content


def _version_1(
    subject: x509.Name, key: SigningKey, issuer: x509.Name, issuer_key: ec.EllipticCurvePrivateKey
) -> x509.Certificate:
    """A version 1 certificate (no version field, no extensions) that ``issuer_key`` signs.

    The X.509 library only builds version 3, so this builds one without
    extensions, drops its version field and signs the result again.
    """
    template = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=60))
        .sign(issuer_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    _, outer_start, _ = _der_element(template, 0)
    _, tbs_start, tbs_end = _der_element(template, outer_start)
    fields, offset = [], tbs_start
    while offset < tbs_end:
        tag, _, end = _der_element(template, offset)
        if tag != 0xA0:  # [0] version
            fields.append(template[offset:end])
        offset = end
    tbs = _der(0x30, b"".join(fields))
    _, _, algorithm_end = _der_element(template, tbs_end)
    signature = issuer_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    signed = tbs + template[tbs_end:algorithm_end] + _der(0x03, b"\x00" + signature)
    cert = x509.load_der_x509_certificate(_der(0x30, signed))
    assert cert.version == x509.Version.v1
    return cert


def _anchor_purpose_case() -> tuple[Leaf, str]:
    """A chain to a trust anchor whose extended key usage allows only client authentication."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    client_only = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
    root = issue("Client Root", root_key, ca=True, extensions=((client_only, False),))
    pki = Pki(root, root_key, root, root_key, {})
    return _chain_case(pki)


def _version_1_root_case() -> tuple[Leaf, str]:
    """A chain to a self-signed version 1 root, which may act as a CA as a trust anchor."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = _version_1(_name("Old Root"), root_key, _name("Old Root"), root_key)
    leaf, _ = _chain_case(Pki(root, root_key, root, root_key, {}))
    return leaf, pem_of(root)


def _anchor_without_basic_constraints_case() -> tuple[Leaf, str]:
    """A chain to a trust anchor that has key usage but no basicConstraints."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = issue("Usage Root", root_key, ca=True, basic_constraints=False, extensions=(_CA_USAGE,))
    return _chain_case(Pki(root, root_key, root, root_key, {}))


def _version_1_intermediate_case(pki: Pki) -> tuple[Leaf, str]:
    """A chain through a version 1 intermediate, which may not act as a CA."""
    assert isinstance(pki.root_key, ec.EllipticCurvePrivateKey)
    inter_key = ec.generate_private_key(ec.SECP256R1())
    inter = _version_1(_name("Old Intermediate"), inter_key, pki.root.subject, pki.root_key)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = issue(
        "leaf.example.test",
        leaf_key,
        issuer=inter,
        issuer_key=inter_key,
        sans=("leaf.example.test",),
    )
    return Leaf(leaf, leaf_key, (inter,)), pki.root_pem


def _organization(*values: str) -> x509.Name:
    """A name of organization attributes followed by the leaf's common name."""
    attributes = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, value) for value in values]
    return x509.Name([*attributes, x509.NameAttribute(NameOID.COMMON_NAME, "leaf.example.test")])


def _pinned_case() -> tuple[Leaf, str]:
    """A self-signed client-only certificate trusted as its own anchor."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = issue(
        "pinned.example.test",
        key,
        sans=("pinned.example.test",),
        eku=(ExtendedKeyUsageOID.CLIENT_AUTH,),
    )
    return Leaf(cert, key, ()), pem_of(cert)


def _self_signed_copies_case() -> tuple[Leaf, str]:
    """A leaf served with twelve copies of one self-signed CA, none of them trusted."""
    key = ec.generate_private_key(ec.SECP256R1())
    copies = tuple(issue("Loop CA", key, ca=True) for _ in range(12))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = issue(
        "leaf.example.test",
        leaf_key,
        issuer=copies[0],
        issuer_key=key,
        sans=("leaf.example.test",),
    )
    unrelated = issue("Unrelated Root", ec.generate_private_key(ec.SECP256R1()), ca=True)
    return Leaf(leaf, leaf_key, copies), pem_of(unrelated)


_PARITY_CASES: dict[str, tuple[Any, bool | None]] = {
    "valid": (_chain_case, True),
    "issuer-key-usage": (
        lambda pki: _chain_case(pki, inter_extensions=(_key_usage(digital_signature=True),)),
        False,
    ),
    "leaf-key-usage": (
        lambda pki: _chain_case(pki, leaf_extensions=(_key_usage(key_cert_sign=True),)),
        False,
    ),
    "leaf-critical-extension": (
        lambda pki: _chain_case(pki, leaf_extensions=(_UNKNOWN_CRITICAL,)),
        False,
    ),
    "issuer-critical-extension": (
        lambda pki: _chain_case(pki, inter_extensions=(_CA_USAGE, _UNKNOWN_CRITICAL)),
        False,
    ),
    "issuer-extended-key-usage": (
        lambda pki: _chain_case(
            pki,
            inter_extensions=(
                _CA_USAGE,
                (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
            ),
        ),
        False,
    ),
    "leaf-any-extended-key-usage": (
        lambda pki: _chain_case(pki, leaf_eku=(ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,)),
        None,
    ),
    "dns-permitted": (
        lambda pki: _chain_case(
            pki, inter_extensions=(_CA_USAGE, _constraints([x509.DNSName("example.test")]))
        ),
        True,
    ),
    "dns-not-permitted": (
        lambda pki: _chain_case(
            pki,
            inter_extensions=(_CA_USAGE, _constraints([x509.DNSName("example.test")])),
            leaf_sans=("leaf.other.test",),
        ),
        False,
    ),
    "dns-excluded": (
        lambda pki: _chain_case(
            pki,
            inter_extensions=(
                _CA_USAGE,
                _constraints(excluded=[x509.DNSName("bad.example.test")]),
            ),
            leaf_sans=("x.bad.example.test",),
        ),
        False,
    ),
    "ip-not-permitted": (
        lambda pki: _chain_case(
            pki,
            inter_extensions=(
                _CA_USAGE,
                _constraints([x509.IPAddress(ipaddress.ip_network("10.0.0.0/8"))]),
            ),
            leaf_sans=("leaf.example.test", "192.0.2.1"),
        ),
        False,
    ),
    "directory-name-not-permitted": (
        lambda pki: _chain_case(
            pki,
            inter_extensions=(
                _CA_USAGE,
                _constraints(
                    [
                        x509.DirectoryName(
                            x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Allowed")])
                        )
                    ]
                ),
            ),
        ),
        False,
    ),
    "directory-name-excluded-in-other-case": (
        lambda pki: _chain_case(
            pki,
            inter_extensions=(
                _CA_USAGE,
                _constraints(
                    excluded=[
                        x509.DirectoryName(
                            x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil Corp")])
                        )
                    ]
                ),
            ),
            leaf_subject=_organization("EVIL CORP"),
        ),
        False,
    ),
    "directory-name-permitted-with-other-spacing": (
        lambda pki: _chain_case(
            pki,
            inter_extensions=(
                _CA_USAGE,
                _constraints(
                    [
                        x509.DirectoryName(
                            x509.Name(
                                [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Allowed Org")]
                            )
                        )
                    ]
                ),
            ),
            leaf_subject=_organization("  ALLOWED \t  org "),
        ),
        True,
    ),
    "anchor-extended-key-usage": (lambda pki: _anchor_purpose_case(), False),
    "version-1-root": (lambda pki: _version_1_root_case(), True),
    "version-1-intermediate": (_version_1_intermediate_case, False),
    "anchor-without-basic-constraints": (
        lambda pki: _anchor_without_basic_constraints_case(),
        True,
    ),
    "pinned-client-certificate": (lambda pki: _pinned_case(), False),
    "self-signed-copies-in-chain": (lambda pki: _self_signed_copies_case(), False),
}


@pytest.mark.parametrize("case", list(_PARITY_CASES))
async def test_offline_chain_verdict_matches_the_live_verifier(pki, tmp_path, case):
    build, expected = _PARITY_CASES[case]
    leaf, anchors = build(pki)
    async with tls_server(tmp_path, leaf) as port:
        live = await run_step({"endpoints": f"127.0.0.1:{port}", "ca_bundle": anchors})
    offline = await run_step({"pem": pem_of(leaf.cert, *leaf.chain), "ca_bundle": anchors})
    [live_record] = live.output["endpoints"]
    [offline_record] = offline.output["endpoints"]
    live_verdict = (live_record["chain_ok"], live_record["chain_error"])
    offline_verdict = (offline_record["chain_ok"], offline_record["chain_error"])
    assert offline_verdict == live_verdict
    if expected is not None:
        assert live_verdict[0] is expected


@pytest.mark.parametrize(
    ("name", "base", "within"),
    [
        ("a.example.test", "example.test", True),
        ("example.test", "example.test", True),
        ("badexample.test", "example.test", False),
        ("a.example.test", ".example.test", True),
        ("example.test", ".example.test", False),
        ("anything.test", "", True),
    ],
)
def test_dns_name_constraint_matching(name, base, within):
    assert tls_certs._dns_within(name, base) is within


@pytest.mark.parametrize(
    ("address", "base", "within"),
    [
        ("ops@example.test", "ops@example.test", True),
        ("dev@example.test", "ops@example.test", False),
        ("ops@EXAMPLE.test", "example.test", True),
        ("ops@mail.example.test", "example.test", False),
        ("ops@mail.example.test", ".example.test", True),
        ("not-an-address", "example.test", False),
    ],
)
def test_email_name_constraint_matching(address, base, within):
    assert tls_certs._email_within(address, base) is within


@pytest.mark.parametrize(
    ("uri", "base", "within"),
    [
        ("https://example.test/path", "example.test", True),
        ("https://user@example.test:8443/", "example.test", True),
        ("https://www.example.test/", ".example.test", True),
        ("https://other.test/", "example.test", False),
        ("urn:example", "example.test", False),
    ],
)
def test_uri_name_constraint_matching(uri, base, within):
    assert tls_certs._uri_within(uri, base) is within


# --- OCSP: responder validity and the certificate ID --------------------------


def test_ocsp_rejects_an_expired_delegated_responder(pki):
    leaf = pki.leaves["rsa"].cert
    delegate_key = ec.generate_private_key(ec.SECP256R1())
    expired_delegate = issue(
        "Expired OCSP Signer",
        delegate_key,
        issuer=pki.inter,
        issuer_key=pki.inter_key,
        eku=(ExtendedKeyUsageOID.OCSP_SIGNING,),
        not_before=NOW - timedelta(days=30),
        not_after=NOW - timedelta(days=1),
    )
    response = _ocsp_response(
        leaf, pki.inter, expired_delegate, delegate_key, certificates=[expired_delegate]
    )
    outcome = evaluate_ocsp_response(response, leaf, pki.inter, now=NOW)
    assert outcome["ocsp"] == "error"
    assert "not signed by the issuer" in outcome["ocsp_detail"]


def test_ocsp_requires_the_issuer_name_hash_to_match(pki):
    leaf = pki.leaves["rsa"].cert
    # The real issuer's key under another name, and a certificate with the
    # leaf's serial number issued under that name: a response about it shares
    # the leaf's serial number and issuer key hash, and only the issuer name
    # hash tells them apart.
    alias = issue(
        "Probe Test Intermediate Alias",
        pki.inter_key,
        issuer=pki.root,
        issuer_key=pki.root_key,
        ca=True,
    )
    twin = (
        x509.CertificateBuilder()
        .subject_name(_name("twin.example.test"))
        .issuer_name(alias.subject)
        .public_key(ec.generate_private_key(ec.SECP256R1()).public_key())
        .serial_number(leaf.serial_number)
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
        .sign(pki.inter_key, hashes.SHA256())
    )
    response = (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=twin,
            issuer=alias,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=NOW - timedelta(hours=2),
            next_update=NOW + timedelta(days=1),
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, pki.inter)
        .sign(pki.inter_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    outcome = evaluate_ocsp_response(response, leaf, pki.inter, now=NOW)
    assert outcome == {
        "ocsp": "error",
        "ocsp_detail": "response does not cover this certificate",
        "revocation_time": None,
    }


async def test_a_malformed_url_in_the_certificate_is_an_ocsp_error_for_that_endpoint(pki):
    key = ec.generate_private_key(ec.SECP256R1())
    bad_ocsp = issue(
        "bad-ocsp.example.test",
        key,
        issuer=pki.inter,
        issuer_key=pki.inter_key,
        ocsp_url="http://ocsp.example.test:abc/",
    )
    result = await run_step(
        {"pem": pem_of(bad_ocsp, pki.inter), "ca_bundle": pki.root_pem, "check_ocsp": True}
    )
    [record] = result.output["endpoints"]
    assert record["ocsp"] == "error"
    assert "failed" in record["ocsp_detail"]

    bad_issuer = issue(
        "bad-issuer.example.test",
        key,
        issuer=pki.inter,
        issuer_key=pki.inter_key,
        ocsp_url="http://ocsp.example.test/",
        issuer_url="http://ca.example.test:abc/ca.crt",
    )
    result = await run_step(
        {"pem": pem_of(bad_issuer), "ca_bundle": pki.root_pem, "check_ocsp": True}
    )
    [record] = result.output["endpoints"]
    assert record["ocsp"] == "unavailable"
    assert "downloading http://ca.example.test:abc/ca.crt failed" in record["ocsp_detail"]


# --- Endpoint identity ----------------------------------------------------------


def test_ipv6_zones_stay_part_of_the_endpoint_key():
    assert tls_certs.normalize_host("[FE80::1%eth0]") == "fe80::1%eth0"
    assert tls_certs.endpoint_key("fe80::1%eth0", 443) != tls_certs.endpoint_key(
        "fe80::1%eth1", 443
    )
    assert tls_certs.endpoint_key("2001:DB8::1", 443) == tls_certs.endpoint_key("2001:db8::1", 443)


def test_fingerprint_overrides_tell_server_names_apart():
    config = TlsProbeConfig.model_validate(
        {
            "expected_fingerprint": "00" * 32,
            "expected_fingerprints": {
                "192.0.2.10:443:a.example.test": "aa" * 32,
                "192.0.2.10:443:B.Example.Test.": "bb" * 32,
                "192.0.2.10:443": "cc" * 32,
            },
        }
    )
    settings = tls_check._Settings.from_config(config)
    assert settings.expected_for("192.0.2.10", 443, "a.example.test") == "aa" * 32
    assert settings.expected_for("192.0.2.10", 443, "b.example.test") == "bb" * 32
    assert settings.expected_for("192.0.2.10", 443, "c.example.test") == "cc" * 32
    assert settings.expected_for("192.0.2.10", 443, None) == "cc" * 32
    assert settings.expected_for("192.0.2.11", 443, "a.example.test") == "00" * 32


# --- CRL: addresses and evaluation ------------------------------------------------


def _distribution_points(*points: x509.DistributionPoint) -> tuple[x509.ExtensionType, bool]:
    return x509.CRLDistributionPoints(list(points)), False


def _point(*urls: str, **kwargs: Any) -> x509.DistributionPoint:
    names = [x509.UniformResourceIdentifier(url) for url in urls]
    return x509.DistributionPoint(names, None, kwargs.get("reasons"), kwargs.get("crl_issuer"))


def _leaf_with(pki: Pki, *extensions: tuple[x509.ExtensionType, bool]) -> x509.Certificate:
    return issue(
        "crl-case.example.test",
        ec.generate_private_key(ec.SECP256R1()),
        issuer=pki.inter,
        issuer_key=pki.inter_key,
        extensions=extensions,
    )


def test_crl_locations_keep_http_addresses_and_say_why_there_are_none(pki):
    assert tls_certs.crl_locations(pki.leaves["no_aia"].cert) == (
        [],
        "the certificate names no CRL distribution point",
    )

    both = _leaf_with(
        pki,
        _distribution_points(
            _point("ldap://ca.example.test/cn=crl", "http://ca.example.test/a.crl"),
            _point("HTTPS://ca.example.test/b.crl", "http://ca.example.test/a.crl"),
        ),
    )
    locations, missing = tls_certs.crl_locations(both)
    assert missing is None
    assert [location.url for location in locations] == [
        "http://ca.example.test/a.crl",
        "HTTPS://ca.example.test/b.crl",
    ]
    assert x509.UniformResourceIdentifier("ldap://ca.example.test/cn=crl") in locations[0].names

    ldap_only = _leaf_with(pki, _distribution_points(_point("ldap://ca.example.test/cn=crl")))
    assert tls_certs.crl_locations(ldap_only) == (
        [],
        "the certificate's CRL distribution points name no HTTP address",
    )

    indirect = _leaf_with(
        pki,
        _distribution_points(
            _point("http://ca.example.test/a.crl", crl_issuer=[x509.DirectoryName(_name("Other"))]),
            _point(
                "http://ca.example.test/b.crl", reasons=frozenset({x509.ReasonFlags.key_compromise})
            ),
        ),
    )
    locations, missing = tls_certs.crl_locations(indirect)
    assert locations == []
    assert missing is not None and "does not support" in missing


def test_load_crl_reads_der_and_pem(pki):
    crl = make_crl(pki.inter, pki.inter_key)
    der = crl.public_bytes(serialization.Encoding.DER)
    pem = crl.public_bytes(serialization.Encoding.PEM)
    assert tls_certs.load_crl(der) == crl
    assert tls_certs.load_crl(b"published by the test CA\n" + pem) == crl
    with pytest.raises(ValueError):
        tls_certs.load_crl(b"not a crl")


def _evaluate(
    crl: x509.CertificateRevocationList,
    cert: x509.Certificate,
    issuer: x509.Certificate,
    names: tuple[str, ...] = ("http://ca.example.test/inter.crl",),
) -> dict[str, Any]:
    return tls_certs.evaluate_crl(
        crl,
        cert,
        issuer,
        url="http://ca.example.test/inter.crl",
        names=frozenset(x509.UniformResourceIdentifier(name) for name in names),
        now=NOW,
    )


def test_crl_reports_good_revoked_and_removed(pki):
    leaf = pki.leaves["crl_revoked"].cert
    next_update = (NOW + timedelta(days=7)).replace(microsecond=0)
    listed = make_crl(
        pki.inter,
        pki.inter_key,
        revoked={leaf.serial_number: x509.ReasonFlags.key_compromise},
        next_update=next_update,
    )
    assert _evaluate(listed, leaf, pki.inter) == {
        "crl": "revoked",
        "crl_detail": "certificate is revoked (reason: key_compromise)",
        "crl_url": "http://ca.example.test/inter.crl",
        "crl_next_update": next_update.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "crl_revocation_time": CRL_REVOKED_AT.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    good = _evaluate(listed, pki.leaves["crl_good"].cert, pki.inter)
    assert (good["crl"], good["crl_detail"]) == ("good", "certificate is not on the CRL")
    assert good["crl_revocation_time"] is None

    no_reason = make_crl(pki.inter, pki.inter_key, revoked={leaf.serial_number: None})
    assert _evaluate(no_reason, leaf, pki.inter)["crl_detail"] == "certificate is revoked"

    held = make_crl(
        pki.inter, pki.inter_key, revoked={leaf.serial_number: x509.ReasonFlags.certificate_hold}
    )
    assert _evaluate(held, leaf, pki.inter)["crl"] == "revoked"

    removed = make_crl(
        pki.inter, pki.inter_key, revoked={leaf.serial_number: x509.ReasonFlags.remove_from_crl}
    )
    assert _evaluate(removed, leaf, pki.inter)["crl"] == "good"


def test_crl_problems_are_errors(pki):
    leaf = pki.leaves["crl_good"].cert
    cases: list[tuple[x509.CertificateRevocationList, x509.Certificate, str]] = [
        (
            make_crl(pki.inter, pki.root_key),
            pki.inter,
            "CRL signature does not verify with the issuer's key",
        ),
        (
            make_crl(pki.inter, pki.inter_key, issuer_name=_name("Someone Else")),
            pki.inter,
            "CRL is not issued by the certificate's issuer",
        ),
        (
            make_crl(pki.inter, pki.inter_key, next_update=NOW - timedelta(hours=1)),
            pki.inter,
            "CRL is stale (next update was ",
        ),
        (
            make_crl(
                pki.inter,
                pki.inter_key,
                this_update=NOW + timedelta(hours=1),
                next_update=NOW + timedelta(days=2),
            ),
            pki.inter,
            "CRL is not valid until ",
        ),
        (
            make_crl(pki.inter, pki.inter_key, extensions=((x509.DeltaCRLIndicator(7), True),)),
            pki.inter,
            "the address serves a delta CRL, not a complete one",
        ),
        (
            make_crl(pki.inter, pki.inter_key, extensions=(_UNKNOWN_CRITICAL,)),
            pki.inter,
            "CRL has an unhandled critical extension",
        ),
        (
            make_crl(
                pki.inter,
                pki.inter_key,
                revoked={leaf.serial_number: None},
                entry_extensions=(
                    (x509.CertificateIssuer([x509.DirectoryName(pki.inter.subject)]), True),
                ),
            ),
            pki.inter,
            "the CRL entry for this certificate has an unhandled critical extension",
        ),
    ]
    for crl, issuer, expected in cases:
        outcome = _evaluate(crl, leaf, issuer)
        assert outcome["crl"] == "error", expected
        assert outcome["crl_detail"].startswith(expected), outcome["crl_detail"]

    # An issuer whose key usage rules out CRL signing.
    no_crl_sign_key = ec.generate_private_key(ec.SECP256R1())
    no_crl_sign = issue(
        "No CRL Sign CA",
        no_crl_sign_key,
        issuer=pki.root,
        issuer_key=pki.root_key,
        ca=True,
        extensions=(_key_usage(key_cert_sign=True),),
    )
    issued = issue(
        "issued.example.test",
        ec.generate_private_key(ec.SECP256R1()),
        issuer=no_crl_sign,
        issuer_key=no_crl_sign_key,
    )
    outcome = _evaluate(make_crl(no_crl_sign, no_crl_sign_key), issued, no_crl_sign)
    assert outcome["crl_detail"] == "the issuer's key usage does not allow signing CRLs"
    # Only a list that verified reports when it is next updated.
    assert outcome["crl_next_update"] is None


def _scoped(pki: Pki, **kwargs: Any) -> x509.CertificateRevocationList:
    options: dict[str, Any] = {
        "full_name": None,
        "relative_name": None,
        "only_contains_user_certs": False,
        "only_contains_ca_certs": False,
        "only_some_reasons": None,
        "indirect_crl": False,
        "only_contains_attribute_certs": False,
        **kwargs,
    }
    scope = x509.IssuingDistributionPoint(**options)
    return make_crl(pki.inter, pki.inter_key, extensions=((scope, True),))


def test_crl_scope_follows_the_issuing_distribution_point(pki):
    leaf = pki.leaves["crl_good"].cert
    own = [x509.UniformResourceIdentifier("http://ca.example.test/inter.crl")]
    other = [x509.UniformResourceIdentifier("http://ca.example.test/other.crl")]
    assert _evaluate(_scoped(pki, full_name=own), leaf, pki.inter)["crl"] == "good"
    assert _evaluate(_scoped(pki, only_contains_user_certs=True), leaf, pki.inter)["crl"] == "good"
    expectations = [
        ({"full_name": other}, "it is for another distribution point"),
        ({"only_contains_ca_certs": True}, "it lists CA certificates only"),
        ({"indirect_crl": True}, "CRL is an indirect CRL"),
        (
            {"only_some_reasons": frozenset({x509.ReasonFlags.key_compromise})},
            "CRL covers only some revocation reasons",
        ),
    ]
    for options, fragment in expectations:
        outcome = _evaluate(_scoped(pki, **options), leaf, pki.inter)
        assert outcome["crl"] == "error"
        assert fragment in outcome["crl_detail"], outcome["crl_detail"]
        assert outcome["crl_next_update"] is not None


# --- The handler: CRL ------------------------------------------------------------


async def test_crl_good_and_revoked_share_one_download(pki, tmp_path, responder):
    services = FakeServices()
    before = len(responder.requests)
    # Served without the intermediate, so the issuer has to be downloaded too.
    async with (
        tls_server(tmp_path, pki.leaves["crl_good"], with_chain=False) as good_port,
        tls_server(tmp_path, pki.leaves["crl_revoked"], with_chain=False) as revoked_port,
    ):
        result = await run_step(
            {
                "endpoints": [f"127.0.0.1:{good_port}", f"127.0.0.1:{revoked_port}"],
                "ca_bundle": pki.root_pem,
                "check_crl": True,
                "require_crl_good": True,
            },
            services=services,
        )
    assert result.success is False
    good, revoked = result.output["endpoints"]
    assert (good["crl"], good["crl_detail"]) == ("good", "certificate is not on the CRL")
    assert good["crl_url"] == responder.crl_url
    assert good["crl_next_update"] is not None
    assert good["ok"] is True
    assert revoked["crl"] == "revoked"
    assert revoked["crl_revocation_time"] == CRL_REVOKED_AT.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert revoked["failures"] == ["CRL revoked: certificate is revoked (reason: key_compromise)"]
    assert result.output["summary"]["crl_revoked"] == 1
    assert "CRL revoked: certificate is revoked" in (result.error or "")
    # Both endpoints share one issuer download and one CRL download.
    downloads = [request for request in responder.requests[before:] if request.startswith("GET")]
    assert sorted(downloads) == ["GET /inter.crl", "GET /issuer.der"]
    kinds = {entry[3] for entry in services.egress if entry[1] == responder.port}
    assert kinds == {"crl download", "issuer download"}


async def test_crl_unavailable_and_download_errors(pki, responder):
    async def crl_record(cert: x509.Certificate) -> dict[str, Any]:
        result = await run_step(
            {"pem": pem_of(cert, pki.inter), "ca_bundle": pki.root_pem, "check_crl": True}
        )
        assert result.success is True, result.error  # nothing requires a good answer
        [record] = result.output["endpoints"]
        return record

    record = await crl_record(pki.leaves["no_aia"].cert)
    assert (record["crl"], record["crl_detail"]) == (
        "unavailable",
        "the certificate names no CRL distribution point",
    )

    dead = f"http://127.0.0.1:{closed_port()}/inter.crl"
    record = await crl_record(_leaf_with(pki, _distribution_points(_point(dead))))
    assert record["crl"] == "error"
    assert record["crl_detail"].startswith("downloading the CRL failed: ConnectError")
    assert record["crl_url"] == dead

    missing = f"http://127.0.0.1:{responder.port}/missing.crl"
    record = await crl_record(_leaf_with(pki, _distribution_points(_point(missing))))
    assert record["crl_detail"] == f"downloading the CRL failed: HTTP 404 from {missing}"

    not_a_crl = f"http://127.0.0.1:{responder.port}/issuer.der"
    record = await crl_record(_leaf_with(pki, _distribution_points(_point(not_a_crl))))
    assert record["crl_detail"].startswith("the CRL cannot be parsed")


async def test_crl_tries_the_next_address_after_a_failure(pki, responder):
    dead = f"http://127.0.0.1:{closed_port()}/inter.crl"
    leaf = _leaf_with(pki, _distribution_points(_point(dead), _point(responder.crl_url)))
    result = await run_step(
        {
            "pem": pem_of(leaf, pki.inter),
            "ca_bundle": pki.root_pem,
            "check_crl": True,
            "require_crl_good": True,
        }
    )
    assert result.success is True, result.error
    [record] = result.output["endpoints"]
    assert (record["crl"], record["crl_url"]) == ("good", responder.crl_url)


async def test_at_most_three_addresses_of_each_kind_are_tried(pki, responder):
    base = f"http://127.0.0.1:{responder.port}"
    crl_leaf = _leaf_with(
        pki, _distribution_points(*(_point(f"{base}/gone-{index}.crl") for index in range(5)))
    )
    before = len(responder.requests)
    result = await run_step(
        {"pem": pem_of(crl_leaf, pki.inter), "ca_bundle": pki.root_pem, "check_crl": True}
    )
    [record] = result.output["endpoints"]
    assert (record["crl"], record["crl_detail"]) == (
        "error",
        f"downloading the CRL failed: HTTP 404 from {base}/gone-0.crl",
    )
    assert responder.requests[before:] == [f"GET /gone-{index}.crl" for index in range(3)]

    access = x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier(responder.url)
            ),
            *(
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(f"{base}/gone-{index}.der"),
                )
                for index in range(5)
            ),
        ]
    )
    issuer_leaf = _leaf_with(pki, (access, False))
    before = len(responder.requests)
    result = await run_step(
        {"pem": pem_of(issuer_leaf), "ca_bundle": pki.root_pem, "check_ocsp": True}
    )
    [record] = result.output["endpoints"]
    assert (record["ocsp"], record["ocsp_detail"]) == (
        "unavailable",
        "the issuer certificate is not available; "
        f"downloading {base}/gone-2.der failed: HTTP 404 from {base}/gone-2.der",
    )
    assert responder.requests[before:] == [f"GET /gone-{index}.der" for index in range(3)]


async def test_the_step_stops_downloading_at_its_limit(pki, responder, monkeypatch):
    monkeypatch.setattr(tls_check, "MAX_RUN_DOWNLOAD_BYTES", 100)
    leaf = issue(
        "limited.example.test",
        ec.generate_private_key(ec.SECP256R1()),
        issuer=pki.inter,
        issuer_key=pki.inter_key,
        ocsp_url=responder.url,
        crl_url=responder.crl_url,
    )
    responder.entries[leaf.serial_number] = _OcspEntry(
        leaf, pki.inter, pki.inter_key, ocsp.OCSPCertStatus.GOOD
    )
    before = len(responder.requests)
    result = await run_step(
        {
            "pem": pem_of(leaf, pki.inter),
            "ca_bundle": pki.root_pem,
            "check_ocsp": True,
            "check_crl": True,
        }
    )
    [record] = result.output["endpoints"]
    limit = "the step's downloads reached their limit of 100 bytes"
    assert (record["ocsp"], record["ocsp_detail"]) == (
        "error",
        f"OCSP request to {responder.url} failed: {limit}",
    )
    assert (record["crl"], record["crl_detail"]) == (
        "error",
        f"downloading the CRL failed: {limit}",
    )
    # The OCSP response used up the limit, so the CRL was never requested.
    assert responder.requests[before:] == ["POST /ocsp"]


async def test_only_a_crl_that_passed_its_check_is_kept(pki, responder, monkeypatch):
    kept: list[Any] = []
    real_close = tls_check._TlsRun.close

    def close(run: tls_check._TlsRun) -> None:
        kept.extend(
            future.result()
            for future in run._crls.values()
            if future.done() and future.exception() is None
        )
        real_close(run)

    monkeypatch.setattr(tls_check._TlsRun, "close", close)
    # The responder publishes the intermediate's CRL; a leaf of the root names it too.
    stray = issue(
        "stray.example.test",
        ec.generate_private_key(ec.SECP256R1()),
        issuer=pki.root,
        issuer_key=pki.root_key,
        crl_url=responder.crl_url,
    )
    result = await run_step({"pem": pem_of(stray), "ca_bundle": pki.root_pem, "check_crl": True})
    [record] = result.output["endpoints"]
    assert (record["crl"], record["crl_detail"]) == (
        "error",
        "CRL is not issued by the certificate's issuer",
    )
    assert kept == ["CRL is not issued by the certificate's issuer"]

    kept.clear()
    result = await run_step(
        {
            "pem": pem_of(pki.leaves["crl_good"].cert, pki.inter),
            "ca_bundle": pki.root_pem,
            "check_crl": True,
        }
    )
    assert result.output["endpoints"][0]["crl"] == "good"
    assert [type(item) for item in kept] == [x509.CertificateRevocationList]


async def test_a_crl_download_the_egress_policy_denies_is_the_step_error(pki):
    services = FakeServices(deny=("127.0.0.1",))
    leaf = pki.leaves["crl_good"].cert
    with pytest.raises(Denied, match="crl download"):
        await run_step(
            {"pem": pem_of(leaf, pki.inter), "ca_bundle": pki.root_pem, "check_crl": True},
            services=services,
        )
    assert [entry[3] for entry in services.egress] == ["crl download"]


async def test_ocsp_and_crl_together_download_the_issuer_once(pki, tmp_path, responder):
    before = len(responder.requests)
    async with tls_server(tmp_path, pki.leaves["rsa"]) as port:
        result = await run_step(
            {
                "endpoints": f"127.0.0.1:{port}",
                "ca_bundle": pki.root_pem,
                "check_ocsp": True,
                "check_crl": True,
            }
        )
    [record] = result.output["endpoints"]
    assert record["ocsp"] == "good", record["ocsp_detail"]
    assert record["crl"] == "unavailable"
    issuer_downloads = [r for r in responder.requests[before:] if r == "GET /issuer.der"]
    assert len(issuer_downloads) <= 1


class _NoGateServices:
    """A host without the egress gate: only secret resolution."""

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        return None


async def test_without_an_egress_gate_only_offline_checks_run(pki):
    services = _NoGateServices()
    offline = await run_step(
        {"pem": pem_of(pki.leaves["rsa"].cert, pki.inter), "ca_bundle": pki.root_pem},
        services=services,
    )
    assert offline.success is True, offline.error
    for config in (
        {"endpoints": "127.0.0.1:443"},
        {"pem": pem_of(pki.leaves["rsa"].cert), "check_ocsp": True},
        {"pem": pem_of(pki.leaves["crl_good"].cert), "check_crl": True},
    ):
        result = await run_step(config, services=services)
        assert result.success is False
        assert "cannot apply the flow's network policy" in (result.error or "")


# --- Unreadable revocation data stays with its endpoint ---------------------------


class _Unreadable:
    """A real OCSP response or CRL, with one attribute that raises when read."""

    def __init__(self, real: Any, name: str, error: Exception) -> None:
        self._real = real
        self._name = name
        self._error = error

    def __getattr__(self, name: str) -> Any:
        if name == self._name:
            raise self._error
        return getattr(self._real, name)


def test_an_ocsp_response_with_an_unknown_algorithm_is_an_ocsp_error(pki, monkeypatch):
    leaf = pki.leaves["rsa"].cert
    data = _ocsp_response(leaf, pki.inter, pki.inter, pki.inter_key)
    real_loader = ocsp.load_der_ocsp_response
    unknown = UnsupportedAlgorithm("Signature algorithm OID: 1.2.3.4 not recognized")
    monkeypatch.setattr(
        ocsp,
        "load_der_ocsp_response",
        lambda raw: _Unreadable(real_loader(raw), "signature_hash_algorithm", unknown),
    )
    outcome = evaluate_ocsp_response(data, leaf, pki.inter, now=NOW)
    assert outcome["ocsp"] == "error"
    assert outcome["ocsp_detail"] == f"response cannot be checked: {unknown}"


async def test_an_unreadable_ocsp_response_fails_only_its_endpoint(pki, responder, monkeypatch):
    rsa_leaf, ec_leaf = pki.leaves["rsa"].cert, pki.leaves["ec"].cert
    served = {"192.0.2.81": rsa_leaf, "192.0.2.82": ec_leaf}

    async def fake_handshake(host, port, server_name, context, timeout):
        chain = [
            cert.public_bytes(serialization.Encoding.DER) for cert in (served[host], pki.inter)
        ]
        return tls_check._Handshake(der=chain[0], version="TLSv1.3", cipher="X", chain_der=chain)

    real_loader = ocsp.load_der_ocsp_response

    def loader(raw: bytes) -> Any:
        response = real_loader(raw)
        if response.serial_number != rsa_leaf.serial_number:
            return response
        return _Unreadable(response, "signature_hash_algorithm", UnsupportedAlgorithm("unknown"))

    monkeypatch.setattr(tls_check, "tls_handshake", fake_handshake)
    monkeypatch.setattr(ocsp, "load_der_ocsp_response", loader)
    result = await run_step({"endpoints": ["192.0.2.81:443", "192.0.2.82:443"], "check_ocsp": True})
    unreadable, readable = result.output["endpoints"]
    assert (unreadable["ocsp"], unreadable["ocsp_detail"]) == (
        "error",
        "response cannot be checked: unknown",
    )
    assert readable["ocsp"] == "good", readable["ocsp_detail"]


def test_an_unreadable_crl_is_a_crl_error(pki):
    leaf = pki.leaves["crl_good"].cert
    crl = make_crl(pki.inter, pki.inter_key)
    bad_name = cast(
        x509.CertificateRevocationList, _Unreadable(crl, "issuer", ValueError("bad name"))
    )
    assert tls_certs.crl_signature_problem(bad_name, pki.inter) == "CRL cannot be checked: bad name"
    bad_date = cast(
        x509.CertificateRevocationList, _Unreadable(crl, "next_update_utc", ValueError("bad date"))
    )
    outcome = tls_certs.crl_status(
        bad_date, leaf, url="http://ca.example.test/inter.crl", names=frozenset(), now=NOW
    )
    assert (outcome["crl"], outcome["crl_detail"]) == ("error", "CRL cannot be read: bad date")


# --- Certificates the checks cannot read -----------------------------------------


#: A subject alternative name holding an x400Address, a name form the X.509
#: library refuses to read.
_X400_SAN = (
    x509.UnrecognizedExtension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, bytes.fromhex("3002a300")),
    False,
)


async def test_an_unreadable_alternative_name_does_not_stop_the_other_endpoints(pki, tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    odd = Leaf(issue("odd.example.test", key, extensions=(_X400_SAN,)), key, ())
    async with (
        tls_server(tmp_path, pki.leaves["rsa"]) as good_port,
        tls_server(tmp_path, odd) as odd_port,
    ):
        result = await run_step(
            {
                "endpoints": [f"127.0.0.1:{good_port}", f"127.0.0.1:{odd_port}"],
                "ca_bundle": pki.root_pem,
            }
        )
    good, odd_record = result.output["endpoints"]
    assert good["ok"] is True and good["subject_cn"] == "rsa.example.test"
    # The unreadable extension counts as absent; the rest of the certificate is reported.
    assert odd_record["error"] is None
    assert odd_record["fingerprint_sha256"] == fingerprint_of(odd.cert)
    assert (odd_record["subject_cn"], odd_record["sans"]) == ("odd.example.test", [])
    assert odd_record["hostname_ok"] is False


async def test_a_certificate_the_checks_cannot_read_is_its_endpoints_error(
    pki, tmp_path, monkeypatch
):
    unreadable = pki.leaves["ec"].cert
    real_fields = tls_certs.certificate_fields
    problem = x509.UnsupportedGeneralNameType("x400Address/EDIPartyName are not supported types")

    def fields(cert: x509.Certificate, *, now: datetime) -> dict[str, Any]:
        if cert == unreadable:
            raise problem
        return real_fields(cert, now=now)

    monkeypatch.setattr(tls_certs, "certificate_fields", fields)
    async with (
        tls_server(tmp_path, pki.leaves["rsa"]) as good_port,
        tls_server(tmp_path, pki.leaves["ec"]) as odd_port,
    ):
        result = await run_step(
            {
                "endpoints": [f"127.0.0.1:{good_port}", f"127.0.0.1:{odd_port}"],
                "ca_bundle": pki.root_pem,
                "check_ocsp": True,
            }
        )
    good, odd_record = result.output["endpoints"]
    assert good["ok"] is True, good["failures"]
    assert odd_record["error"] == f"cannot read the certificate: {problem}"
    assert set(odd_record) == set(good)
    assert all(odd_record[key] is None for key in tls_certs.CERTIFICATE_FIELDS)
    assert (odd_record["ocsp"], odd_record["hostname_ok"]) == (None, None)
    assert odd_record["reachable"] is True and odd_record["chain_ok"] is True
    assert result.success is False
    assert f"127.0.0.1:{odd_port} (cannot read the certificate" in (result.error or "")

    pasted = await run_step({"pem": pem_of(unreadable, pki.inter), "ca_bundle": pki.root_pem})
    [record] = pasted.output["endpoints"]
    assert record["error"] == f"cannot read the certificate: {problem}"
    assert record["fingerprint_sha256"] is None
    assert pasted.success is False
    assert "pem certificate (cannot read the certificate" in (pasted.error or "")


# --- Responses and lists without a next update ---------------------------------


def _undated_ocsp_response(pki: Pki, cert: x509.Certificate, produced: datetime) -> bytes:
    return (
        ocsp.OCSPResponseBuilder()
        .add_response(
            cert=cert,
            issuer=pki.inter,
            algorithm=hashes.SHA256(),
            cert_status=ocsp.OCSPCertStatus.GOOD,
            this_update=produced,
            next_update=None,
            revocation_time=None,
            revocation_reason=None,
        )
        .responder_id(ocsp.OCSPResponderEncoding.NAME, pki.inter)
        .sign(pki.inter_key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def test_an_ocsp_response_without_next_update_counts_for_a_limited_time(pki):
    leaf = pki.leaves["rsa"].cert
    fresh = _undated_ocsp_response(pki, leaf, NOW - timedelta(days=1))
    assert evaluate_ocsp_response(fresh, leaf, pki.inter, now=NOW)["ocsp"] == "good"
    produced = (NOW - tls_certs.MAX_UNDATED_AGE - timedelta(hours=1)).replace(microsecond=0)
    old = _undated_ocsp_response(pki, leaf, produced)
    outcome = evaluate_ocsp_response(old, leaf, pki.inter, now=NOW)
    assert outcome == {
        "ocsp": "error",
        "ocsp_detail": (
            "response names no next update and is older than 7 days "
            f"(produced {produced.strftime('%Y-%m-%dT%H:%M:%SZ')})"
        ),
        "revocation_time": None,
    }


class _Undated:
    """A real CRL that reads as if it named no next update and was issued at ``issued``."""

    def __init__(self, real: x509.CertificateRevocationList, issued: datetime) -> None:
        self._real = real
        self.next_update_utc = None
        self.last_update_utc = issued

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


def test_a_crl_without_next_update_counts_for_a_limited_time(pki):
    leaf = pki.leaves["crl_good"].cert
    crl = make_crl(pki.inter, pki.inter_key)

    def status(issued: datetime) -> dict[str, Any]:
        undated = cast(x509.CertificateRevocationList, _Undated(crl, issued))
        return tls_certs.crl_status(
            undated, leaf, url="http://ca.example.test/inter.crl", names=frozenset(), now=NOW
        )

    assert status(NOW - timedelta(days=1))["crl"] == "good"
    issued = (NOW - tls_certs.MAX_UNDATED_AGE - timedelta(hours=1)).replace(microsecond=0)
    outcome = status(issued)
    assert outcome["crl"] == "error"
    assert outcome["crl_detail"] == (
        "CRL names no next update and is older than 7 days "
        f"(produced {issued.strftime('%Y-%m-%dT%H:%M:%SZ')})"
    )
    assert outcome["crl_next_update"] is None
