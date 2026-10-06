# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""TlsProbeHandler: report and evaluate the TLS certificates endpoints serve.

The step connects to each endpoint twice: once permissively to read what the
server presents (certificate, protocol version, cipher), and once with a
verifying context to learn whether the chain validates. The host name is
checked locally against the certificate, so a chain verdict and a name
verdict never mask each other. A pasted certificate is evaluated offline the
same way. Revocation is checked on request, through OCSP and through the
issuer's CRL. The X.509 rules themselves live in :mod:`.tls_certs`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
import socket
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
from cryptography import x509
from pydantic import BaseModel, ConfigDict, Field, field_validator

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    InvalidConfigError,
    StepKind,
)
from hegemony_step_sdk.concurrency import for_each_target_device

from . import tls_certs
from .targets import all_probe_targets

logger = logging.getLogger(__name__)

#: Upper bound for ``max_parallel``.
MAX_PARALLEL_LIMIT = 50

#: Largest OCSP response or issuer certificate download the step reads.
MAX_FETCH_BYTES = 1024 * 1024

#: Largest CRL the step downloads.
MAX_CRL_BYTES = 20 * 1024 * 1024

#: Most bytes one run downloads in all (OCSP responses, issuer certificates
#: and CRLs together); a request past it is an error for its endpoint.
MAX_RUN_DOWNLOAD_BYTES = 64 * 1024 * 1024

#: Most CRL addresses tried for one certificate.
MAX_CRL_ADDRESSES = 3

#: Most caIssuers addresses tried for one certificate's issuer.
MAX_ISSUER_ADDRESSES = 3

#: Request extension that names what an HTTP request is for, in egress checks.
_EGRESS_KIND = "hegemony.egress_kind"

#: Endpoints named one by one in the step error before the rest are counted.
MAX_ERROR_ENDPOINTS = 20

#: A secret reference written bare (``vault://orgs/acme/secrets/tls/ca``)
#: rather than as a ``{{ secret('...') }}`` template.
_BARE_SECRET_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s'\"{}\\]+$")

#: Template syntax, which the host renders (``{{ secret('...') }}``).
_TEMPLATE_RE = re.compile(r"\{\{|\{%")

#: What a failed connection or handshake raises: ssl and timeout errors are
#: OSErrors, and a host name the IDNA codec cannot encode is a UnicodeError.
_DIAL_ERRORS = (OSError, EOFError, UnicodeError)


class TlsProbeConfig(BaseModel):
    """Config for ``probe.tls``."""

    model_config = ConfigDict(extra="allow")

    port: int = Field(
        default=443,
        ge=1,
        le=65535,
        title="Port",
        description=(
            "TCP port the step's targets are checked on. Endpoints listed below "
            "carry their own port. Defaults to 443."
        ),
        json_schema_extra={"x_placeholder": "443"},
    )
    sni: str = Field(
        default="",
        title="Server Name (SNI)",
        description=(
            "Host name sent to the step's targets during the handshake and checked "
            "against their certificates. Leave empty to use each target's address. "
            "With a pasted certificate, the name it is checked against."
        ),
        json_schema_extra={"x_placeholder": "portal.example.com"},
    )
    endpoints: list[str] | str = Field(
        default_factory=list,
        title="Endpoints",
        description=(
            "Further endpoints to check besides the step's targets, one per line as "
            "host:port or host:port:sni. Write IPv6 addresses in brackets, such as "
            "[2001:db8::1]:443. A template that renders a comma- or newline-separated "
            "list works too. At most 500 endpoints per step."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_rows": 3,
            "x_col_span": 2,
            "x_placeholder": "portal.example.com:443\n192.0.2.10:8443:device.example.com",
        },
    )
    pem: str = Field(
        default="",
        title="Certificate PEM",
        description=(
            "Check this certificate instead of connecting anywhere: paste PEM text "
            "with the server certificate first, then any chain certificates. Cannot "
            "be combined with targets or endpoints."
        ),
        json_schema_extra={
            "x_rows": 6,
            "x_col_span": 2,
            "x_placeholder": "-----BEGIN CERTIFICATE-----",
            "x_advanced": True,
        },
    )
    attempt_timeout_seconds: int = Field(
        default=10,
        ge=1,
        le=300,
        title="Timeout (sec)",
        description=(
            "Time limit for each connection and handshake, and for each OCSP "
            "request and download including its whole response, in seconds. "
            "Defaults to 10."
        ),
    )
    require_reachable: bool = Field(
        default=True,
        title="Require reachable",
        description=(
            "Fail the step when an endpoint cannot be reached or completes no TLS "
            "handshake. Turn off to report unreachable endpoints without failing."
        ),
    )
    min_days_left: int | None = Field(
        default=None,
        title="Minimum days left",
        description=(
            "Fail the step when a certificate expires in fewer whole days than this. "
            "0 fails only expired certificates; leave empty to never fail on expiry."
        ),
        json_schema_extra={"x_placeholder": "30"},
    )
    require_valid_chain: bool = Field(
        default=False,
        title="Require valid chain",
        description=(
            "Fail the step when a certificate does not chain to a trusted CA: the "
            "worker's system trust store, or only the CA bundle when one is set."
        ),
    )
    require_hostname_match: bool = Field(
        default=False,
        title="Require host name match",
        description=(
            "Fail the step when a certificate is not valid for the name it was "
            "reached by (the SNI name, or else the endpoint's host or address)."
        ),
    )
    expected_fingerprint: str = Field(
        default="",
        title="Expected fingerprint",
        description=(
            "SHA-256 fingerprint every certificate must have; colons and case are "
            "ignored. A certificate with any other fingerprint fails the step."
        ),
        json_schema_extra={"x_placeholder": "AB:CD:...", "x_col_span": 2},
    )
    expected_fingerprints: dict[str, str] = Field(
        default_factory=dict,
        title="Expected fingerprints per endpoint",
        description=(
            "host:port=fingerprint or host:port:sni=fingerprint, one per line. Overrides "
            "Expected fingerprint for the endpoints it names: an entry with a server name "
            "applies only to that name, one without to every server name on that host "
            "and port."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_rows": 2,
            "x_col_span": 2,
            "x_placeholder": "portal.example.com:443=AB:CD:...",
            "x_advanced": True,
        },
    )
    ca_bundle: str = Field(
        default="",
        title="CA bundle",
        description=(
            "PEM certificates to trust instead of the worker's system store when "
            "validating chains, or a secret reference holding them (a bare "
            "reference or a secret() template)."
        ),
        json_schema_extra={
            "x_rows": 4,
            "x_col_span": 2,
            "x_placeholder": "vault://orgs/acme/secrets/tls/internal-ca",
            "x_advanced": True,
        },
    )
    check_ocsp: bool = Field(
        default=False,
        title="Check OCSP",
        description=(
            "Ask each certificate's OCSP responder whether it has been revoked. "
            "Needs the worker to reach the responder named in the certificate."
        ),
    )
    require_ocsp_good: bool = Field(
        default=False,
        title="Require OCSP good",
        description=(
            "With Check OCSP on, fail the step unless the responder reports every "
            "certificate good (revoked, unknown, or no answer fails)."
        ),
        json_schema_extra={"x_show_when": {"field": "check_ocsp", "value": True}},
    )
    check_crl: bool = Field(
        default=False,
        title="Check CRL",
        description=(
            "Download each certificate's certificate revocation list (CRL) from the "
            "address the certificate names and look the certificate up in it. Needs "
            "the worker to reach that address."
        ),
    )
    require_crl_good: bool = Field(
        default=False,
        title="Require CRL good",
        description=(
            "With Check CRL on, fail the step unless a current CRL signed by the issuer "
            "leaves every certificate off (revoked, a stale or unverifiable list, or no "
            "list fails)."
        ),
        json_schema_extra={"x_show_when": {"field": "check_crl", "value": True}},
    )
    warn_days: list[int] = Field(
        default_factory=lambda: [30, 14, 7],
        title="Warning windows (days)",
        description=(
            "Day counts, one per line, for the expiry counters in the output "
            "summary (warn_30 counts certificates with fewer than 30 days left). "
            "They never fail the step."
        ),
        json_schema_extra={"x_widget": "commands", "x_rows": 2, "x_advanced": True},
    )
    include_pem: bool = Field(
        default=False,
        title="Include certificate PEM",
        description=(
            "Add each served certificate as PEM text to the step output, for later "
            "steps that store or compare it."
        ),
        json_schema_extra={"x_advanced": True},
    )
    max_parallel: int = Field(
        default=10,
        ge=1,
        le=MAX_PARALLEL_LIMIT,
        title="Parallel checks",
        description="How many endpoints are checked at the same time (1-50). Defaults to 10.",
        json_schema_extra={"x_advanced": True},
    )

    @field_validator("warn_days")
    @classmethod
    def _non_negative_windows(cls, value: list[int]) -> list[int]:
        """Refuse negative warning windows."""
        if any(days < 0 for days in value):
            raise ValueError("warning windows must be 0 or more days")
        return value


def is_bare_secret_ref(value: str) -> bool:
    """Whether ``value`` is a bare secret reference like ``vault://path/key``."""
    return bool(_BARE_SECRET_REF_RE.match(value.strip()))


def _templated(value: Any) -> bool:
    """Whether ``value`` (or any item or key inside it) still holds template syntax."""
    if isinstance(value, str):
        return bool(_TEMPLATE_RE.search(value))
    if isinstance(value, list | tuple):
        return any(_templated(item) for item in value)
    if isinstance(value, dict):
        return any(_templated(key) or _templated(item) for key, item in value.items())
    return False


async def resolve_ca_bundle(ctx: HandlerContext, raw: str) -> str:
    """The CA bundle as PEM text.

    ``ca_bundle`` is a raw config key, so it arrives as written: a bare
    reference resolves through the host as ``{{ secret('<reference>') }}``,
    a template renders through the host as written, and anything else is PEM
    text used as is. Raises ``ValueError`` when a reference resolves to nothing.
    """
    text = (raw or "").strip()
    if not text:
        return ""
    bare = is_bare_secret_ref(text)
    if bare:
        template = "{{ secret('" + text + "') }}"
    elif _TEMPLATE_RE.search(text):
        template = text
    else:
        return text
    value = await ctx.require_services().resolve_secret_ref(template, source="probe.tls.ca_bundle")
    if not value or not value.strip():
        raise ValueError("the CA bundle reference resolved to an empty value")
    return value


def observe_context() -> ssl.SSLContext:
    """Client context that accepts any certificate and any protocol the library offers.

    Reading what a server presents is observation, so the step completes the
    handshake even with outdated servers; whether the chain verifies is
    judged separately with :func:`verify_context`.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(ValueError, ssl.SSLError):
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    with contextlib.suppress(ssl.SSLError):
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    return context


def verify_context(ca_pem: str | None) -> ssl.SSLContext:
    """Verifying client context: the system store, or only ``ca_pem`` when given.

    The host name is not checked here (it is checked locally), strict X.509
    mode is off so the verdict does not depend on the Python version, and
    every trusted certificate counts as an anchor, an intermediate included -
    the same rules the offline validator applies to a pasted certificate.
    """
    context = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
    context.check_hostname = False
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    strict = getattr(ssl, "VERIFY_X509_STRICT", 0)
    context.verify_flags &= ~strict
    return context


@dataclass(slots=True)
class _Handshake:
    """What one completed handshake showed."""

    der: bytes | None
    version: str | None
    cipher: str | None
    chain_der: list[bytes] = field(default_factory=list)


async def tls_handshake(
    host: str,
    port: int,
    server_name: str | None,
    context: ssl.SSLContext,
    timeout: float,
) -> _Handshake:
    """Connect, complete a TLS handshake, record what the server presented, close."""

    async def _run() -> _Handshake:
        """Open the connection, record the handshake, and close it again."""
        _reader, writer = await asyncio.open_connection(
            host,
            port,
            ssl=context,
            server_hostname=server_name or "",
            ssl_handshake_timeout=timeout,
        )
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                raise ssl.SSLError("no TLS session was established")
            cipher = ssl_object.cipher()
            chain: list[bytes] = []
            get_chain = getattr(ssl_object, "get_unverified_chain", None)
            if callable(get_chain):
                with contextlib.suppress(Exception):
                    chain = [item for item in (get_chain() or []) if isinstance(item, bytes)]
            return _Handshake(
                der=ssl_object.getpeercert(binary_form=True),
                version=ssl_object.version(),
                cipher=cipher[0] if cipher else None,
                chain_der=chain,
            )
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), 1.0)

    return await asyncio.wait_for(_run(), timeout)


def describe_dial_error(exc: BaseException, timeout: float) -> str:
    """Short human reason for a failed connection or handshake."""
    if isinstance(exc, TimeoutError):
        return f"timed out after {timeout:g}s"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return exc.verify_message or str(exc)
    if isinstance(exc, ssl.SSLError):
        return f"TLS handshake failed: {exc.reason or exc}"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused"
    if isinstance(exc, socket.gaierror):
        return f"cannot resolve host: {exc.strerror or exc}"
    if isinstance(exc, UnicodeError):
        return f"invalid host name: {exc}"
    if isinstance(exc, OSError) and exc.strerror:
        return exc.strerror
    return str(exc) or type(exc).__name__


class _FetchError(Exception):
    """An OCSP request or a download that returned something unusable."""


@dataclass
class _Settings:
    """The step's validated settings, with fingerprints normalised."""

    config: TlsProbeConfig
    expected_default: str | None
    expected_by_endpoint: dict[tuple[str, int, str], str]

    @classmethod
    def from_config(cls, config: TlsProbeConfig) -> _Settings:
        """Settings from a validated config, with every expected fingerprint normalised."""
        expected_default = (
            tls_certs.normalize_fingerprint(config.expected_fingerprint)
            if config.expected_fingerprint.strip()
            else None
        )
        by_endpoint: dict[tuple[str, int, str], str] = {}
        for key, value in config.expected_fingerprints.items():
            spec = tls_certs.parse_endpoint(key, default_port=config.port)
            host, port = tls_certs.endpoint_key(spec.host, spec.port)
            by_endpoint[(host, port, _sni_key(spec.sni))] = tls_certs.normalize_fingerprint(value)
        return cls(config, expected_default, by_endpoint)

    def expected_for(self, host: str | None, port: int | None, sni: str | None) -> str | None:
        """The fingerprint expected at ``host:port`` with server name ``sni``.

        An entry naming this server name wins, then an entry for the host and
        port without one, then Expected fingerprint; None when none applies.
        """
        if host and port:
            endpoint = tls_certs.endpoint_key(host, port)
            for name in (_sni_key(sni), ""):
                override = self.expected_by_endpoint.get((*endpoint, name))
                if override is not None:
                    return override
        return self.expected_default


def _sni_key(sni: str | None) -> str:
    """Comparable form of a server name for fingerprint overrides (empty when none)."""
    return (sni or "").strip().rstrip(".").lower()


class _TlsRun:
    """One step execution: shared contexts, trust anchors, and the revocation client."""

    def __init__(
        self,
        settings: _Settings,
        *,
        now: datetime,
        enforce: Callable[..., Awaitable[Any]] | None,
        bundle_anchors: list[x509.Certificate] | None,
        bundle_pem: str | None,
    ) -> None:
        """Hold the settings and trust anchors for one run; contexts are built on first use."""
        self.settings = settings
        self.config = settings.config
        self.now = now
        self.enforce = enforce
        self.bundle_anchors = bundle_anchors
        self.bundle_pem = bundle_pem
        self.timeout = float(self.config.attempt_timeout_seconds)
        self.client: httpx.AsyncClient | None = None
        self._observe: ssl.SSLContext | None = None
        self._verify: ssl.SSLContext | None = None
        # Endpoints often share an issuer and its CRL: each issuer file is
        # downloaded and parsed once per run, and each CRL once per run and
        # issuer. A CRL is kept only once its signature verified; for one
        # that did not, only the reason is.
        self._issuer_files: dict[str, asyncio.Future[list[x509.Certificate]]] = {}
        self._crls: dict[tuple[str, str], asyncio.Future[x509.CertificateRevocationList | str]] = {}
        self.downloaded = 0

    # --- records ---------------------------------------------------------

    def blank_record(self, plan: dict[str, Any]) -> dict[str, Any]:
        """An endpoint record with every key present and nothing determined yet."""
        record: dict[str, Any] = {
            "source": plan["source"],
            "host": plan["host"],
            "port": plan["port"],
            "sni": plan["sni"],
            "device_id": plan["device_id"],
            "device_name": plan["device_name"],
            "reachable": None,
            "error": None,
            "tls_version": None,
            "cipher": None,
            "chain_ok": None,
            "chain_error": None,
            "hostname_ok": None,
            "matches_expected": None,
            "ocsp": None,
            "ocsp_detail": None,
            "revocation_time": None,
            "crl": None,
            "crl_detail": None,
            "crl_url": None,
            "crl_next_update": None,
            "crl_revocation_time": None,
            **tls_certs.empty_certificate_fields(),
        }
        if self.config.include_pem:
            record["certificate_pem"] = None
        record["ok"] = True
        record["failures"] = []
        return record

    async def describe(
        self,
        record: dict[str, Any],
        leaf: x509.Certificate,
        *,
        hostname: str | None,
        issuer_candidates: list[x509.Certificate],
    ) -> None:
        """Fill the certificate fields and every verdict except the chain's.

        The record changes only once everything is known, so a certificate
        the checks cannot read leaves it as it was; the caller records why.
        """
        found = tls_certs.certificate_fields(leaf, now=self.now)
        if self.config.include_pem:
            found["certificate_pem"] = tls_certs.certificate_pem(leaf)
        if hostname:
            dns_names, ip_addresses = tls_certs.san_names(leaf)
            found["hostname_ok"] = tls_certs.hostname_matches(
                hostname, dns_names, ip_addresses, tls_certs.common_name(leaf)
            )
        expected = self.settings.expected_for(record["host"], record["port"], record["sni"])
        if expected is not None:
            found["matches_expected"] = found["fingerprint_sha256"] == expected
        if self.config.check_ocsp:
            found.update(await self.check_ocsp(leaf, issuer_candidates))
        if self.config.check_crl:
            found.update(await self.check_crl(leaf, issuer_candidates))
        record.update(found)

    # --- live endpoints --------------------------------------------------

    def observe_context(self) -> ssl.SSLContext:
        """The permissive context for the first handshake, built once per run."""
        if self._observe is None:
            self._observe = observe_context()
        return self._observe

    def verify_context(self) -> ssl.SSLContext:
        """The verifying context for the second handshake, built once per run."""
        if self._verify is None:
            self._verify = verify_context(self.bundle_pem)
        return self._verify

    async def probe_endpoint(self, plan: dict[str, Any]) -> dict[str, Any]:
        """Check one live endpoint: egress gate, both handshakes, then the certificate's details."""
        record = self.blank_record(plan)
        host: str | None = plan["host"]
        port: int = plan["port"]
        if not host:
            record["reachable"] = False
            record["error"] = "target has no management address"
            return record
        server_name = plan["sni"] or host
        sent_sni = None if tls_certs.is_ip_literal(server_name) else server_name
        record["sni"] = sent_sni
        # The step opens its own sockets rather than going through
        # services.run_probe, so it walks the flow's egress gate itself. Outside
        # any try: a denial is the step's error, not an unreachable endpoint.
        if self.enforce is not None:
            await self.enforce(host, port, proto="tcp", kind="tls probe")
        address = host.strip("[]")
        try:
            seen = await tls_handshake(
                address, port, sent_sni, self.observe_context(), self.timeout
            )
        except _DIAL_ERRORS as exc:
            record["reachable"] = False
            record["error"] = describe_dial_error(exc, self.timeout)
            return record
        record["reachable"] = True
        record["tls_version"] = seen.version
        record["cipher"] = seen.cipher
        if not seen.der:
            record["error"] = "the server presented no certificate"
            return record
        try:
            leaf = x509.load_der_x509_certificate(seen.der)
        except ValueError as exc:
            record["error"] = f"cannot parse the served certificate: {exc}"
            return record

        try:
            verified = await tls_handshake(
                address, port, sent_sni, self.verify_context(), self.timeout
            )
        except ssl.SSLCertVerificationError as exc:
            record["chain_ok"] = False
            record["chain_error"] = exc.verify_message or str(exc)
        except _DIAL_ERRORS as exc:
            record["chain_error"] = (
                f"verifying handshake failed: {describe_dial_error(exc, self.timeout)}"
            )
        else:
            if verified.der == seen.der:
                record["chain_ok"] = True
            else:
                # A verdict on another certificate says nothing about the one described.
                record["chain_error"] = (
                    "the server presented a different certificate to the verifying "
                    "handshake, so the chain of the reported one was not verified"
                )

        served_chain: list[x509.Certificate] = []
        for der in seen.chain_der[1:]:
            with contextlib.suppress(ValueError):
                served_chain.append(x509.load_der_x509_certificate(der))
        try:
            await self.describe(
                record,
                leaf,
                hostname=server_name,
                issuer_candidates=served_chain + list(self.bundle_anchors or []),
            )
        except tls_certs._UNREADABLE as exc:
            record["error"] = _unreadable_reason(exc)
        return record

    # --- pasted certificate ----------------------------------------------

    async def evaluate_pem(
        self, plan: dict[str, Any], certs: list[x509.Certificate]
    ) -> dict[str, Any]:
        """Check a pasted certificate and chain offline, against the CA bundle or the system store."""
        record = self.blank_record(plan)
        leaf, chain = certs[0], certs[1:]
        anchors = self.bundle_anchors
        if anchors is None:
            anchors = await asyncio.to_thread(tls_certs.load_system_anchors)
        if anchors:
            # The path search is CPU-bound (signature checks), so it runs off the event loop.
            record["chain_ok"], record["chain_error"] = await asyncio.to_thread(
                tls_certs.verify_chain_offline, leaf, chain, anchors, now=self.now
            )
        else:
            record["chain_error"] = (
                "no trust anchors: the worker's system trust store could not be "
                "loaded; set a CA bundle"
            )
        try:
            await self.describe(
                record, leaf, hostname=plan["sni"], issuer_candidates=chain + list(anchors)
            )
        except tls_certs._UNREADABLE as exc:
            record["error"] = _unreadable_reason(exc)
        return record

    # --- revocation: shared HTTP ------------------------------------------

    async def _authorize(self, request: httpx.Request) -> None:
        """Walk every revocation-related request past the flow's egress gate."""
        if self.enforce is None:
            return
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        kind = str(request.extensions.get(_EGRESS_KIND) or "connection")
        await self.enforce(request.url.host, port, proto="tcp", kind=kind)

    async def fetch(
        self,
        method: str,
        url: str,
        *,
        kind: str,
        limit: int = MAX_FETCH_BYTES,
        content: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> bytes:
        """One revocation-related HTTP request: the body of a 200 response, capped at ``limit``.

        ``kind`` names the request in the egress check (``ocsp check``,
        ``issuer download``, ``crl download``). The whole exchange, the body
        included, must finish within the attempt timeout: the client's own
        timeouts bound each read, which a responder that trickles its answer
        never trips.
        """
        if self.client is None:
            raise _FetchError("the revocation client is not open")
        if self.downloaded >= MAX_RUN_DOWNLOAD_BYTES:
            raise self._download_limit_reached()
        chunks: list[bytes] = []
        try:
            async with (
                asyncio.timeout(self.timeout),
                self.client.stream(
                    method, url, content=content, headers=headers, extensions={_EGRESS_KIND: kind}
                ) as response,
            ):
                if response.status_code != 200:
                    raise _FetchError(f"HTTP {response.status_code} from {url}")
                total = 0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > limit:
                        raise _FetchError(f"response from {url} exceeds {limit} bytes")
                    self.downloaded += len(chunk)
                    if self.downloaded > MAX_RUN_DOWNLOAD_BYTES:
                        raise self._download_limit_reached()
                    chunks.append(chunk)
        except TimeoutError:
            raise _FetchError(f"timed out after {self.timeout:g}s") from None
        return b"".join(chunks)

    @staticmethod
    def _download_limit_reached() -> _FetchError:
        """The error for a request past the run's download limit."""
        return _FetchError(
            f"the step's downloads reached their limit of {MAX_RUN_DOWNLOAD_BYTES} bytes"
        )

    async def _once(
        self,
        cache: dict[Any, asyncio.Future[Any]],
        key: Any,
        make: Callable[[], Awaitable[Any]],
    ) -> Any:
        """``await make()`` once per ``key`` and run; later callers share its result or error.

        The shared work is shielded, so one endpoint's cancellation does not
        cancel it for the others.
        """
        future = cache.get(key)
        if future is None:
            future = asyncio.ensure_future(make())
            cache[key] = future
        return await asyncio.shield(future)

    def close(self) -> None:
        """Cancel shared downloads nobody waits for any more."""
        for cache in (self._issuer_files, self._crls):
            for future in cache.values():
                if not future.done():
                    future.cancel()

    async def issuer_of(
        self, cert: x509.Certificate, candidates: list[x509.Certificate]
    ) -> tuple[x509.Certificate | None, str]:
        """The issuer of ``cert`` from ``candidates`` or downloaded, else None and why not."""
        issuer = tls_certs.find_issuer(cert, candidates)
        if issuer is not None:
            return issuer, ""
        problem = ""
        for url in tls_certs.ca_issuer_urls(cert)[:MAX_ISSUER_ADDRESSES]:
            try:
                downloaded = await self._once(
                    self._issuer_files, url, lambda url=url: self._load_issuer_file(url)
                )
            except (httpx.HTTPError, httpx.InvalidURL, _FetchError) as exc:
                problem = f"; downloading {url} failed: {_http_reason(exc)}"
                continue
            issuer = tls_certs.find_issuer(cert, downloaded)
            if issuer is not None:
                return issuer, ""
            problem = f"; {url} did not hold the issuer"
        return None, "the issuer certificate is not available" + problem

    async def _load_issuer_file(self, url: str) -> list[x509.Certificate]:
        """Download the certificates at a caIssuers ``url`` and parse them off the event loop."""
        data = await self.fetch("GET", url, kind="issuer download")
        return await asyncio.to_thread(tls_certs.load_certificates_any, data)

    # --- OCSP ------------------------------------------------------------

    async def check_ocsp(
        self, cert: x509.Certificate, candidates: list[x509.Certificate]
    ) -> dict[str, Any]:
        """The OCSP status of ``cert``, finding its issuer among ``candidates`` or by download."""
        urls = tls_certs.ocsp_responder_urls(cert)
        if not urls:
            return tls_certs.ocsp_outcome("unavailable", "the certificate names no OCSP responder")
        issuer, problem = await self.issuer_of(cert, candidates)
        if issuer is None:
            return tls_certs.ocsp_outcome("unavailable", problem)
        url = urls[0]
        try:
            data = await self.fetch(
                "POST",
                url,
                kind="ocsp check",
                content=tls_certs.build_ocsp_request(cert, issuer),
                headers={
                    "Content-Type": "application/ocsp-request",
                    "Accept": "application/ocsp-response",
                },
            )
        except (httpx.HTTPError, httpx.InvalidURL, _FetchError) as exc:
            return tls_certs.ocsp_outcome(
                "error", f"OCSP request to {url} failed: {_http_reason(exc)}"
            )
        return tls_certs.evaluate_ocsp_response(data, cert, issuer, now=self.now)

    # --- CRL -------------------------------------------------------------

    async def _load_crl(
        self, url: str, issuer: x509.Certificate
    ) -> x509.CertificateRevocationList | str:
        """The CRL at ``url`` if ``issuer`` signed it, else why it cannot be used.

        Parsed and checked off the event loop, since CRLs can be large.
        """
        data = await self.fetch("GET", url, kind="crl download", limit=MAX_CRL_BYTES)
        return await asyncio.to_thread(tls_certs.load_checked_crl, data, issuer)

    async def check_crl(
        self, cert: x509.Certificate, candidates: list[x509.Certificate]
    ) -> dict[str, Any]:
        """The CRL status of ``cert``: looked up in the issuer's list from the address it names.

        Each address, up to ``MAX_CRL_ADDRESSES``, is tried in turn until one
        gives an answer (good or revoked); otherwise the first address's
        problem is reported.
        """
        locations, missing = tls_certs.crl_locations(cert)
        if not locations:
            return tls_certs.crl_outcome("unavailable", missing)
        issuer, problem = await self.issuer_of(cert, candidates)
        if issuer is None:
            return tls_certs.crl_outcome("unavailable", problem)
        outcomes: list[dict[str, Any]] = []
        for location in locations[:MAX_CRL_ADDRESSES]:
            outcome = await self._crl_outcome(location, cert, issuer)
            if outcome["crl"] in ("good", "revoked"):
                return outcome
            outcomes.append(outcome)
        return outcomes[0]

    async def _crl_outcome(
        self, location: tls_certs.CrlLocation, cert: x509.Certificate, issuer: x509.Certificate
    ) -> dict[str, Any]:
        """``cert`` judged against the CRL at one address."""
        url = location.url
        key = (url, tls_certs.fingerprint_sha256(issuer))
        try:
            crl = await self._once(self._crls, key, lambda: self._load_crl(url, issuer))
        except (httpx.HTTPError, httpx.InvalidURL, _FetchError) as exc:
            return tls_certs.crl_outcome(
                "error", f"downloading the CRL failed: {_http_reason(exc)}", url=url
            )
        except ValueError as exc:
            return tls_certs.crl_outcome("error", f"the CRL cannot be parsed: {exc}", url=url)
        if isinstance(crl, str):
            return tls_certs.crl_outcome("error", crl, url=url)
        return tls_certs.crl_status(crl, cert, url=url, names=location.names, now=self.now)

    # --- verdicts --------------------------------------------------------

    def assess(self, record: dict[str, Any]) -> None:
        """Apply the enabled assertions; sets ``ok`` and ``failures``."""
        config = self.config
        reasons: list[str] = []
        has_certificate = record["fingerprint_sha256"] is not None
        if record["source"] == "pem":
            if not has_certificate:
                reasons.append(record["error"] or "no certificate")
        else:
            if not record["host"]:
                reasons.append(record["error"] or "no address")
            elif record["reachable"] is False:
                if config.require_reachable:
                    reasons.append(f"unreachable: {record['error']}")
            elif not has_certificate and config.require_reachable:
                reasons.append(record["error"] or "no certificate")
        if has_certificate:
            if config.min_days_left is not None and record["days_left"] < config.min_days_left:
                if record["expired"]:
                    reasons.append(f"expired on {record['not_after']}")
                else:
                    reasons.append(
                        f"{record['days_left']} days left (minimum {config.min_days_left})"
                    )
            if config.require_valid_chain and record["chain_ok"] is not True:
                prefix = "chain not valid" if record["chain_ok"] is False else "chain not verified"
                reasons.append(f"{prefix}: {record['chain_error']}")
            if config.require_hostname_match and record["hostname_ok"] is not True:
                if record["hostname_ok"] is None:
                    reasons.append("no host name to check (set Server Name)")
                else:
                    name = record["sni"] or record["host"]
                    reasons.append(f"certificate is not valid for {name}")
            if record["matches_expected"] is False:
                reasons.append("fingerprint does not match the expected one")
            if config.check_ocsp and config.require_ocsp_good and record["ocsp"] != "good":
                reasons.append(f"OCSP {record['ocsp']}: {record['ocsp_detail']}")
            if config.check_crl and config.require_crl_good and record["crl"] != "good":
                reasons.append(f"CRL {record['crl']}: {record['crl_detail']}")
        record["failures"] = reasons
        record["ok"] = not reasons


def _unreadable_reason(exc: BaseException) -> str:
    """The endpoint error for a certificate the checks cannot read."""
    return f"cannot read the certificate: {exc}"


def _http_reason(exc: BaseException) -> str:
    """A short reason for a failed revocation-related HTTP request."""
    text = str(exc)
    if isinstance(exc, _FetchError):
        return text
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _plural(count: int, word: str) -> str:
    """``count`` followed by ``word``, pluralised with ``s`` unless the count is 1."""
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def summarize(records: list[dict[str, Any]], warn_days: list[int]) -> dict[str, Any]:
    """The output ``summary``: counts over every endpoint record."""
    days = [record["days_left"] for record in records if record["days_left"] is not None]
    summary: dict[str, Any] = {
        "total": len(records),
        "reachable": sum(record["reachable"] is True for record in records),
        "unreachable": sum(record["reachable"] is False for record in records),
        "expired": sum(record["expired"] is True for record in records),
        "chain_failures": sum(record["chain_ok"] is False for record in records),
        "hostname_failures": sum(record["hostname_ok"] is False for record in records),
        "mismatches": sum(record["matches_expected"] is False for record in records),
        "ocsp_revoked": sum(record["ocsp"] == "revoked" for record in records),
        "crl_revoked": sum(record["crl"] == "revoked" for record in records),
        "failed": sum(not record["ok"] for record in records),
    }
    for window in sorted(set(warn_days), reverse=True):
        summary[f"warn_{window}"] = sum(value < window for value in days)
    summary["min_days_left"] = min(days) if days else None
    return summary


def _config_error(message: str) -> HandlerResult:
    """A failed result for a configuration problem found at run time."""
    return HandlerResult(success=False, error=message, summary="TLS check configuration error")


def _endpoint_plans(
    ctx: HandlerContext, config: TlsProbeConfig, listed: list[tls_certs.EndpointSpec]
) -> list[dict[str, Any]]:
    """Targets first, then listed endpoints, without repeating an endpoint."""
    plans: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    target_sni = config.sni.strip() or None

    def _add(plan: dict[str, Any]) -> None:
        """Append ``plan`` unless the same host, port and SNI is already planned."""
        if plan["host"]:
            host, port = tls_certs.endpoint_key(plan["host"], plan["port"])
            key = (host, port, (plan["sni"] or "").lower())
            if key in seen:
                return
            seen.add(key)
        plans.append(plan)

    for device in all_probe_targets(ctx):
        host = str(device.get("mgmt_host") or "").strip() or None
        _add(
            {
                "source": "target",
                "host": host,
                "port": config.port,
                "sni": target_sni,
                # None for a direct-IP target: it has no inventory identity, and
                # the artifact column behind evidence device_id is a UUID.
                "device_id": device.get("id"),
                "device_name": device.get("name") or device.get("id") or host,
            }
        )
    for spec in listed:
        _add(
            {
                "source": "endpoint",
                "host": spec.host,
                "port": spec.port,
                "sni": spec.sni,
                "device_id": None,
                "device_name": None,
            }
        )
    return plans


class TlsProbeHandler(BaseHandler):
    """Report the TLS certificate each endpoint serves and evaluate it."""

    handler_id = "probe.tls"
    supported_kinds = [StepKind.CHECK]
    display_name = "TLS Certificate Check"
    description = (
        "Read the TLS certificate endpoints serve and check expiry, chain, host name, "
        "and fingerprint."
    )
    category = "Checks"
    config_model = TlsProbeConfig
    default_config = {"port": 443, "attempt_timeout_seconds": 10, "require_reachable": True}
    # The CA bundle may be a secret reference; it is resolved here, not by the
    # step template engine, so a bare reference is understood too.
    raw_config_keys = frozenset({"ca_bundle"})

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate the step's fields; templated values are checked once rendered."""
        errors = super().validate_config(config)
        if errors:
            return errors
        port = int(config.get("port") or 443)
        endpoints = config.get("endpoints")
        has_endpoints = False
        if not _templated(endpoints):
            try:
                specs = tls_certs.parse_endpoints(endpoints, default_port=port)
            except ValueError as exc:
                errors.append(f"endpoints: {exc}")
            else:
                has_endpoints = bool(specs)
                if len(specs) > tls_certs.MAX_ENDPOINTS:
                    errors.append(f"endpoints: at most {tls_certs.MAX_ENDPOINTS} are allowed")
        pem = config.get("pem") or ""
        if isinstance(pem, str) and pem.strip() and not _templated(pem):
            if has_endpoints:
                errors.append("pem: a pasted certificate cannot be combined with endpoints")
            try:
                pasted = tls_certs.load_pem_certificates(pem)
            except ValueError as exc:
                errors.append(f"pem: {exc}")
            else:
                if not pasted:
                    errors.append("pem: no PEM certificate found")
                elif len(pasted) > tls_certs.MAX_PEM_CERTIFICATES:
                    errors.append(
                        f"pem: at most {tls_certs.MAX_PEM_CERTIFICATES} certificates are allowed"
                    )
        fingerprint = config.get("expected_fingerprint") or ""
        if isinstance(fingerprint, str) and fingerprint.strip() and not _templated(fingerprint):
            try:
                tls_certs.normalize_fingerprint(fingerprint)
            except ValueError as exc:
                errors.append(f"expected_fingerprint: {exc}")
        for key, value in (config.get("expected_fingerprints") or {}).items():
            if _templated(key) or _templated(value):
                continue
            try:
                tls_certs.parse_endpoint(key, default_port=port)
                tls_certs.normalize_fingerprint(value)
            except ValueError as exc:
                errors.append(f"expected_fingerprints.{key}: {exc}")
        ca_bundle = config.get("ca_bundle") or ""
        if (
            isinstance(ca_bundle, str)
            and ca_bundle.strip()
            and not _templated(ca_bundle)
            and not is_bare_secret_ref(ca_bundle)
        ):
            try:
                if not tls_certs.load_pem_certificates(ca_bundle):
                    errors.append("ca_bundle: no PEM certificate found")
            except ValueError as exc:
                errors.append(f"ca_bundle: {exc}")
        return errors

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Check every planned endpoint (or the pasted certificate) and assess the results."""
        try:
            config = self.parse_config(ctx.config, TlsProbeConfig)
        except InvalidConfigError as exc:
            return exc.result()
        try:
            settings = _Settings.from_config(config)
            listed = tls_certs.parse_endpoints(config.endpoints, default_port=config.port)
        except ValueError as exc:
            return _config_error(f"Invalid configuration: {exc}")

        pem_text = config.pem.strip()
        try:
            supplied = tls_certs.load_pem_certificates(pem_text) if pem_text else []
        except ValueError as exc:
            return _config_error(f"Invalid certificate PEM: {exc}")
        if pem_text and not supplied:
            return _config_error("Invalid certificate PEM: no PEM certificate found")
        if len(supplied) > tls_certs.MAX_PEM_CERTIFICATES:
            return _config_error(
                f"Invalid certificate PEM: {len(supplied)} certificates "
                f"(at most {tls_certs.MAX_PEM_CERTIFICATES})"
            )

        plans = _endpoint_plans(ctx, config, listed)
        if supplied and plans:
            return _config_error(
                "A pasted certificate PEM cannot be combined with targets or endpoints"
            )
        if not supplied and not plans:
            return HandlerResult(
                success=False,
                error="No target devices, IPs, endpoints, or certificate PEM configured",
                summary="Missing targets",
            )
        if len(plans) > tls_certs.MAX_ENDPOINTS:
            return _config_error(
                f"Too many endpoints: {len(plans)} (at most {tls_certs.MAX_ENDPOINTS})"
            )

        try:
            bundle_text = await resolve_ca_bundle(ctx, config.ca_bundle)
            bundle_anchors = tls_certs.load_pem_certificates(bundle_text) if bundle_text else None
        except ValueError as exc:
            return _config_error(f"Invalid CA bundle: {exc}")
        if bundle_text and not bundle_anchors:
            return _config_error("Invalid CA bundle: no PEM certificate found")
        bundle_pem = tls_certs.certificates_to_pem(bundle_anchors) if bundle_anchors else None

        checks_revocation = config.check_ocsp or config.check_crl
        needs_network = bool(plans) or checks_revocation
        enforce = getattr(ctx.require_services(), "enforce_egress", None) if needs_network else None
        if needs_network and enforce is None:
            # Fail closed: the step dials every destination itself, so without
            # the gate nothing would apply the flow's network policy.
            return _config_error(
                "this platform cannot apply the flow's network policy to the step's "
                "connections; only a pasted certificate without revocation checks can run"
            )
        run = _TlsRun(
            settings,
            now=datetime.now(UTC),
            enforce=enforce,
            bundle_anchors=bundle_anchors,
            bundle_pem=bundle_pem,
        )
        if bundle_pem is not None and plans:
            try:
                run.verify_context()
            except ssl.SSLError as exc:
                return _config_error(f"Invalid CA bundle: {exc}")

        async with contextlib.AsyncExitStack() as stack:
            if checks_revocation:
                run.client = await stack.enter_async_context(
                    httpx.AsyncClient(
                        trust_env=False,
                        timeout=run.timeout,
                        follow_redirects=False,
                        event_hooks={"request": [run._authorize]},
                    )
                )
            # Registered after the client, so it runs before the client closes.
            stack.callback(run.close)
            if supplied:
                pem_plan = {
                    "source": "pem",
                    "host": None,
                    "port": None,
                    "sni": config.sni.strip() or None,
                    "device_id": None,
                    "device_name": None,
                }
                records = [await run.evaluate_pem(pem_plan, supplied)]
            else:
                records = await for_each_target_device(
                    plans,
                    run.probe_endpoint,
                    max_parallel=min(config.max_parallel, len(plans)),
                )

        for record in records:
            run.assess(record)
        return _result(records, config, pem_mode=bool(supplied))


def _evidence_name(record: dict[str, Any]) -> str:
    """Name of the evidence record for one endpoint record."""
    if record["source"] == "pem":
        return "tls_pem"
    return f"tls_{record['host'] or record['device_name'] or 'unknown'}_{record['port']}"


def _result(
    records: list[dict[str, Any]], config: TlsProbeConfig, *, pem_mode: bool
) -> HandlerResult:
    """The step result: summary text, metrics, evidence, output and the error for failing endpoints."""
    summary = summarize(records, config.warn_days)
    min_days = summary["min_days_left"]
    failing = [record for record in records if not record["ok"]]

    if pem_mode:
        text = "tls: pem certificate"
    else:
        text = f"tls: {_plural(summary['total'], 'endpoint')}, {summary['reachable']} reachable"
    if min_days is not None:
        text += f", min {min_days} days left"
    if failing:
        text += f", {summary['failed']} failing"

    metrics: dict[str, Any] = {"endpoints": summary["total"], "unreachable": summary["unreachable"]}
    if min_days is not None:
        metrics["min_days_left"] = min_days
    evidence = [
        {
            "kind": "transport_meta",
            "name": _evidence_name(record),
            "device_id": record["device_id"],
            "content_json": dict(record),
        }
        for record in records
    ]
    output = {
        "endpoints": records,
        "summary": summary,
        "all_ok": not failing,
        "min_days_left": min_days,
    }
    if not failing:
        return HandlerResult(
            success=True, summary=text, metrics=metrics, evidence=evidence, output=output
        )

    def _label(record: dict[str, Any]) -> str:
        """How a failing endpoint is named in the step error."""
        if record["source"] == "pem":
            return "pem certificate"
        if record["host"]:
            return tls_certs.endpoint_label(record["host"], record["port"])
        return str(record["device_name"] or "unknown target")

    listed = [
        f"{_label(record)} ({'; '.join(record['failures'])})"
        for record in failing[:MAX_ERROR_ENDPOINTS]
    ]
    if len(failing) > MAX_ERROR_ENDPOINTS:
        listed.append(f"and {len(failing) - MAX_ERROR_ENDPOINTS} more")
    error = (
        f"TLS check failed for {len(failing)} of {_plural(len(records), 'endpoint')}: "
        + ", ".join(listed)
    )
    return HandlerResult(
        success=False,
        summary=text,
        metrics=metrics,
        evidence=evidence,
        error=error,
        output=output,
    )
