# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SnmpProbeHandler: read-only SNMP GET and walk, with the values in the output.

The step reads values from each target's SNMP agent (SNMPv2c or SNMPv3) and
hands them to later steps. It only reads: it sends GET, GETNEXT and GETBULK
requests and never SET. Credentials are step settings given as secret
references, resolved by the host and redacted from the step's output.

The step dials UDP itself, so it resolves the target's address first, asks
the flow's egress policy about that address, and then queries exactly it.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import socket
import string
import time
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from hegemony_step_sdk import (
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    InvalidConfigError,
    OutputField,
    StepKind,
    for_each_target_device,
)

from .targets import DEFAULT_MAX_PARALLEL_TARGETS, TargetOutcome, all_probe_targets, merge_outcomes

logger = logging.getLogger(__name__)

HANDLER_ID = "probe.snmp"

#: The agent's standard UDP port.
SNMP_PORT = 161

#: sysDescr.0, sysObjectID.0, sysUpTime.0 and sysName.0 (SNMPv2-MIB): what a
#: step reads when its author lists no OID, enough to show the agent answers
#: and which device it is.
DEFAULT_OIDS = (
    "1.3.6.1.2.1.1.1.0",
    "1.3.6.1.2.1.1.2.0",
    "1.3.6.1.2.1.1.3.0",
    "1.3.6.1.2.1.1.5.0",
)

#: Most OIDs one step asks for. A GET sends them in one request, and agents
#: refuse requests that do not fit one UDP datagram.
MAX_OIDS = 64
#: Rows a walk reads under one OID when the step does not say, and at most.
DEFAULT_MAX_ROWS = 100
MAX_ROWS_LIMIT = 1000
#: Characters of one value kept; a longer value is cut and marked.
MAX_VALUE_CHARS = 1024
#: Bytes of values the whole step puts in its output. Every value stays in the
#: evidence; a target whose values would go past this keeps only ok/error.
MAX_OUTPUT_VALUE_BYTES = 48 * 1024
#: A resolved credential shorter than this cannot be kept reliably out of the
#: step's output (the host redacts values from this length up).
MIN_SECRET_CHARS = 4
#: SNMPv3 keys must be at least 8 characters (RFC 3414, section 11.2).
MIN_V3_KEY_CHARS = 8

_OID_RE = re.compile(r"^\.?(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+$")
_BARE_SECRET_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s'\"{}\\]+$")
_TEMPLATE_RE = re.compile(r"\{\{|\{%")
#: Whitespace kept in a text value, next to every printable character.
_WHITESPACE = frozenset(string.whitespace)

AuthProtocol = Literal["none", "sha", "sha224", "sha256", "sha384", "sha512"]
PrivProtocol = Literal[
    "none", "aes128", "aes192", "aes256", "aes192_blumenthal", "aes256_blumenthal"
]

#: pysnmp's names for the protocols, looked up when the step runs.
_AUTH_PROTOCOLS = {
    "none": "usmNoAuthProtocol",
    "sha": "usmHMACSHAAuthProtocol",
    "sha224": "usmHMAC128SHA224AuthProtocol",
    "sha256": "usmHMAC192SHA256AuthProtocol",
    "sha384": "usmHMAC256SHA384AuthProtocol",
    "sha512": "usmHMAC384SHA512AuthProtocol",
}
_PRIV_PROTOCOLS = {
    "none": "usmNoPrivProtocol",
    "aes128": "usmAesCfb128Protocol",
    # The key extension Cisco and most vendors use for AES-192 and AES-256.
    "aes192": "usmAesCfb192Protocol",
    "aes256": "usmAesCfb256Protocol",
    # The other key extension (draft-blumenthal-aes-usm-04), as in Net-SNMP.
    "aes192_blumenthal": "usmAesBlumenthalCfb192Protocol",
    "aes256_blumenthal": "usmAesBlumenthalCfb256Protocol",
}

#: Config keys that hold credentials. They reach the handler as written, so
#: the handler resolves them itself and can refuse a value written in clear.
SECRET_FIELDS = ("community", "auth_secret", "priv_secret")

_SECRET_DESCRIPTION = (
    "a secret reference such as vault://orgs/acme/secrets/snmp/{key}, or a "
    "{{{{ secret('...') }}}} template. A value written in clear is refused."
)


def normalize_oid(value: str) -> str:
    """``value`` without surrounding spaces or a leading dot."""
    return value.strip().lstrip(".")


def oid_error(value: str) -> str | None:
    """Why ``value`` is not a numeric OID, or None when it is one."""
    if _OID_RE.match(value.strip()):
        return None
    return (
        f"OID {value.strip()!r} must be numeric, such as 1.3.6.1.2.1.1.5.0; "
        "MIB names are not accepted"
    )


def _is_secret_ref(value: str) -> bool:
    """Whether ``value`` is written as a secret reference or a template."""
    text = value.strip()
    return bool(_BARE_SECRET_REF_RE.match(text) or _TEMPLATE_RE.search(text))


class SnmpProbeConfig(BaseModel):
    """Config for ``probe.snmp``."""

    model_config = ConfigDict(extra="allow")

    operation: Literal["get", "walk"] = Field(
        default="get",
        title="Operation",
        description=(
            "Get reads exactly the listed OIDs. Walk reads every value under each "
            "listed OID (a table or a subtree), up to Max Rows per OID. Defaults to Get."
        ),
        json_schema_extra={"x_option_labels": {"get": "Get", "walk": "Walk"}},
    )
    oids: list[str] = Field(
        default_factory=lambda: list(DEFAULT_OIDS),
        title="OIDs",
        description=(
            "Numeric OIDs, one per line (at most 64). Defaults to sysDescr.0, "
            "sysObjectID.0, sysUpTime.0 and sysName.0."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_rows": 4,
            "x_col_span": 2,
            "x_placeholder": "1.3.6.1.2.1.1.5.0\n1.3.6.1.2.1.2.2.1.8",
        },
    )
    version: Literal["v2c", "v3"] = Field(
        default="v2c",
        title="SNMP Version",
        description="SNMPv2c with a community, or SNMPv3 with a user. Defaults to v2c.",
        json_schema_extra={"x_option_labels": {"v2c": "SNMPv2c", "v3": "SNMPv3"}},
    )
    community: str = Field(
        default="",
        title="Community",
        description="The SNMPv2c community: " + _SECRET_DESCRIPTION.format(key="community"),
        json_schema_extra={
            "x_show_when": {"field": "version", "value": "v2c"},
            "x_placeholder": "vault://orgs/acme/secrets/snmp/community",
            "x_col_span": 2,
        },
    )
    username: str = Field(
        default="",
        title="User",
        description="The SNMPv3 user name.",
        json_schema_extra={"x_show_when": {"field": "version", "value": "v3"}},
    )
    context_name: str = Field(
        default="",
        title="Context",
        description="The SNMPv3 context name. Empty uses the agent's default context.",
        json_schema_extra={"x_show_when": {"field": "version", "value": "v3"}, "x_advanced": True},
    )
    auth_protocol: AuthProtocol = Field(
        default="sha256",
        title="Authentication",
        description=(
            "The SNMPv3 authentication protocol; None sends requests unauthenticated "
            "(noAuthNoPriv). Defaults to SHA-256."
        ),
        json_schema_extra={
            "x_show_when": {"field": "version", "value": "v3"},
            "x_option_labels": {
                "none": "None",
                "sha": "SHA-1",
                "sha224": "SHA-224",
                "sha256": "SHA-256",
                "sha384": "SHA-384",
                "sha512": "SHA-512",
            },
        },
    )
    auth_secret: str = Field(
        default="",
        title="Authentication Key",
        description="The SNMPv3 authentication passphrase: "
        + _SECRET_DESCRIPTION.format(key="auth"),
        json_schema_extra={
            "x_show_when": {"field": "version", "value": "v3"},
            "x_placeholder": "vault://orgs/acme/secrets/snmp/auth",
            "x_col_span": 2,
        },
    )
    priv_protocol: PrivProtocol = Field(
        default="aes128",
        title="Privacy",
        description=(
            "The SNMPv3 encryption protocol; None sends values unencrypted (authNoPriv). "
            "AES-192 and AES-256 use the key extension Cisco and most vendors use; the "
            "Blumenthal variants are the one Net-SNMP uses. Defaults to AES-128."
        ),
        json_schema_extra={
            "x_show_when": {"field": "version", "value": "v3"},
            "x_option_labels": {
                "none": "None",
                "aes128": "AES-128",
                "aes192": "AES-192",
                "aes256": "AES-256",
                "aes192_blumenthal": "AES-192 (Blumenthal)",
                "aes256_blumenthal": "AES-256 (Blumenthal)",
            },
        },
    )
    priv_secret: str = Field(
        default="",
        title="Privacy Key",
        description="The SNMPv3 encryption passphrase: " + _SECRET_DESCRIPTION.format(key="priv"),
        json_schema_extra={
            "x_show_when": {"field": "version", "value": "v3"},
            "x_placeholder": "vault://orgs/acme/secrets/snmp/priv",
            "x_col_span": 2,
        },
    )
    port: int = Field(
        default=SNMP_PORT,
        ge=1,
        le=65535,
        title="Port",
        description="The agent's UDP port. Defaults to 161.",
        json_schema_extra={"x_advanced": True},
    )
    max_rows: int = Field(
        default=DEFAULT_MAX_ROWS,
        ge=1,
        le=MAX_ROWS_LIMIT,
        title="Max Rows",
        description=(
            "Most values a walk reads under one OID (1-1000). The walk stops there and "
            "says it was cut short. Defaults to 100."
        ),
        json_schema_extra={"x_show_when": {"field": "operation", "value": "walk"}},
    )
    attempt_timeout_seconds: int = Field(
        default=5,
        ge=1,
        le=60,
        title="Timeout (sec)",
        description=(
            "How long one request waits for the agent's answer, in seconds (1-60). Defaults to 5."
        ),
    )
    attempts: int = Field(
        default=2,
        ge=1,
        le=10,
        title="Attempts",
        description=(
            "How many times a request is sent before the target fails (1-10). SNMP runs "
            "over UDP, so one lost packet is common. Defaults to 2."
        ),
    )
    max_parallel_devices: int = Field(
        default=DEFAULT_MAX_PARALLEL_TARGETS,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Targets queried at the same time (1 = one after another). Defaults to 10.",
    )

    @field_validator("oids")
    @classmethod
    def _numeric_oids(cls, value: list[str]) -> list[str]:
        """Numeric OIDs only, at most :data:`MAX_OIDS`, blank lines dropped."""
        oids = [normalize_oid(item) for item in value if item.strip()]
        if not oids:
            raise ValueError("list at least one OID")
        if len(oids) > MAX_OIDS:
            raise ValueError(f"list at most {MAX_OIDS} OIDs")
        for item in oids:
            error = oid_error(item)
            if error:
                raise ValueError(error)
        return oids


def _validation_errors(config: SnmpProbeConfig) -> list[str]:
    """Checks across fields that the model's own validators cannot make."""
    errors: list[str] = []
    for name in SECRET_FIELDS:
        value = getattr(config, name)
        if value.strip() and not _is_secret_ref(value):
            errors.append(
                f"'{name}' must be a secret reference or a {{{{ secret('...') }}}} template; "
                "a value written in clear would be stored in the flow and not redacted"
            )
    if config.version == "v2c":
        if not config.community.strip():
            errors.append("'community' is required for SNMPv2c")
        return errors
    if not config.username.strip():
        errors.append("'username' is required for SNMPv3")
    if config.auth_protocol == "none":
        if config.priv_protocol != "none":
            errors.append("SNMPv3 privacy needs authentication: set Authentication too")
    elif not config.auth_secret.strip():
        errors.append("'auth_secret' is required when Authentication is set")
    if config.priv_protocol != "none" and not config.priv_secret.strip():
        errors.append("'priv_secret' is required when Privacy is set")
    return errors


@dataclass(frozen=True)
class _Credentials:
    """The resolved credentials; never logged or put in evidence."""

    community: str = ""
    auth_key: str = ""
    priv_key: str = ""


async def _resolve_secret(ctx: HandlerContext, field: str, raw: str) -> str:
    """Resolve one credential field, written as a reference or a template."""
    text = raw.strip()
    template = "{{ secret('" + text + "') }}" if _BARE_SECRET_REF_RE.match(text) else text
    value = await ctx.require_services().resolve_secret_ref(
        template, source=f"{HANDLER_ID}.{field}"
    )
    if not value:
        raise ValueError(f"'{field}' resolved to an empty value")
    if len(value) < MIN_SECRET_CHARS:
        raise ValueError(
            f"'{field}' resolved to a value shorter than {MIN_SECRET_CHARS} characters, "
            "too short to keep reliably out of the step's output"
        )
    return value


async def resolve_credentials(ctx: HandlerContext, config: SnmpProbeConfig) -> _Credentials:
    """The credentials the step's version and protocols need, resolved."""
    if config.version == "v2c":
        return _Credentials(community=await _resolve_secret(ctx, "community", config.community))
    auth_key = priv_key = ""
    if config.auth_protocol != "none":
        auth_key = await _resolve_secret(ctx, "auth_secret", config.auth_secret)
    if config.priv_protocol != "none":
        priv_key = await _resolve_secret(ctx, "priv_secret", config.priv_secret)
    for field, key in (("auth_secret", auth_key), ("priv_secret", priv_key)):
        if key and len(key) < MIN_V3_KEY_CHARS:
            raise ValueError(
                f"'{field}' resolved to a passphrase shorter than {MIN_V3_KEY_CHARS} "
                "characters, which SNMPv3 does not accept"
            )
    return _Credentials(auth_key=auth_key, priv_key=priv_key)


def render_value(value: Any) -> tuple[str, Any]:
    """``(type name, plain value)`` for one value an agent returned.

    Numbers (integers, counters, gauges, time ticks) become ints, OIDs and IP
    addresses their dotted text, and octet strings text when they are
    printable UTF-8, else ``0x`` and hex. A value longer than
    :data:`MAX_VALUE_CHARS` is cut and ends with ``…``.
    """
    from pyasn1.type import univ
    from pysnmp.proto import rfc1902

    type_name = type(value).__name__
    if isinstance(value, rfc1902.IpAddress):
        rendered: Any = value.prettyPrint()
    elif isinstance(value, univ.Integer):
        return type_name, int(value)
    elif isinstance(value, univ.ObjectIdentifier):
        rendered = ".".join(str(part) for part in value.asTuple())
    elif isinstance(value, univ.OctetString):
        raw = bytes(value.asOctets())
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is not None and all(char.isprintable() or char in _WHITESPACE for char in text):
            rendered = text
        else:
            rendered = "0x" + raw.hex()
    else:
        rendered = value.prettyPrint()
    if isinstance(rendered, str) and len(rendered) > MAX_VALUE_CHARS:
        rendered = rendered[: MAX_VALUE_CHARS - 1] + "…"
    return type_name, rendered


def _is_missing(value: Any) -> str | None:
    """``noSuchObject``/``noSuchInstance``/``endOfMibView`` for an exception value, else None."""
    from pysnmp.proto import rfc1905

    if isinstance(value, rfc1905.NoSuchObject):
        return "noSuchObject"
    if isinstance(value, rfc1905.NoSuchInstance):
        return "noSuchInstance"
    if isinstance(value, rfc1905.EndOfMibView):
        return "endOfMibView"
    return None


def _oid_text(name: Any) -> str:
    """Dotted text of an OID in a response."""
    return ".".join(str(part) for part in name.asTuple())


async def resolve_address(host: str, port: int) -> str:
    """The IP address ``host`` names: itself when it is one, else its first UDP address."""
    text = host.strip().strip("[]")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(text, port, type=socket.SOCK_DGRAM)
    if not infos:
        raise OSError(f"{text} has no address")
    return str(infos[0][4][0])


class _Query:
    """One step's SNMP settings, run against one address at a time."""

    def __init__(self, config: SnmpProbeConfig, credentials: _Credentials) -> None:
        self.config = config
        self.credentials = credentials

    def _auth_data(self, hlapi: Any) -> Any:
        if self.config.version == "v2c":
            # mpModel=1 is SNMPv2c.
            return hlapi.CommunityData(self.credentials.community, mpModel=1)
        return hlapi.UsmUserData(
            self.config.username.strip(),
            authKey=self.credentials.auth_key or None,
            privKey=self.credentials.priv_key or None,
            authProtocol=getattr(hlapi, _AUTH_PROTOCOLS[self.config.auth_protocol]),
            privProtocol=getattr(hlapi, _PRIV_PROTOCOLS[self.config.priv_protocol]),
        )

    async def run(self, address: str) -> dict[str, Any]:
        """Query ``address``; returns ``values``, ``types``, ``missing``, ``truncated``.

        Raises :class:`SnmpError` when the agent does not answer or refuses
        the request.
        """
        from pysnmp.hlapi.v3arch import asyncio as hlapi

        engine = hlapi.SnmpEngine()
        try:
            transport_class = (
                hlapi.Udp6TransportTarget
                if ipaddress.ip_address(address).version == 6
                else hlapi.UdpTransportTarget
            )
            target = await transport_class.create(
                (address, self.config.port),
                timeout=self.config.attempt_timeout_seconds,
                retries=self.config.attempts - 1,
            )
            auth = self._auth_data(hlapi)
            context = hlapi.ContextData(contextName=self.config.context_name.strip())
            if self.config.operation == "get":
                return await self._get(hlapi, engine, auth, target, context)
            return await self._walk(hlapi, engine, auth, target, context)
        finally:
            try:
                engine.close_dispatcher()
            except Exception:  # noqa: BLE001 - cleanup never hides the result
                logger.debug("SNMP engine close failed", exc_info=True)

    async def _get(self, hlapi, engine, auth, target, context) -> dict[str, Any]:
        error_indication, error_status, error_index, var_binds = await hlapi.get_cmd(
            engine,
            auth,
            target,
            context,
            *(hlapi.ObjectType(hlapi.ObjectIdentity(oid)) for oid in self.config.oids),
            lookupMib=False,
        )
        _raise_on_error(error_indication, error_status, error_index, self.config.oids)
        values: dict[str, Any] = {}
        types: dict[str, str] = {}
        missing: dict[str, str] = {}
        for name, value in var_binds:
            oid = _oid_text(name)
            absent = _is_missing(value)
            if absent:
                missing[oid] = absent
                continue
            types[oid], values[oid] = render_value(value)
        return {"values": values, "types": types, "missing": missing, "truncated": []}

    async def _walk(self, hlapi, engine, auth, target, context) -> dict[str, Any]:
        values: dict[str, Any] = {}
        types: dict[str, str] = {}
        missing: dict[str, str] = {}
        truncated: list[str] = []
        max_rows = self.config.max_rows
        for base in self.config.oids:
            prefix = base + "."
            rows = 0
            walk = hlapi.bulk_walk_cmd(
                engine,
                auth,
                target,
                context,
                0,
                min(max_rows + 1, 50),
                hlapi.ObjectType(hlapi.ObjectIdentity(base)),
                lookupMib=False,
                lexicographicMode=False,
            )
            cut = False
            async for error_indication, error_status, error_index, var_binds in walk:
                _raise_on_error(error_indication, error_status, error_index, [base])
                for name, value in var_binds:
                    oid = _oid_text(name)
                    if not oid.startswith(prefix) or _is_missing(value):
                        continue
                    if rows >= max_rows:
                        cut = True
                        break
                    types[oid], values[oid] = render_value(value)
                    rows += 1
                if cut:
                    break
            await walk.aclose()
            if cut:
                truncated.append(base)
            elif rows == 0:
                missing[base] = "no values under this OID"
        return {"values": values, "types": types, "missing": missing, "truncated": truncated}


class SnmpError(Exception):
    """The agent did not answer, or answered with an error."""


def _raise_on_error(error_indication, error_status, error_index, oids: list[str]) -> None:
    """Turn pysnmp's error triple into :class:`SnmpError`."""
    if error_indication:
        raise SnmpError(str(error_indication))
    if error_status and int(error_status):
        status = (
            error_status.prettyPrint() if hasattr(error_status, "prettyPrint") else error_status
        )
        index = int(error_index or 0)
        where = f" at {oids[index - 1]}" if 0 < index <= len(oids) else ""
        raise SnmpError(f"agent returned {status}{where}")


def _output_values(outcomes: list[TargetOutcome]) -> tuple[dict[str, Any], list[str]]:
    """Each target's result for the step output, and the targets whose values did not fit."""
    from .targets import chain_output

    output = chain_output(outcomes)["targets"]
    omitted: list[str] = []
    used = 0
    for name, result in output.items():
        size = len(json.dumps(result.get("values") or {}, ensure_ascii=False).encode())
        if used + size > MAX_OUTPUT_VALUE_BYTES:
            result["values"] = {}
            result["types"] = {}
            omitted.append(name)
            continue
        used += size
    return output, omitted


class SnmpProbeHandler(BaseHandler):
    """Read SNMP values from every target, and pass them to later steps."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.CHECK]
    display_name = "SNMP Check"
    description = "Read values from each target's SNMP agent (read only) and output them."
    category = "Checks"
    config_model = SnmpProbeConfig
    # Credentials reach the handler as written, so it resolves them itself
    # and refuses values written in clear.
    raw_config_keys = frozenset(SECRET_FIELDS)
    default_config = {"operation": "get", "version": "v2c", "oids": list(DEFAULT_OIDS)}
    output_fields = (
        OutputField(
            "targets",
            "Each target's result by target name: ok, error, latency_ms, address, "
            "values (by OID), types, missing and truncated",
            "object",
        ),
        OutputField(
            "omitted",
            "Targets whose values did not fit in the output; their values are in the evidence",
            "list",
        ),
    )

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        errors = super().validate_config(config)
        if errors:
            return errors
        return _validation_errors(SnmpProbeConfig.model_validate(config))

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        targets = all_probe_targets(ctx)
        if not targets:
            return HandlerResult(
                success=False,
                error="No target devices or IPs configured",
                summary="Missing targets",
            )
        try:
            config = self.parse_config(ctx.config, SnmpProbeConfig)
        except InvalidConfigError as exc:
            return exc.result()

        services = ctx.require_services()
        # Fail closed: the step dials every agent itself, so without the gate
        # nothing would apply the flow's network policy.
        enforce = getattr(services, "enforce_egress", None)
        if enforce is None:
            return HandlerResult(
                success=False,
                error="this platform cannot apply the flow's network policy to SNMP queries",
                summary="SNMP check configuration error",
            )
        try:
            credentials = await resolve_credentials(ctx, config)
        except ValueError as exc:
            return HandlerResult(
                success=False, error=str(exc), summary="SNMP check configuration error"
            )

        query = _Query(config, credentials)

        async def _check(device: dict[str, Any]) -> TargetOutcome:
            device_id = device.get("id")
            name = device.get("name") or device_id or "unknown"
            host = device.get("mgmt_host") or device.get("hostname")
            if not host:
                return TargetOutcome(name, ok=False, error="no management address")
            try:
                address = await resolve_address(str(host), config.port)
            except OSError as exc:
                return TargetOutcome(name, ok=False, error=f"cannot resolve {host}: {exc}")
            # Outside any try: a denial is the step's error, not a dead agent.
            await enforce(address, config.port, proto="udp", kind="snmp query")
            record: dict[str, Any] = {
                "device_id": device_id,
                "device_name": name,
                "address": address,
                "port": config.port,
                "version": config.version,
                "operation": config.operation,
                "oids": list(config.oids),
            }
            start = time.perf_counter()
            try:
                found = await query.run(address)
            except SnmpError as exc:
                error = str(exc)
                found = None
            except (TimeoutError, OSError) as exc:
                error = str(exc) or type(exc).__name__
                found = None
            latency_ms = round((time.perf_counter() - start) * 1000, 3)
            if found is None:
                ok = False
                record.update(values={}, types={}, missing={}, truncated=[])
            else:
                error = None
                record.update(found)
                if found["missing"]:
                    ok = False
                    error = "no value for " + ", ".join(
                        f"{oid} ({why})" for oid, why in found["missing"].items()
                    )
                else:
                    ok = True
            record.update(success=ok, error=error)
            return TargetOutcome(
                name,
                ok=ok,
                error=error,
                latency_ms=latency_ms if found is not None else None,
                evidence={
                    "kind": "transport_meta",
                    "name": f"snmp_{config.operation}_{name}",
                    "device_id": device_id,
                    "content_json": record,
                },
            )

        outcomes = await for_each_target_device(
            targets, _check, max_parallel=config.max_parallel_devices
        )
        evidence, metrics, failures = merge_outcomes(outcomes)
        output_targets, omitted = _output_values(outcomes)
        passed = sum(outcome.ok for outcome in outcomes)
        values = sum(
            len((outcome.evidence or {}).get("content_json", {}).get("values") or {})
            for outcome in outcomes
        )
        metrics["values_read"] = values
        summary = f"snmp {config.operation}: {passed}/{len(targets)} targets OK, {values} values"
        output = {"targets": output_targets, "omitted": omitted}
        if failures:
            return HandlerResult(
                success=False,
                error=f"Failed: {', '.join(failures)}",
                summary=summary,
                metrics=metrics,
                evidence=evidence,
                output=output,
            )
        return HandlerResult(
            success=True, summary=summary, metrics=metrics, evidence=evidence, output=output
        )
