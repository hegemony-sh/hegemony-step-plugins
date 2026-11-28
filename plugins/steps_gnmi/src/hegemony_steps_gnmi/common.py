# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What the ``gnmi.*`` steps share: settings, sessions, fan-out and output.

The fan-out and the output shape follow the ``netconf.*`` steps (devices by
name, text cut to an output budget, ``cli_output`` evidence), copied rather
than imported so neither wheel depends on the other.
"""

from __future__ import annotations

import contextlib
import json
import logging
import re
import time
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

import grpc
from pydantic import BaseModel, ConfigDict, Field, model_validator

from hegemony_step_sdk import (
    MAX_PARALLEL_DEVICES_LIMIT,
    HandlerContext,
    HandlerResult,
    HandlerServices,
    for_each_target_device,
)
from hegemony_step_sdk.trust import combined_ca_pem, org_trusted_ca_pem

from .client import (
    DEFAULT_GNMI_PORT,
    DestinationRefused,
    GnmiError,
    GnmiSession,
    Login,
    TlsSettings,
    open_session,
)
from .paths import PathError
from .values import GnmiValueError

logger = logging.getLogger(__name__)

#: Characters of one device's text kept in the step output; the evidence
#: keeps all of it.
MAX_OUTPUT_TEXT_CHARS = 16 * 1024
#: Characters of text the whole step puts in its output.
MAX_OUTPUT_TOTAL_CHARS = 64 * 1024
TRUNCATED_NOTE = "\n… [cut short: the full text is in the step's evidence]"
#: Secrets shorter than this could not be kept out of reported text reliably.
MIN_SECRET_CHARS = 4

#: Fields whose secret references the step resolves itself.
SECRET_FIELDS = ("password", "ca_bundle", "client_certificate", "client_key")

_BARE_SECRET_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s'\"{}\\]+$")
_TEMPLATE_RE = re.compile(r"\{\{|\{%")
_PEM_CERTIFICATE = "-----BEGIN CERTIFICATE-----"
_PEM_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def is_bare_secret_ref(value: str) -> bool:
    return bool(_BARE_SECRET_REF_RE.match(value.strip()))


def is_templated(value: str) -> bool:
    return bool(_TEMPLATE_RE.search(value))


class GnmiConnectionConfig(BaseModel):
    """Connection, login and TLS settings every ``gnmi.*`` step has."""

    model_config = ConfigDict(extra="allow")

    port: int = Field(
        default=DEFAULT_GNMI_PORT,
        ge=1,
        le=65535,
        title="Port",
        description=(
            "The device's gNMI port. Defaults to 9339 (the IANA port); vendors differ: "
            "6030 on Arista EOS, 57400 on Nokia SR Linux and Cisco IOS XR, 32767 on Junos."
        ),
    )
    credentials: Literal["device", "step", "none"] = Field(
        default="device",
        title="Login",
        description=(
            "Device uses each device's SSH username and password from the inventory. Step "
            "uses Username and Password below for every device. None sends no login, for a "
            "device that authenticates by client certificate alone."
        ),
        json_schema_extra={
            "x_option_labels": {
                "device": "Device's SSH login",
                "step": "Username and password of this step",
                "none": "No login (client certificate only)",
            }
        },
    )
    username: str = Field(
        default="",
        title="Username",
        description="The gNMI username for every device.",
        json_schema_extra={"x_show_when": {"field": "credentials", "value": "step"}},
    )
    password: str = Field(
        default="",
        title="Password",
        description=(
            "The password: a secret reference such as vault://orgs/acme/secrets/gnmi/password, "
            "a {{ secret('...') }} template, or literal text. A value resolved from a "
            "reference is redacted from the run's logs; literal text is not, so prefer a "
            "reference."
        ),
        json_schema_extra={
            "x_show_when": {"field": "credentials", "value": "step"},
            "x_placeholder": "vault://orgs/acme/secrets/gnmi/password",
        },
    )
    use_tls: bool = Field(
        default=True,
        title="Use TLS",
        description=(
            "Encrypt the connection and verify the device's certificate. Off sends gRPC in "
            "plaintext, for lab devices only."
        ),
        json_schema_extra={"x_advanced": True},
    )
    ca_bundle: str = Field(
        default="",
        title="CA Bundle",
        description=(
            "Trust only these certificates for the device, instead of the system "
            "authorities and the organization's trusted CAs: PEM text, a secret reference, or "
            "a {{ secret('...') }} template. For a lab device with a self-signed certificate, "
            "give that certificate. Empty trusts the system authorities plus the "
            "organization's trusted CAs (Settings, Trusted CAs)."
        ),
        json_schema_extra={
            "x_widget": "textarea",
            "x_rows": 3,
            "x_col_span": 2,
            "x_advanced": True,
            "x_show_when": {"field": "use_tls", "value": True},
        },
    )
    tls_server_name: str = Field(
        default="",
        title="TLS Server Name",
        description=(
            "The name the device's certificate must carry, when it is not the device's "
            "management address. Empty checks the management address."
        ),
        json_schema_extra={"x_advanced": True, "x_show_when": {"field": "use_tls", "value": True}},
    )
    client_certificate: str = Field(
        default="",
        title="Client Certificate",
        description=(
            "A certificate the step presents to the device (mutual TLS): PEM text or a secret "
            "reference. Set it with Client Key."
        ),
        json_schema_extra={
            "x_widget": "textarea",
            "x_rows": 3,
            "x_col_span": 2,
            "x_advanced": True,
            "x_show_when": {"field": "use_tls", "value": True},
        },
    )
    client_key: str = Field(
        default="",
        title="Client Key",
        description=(
            "The private key of Client Certificate: a secret reference such as "
            "vault://orgs/acme/secrets/gnmi/client-key, or a {{ secret('...') }} template."
        ),
        json_schema_extra={
            "x_advanced": True,
            "x_show_when": {"field": "use_tls", "value": True},
            "x_placeholder": "vault://orgs/acme/secrets/gnmi/client-key",
        },
    )
    allow_insecure_auth: bool = Field(
        default=False,
        title="Allow login without TLS",
        description=(
            "Send the username and password over a plaintext connection, where anyone on the "
            "path can read them. Only for lab devices."
        ),
        json_schema_extra={"x_advanced": True, "x_show_when": {"field": "use_tls", "value": False}},
    )
    connect_timeout_seconds: int = Field(
        default=15,
        ge=1,
        le=300,
        title="Connect Timeout (sec)",
        description=(
            "How long connecting, the TLS handshake and the first request (Capabilities) "
            "may take. Defaults to 15."
        ),
        json_schema_extra={"x_advanced": True},
    )
    rpc_timeout_seconds: int = Field(
        default=120,
        ge=1,
        le=3600,
        title="Request Timeout (sec)",
        description="How long the device may take to answer one request. Defaults to 120.",
        json_schema_extra={"x_advanced": True},
    )

    @model_validator(mode="after")
    def _connection_settings(self) -> GnmiConnectionConfig:
        errors = connection_errors(self)
        if errors:
            raise ValueError("; ".join(errors))
        return self


def connection_errors(config: GnmiConnectionConfig) -> list[str]:
    """Problems with the login and TLS settings that need no device to find."""
    errors: list[str] = []
    if config.credentials == "step":
        if not config.username.strip():
            errors.append("'username' is required when Login is this step's")
        if not config.password.strip():
            errors.append("'password' is required when Login is this step's")
    if not config.use_tls and config.credentials != "none" and not config.allow_insecure_auth:
        errors.append(
            "without TLS the login would travel in plaintext; turn on 'allow_insecure_auth' "
            "for a lab device, or set Login to none"
        )
    if not config.use_tls and (
        config.ca_bundle.strip() or config.client_certificate.strip() or config.client_key.strip()
    ):
        errors.append("'ca_bundle', 'client_certificate' and 'client_key' need Use TLS on")
    if bool(config.client_certificate.strip()) != bool(config.client_key.strip()):
        errors.append("'client_certificate' and 'client_key' are set together")
    for name, marker in (("ca_bundle", _PEM_CERTIFICATE), ("client_certificate", _PEM_CERTIFICATE)):
        value = getattr(config, name).strip()
        if value and not (is_templated(value) or is_bare_secret_ref(value) or marker in value):
            errors.append(
                f"'{name}' must hold PEM certificates ({marker}), a secret reference, or a "
                "{{ secret('...') }} template"
            )
    key = config.client_key.strip()
    if key and not (is_templated(key) or is_bare_secret_ref(key)):
        errors.append(
            "'client_key' must be a secret reference or a {{ secret('...') }} template, so the "
            "key is stored in a secret backend and redacted from the run"
        )
    return errors


def max_parallel_field(default: int) -> Any:
    """The Max Parallel Devices field with the step's own default."""
    return Field(
        default=default,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description=(
            f"Devices worked on at the same time (1 = one after another). Defaults to {default}."
        ),
    )


class StepUnavailable(Exception):
    """The step cannot run on this platform (no egress gate)."""


async def resolve_secret_text(services: HandlerServices, raw: str, *, field: str) -> str:
    """One secret field as written, resolved: a bare reference, a template, or literal text.

    The rules of ``http.request``'s secret fields: the written text decides,
    a value the host resolves is registered for redaction, literal text is
    used as it is. Raises ``ValueError`` (never naming the value).
    """
    text = raw.strip()
    if not text:
        return ""
    bare = is_bare_secret_ref(text)
    if bare:
        template = "{{ secret('" + text + "') }}"
    elif is_templated(text):
        template = text
    else:
        return raw
    value = await services.resolve_secret_ref(template, source=f"gnmi.{field}") or ""
    if not value:
        raise ValueError(f"{field} resolved to an empty value")
    return value


@dataclass
class ResolvedAccess:
    """What every device of a step shares: TLS material and the step's own login."""

    tls: TlsSettings
    step_login: Login | None = None


async def resolve_access(services: HandlerServices, config: GnmiConnectionConfig) -> ResolvedAccess:
    """Resolve the step's secrets and TLS trust once. Raises ``ValueError``/``RuntimeError``."""
    step_login: Login | None = None
    if config.credentials == "step":
        password = await resolve_secret_text(services, config.password, field="password")
        if len(password) < MIN_SECRET_CHARS:
            raise ValueError(
                f"password resolved to fewer than {MIN_SECRET_CHARS} characters, too short to "
                "keep reliably out of the step's output"
            )
        step_login = Login(username=config.username.strip(), password=password)
    if not config.use_tls:
        return ResolvedAccess(tls=TlsSettings(use_tls=False), step_login=step_login)
    ca_bundle = await resolve_secret_text(services, config.ca_bundle, field="ca_bundle")
    if ca_bundle.strip():
        if _PEM_CERTIFICATE not in ca_bundle:
            raise ValueError("ca_bundle holds no PEM certificate (-----BEGIN CERTIFICATE-----)")
        root = ca_bundle.strip() + "\n"
    else:
        # The system store plus the organization's trusted CAs, as http.request
        # trusts. RuntimeError (the list cannot be loaded) propagates.
        root = combined_ca_pem(await org_trusted_ca_pem(services))
    certificate = await resolve_secret_text(
        services, config.client_certificate, field="client_certificate"
    )
    key = await resolve_secret_text(services, config.client_key, field="client_key")
    if certificate.strip() and _PEM_CERTIFICATE not in certificate:
        raise ValueError("client_certificate holds no PEM certificate")
    if key.strip() and not _PEM_KEY_RE.search(key):
        raise ValueError("client_key holds no PEM private key (-----BEGIN ... PRIVATE KEY-----)")
    tls = TlsSettings(
        use_tls=True,
        root_pem=root.encode() if root.strip() else None,
        client_cert_pem=certificate.strip().encode() + b"\n" if certificate.strip() else None,
        client_key_pem=key.strip().encode() + b"\n" if key.strip() else None,
        server_name=config.tls_server_name.strip(),
    )
    return ResolvedAccess(tls=tls, step_login=step_login)


def egress_gate(ctx: HandlerContext) -> Callable[..., Awaitable[None]]:
    """The host's ``enforce_egress``; a platform without it cannot run gNMI steps."""
    services = ctx.require_services()
    enforce = getattr(services, "enforce_egress", None)
    if enforce is None:
        # Fail closed: the step dials the device itself, so without the gate
        # nothing would apply the flow's network policy.
        raise StepUnavailable(
            "this platform cannot apply the flow's network policy to gNMI connections; "
            "upgrade Hegemony to a release that supports the gnmi steps"
        )
    return enforce


def _jump_host(device: dict[str, Any]) -> Any:
    access = device.get("access_config")
    return access.get("jump_host") if isinstance(access, dict) else None


async def device_login(
    services: HandlerServices, device: dict[str, Any], config: GnmiConnectionConfig, access: Any
) -> Login:
    """The login for ``device``: the step's, the device's SSH login, or none."""
    if config.credentials == "none":
        return Login()
    if access.step_login is not None:
        return access.step_login
    credentials = await services.resolve_device_credentials(device)
    if not credentials.username or not credentials.password:
        raise GnmiError(
            "the device's SSH login has no password (gNMI logs in with a username and "
            "password); set Login to this step's username and password"
        )
    return Login(username=credentials.username, password=credentials.password)


@contextlib.asynccontextmanager
async def gnmi_session(
    ctx: HandlerContext,
    device: dict[str, Any],
    config: GnmiConnectionConfig,
    access: ResolvedAccess,
) -> AsyncIterator[GnmiSession]:
    """An open gNMI session to ``device``, Capabilities answered; closed on exit."""
    services = ctx.require_services()
    enforce = egress_gate(ctx)
    host = str(device.get("mgmt_host") or "").strip()
    if not host:
        raise GnmiError("the device has no management address (mgmt_host)")
    if _jump_host(device):
        raise GnmiError(
            "the device is reached through a jump host, which gNMI steps cannot use; reach "
            "it directly or use the netconf or netcli steps"
        )
    login = await device_login(services, device, config, access)

    async def log(line: str) -> None:
        # The Logs tab's live view: one line per request and its outcome,
        # never the paths' values or the login.
        await ctx.emit_output(line + "\n", device=device, command="gnmi")

    started = time.monotonic()
    scheme = "TLS" if access.tls.use_tls else "plaintext"
    await log(f"connecting to gNMI on port {config.port} ({scheme})")
    try:
        session = await open_session(
            host,
            config.port,
            tls=access.tls,
            login=login,
            connect_timeout=float(config.connect_timeout_seconds),
            rpc_timeout=float(config.rpc_timeout_seconds),
            enforce=enforce,
            log=log,
        )
    except GnmiError as exc:
        if exc.code == grpc.StatusCode.DEADLINE_EXCEEDED:
            await log(f"no answer within {config.connect_timeout_seconds} s")
            raise GnmiError(
                f"the device did not answer on port {config.port} within "
                f"{config.connect_timeout_seconds} s; check the port, or raise Connect Timeout"
            ) from None
        await log(f"connecting failed: {exc}")
        raise
    capabilities = session.capabilities
    encodings = ", ".join(sorted(session.supported_encodings())) or "none listed"
    await log(
        f"gNMI {capabilities.gNMI_version or '?'} on {session.address} after "
        f"{time.monotonic() - started:.1f} s ({len(capabilities.supported_models)} models; "
        f"encodings: {encodings})"
    )
    try:
        yield session
    finally:
        await session.close()
        await log("gNMI connection closed")


def pick_encoding(session: GnmiSession, wanted: str, *, choices: Iterable[str]) -> str:
    """The encoding to use: ``wanted``, or for ``auto`` the first of ``choices`` it lists."""
    if wanted != "auto":
        return wanted
    supported = session.supported_encodings()
    for choice in choices:
        if choice in supported:
            return choice
    return next(iter(choices))


def device_label(device: dict[str, Any]) -> str:
    return str(device.get("name") or device.get("mgmt_host") or device.get("id") or "unknown")


def pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)


@dataclass
class DeviceOutcome:
    """One device's part of a step: its output, evidence and error."""

    device: dict[str, Any]
    ok: bool = True
    error: str | None = None
    output: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    #: Output keys that hold long text, cut to the output budget.
    text_keys: tuple[str, ...] = ()
    #: Output keys that hold structured values, dropped when over budget.
    value_keys: tuple[str, ...] = ()

    @property
    def name(self) -> str:
        return device_label(self.device)


def describe_error(exc: BaseException) -> str:
    """The step's wording for a failure on one device."""
    if isinstance(
        exc,
        (GnmiError, DestinationRefused, PathError, GnmiValueError, ValueError, PermissionError),
    ):
        return str(exc)
    if isinstance(exc, TimeoutError):
        return str(exc) or "timed out"
    if isinstance(exc, OSError):
        return f"connection failed: {exc}"
    return f"{type(exc).__name__}: {exc}"


async def run_per_device(
    ctx: HandlerContext,
    devices: list[dict[str, Any]],
    work: Callable[[dict[str, Any], DeviceOutcome], Awaitable[None]],
    *,
    max_parallel: int,
) -> list[DeviceOutcome]:
    """Run ``work`` for every device; a failure is recorded on its outcome.

    A refusal by the flow's egress policy is recorded on that device too, so
    the others keep their results. Only :class:`StepUnavailable` propagates.
    """

    async def _one(device: dict[str, Any]) -> DeviceOutcome:
        outcome = DeviceOutcome(device)
        try:
            await work(device, outcome)
        except StepUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 - one device's failure is its own
            outcome.ok = False
            outcome.error = describe_error(exc)
            # The device's error text can echo values, so the log names only
            # the kind of failure.
            logger.info(
                "gnmi step failed on a device",
                extra={
                    "run_id": ctx.run_id,
                    "device": outcome.name,
                    "error_type": type(exc).__name__,
                },
            )
        return outcome

    return await for_each_target_device(devices, _one, max_parallel=max_parallel)


def _cap(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[:limit] + TRUNCATED_NOTE, True


def build_result(
    outcomes: list[DeviceOutcome], *, summary: str, extra_output: dict[str, Any] | None = None
) -> HandlerResult:
    """The step result: devices keyed by name, text and values cut to the output budget."""
    names = Counter(outcome.name for outcome in outcomes)
    devices: dict[str, Any] = {}
    truncated: list[str] = []
    used = 0
    for outcome in outcomes:
        key = outcome.name
        if names[key] > 1 and outcome.device.get("id"):
            key = f"{key} ({outcome.device['id']})"
        number = 2
        base = key
        while key in devices:
            key, number = f"{base} #{number}", number + 1
        entry = {
            **outcome.output,
            "device_id": outcome.device.get("id"),
            "ok": outcome.ok,
            "error": outcome.error,
        }
        for value_key in outcome.value_keys:
            if entry.get(value_key) is None:
                continue
            size = len(json.dumps(entry[value_key], ensure_ascii=False))
            room = max(0, min(MAX_OUTPUT_TEXT_CHARS, MAX_OUTPUT_TOTAL_CHARS - used))
            if size > room:
                entry[value_key] = None
                truncated.append(f"{key}.{value_key}")
            else:
                used += size
        for text_key in outcome.text_keys:
            text = entry.get(text_key)
            if not isinstance(text, str):
                continue
            room = max(0, min(MAX_OUTPUT_TEXT_CHARS, MAX_OUTPUT_TOTAL_CHARS - used))
            entry[text_key], cut = _cap(text, room)
            used += min(len(text), room)
            if cut:
                truncated.append(f"{key}.{text_key}")
        devices[key] = entry
    evidence = [item for outcome in outcomes for item in outcome.evidence]
    failures = [f"{outcome.name} ({outcome.error})" for outcome in outcomes if not outcome.ok]
    output = {"devices": devices, "truncated": truncated, **(extra_output or {})}
    if failures:
        return HandlerResult(
            success=False,
            summary=summary,
            error="Failed: " + "; ".join(failures),
            evidence=evidence,
            output=output,
        )
    return HandlerResult(success=True, summary=summary, evidence=evidence, output=output)


def text_evidence(
    device: dict[str, Any], name: str, text: str, *, command: str, success: bool = True
) -> dict[str, Any]:
    """A text artifact other steps read like a CLI capture (evidence.*, git.commit)."""
    return {
        "kind": "cli_output",
        "name": f"{device_label(device)}:{name}",
        "device_id": device.get("id"),
        "content_text": text,
        "content_json": {
            "device_id": device.get("id"),
            "device_name": device_label(device),
            "command": command,
            "success": success,
        },
    }


def no_targets() -> HandlerResult:
    return HandlerResult(
        success=False, error="No target devices configured", summary="Missing targets"
    )


def unavailable(exc: StepUnavailable) -> HandlerResult:
    return HandlerResult(success=False, error=str(exc), summary="gNMI unavailable")


async def prepare(
    ctx: HandlerContext, config: GnmiConnectionConfig
) -> ResolvedAccess | HandlerResult:
    """Check the platform and resolve the step's secrets, or the failed result."""
    try:
        egress_gate(ctx)
    except StepUnavailable as exc:
        return unavailable(exc)
    try:
        return await resolve_access(ctx.require_services(), config)
    except ValueError as exc:
        return HandlerResult(
            success=False, error=f"Invalid gNMI config: {exc}", summary="Config error"
        )
    except RuntimeError as exc:
        return HandlerResult(
            success=False,
            error=f"Could not load the organization's trusted CAs: {exc}",
            summary="Trusted CAs unavailable",
        )
