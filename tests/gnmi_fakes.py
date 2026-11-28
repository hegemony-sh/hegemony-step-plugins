# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""An in-process gNMI device over real gRPC (TLS or plaintext) for the gnmi steps' tests.

``FakeGnmiDevice`` keeps a configuration tree as nested dicts. A keyed list
entry is stored under its element text (``interface[name=Ethernet1]``), so
paths map onto the tree one element at a time. Get returns the subtree at
each path (``NOT_FOUND`` when absent); Set applies deletes, replaces and
updates to a copy and keeps it only when all of them succeed, as the gNMI
specification requires. Every request and its call metadata are recorded.

``Pki`` makes a CA, a server certificate (for ``device.test`` and
127.0.0.1) and a client certificate with ``cryptography``.
"""

from __future__ import annotations

import copy
import datetime
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any

import grpc
import grpc.aio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from hegemony_step_sdk import DeviceCredentials
from hegemony_steps_gnmi import messages

# --- Certificates ---------------------------------------------------------------


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _cert(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: x509.Certificate | None,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool = False,
    names: tuple[str, ...] = (),
    client: bool = False,
) -> x509.Certificate:
    now = datetime.datetime.now(datetime.UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    alt: list[x509.GeneralName] = []
    for value in names:
        try:
            alt.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            alt.append(x509.DNSName(value))
    if alt:
        builder = builder.add_extension(x509.SubjectAlternativeName(alt), critical=False)
    if not ca:
        usage = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH if client else None
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([usage] if usage else [x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


@dataclass
class Pki:
    """A CA with a server and a client certificate, as PEM bytes."""

    ca_pem: bytes
    server_cert_pem: bytes
    server_key_pem: bytes
    client_cert_pem: bytes
    client_key_pem: bytes

    @classmethod
    def make(cls, server_names: tuple[str, ...] = ("device.test", "127.0.0.1")) -> Pki:
        ca_key = _key()
        ca = _cert("Test CA", ca_key, None, ca_key, ca=True)
        server_key = _key()
        server = _cert("device", server_key, ca, ca_key, names=server_names)
        client_key = _key()
        client = _cert("hegemony", client_key, ca, ca_key, client=True)

        def pem(cert: x509.Certificate) -> bytes:
            return cert.public_bytes(serialization.Encoding.PEM)

        return cls(
            ca_pem=pem(ca),
            server_cert_pem=pem(server),
            server_key_pem=_pem_key(server_key),
            client_cert_pem=pem(client),
            client_key_pem=_pem_key(client_key),
        )


# --- The device ------------------------------------------------------------------


def _elem_key(elem: Any) -> str:
    keys = "".join(f"[{name}={value}]" for name, value in sorted(dict(elem.key).items()))
    return elem.name + keys


def _merge(target: dict[str, Any], value: dict[str, Any]) -> None:
    for key, item in value.items():
        if isinstance(item, dict) and isinstance(target.get(key), dict):
            _merge(target[key], item)
        else:
            target[key] = copy.deepcopy(item)


class _Abort(Exception):
    def __init__(self, code: grpc.StatusCode, details: str) -> None:
        self.code = code
        self.details = details


@dataclass
class FakeGnmiDevice:
    """A gNMI device: a configuration tree, a login, the encodings it lists."""

    tree: dict[str, Any] = field(default_factory=dict)
    username: str = "admin"
    password: str = "s3cret-pass"
    require_login: bool = True
    encodings: tuple[str, ...] = ("JSON", "JSON_IETF", "PROTO")
    version: str = "0.10.0"
    #: A gRPC status the next Set answers with instead of applying it.
    fail_set: tuple[grpc.StatusCode, str] | None = None
    #: Gets after this many answer with this status (read-back failures).
    fail_get_after: tuple[int, grpc.StatusCode, str] | None = None
    requests: list[tuple[str, Any, dict[str, str]]] = field(default_factory=list)

    def count(self, method: str) -> int:
        return sum(1 for name, _, _ in self.requests if name == method)

    def _check_login(self, metadata: dict[str, str]) -> None:
        if not self.require_login:
            return
        if metadata.get("username") != self.username or metadata.get("password") != self.password:
            raise _Abort(grpc.StatusCode.UNAUTHENTICATED, "bad username or password")

    def _walk(self, tree: dict[str, Any], path: Any, *, create: bool = False) -> tuple[Any, str]:
        """``(parent dict, last key)`` of ``path`` in ``tree``."""
        elems = list(path.elem)
        if not elems:
            raise _Abort(grpc.StatusCode.INVALID_ARGUMENT, "the root cannot be changed")
        node = tree
        for elem in elems[:-1]:
            key = _elem_key(elem)
            if key not in node:
                if not create:
                    raise _Abort(grpc.StatusCode.NOT_FOUND, f"{key} does not exist")
                node[key] = {}
            node = node[key]
            if not isinstance(node, dict):
                raise _Abort(grpc.StatusCode.INVALID_ARGUMENT, f"{key} is a leaf")
        return node, _elem_key(elems[-1])

    def _value(self, typed: Any) -> Any:
        kind = typed.WhichOneof("value")
        if kind in ("json_val", "json_ietf_val"):
            return json.loads(getattr(typed, kind))
        if kind is None:
            raise _Abort(grpc.StatusCode.INVALID_ARGUMENT, "an update has no value")
        return getattr(typed, kind)

    async def capabilities(self, request: Any, metadata: dict[str, str]) -> Any:
        self.requests.append(("Capabilities", request, metadata))
        self._check_login(metadata)
        reply = messages.CapabilityResponse(gNMI_version=self.version)
        model = reply.supported_models.add()
        model.name, model.organization, model.version = "openconfig-interfaces", "OpenConfig", "3.0"
        for name in self.encodings:
            reply.supported_encodings.append(messages.enum_value("gnmi.Encoding", name))
        return reply

    async def get(self, request: Any, metadata: dict[str, str]) -> Any:
        self.requests.append(("Get", request, metadata))
        self._check_login(metadata)
        if self.fail_get_after is not None and self.count("Get") > self.fail_get_after[0]:
            raise _Abort(self.fail_get_after[1], self.fail_get_after[2])
        encoding = messages.enum_name("gnmi.Encoding", request.encoding)
        if encoding not in self.encodings:
            raise _Abort(grpc.StatusCode.UNIMPLEMENTED, f"encoding {encoding} not supported")
        reply = messages.GetResponse()
        for path in request.path:
            if list(path.elem):
                parent, key = self._walk(self.tree, path)
                if key not in parent:
                    raise _Abort(grpc.StatusCode.NOT_FOUND, f"{key} does not exist")
                value = parent[key]
            else:
                value = self.tree
            notification = reply.notification.add()
            notification.timestamp = 1_700_000_000_000_000_000
            update = notification.update.add()
            update.path.CopyFrom(path)
            data = json.dumps(value).encode()
            if encoding == "JSON_IETF":
                update.val.json_ietf_val = data
            elif encoding == "JSON":
                update.val.json_val = data
            elif isinstance(value, str):
                update.val.string_val = value
            else:
                update.val.json_val = data
        return reply

    async def set(self, request: Any, metadata: dict[str, str]) -> Any:
        self.requests.append(("Set", request, metadata))
        self._check_login(metadata)
        if self.fail_set is not None:
            code, details = self.fail_set
            raise _Abort(code, details)
        tree = copy.deepcopy(self.tree)
        reply = messages.SetResponse(timestamp=1_700_000_000_000_000_001)
        operation = "gnmi.UpdateResult.Operation"
        for path in request.delete:
            parent, key = self._walk(tree, path)
            parent.pop(key, None)
            reply.response.add(path=path, op=messages.enum_value(operation, "DELETE"))
        for update in request.replace:
            parent, key = self._walk(tree, update.path, create=True)
            parent[key] = self._value(update.val)
            reply.response.add(path=update.path, op=messages.enum_value(operation, "REPLACE"))
        for update in request.update:
            parent, key = self._walk(tree, update.path, create=True)
            value = self._value(update.val)
            if isinstance(value, dict) and isinstance(parent.get(key), dict):
                _merge(parent[key], value)
            else:
                parent[key] = value
            reply.response.add(path=update.path, op=messages.enum_value(operation, "UPDATE"))
        self.tree = tree  # all of it, or (on an error above) none of it
        return reply


class FakeGnmiServer:
    """A ``grpc.aio`` server for one :class:`FakeGnmiDevice` on 127.0.0.1."""

    def __init__(
        self,
        device: FakeGnmiDevice,
        *,
        pki: Pki | None = None,
        require_client_cert: bool = False,
    ) -> None:
        self.device = device
        self.pki = pki
        self.require_client_cert = require_client_cert
        self.port = 0
        self._server: grpc.aio.Server | None = None

    def _handler(self, method: Any, request_class: Any) -> Any:
        async def call(request: Any, context: grpc.aio.ServicerContext) -> Any:
            metadata = {key: value for key, value in context.invocation_metadata() or ()}
            try:
                return await method(request, metadata)
            except _Abort as exc:
                await context.abort(exc.code, exc.details)
                raise AssertionError("context.abort returns only by raising") from exc

        return grpc.unary_unary_rpc_method_handler(
            call,
            request_deserializer=request_class.FromString,
            response_serializer=lambda message: message.SerializeToString(),
        )

    async def start(self) -> FakeGnmiServer:
        server = grpc.aio.server()
        handlers = {
            "Capabilities": self._handler(self.device.capabilities, messages.CapabilityRequest),
            "Get": self._handler(self.device.get, messages.GetRequest),
            "Set": self._handler(self.device.set, messages.SetRequest),
        }
        server.add_generic_rpc_handlers(
            (grpc.method_handlers_generic_handler(messages.SERVICE, handlers),)
        )
        if self.pki is None:
            self.port = server.add_insecure_port("127.0.0.1:0")
        else:
            credentials = grpc.ssl_server_credentials(
                [(self.pki.server_key_pem, self.pki.server_cert_pem)],
                root_certificates=self.pki.ca_pem if self.require_client_cert else None,
                require_client_auth=self.require_client_cert,
            )
            self.port = server.add_secure_port("127.0.0.1:0", credentials)
        await server.start()
        self._server = server
        return self

    async def stop(self) -> None:
        if self._server is not None:
            await self._server.stop(grace=None)


# --- Platform services -------------------------------------------------------------


class FakeServices:
    """``HandlerServices`` for the gnmi steps: egress, credentials, secrets, trusted CAs."""

    def __init__(
        self,
        *,
        org_ca_pem: bytes | None = None,
        credentials: DeviceCredentials | None = None,
        secrets: dict[str, str] | None = None,
        denied: set[str] | None = None,
    ) -> None:
        self.org_ca_pem = org_ca_pem
        self.credentials = credentials or DeviceCredentials(
            username="admin", password="s3cret-pass"
        )
        self.secrets = secrets or {}
        self.denied = denied or set()
        self.egress: list[tuple[str, int | None, str | None]] = []
        self.resolved: list[str] = []

    async def enforce_egress(
        self, host: str, port: int | None = None, *, proto: str | None = None, kind: str = ""
    ) -> None:
        self.egress.append((host, port, kind))
        if host in self.denied:
            raise PermissionError(f"egress policy denies {host}")

    async def resolve_device_credentials(self, device: dict[str, Any]) -> DeviceCredentials:
        return self.credentials

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        self.resolved.append(source)
        assert ref is not None
        for name, value in self.secrets.items():
            if name in ref:
                return value
        return None

    async def trusted_ca_certificates(self) -> str:
        return self.org_ca_pem.decode() if self.org_ca_pem else ""
