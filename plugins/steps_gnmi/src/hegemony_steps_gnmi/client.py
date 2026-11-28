# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""A gNMI client on ``grpc.aio``: dial, log in, Capabilities, Get and Set.

The wheel dials the device itself (the platform has no gNMI channel to hand
out), so this module applies what the platform applies to the connections
it opens:

- **Egress.** The flow's egress policy (``services.enforce_egress``) is
  asked about the device's name and about every address it resolves to,
  and the channel dials an address that was checked, never the name, so a
  second lookup cannot lead it elsewhere. Loopback, link-local (cloud
  metadata included), unspecified and multicast addresses are refused.
- **Proxies.** gRPC's own HTTP proxy support is off: the environment's
  ``http_proxy`` would otherwise carry the connection somewhere the policy
  never saw.
- **TLS.** The channel verifies the device's certificate against the
  worker's system store and the organization's trusted CAs, or against the
  step's CA bundle alone, for the device's name (or the step's TLS server
  name). There is no "skip verification" mode: a lab device with a
  self-signed certificate is trusted by giving that certificate as the CA
  bundle.
- **Credentials** travel as the ``username`` and ``password`` call metadata
  gNMI devices read, and never over a plaintext channel unless the step
  allows it in so many words.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

import grpc
import grpc.aio

from . import messages

#: The IANA-assigned gNMI port. Vendors' defaults differ (6030 on Arista EOS,
#: 57400 on Nokia SR Linux and IOS XR, 32767 on Junos), so steps make it a
#: setting.
DEFAULT_GNMI_PORT = 9339
#: Largest reply a step accepts (a full configuration Get can be large).
MAX_MESSAGE_BYTES = 64 * 1024 * 1024
#: Characters of a device's error text a step reports.
MAX_ERROR_DETAIL_CHARS = 500

_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
        ipaddress.ip_address("100.100.100.200"),
    }
)
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")
_BROADCAST = ipaddress.ip_address("255.255.255.255")

#: Statuses after which the next address is tried.
_UNREACHABLE = frozenset({grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED})

Log = Callable[[str], Awaitable[None]]
Enforce = Callable[..., Awaitable[None]]


class GnmiError(Exception):
    """A gNMI request that failed, or a device the step cannot use.

    ``code`` is the gRPC status of a failed call, None for anything else.
    """

    def __init__(self, message: str, *, code: grpc.StatusCode | None = None) -> None:
        super().__init__(message)
        self.code = code


class DestinationRefused(GnmiError):
    """The step will not dial this address."""


@dataclass(frozen=True)
class TlsSettings:
    """How the channel is secured.

    ``root_pem`` None verifies against gRPC's own roots; the steps always
    pass the system store and the organization's trusted CAs, or the step's
    CA bundle.
    """

    use_tls: bool = True
    root_pem: bytes | None = field(default=None, repr=False)
    client_cert_pem: bytes | None = field(default=None, repr=False)
    client_key_pem: bytes | None = field(default=None, repr=False)
    server_name: str = ""


@dataclass(frozen=True)
class Login:
    """The ``username`` and ``password`` call metadata; empty sends none."""

    username: str = ""
    password: str = field(default="", repr=False)

    def metadata(self) -> tuple[tuple[str, str], ...]:
        if not self.username and not self.password:
            return ()
        return (("username", self.username), ("password", self.password))


def blocked_address_reason(address: str) -> str | None:
    """Why the step refuses to dial the IP ``address``, or None when it may.

    The same addresses ``http.request`` refuses, for the same reasons
    (copied rather than imported, so this wheel does not depend on that one).
    Private addresses are allowed: the flow's egress policy decides those.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if isinstance(ip, ipaddress.IPv6Address) and ip.scope_id:
        ip = ipaddress.IPv6Address(str(ip).split("%", 1)[0])
    if ip in _METADATA_ADDRESSES:
        return "a cloud instance metadata address"
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address"
    if ip.is_unspecified or (isinstance(ip, ipaddress.IPv4Address) and ip in _THIS_NETWORK):
        return "an unspecified address"
    if ip.is_multicast:
        return "a multicast address"
    if ip == _BROADCAST:
        return "the broadcast address"
    return None


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


async def resolve_addresses(host: str, port: int) -> list[str]:
    """The addresses to dial for ``host``, in the resolver's order, without repeats."""
    if is_ip_literal(host):
        return [host]
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise GnmiError(f"cannot resolve {host}: {exc}") from None
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise GnmiError(f"cannot resolve {host}: no addresses")
    return addresses


def _target(address: str, port: int) -> str:
    """A gRPC target that dials ``address`` itself, with no name resolution."""
    if ":" in address:
        return f"ipv6:[{address}]:{port}"
    return f"ipv4:{address}:{port}"


def describe_rpc_error(exc: grpc.aio.AioRpcError, *, operation: str, timeout: float) -> str:
    """One line for a failed call: what failed, the gRPC status and the device's text."""
    code = exc.code()
    detail = (exc.details() or "").strip().replace("\n", " ")
    if len(detail) > MAX_ERROR_DETAIL_CHARS:
        detail = detail[:MAX_ERROR_DETAIL_CHARS] + "…"
    name = code.name if code is not None else "UNKNOWN"
    if code == grpc.StatusCode.DEADLINE_EXCEEDED:
        return f"{operation}: no answer within {timeout:g} s"
    if code == grpc.StatusCode.UNAUTHENTICATED:
        return f"{operation}: the device refused the login ({name}: {detail})"
    if code == grpc.StatusCode.UNIMPLEMENTED:
        return f"{operation}: the device does not implement it ({name}: {detail})"
    return f"{operation} failed ({name}: {detail})" if detail else f"{operation} failed ({name})"


class GnmiSession:
    """An open channel to one device; the caller closes it."""

    def __init__(
        self,
        channel: grpc.aio.Channel,
        *,
        address: str,
        login: Login,
        timeout: float,
        log: Log | None = None,
    ) -> None:
        self._channel = channel
        self.address = address
        self._metadata = login.metadata()
        self.timeout = timeout
        self._log = log
        self.capabilities: Any = None

    async def _call(self, method: str, request: Any, response_class: Any, *, timeout: float) -> Any:
        call = self._channel.unary_unary(
            f"/{messages.SERVICE}/{method}",
            request_serializer=lambda message: message.SerializeToString(),
            response_deserializer=response_class.FromString,
        )
        started = time.monotonic()
        try:
            reply = await call(request, timeout=timeout, metadata=self._metadata or None)
        except grpc.aio.AioRpcError as exc:
            text = describe_rpc_error(exc, operation=method, timeout=timeout)
            await self._note(f"{method}: {text.split(': ', 1)[-1]}")
            raise GnmiError(text, code=exc.code()) from None
        await self._note(f"{method}: ok ({(time.monotonic() - started) * 1000:.0f} ms)")
        return reply

    async def _note(self, line: str) -> None:
        if self._log is not None:
            await self._log(line)

    async def fetch_capabilities(self, *, timeout: float | None = None) -> Any:
        self.capabilities = await self._call(
            "Capabilities",
            messages.CapabilityRequest(),
            messages.CapabilityResponse,
            timeout=timeout or self.timeout,
        )
        return self.capabilities

    def supported_encodings(self) -> frozenset[str]:
        if self.capabilities is None:
            return frozenset()
        return frozenset(
            messages.enum_name("gnmi.Encoding", number).lower()
            for number in self.capabilities.supported_encodings
        )

    async def get(
        self,
        paths: Sequence[Any],
        *,
        prefix: Any | None = None,
        data_type: str = "ALL",
        encoding: str = "JSON_IETF",
    ) -> Any:
        request = messages.GetRequest()
        if prefix is not None:
            request.prefix.CopyFrom(prefix)
        for path in paths:
            request.path.add().CopyFrom(path)
        request.type = messages.enum_value("gnmi.GetRequest.DataType", data_type)
        request.encoding = messages.enum_value("gnmi.Encoding", encoding)
        return await self._call("Get", request, messages.GetResponse, timeout=self.timeout)

    async def set(
        self,
        *,
        prefix: Any | None = None,
        deletes: Sequence[Any] = (),
        replaces: Sequence[tuple[Any, Any]] = (),
        updates: Sequence[tuple[Any, Any]] = (),
    ) -> Any:
        request = messages.SetRequest()
        if prefix is not None:
            request.prefix.CopyFrom(prefix)
        for path in deletes:
            request.delete.add().CopyFrom(path)
        for target, items in ((request.replace, replaces), (request.update, updates)):
            for path, value in items:
                update = target.add()
                update.path.CopyFrom(path)
                update.val.CopyFrom(value)
        return await self._call("Set", request, messages.SetResponse, timeout=self.timeout)

    async def close(self) -> None:
        await self._channel.close(grace=None)


def _channel_options(tls: TlsSettings, host: str) -> list[tuple[str, Any]]:
    options: list[tuple[str, Any]] = [
        ("grpc.max_receive_message_length", MAX_MESSAGE_BYTES),
        ("grpc.max_send_message_length", MAX_MESSAGE_BYTES),
        # The environment's http_proxy would carry the connection past the
        # egress policy: dial the checked address directly.
        ("grpc.enable_http_proxy", 0),
        ("grpc.enable_retries", 0),
        # No subchannel shared with another step's channel (other credentials).
        ("grpc.use_local_subchannel_pool", 1),
    ]
    if tls.use_tls:
        name = tls.server_name or host
        options.append(("grpc.ssl_target_name_override", name))
        options.append(("grpc.default_authority", name))
    return options


def _make_channel(address: str, port: int, host: str, tls: TlsSettings) -> grpc.aio.Channel:
    target = _target(address, port)
    options = _channel_options(tls, host)
    if not tls.use_tls:
        return grpc.aio.insecure_channel(target, options=options)
    credentials = grpc.ssl_channel_credentials(
        root_certificates=tls.root_pem,
        private_key=tls.client_key_pem,
        certificate_chain=tls.client_cert_pem,
    )
    return grpc.aio.secure_channel(target, credentials, options=options)


async def open_session(
    host: str,
    port: int,
    *,
    tls: TlsSettings,
    login: Login,
    connect_timeout: float,
    rpc_timeout: float,
    enforce: Enforce,
    log: Log | None = None,
) -> GnmiSession:
    """A session to ``host``:``port`` whose Capabilities call has answered.

    Every address ``host`` resolves to is checked first; they are then tried
    in order until one answers. Capabilities is the first call: it proves
    the TLS handshake and the login, and tells the steps which encodings the
    device speaks. Raises :class:`GnmiError`, or the egress policy's denial.
    """
    if not is_ip_literal(host):
        await enforce(host, port, proto="tcp", kind="gnmi")
    addresses = await resolve_addresses(host, port)
    for address in addresses:
        reason = blocked_address_reason(address)
        if reason:
            shown = host if address == host else f"{host} ({address})"
            raise DestinationRefused(
                f"refused to connect to {shown}: it is {reason}, which gNMI steps never reach"
            )
        await enforce(address, port, proto="tcp", kind="gnmi")
    failures: list[tuple[str, str]] = []
    for address in addresses:
        channel = _make_channel(address, port, host, tls)
        session = GnmiSession(channel, address=address, login=login, timeout=rpc_timeout, log=log)
        try:
            await session.fetch_capabilities(timeout=connect_timeout)
        except GnmiError as exc:
            await session.close()
            failures.append((address, str(exc)))
            if exc.code in _UNREACHABLE:
                continue  # this address is unreachable: try the next one
            raise
        except BaseException:
            await session.close()
            raise
        return session
    if len(failures) == 1:
        raise GnmiError(failures[0][1], code=grpc.StatusCode.UNAVAILABLE)
    raise GnmiError(
        "no address answered: " + "; ".join(f"{address}: {text}" for address, text in failures),
        code=grpc.StatusCode.UNAVAILABLE,
    )
