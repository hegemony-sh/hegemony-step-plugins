# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What ``http.request`` refuses to reach, resolve, send on, or put in its output.

- **Secrets.** Secret fields are listed in the handler's ``raw_config_keys``,
  so they arrive as written and are resolved here through
  ``services.resolve_secret_ref`` (the same rules as ``container.run``'s
  ``resolve_secret_values``, copied rather than imported so this wheel does
  not depend on the optional container wheel).
- **Destinations.** Loopback, link-local (cloud metadata included),
  unspecified and multicast addresses are refused before any connection.
- **Headers.** Credential-bearing response headers never reach the output,
  and request headers are recorded by name only.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
from collections.abc import Iterable
from typing import Any

import httpx

from hegemony_step_sdk import HandlerServices

#: A secret reference written bare (``vault://orgs/acme/secrets/api/token``)
#: rather than as a ``{{ secret('...') }}`` template.
_BARE_SECRET_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s'\"{}\\]+$")

#: Template syntax, which the host renders (``{{ secret('…') }}``).
_TEMPLATE_RE = re.compile(r"\{\{|\{%")

#: Default port per supported scheme.
SCHEME_PORTS = {"http": 80, "https": 443}

#: Cloud instance metadata services: AWS, GCP, Azure and others on the IPv4
#: link-local address, AWS's IPv6 endpoint (a unique-local address), and
#: Alibaba Cloud's (in the shared address space 100.64.0.0/10).
_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
        ipaddress.ip_address("100.100.100.200"),
    }
)
#: "This network": Linux connects 0.0.0.0/8 to the local host.
_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")
_BROADCAST = ipaddress.ip_address("255.255.255.255")

#: Response headers that carry credentials or session state: never in output
#: or evidence.
DROPPED_RESPONSE_HEADERS = frozenset(
    {"set-cookie", "set-cookie2", "authorization", "proxy-authorization", "cookie"}
)

#: Replacement for a credential found in text the step reports.
REDACTED = "[redacted]"

#: Credentials shorter than this could not be searched for in reported text
#: without mangling everything they match, so the step refuses them.
MIN_SCRUB_LENGTH = 4


class RequestRefused(Exception):
    """The step refuses a request before sending it (destination, scheme, redirect)."""


def is_bare_secret_ref(value: str) -> bool:
    """Whether ``value`` is a bare secret reference like ``vault://path/key``."""
    return bool(_BARE_SECRET_REF_RE.match(value.strip()))


def is_templated(value: Any) -> bool:
    """Whether ``value`` is a string still holding template syntax."""
    return isinstance(value, str) and bool(_TEMPLATE_RE.search(value))


async def resolve_secret_text(
    services: HandlerServices, raw: str, *, field: str, source: str
) -> str:
    """Resolve one secret field, as written by the step author, into its value.

    ``raw`` is one of:

    - a bare reference (``vault://orgs/acme/secrets/api/token``), resolved
      through the host as ``{{ secret('<reference>') }}``;
    - a template (``{{ secret('vault://…') }}``), rendered through the host;
    - anything else, used as written.

    The written text decides, never the resolved value, so a value that
    looks like a reference is not resolved a second time. Any
    ``scheme://…`` text is read as a reference, since only the host knows
    its backends' schemes. The host registers every value it resolves for
    redaction; a literal is not registered.

    Raises ``ValueError`` when a reference or template resolves to nothing.
    The message never contains the value.
    """
    bare = is_bare_secret_ref(raw)
    if bare:
        template = "{{ secret('" + raw.strip() + "') }}"
    elif is_templated(raw):
        template = raw
    else:
        return raw
    value = await services.resolve_secret_ref(template, source=source) or ""
    if not value and bare:
        scheme = raw.strip().split("://", 1)[0]
        raise ValueError(
            f"{field} resolved to an empty value: it is written as a secret reference "
            f"(scheme {scheme!r}), and no secret backend returned a value for it. Check "
            "the reference; a literal value shaped like a URL cannot be written directly, "
            "so store it in a secret backend and reference it"
        )
    if not value:
        raise ValueError(f"{field} resolved to an empty value")
    return value


def blocked_address_reason(address: str) -> str | None:
    """Why the step refuses to connect to the IP ``address``, or None when it may.

    Refused: loopback, link-local (cloud instance metadata included),
    unspecified (``0.0.0.0/8``, ``::``), multicast and the IPv4 broadcast
    address, IPv4-mapped IPv6 forms included. Private (RFC 1918, ULA)
    addresses are allowed: the flow's egress policy decides those.
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


def _ip_literal(host: str) -> str | None:
    """``host`` when it is an IP address literal, else None."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return host


async def resolve_host(host: str, port: int) -> list[str]:
    """Every address ``host`` resolves to for a TCP connection (the event loop's resolver)."""
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


async def check_destination(host: str, port: int) -> None:
    """Refuse ``host`` when it is, or resolves to, an address the step never reaches.

    A literal IP is judged as written. A name is resolved first, and refused
    when any address it resolves to is refused: the connection may use any
    of them. Raises :class:`RequestRefused`.
    """
    literal = _ip_literal(host)
    if literal is not None:
        reason = blocked_address_reason(literal)
        if reason:
            raise RequestRefused(
                f"refused to send a request to {host}: it is {reason}, which this step "
                "never reaches"
            )
        return
    try:
        addresses = await resolve_host(host, port)
    except OSError as exc:
        raise RequestRefused(f"cannot resolve host {host}: {exc}") from None
    except ValueError as exc:
        # UnicodeError included: the resolver refuses an empty or overlong label.
        raise RequestRefused(f"cannot resolve host {host}: not a valid host name ({exc})") from None
    if not addresses:
        raise RequestRefused(f"cannot resolve host {host}: no addresses")
    for address in addresses:
        reason = blocked_address_reason(address)
        if reason:
            raise RequestRefused(
                f"refused to send a request to {host}: it resolves to {address}, {reason}, "
                "which this step never reaches"
            )


def url_port(url: httpx.URL) -> int:
    """The port a request to ``url`` connects to."""
    return url.port or SCHEME_PORTS.get(url.scheme, 80)


def url_host(url: httpx.URL) -> str:
    """The host a request to ``url`` connects to, in ASCII (``xn--`` labels kept).

    ``url.host`` decodes ``xn--`` labels to Unicode, and the resolver would
    encode that text again by older IDNA rules, possibly into another name,
    so the step checks and compares the name the connection uses.
    """
    return url.raw_host.decode("ascii")


def same_origin(a: httpx.URL, b: httpx.URL) -> bool:
    """Whether two URLs share scheme, host and port."""
    return a.scheme == b.scheme and url_host(a) == url_host(b) and url_port(a) == url_port(b)


def filtered_response_headers(headers: httpx.Headers) -> dict[str, str]:
    """Response headers as ``lower-case name -> value``, credential-bearing ones dropped.

    Repeated headers are joined with ``", "``.
    """
    result: dict[str, str] = {}
    for name, value in headers.multi_items():
        key = name.lower()
        if key in DROPPED_RESPONSE_HEADERS:
            continue
        result[key] = f"{result[key]}, {value}" if key in result else value
    return result


def _escaped_forms(secret: str) -> set[str]:
    """``secret`` as it appears in text: as is, and escaped inside a JSON string.

    A response that repeats the secret in JSON text may escape its quotes,
    backslashes, control and non-ASCII characters, and slashes, so each of
    those forms is searched for too.
    """
    forms = {secret}
    for ensure_ascii in (True, False):
        forms.add(json.dumps(secret, ensure_ascii=ensure_ascii)[1:-1])
    forms.update([form.replace("/", "\\/") for form in forms])
    return forms


class Scrubber:
    """Replaces known credential values in text and nested JSON-shaped data."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        """Keep the credentials worth searching for, raw and JSON-escaped, longest first."""
        unique = {
            form
            for s in secrets
            if isinstance(s, str) and len(s) >= MIN_SCRUB_LENGTH
            for form in _escaped_forms(s)
        }
        # Longest first, so a value containing another is replaced whole.
        self._secrets = sorted(unique, key=len, reverse=True)

    def text(self, value: str) -> str:
        """``value`` with every known credential replaced."""
        for secret in self._secrets:
            if secret in value:
                value = value.replace(secret, REDACTED)
        return value

    def tree(self, value: Any) -> Any:
        """``value`` (dicts, lists, strings, numbers) with every known credential replaced.

        A number that contains a credential (a numeric one the server echoes as a
        JSON number) is replaced whole; other numbers are kept.
        """
        if not self._secrets:
            return value
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            rendered = json.dumps(value)
            return REDACTED if any(secret in rendered for secret in self._secrets) else value
        if isinstance(value, dict):
            return {self.tree(k): self.tree(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.tree(item) for item in value]
        return value


__all__ = [
    "DROPPED_RESPONSE_HEADERS",
    "MIN_SCRUB_LENGTH",
    "REDACTED",
    "SCHEME_PORTS",
    "RequestRefused",
    "Scrubber",
    "blocked_address_reason",
    "check_destination",
    "filtered_response_headers",
    "is_bare_secret_ref",
    "is_templated",
    "resolve_host",
    "resolve_secret_text",
    "same_origin",
    "url_host",
    "url_port",
]
