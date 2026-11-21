# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""A NETCONF client over the byte channel the host opens (RFC 6241, RFC 6242).

The host (``services.open_netconf``) gives the handler an SSH session with the
``netconf`` subsystem started; this module speaks the protocol on it: the
hello exchange, end-of-message (base:1.0) or chunked (base:1.1) framing,
``<rpc>`` requests with their ``message-id``, and ``<rpc-error>`` replies.

Replies are parsed with the standard library's expat parser. A reply that
declares a DOCTYPE or an entity is refused before parsing, so no entity is
ever expanded.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from dataclasses import dataclass, field
from typing import Any
from xml.dom import minidom
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

BASE_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"

CAP_BASE_10 = "urn:ietf:params:netconf:base:1.0"
CAP_BASE_11 = "urn:ietf:params:netconf:base:1.1"
CAP_PREFIX = "urn:ietf:params:netconf:capability:"
CAP_CANDIDATE = CAP_PREFIX + "candidate:1.0"
CAP_CONFIRMED_10 = CAP_PREFIX + "confirmed-commit:1.0"
CAP_CONFIRMED_11 = CAP_PREFIX + "confirmed-commit:1.1"
CAP_VALIDATE_10 = CAP_PREFIX + "validate:1.0"
CAP_VALIDATE_11 = CAP_PREFIX + "validate:1.1"
CAP_ROLLBACK_ON_ERROR = CAP_PREFIX + "rollback-on-error:1.0"
CAP_STARTUP = CAP_PREFIX + "startup:1.0"
CAP_WRITABLE_RUNNING = CAP_PREFIX + "writable-running:1.0"
CAP_XPATH = CAP_PREFIX + "xpath:1.0"

#: Cisco's module with the ``save-config`` RPC (running to startup on IOS XE).
CISCO_IA_NS = "http://cisco.com/yang/cisco-ia"

EOM = b"]]>]]>"
#: Largest message the client accepts; a bigger one fails the request.
MAX_MESSAGE_BYTES = 64 * 1024 * 1024
#: Largest chunk size RFC 6242 allows (4294967295).
_MAX_CHUNK = 4294967295
_CHUNK_HEADER = re.compile(rb"\n#([1-9][0-9]{0,9})\n")
_END_OF_CHUNKS = b"\n##\n"
_UNSAFE_MARKUP = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


class NetconfError(Exception):
    """The session failed: framing, a closed channel, a timeout, a malformed reply."""


@dataclass(frozen=True)
class RpcError:
    """One ``<rpc-error>`` of a reply (RFC 6241, section 4.3)."""

    error_type: str = ""
    tag: str = ""
    severity: str = "error"
    message: str = ""
    path: str = ""
    info: str = ""

    def describe(self) -> str:
        """``tag: message (path)``, the way the step reports it."""
        text = self.tag or "error"
        if self.message:
            text += f": {self.message}"
        if self.path:
            text += f" ({self.path})"
        if self.info and not self.message:
            text += f" [{self.info}]"
        return text


class RpcFailed(NetconfError):
    """The device answered with one or more ``<rpc-error>`` of severity error."""

    def __init__(self, operation: str, errors: list[RpcError]) -> None:
        self.operation = operation
        self.errors = errors
        detail = "; ".join(error.describe() for error in errors) or "rpc-error"
        super().__init__(f"{operation} failed: {detail}")

    def has_tag(self, *tags: str) -> bool:
        return any(error.tag in tags for error in self.errors)


@dataclass
class Reply:
    """One ``<rpc-reply>``: the parsed element, its raw text, and warnings."""

    element: ET.Element
    text: str
    warnings: list[RpcError] = field(default_factory=list)

    def data(self) -> str:
        """The content of the reply's ``<data>`` element as the device wrote it ("" if none)."""
        return element_content(self.text, "data")

    def pretty_data(self) -> str:
        """``data()`` indented, with the prefixes the device declared above it kept."""
        return pretty(self.data(), inherited_prefixes(self.text, "rpc-reply", "data"))


_PREFIX_DECLARATION = re.compile(r"""xmlns:([A-Za-z_][\w.-]*)\s*=\s*(["'])(.*?)\2""")


def inherited_prefixes(text: str, *names: str) -> dict[str, str]:
    """Prefixed namespace declarations on the opening tags of ``names`` (outermost first).

    A device may declare a model's prefix on ``<rpc-reply>`` or ``<data>``
    and use it inside; the extracted content needs those declarations back to
    be well-formed on its own.
    """
    found: dict[str, str] = {}
    for name in names:
        opening = re.search(rf"<(?:[A-Za-z_][\w.-]*:)?{name}(\s[^>]*)?/?>", text)
        if opening and opening.group(1):
            for prefix, _quote, uri in _PREFIX_DECLARATION.findall(opening.group(1)):
                found[prefix] = uri
    return found


def local_name(tag: str) -> str:
    """``{ns}name`` -> ``name``."""
    return tag.rsplit("}", 1)[-1]


def parse_xml(text: str, *, what: str) -> ET.Element:
    """Parse ``text``, refusing DOCTYPE and entity declarations."""
    if _UNSAFE_MARKUP.search(text):
        raise NetconfError(f"{what} declares a DOCTYPE or an entity, which is not accepted")
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise NetconfError(f"{what} is not well-formed XML: {exc}") from None


def check_fragment(text: str, *, what: str) -> list[ET.Element]:
    """Parse ``text`` as a sequence of XML elements (a config's top-level nodes).

    Raises ``NetconfError`` when it is not well-formed or holds text outside
    its elements.
    """
    wrapped = parse_xml(f"<hegemony-fragment>{text}</hegemony-fragment>", what=what)
    if (wrapped.text or "").strip() or any((child.tail or "").strip() for child in wrapped):
        raise NetconfError(f"{what} has text outside its XML elements")
    return list(wrapped)


def element_content(text: str, name: str) -> str:
    """The raw content of the first top-level ``<name>`` child of a reply, prefixes kept.

    Slices the reply text instead of re-serializing the parsed tree, so the
    device's own namespace prefixes and layout reach the step's evidence.
    """
    opening = re.search(rf"<(?:[A-Za-z_][\w.-]*:)?{name}(\s[^>]*)?(/?)>", text)
    if opening is None or opening.group(2) == "/":
        return ""
    closings = list(re.finditer(rf"</(?:[A-Za-z_][\w.-]*:)?{name}\s*>", text))
    closing = closings[-1] if closings else None
    if closing is None or closing.start() < opening.end():
        return ""
    return text[opening.end() : closing.start()]


def pretty(text: str, namespaces: dict[str, str] | None = None) -> str:
    """``text`` (an XML fragment) indented one element per line, for diffs and evidence.

    ``namespaces`` are prefix declarations from above the fragment
    (:func:`inherited_prefixes`); each top element that uses no declaration of
    its own for a prefix gets it, so the result stands on its own.
    """
    if not text.strip():
        return ""
    namespaces = namespaces or {}
    declarations = "".join(
        f' xmlns:{prefix}="{escape(uri, {chr(34): "&quot;"})}"'
        for prefix, uri in namespaces.items()
    )
    try:
        document = minidom.parseString(
            f"<hegemony-fragment{declarations}>{text}</hegemony-fragment>"
        )
    except Exception:  # noqa: BLE001 - not well-formed: show it as it came
        return text.strip() + "\n"
    root = document.documentElement
    if root is None:
        return text.strip() + "\n"
    _strip_blank_text(root)
    for node in root.childNodes:
        if node.nodeType == node.ELEMENT_NODE:
            for prefix, uri in namespaces.items():
                if not node.hasAttribute(f"xmlns:{prefix}"):
                    node.setAttribute(f"xmlns:{prefix}", uri)
    lines = []
    for node in root.childNodes:
        lines.append(node.toprettyxml(indent="  "))
    return "".join(lines).strip() + "\n"


def _strip_blank_text(node: Any) -> None:
    for child in list(node.childNodes):
        if child.nodeType == child.TEXT_NODE and not child.data.strip():
            node.removeChild(child)
        elif child.nodeType == child.ELEMENT_NODE:
            _strip_blank_text(child)


def _rpc_errors(reply: ET.Element) -> list[RpcError]:
    errors = []
    for node in reply:
        if local_name(node.tag) != "rpc-error":
            continue
        fields: dict[str, str] = {}
        info = ""
        for child in node:
            name = local_name(child.tag)
            if name == "error-info":
                info = " ".join(
                    f"{local_name(item.tag)}={(item.text or '').strip()}" for item in child
                )
            else:
                fields[name] = (child.text or "").strip()
        errors.append(
            RpcError(
                error_type=fields.get("error-type", ""),
                tag=fields.get("error-tag", ""),
                severity=fields.get("error-severity", "error") or "error",
                message=fields.get("error-message", ""),
                path=fields.get("error-path", ""),
                info=info,
            )
        )
    return errors


def datastore(name: str) -> str:
    """``<name/>`` for a datastore name, or a ``<url>`` for a URL."""
    if name in ("running", "candidate", "startup"):
        return f"<{name}/>"
    raise ValueError(f"unknown datastore {name!r}")


def filter_xml(filter_type: str, value: str) -> str:
    """The ``<filter>`` element for a subtree or XPath filter ("" for none)."""
    if not value.strip():
        return ""
    if filter_type == "xpath":
        return f'<filter type="xpath" select="{escape(value.strip(), {chr(34): "&quot;"})}"/>'
    check_fragment(value, what="the subtree filter")
    return f'<filter type="subtree">{value}</filter>'


class NetconfSession:
    """One NETCONF session on a host-opened byte channel."""

    def __init__(self, channel: Any, *, timeout: float = 60.0) -> None:
        self._channel = channel
        self.timeout = timeout
        self.capabilities: frozenset[str] = frozenset()
        self.session_id = ""
        self._chunked = False
        self._buffer = b""
        self._message_id = 0
        self._closed = False

    # --- capabilities ---------------------------------------------------

    def supports(self, capability: str) -> bool:
        """Whether the server advertised ``capability`` (parameters ignored)."""
        return any(item.split("?", 1)[0] == capability for item in self.capabilities)

    def has_module(self, namespace: str) -> bool:
        """Whether the server advertised a YANG module in ``namespace``."""
        return any(item.split("?", 1)[0] == namespace for item in self.capabilities)

    @property
    def can_validate(self) -> bool:
        return self.supports(CAP_VALIDATE_11) or self.supports(CAP_VALIDATE_10)

    @property
    def can_confirm(self) -> bool:
        return self.supports(CAP_CONFIRMED_11) or self.supports(CAP_CONFIRMED_10)

    # --- framing --------------------------------------------------------

    async def _send(self, text: str) -> None:
        payload = text.encode("utf-8")
        if self._chunked:
            data = b"\n#%d\n" % len(payload) + payload + _END_OF_CHUNKS
        else:
            data = payload + EOM
        await self._channel.write(data)

    async def _fill(self) -> None:
        chunk = await self._channel.read(65536)
        if not chunk:
            raise NetconfError("the device closed the NETCONF session")
        self._buffer += chunk
        if len(self._buffer) > MAX_MESSAGE_BYTES + 64:
            raise NetconfError(f"a NETCONF message exceeded {MAX_MESSAGE_BYTES} bytes")

    async def _receive(self) -> str:
        if self._chunked:
            return await self._receive_chunked()
        while True:
            end = self._buffer.find(EOM)
            if end >= 0:
                message, self._buffer = self._buffer[:end], self._buffer[end + len(EOM) :]
                return message.decode("utf-8", "replace")
            await self._fill()

    async def _receive_chunked(self) -> str:
        parts: list[bytes] = []
        size = 0
        while True:
            while len(self._buffer) < 4:
                await self._fill()
            if self._buffer.startswith(_END_OF_CHUNKS):
                self._buffer = self._buffer[len(_END_OF_CHUNKS) :]
                return b"".join(parts).decode("utf-8", "replace")
            match = _CHUNK_HEADER.match(self._buffer)
            if match is None:
                if len(self._buffer) > 16 or (self._buffer and not self._buffer.startswith(b"\n")):
                    raise NetconfError("malformed NETCONF chunk header")
                await self._fill()
                continue
            length = int(match.group(1))
            if length > _MAX_CHUNK or size + length > MAX_MESSAGE_BYTES:
                raise NetconfError(f"a NETCONF message exceeded {MAX_MESSAGE_BYTES} bytes")
            while len(self._buffer) < match.end() + length:
                await self._fill()
            parts.append(self._buffer[match.end() : match.end() + length])
            size += length
            self._buffer = self._buffer[match.end() + length :]

    # --- session --------------------------------------------------------

    async def hello(self) -> None:
        """Exchange hellos; switch to chunked framing when both sides speak base:1.1."""
        await self._send(
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<hello xmlns="{BASE_NS}"><capabilities>'
            f"<capability>{CAP_BASE_10}</capability>"
            f"<capability>{CAP_BASE_11}</capability>"
            "</capabilities></hello>"
        )
        text = await asyncio.wait_for(self._receive(), timeout=self.timeout)
        root = parse_xml(text, what="the device's hello")
        if local_name(root.tag) != "hello":
            raise NetconfError("the device did not start with a NETCONF hello")
        capabilities = set()
        for node in root.iter():
            name = local_name(node.tag)
            if name == "capability" and node.text:
                capabilities.add(node.text.strip())
            elif name == "session-id" and node.text:
                self.session_id = node.text.strip()
        self.capabilities = frozenset(capabilities)
        if not (self.supports(CAP_BASE_10) or self.supports(CAP_BASE_11)):
            raise NetconfError("the device's hello names no NETCONF base capability")
        self._chunked = self.supports(CAP_BASE_11)

    async def rpc(self, body: str, *, operation: str = "", timeout: float | None = None) -> Reply:
        """Send ``<rpc>body</rpc>`` and return its reply.

        Raises:
            RpcFailed: the reply holds an ``<rpc-error>`` of severity error.
            NetconfError: no reply in time, a closed session, or a reply
                that is not one.
        """
        self._message_id += 1
        message_id = str(self._message_id)
        limit = self.timeout if timeout is None else timeout
        name = operation or _operation_name(body)
        # One deadline for the whole request: sending (a device that stops
        # reading stalls the write) and every message read until the reply.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + limit
        try:
            await asyncio.wait_for(
                self._send(f'<rpc xmlns="{BASE_NS}" message-id="{message_id}">{body}</rpc>'),
                timeout=limit,
            )
        except TimeoutError:
            raise NetconfError(
                f"{name}: the device did not accept the request within {limit:g} s"
            ) from None
        while True:
            try:
                text = await asyncio.wait_for(
                    self._receive(), timeout=max(0.0, deadline - loop.time())
                )
            except TimeoutError:
                raise NetconfError(f"{name}: no reply within {limit:g} s") from None
            root = parse_xml(text, what=f"the reply to {name}")
            if local_name(root.tag) == "notification":
                continue
            if local_name(root.tag) != "rpc-reply":
                raise NetconfError(f"{name}: the device sent <{local_name(root.tag)}>, not a reply")
            if root.get("message-id") not in (None, message_id):
                raise NetconfError(
                    f"{name}: the reply's message-id {root.get('message-id')!r} is not "
                    f"{message_id!r}"
                )
            errors = _rpc_errors(root)
            failures = [error for error in errors if error.severity != "warning"]
            if failures:
                raise RpcFailed(name, failures)
            return Reply(root, text, [error for error in errors if error.severity == "warning"])

    async def close(self) -> None:
        """Send ``<close-session>`` (best effort) and close the channel."""
        if self._closed:
            return
        self._closed = True
        # Bounded as a whole (the request has its own deadline too), so a
        # stalled device cannot keep the channel, and its locks, open.
        with contextlib.suppress(Exception):
            await asyncio.wait_for(
                self.rpc("<close-session/>", timeout=min(self.timeout, 10.0)),
                timeout=min(self.timeout, 10.0) + 1.0,
            )
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self._channel.close(), timeout=10.0)

    # --- operations -----------------------------------------------------

    async def get_config(self, source: str, filter_body: str = "") -> Reply:
        return await self.rpc(
            f"<get-config><source>{datastore(source)}</source>{filter_body}</get-config>",
            operation=f"get-config {source}",
        )

    async def get(self, filter_body: str = "") -> Reply:
        return await self.rpc(f"<get>{filter_body}</get>", operation="get")

    async def edit_config(
        self,
        target: str,
        config: str,
        *,
        default_operation: str = "",
        error_option: str = "",
        test_option: str = "",
    ) -> Reply:
        parts = [f"<target>{datastore(target)}</target>"]
        if default_operation:
            parts.append(f"<default-operation>{default_operation}</default-operation>")
        if test_option:
            parts.append(f"<test-option>{test_option}</test-option>")
        if error_option:
            parts.append(f"<error-option>{error_option}</error-option>")
        parts.append(f"<config>{config}</config>")
        return await self.rpc(
            f"<edit-config>{''.join(parts)}</edit-config>", operation=f"edit-config {target}"
        )

    async def lock(self, target: str) -> Reply:
        return await self.rpc(
            f"<lock><target>{datastore(target)}</target></lock>", operation=f"lock {target}"
        )

    async def unlock(self, target: str) -> Reply:
        return await self.rpc(
            f"<unlock><target>{datastore(target)}</target></unlock>",
            operation=f"unlock {target}",
        )

    async def discard_changes(self) -> Reply:
        return await self.rpc("<discard-changes/>", operation="discard-changes")

    async def validate(self, source: str) -> Reply:
        return await self.rpc(
            f"<validate><source>{datastore(source)}</source></validate>",
            operation=f"validate {source}",
        )

    async def commit(
        self,
        *,
        confirmed: bool = False,
        confirm_timeout: int | None = None,
        persist: str = "",
        persist_id: str = "",
        timeout: float | None = None,
    ) -> Reply:
        parts = []
        if confirmed:
            parts.append("<confirmed/>")
            if confirm_timeout is not None:
                parts.append(f"<confirm-timeout>{int(confirm_timeout)}</confirm-timeout>")
            if persist:
                parts.append(f"<persist>{escape(persist)}</persist>")
        if persist_id:
            parts.append(f"<persist-id>{escape(persist_id)}</persist-id>")
        name = "confirmed commit" if confirmed else "commit"
        return await self.rpc(f"<commit>{''.join(parts)}</commit>", operation=name, timeout=timeout)

    async def cancel_commit(self, persist_id: str = "") -> Reply:
        body = f"<persist-id>{escape(persist_id)}</persist-id>" if persist_id else ""
        return await self.rpc(f"<cancel-commit>{body}</cancel-commit>", operation="cancel-commit")

    async def save_config(self) -> str:
        """Copy running to startup; returns how ("copy-config" or "save-config").

        Uses ``<copy-config>`` when the device has the startup datastore, else
        the ``save-config`` RPC of Cisco's ``cisco-ia`` module when the device
        advertises it (IOS XE keeps no NETCONF startup datastore).

        Raises:
            NetconfError: the device offers neither.
        """
        if self.supports(CAP_STARTUP):
            await self.rpc(
                "<copy-config><target><startup/></target><source><running/></source></copy-config>",
                operation="copy-config running to startup",
            )
            return "copy-config"
        if self.has_module(CISCO_IA_NS):
            await self.rpc(f'<save-config xmlns="{CISCO_IA_NS}"/>', operation="save-config")
            return "save-config"
        raise NetconfError(
            "the device offers no way to save the running configuration over NETCONF "
            "(no :startup capability and no cisco-ia save-config)"
        )


def _operation_name(body: str) -> str:
    match = re.match(r"\s*<(?:[\w.-]+:)?([\w.-]+)", body)
    return match.group(1) if match else "rpc"
