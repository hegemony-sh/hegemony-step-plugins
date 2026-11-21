# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""An in-process NETCONF device for the netconf and cisco.iosxe step tests.

It speaks real NETCONF framing (end-of-message for the hello, then chunked
when both sides offer base:1.1) over a byte channel shaped like the one
``services.open_netconf`` returns, and keeps a small datastore model:

- running, candidate and startup configurations, each a list of top-level
  XML elements, merged or replaced by element name;
- a CLI configuration beside them for Cisco's ``config-ios-cli-trans`` and
  ``get-modelled-config-clis`` RPCs;
- datastore locks per session, and confirmed commits with or without a
  persist id, rolled back on cancel-commit, on expiry (``expire()``), or when
  the session of a commit without a persist id ends.
"""

from __future__ import annotations

import asyncio
import copy
import re
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

BASE_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
CLI_RPC_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-cli-rpc"
CISCO_IA_NS = "http://cisco.com/yang/cisco-ia"
EOM = b"]]>]]>"

ALL_CAPABILITIES = (
    "urn:ietf:params:netconf:base:1.0",
    "urn:ietf:params:netconf:base:1.1",
    "urn:ietf:params:netconf:capability:candidate:1.0",
    "urn:ietf:params:netconf:capability:confirmed-commit:1.0",
    "urn:ietf:params:netconf:capability:confirmed-commit:1.1",
    "urn:ietf:params:netconf:capability:validate:1.1",
    "urn:ietf:params:netconf:capability:rollback-on-error:1.0",
    "urn:ietf:params:netconf:capability:writable-running:1.0",
    "urn:ietf:params:netconf:capability:xpath:1.0",
    f"{CISCO_IA_NS}?module=cisco-ia&revision=2023-03-01",
    f"{CLI_RPC_NS}?module=Cisco-IOS-XE-cli-rpc&revision=2023-11-01",
)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml(elements: list[ET.Element]) -> str:
    return "".join(ET.tostring(element, encoding="unicode") for element in elements)


@dataclass
class Pending:
    """A confirmed commit waiting for its confirmation."""

    backup: list[ET.Element]
    backup_cli: str
    persist: str = ""
    session: int = 0


@dataclass
class FakeNetconfDevice:
    """One device's datastores, shared by every session to it."""

    capabilities: tuple[str, ...] = ALL_CAPABILITIES
    running: list[ET.Element] = field(default_factory=list)
    running_cli: str = "hostname r1\n"
    startup: list[ET.Element] = field(default_factory=list)
    #: Fail sessions opened after this many (the "is it manageable" check).
    accept_sessions: int = 1_000_000
    #: Reply to edit-config with this rpc-error tag.
    fail_edit: str = ""
    #: Reply to commit with this rpc-error tag.
    fail_commit: str = ""
    #: Speak base:1.0 framing only.
    base10_only: bool = False

    candidate: list[ET.Element] = field(default_factory=list)
    candidate_cli: str = ""
    locks: dict[str, int] = field(default_factory=dict)
    pending: Pending | None = None
    sessions_opened: int = 0
    saved: int = 0
    requests: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.candidate = copy.deepcopy(self.running)
        self.candidate_cli = self.running_cli

    @classmethod
    def with_config(cls, xml: str, **kwargs: Any) -> FakeNetconfDevice:
        root = ET.fromstring(f"<wrap>{xml}</wrap>")
        return cls(running=list(root), **kwargs)

    def running_xml(self) -> str:
        return _xml(self.running)

    def expire(self) -> None:
        """The confirm timeout ran out: restore the previous configuration."""
        self._rollback()

    def _rollback(self) -> None:
        if self.pending is None:
            return
        self.running = self.pending.backup
        self.running_cli = self.pending.backup_cli
        self.candidate = copy.deepcopy(self.running)
        self.candidate_cli = self.running_cli
        self.pending = None

    async def open(self) -> FakeChannel:
        self.sessions_opened += 1
        if self.sessions_opened > self.accept_sessions:
            raise OSError("connection refused")
        channel = FakeChannel(self, self.sessions_opened)
        channel.start()
        return channel


def _merge(store: list[ET.Element], new: list[ET.Element]) -> list[ET.Element]:
    """Merge ``new`` top-level elements into ``store`` by name, children by name."""
    result = copy.deepcopy(store)
    for element in new:
        operation = element.get("operation") or element.get(f"{{{BASE_NS}}}operation")
        existing = next((item for item in result if item.tag == element.tag), None)
        clean = copy.deepcopy(element)
        clean.attrib.pop("operation", None)
        clean.attrib.pop(f"{{{BASE_NS}}}operation", None)
        if operation in ("delete", "remove"):
            if existing is not None:
                result.remove(existing)
            continue
        if existing is None or operation == "replace":
            if existing is not None:
                result[result.index(existing)] = clean
            else:
                result.append(clean)
            continue
        for child in list(clean):
            old = existing.find(child.tag)
            if old is not None:
                existing[list(existing).index(old)] = child
            else:
                existing.append(child)
    return result


_CHUNK_HEADER = re.compile(rb"\n#([1-9][0-9]{0,9})\n")


def _take_chunked(buffer: bytes) -> tuple[bytes, bytes] | None:
    """``(message, rest)`` when ``buffer`` starts with a whole chunked message, else None."""
    parts: list[bytes] = []
    position = 0
    while True:
        if buffer.startswith(b"\n##\n", position):
            return b"".join(parts), buffer[position + 4 :]
        header = _CHUNK_HEADER.match(buffer, position)
        if header is None:
            return None
        end = header.end() + int(header.group(1))
        if end > len(buffer):
            return None
        parts.append(buffer[header.end() : end])
        position = end


class FakeChannel:
    """The byte stream of one session, served by the fake device."""

    def __init__(self, device: FakeNetconfDevice, session_id: int) -> None:
        self.device = device
        self.session_id = session_id
        self._to_server: asyncio.Queue[bytes] = asyncio.Queue()
        self._to_client: asyncio.Queue[bytes] = asyncio.Queue()
        self._task: asyncio.Task | None = None
        self._chunked = False
        self.closed = False

    def start(self) -> None:
        self._task = asyncio.ensure_future(self._serve())

    # --- the channel the step sees ----------------------------------------

    async def write(self, data: bytes) -> None:
        if self.closed:
            raise OSError("channel closed")
        await self._to_server.put(data)

    async def read(self, max_bytes: int = 65536) -> bytes:
        return await self._to_client.get()

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        await self._to_server.put(b"")
        if self._task is not None:
            await asyncio.wait([self._task], timeout=2)

    # --- the server side --------------------------------------------------

    async def _send(self, text: str) -> None:
        payload = text.encode()
        if self._chunked:
            # Two chunks, to exercise reassembly.
            half = len(payload) // 2 or len(payload)
            data = (
                b"".join(
                    b"\n#%d\n" % len(part) + part
                    for part in (payload[:half], payload[half:])
                    if part
                )
                + b"\n##\n"
            )
        else:
            data = payload + EOM
        await self._to_client.put(data)

    async def _messages(self):
        buffer = b""
        while True:
            if self._chunked:
                taken = _take_chunked(buffer)
                if taken is not None:
                    message, buffer = taken
                    yield message.decode()
                    continue
            else:
                end = buffer.find(EOM)
                if end >= 0:
                    message, buffer = buffer[:end], buffer[end + len(EOM) :]
                    yield message.decode()
                    continue
            data = await self._to_server.get()
            if not data:
                return
            buffer += data

    async def _serve(self) -> None:
        device = self.device
        capabilities = [
            cap
            for cap in device.capabilities
            if not (device.base10_only and cap.endswith("base:1.1"))
        ]
        await self._send(
            f'<hello xmlns="{BASE_NS}"><capabilities>'
            + "".join(f"<capability>{escape(cap)}</capability>" for cap in capabilities)
            + f"</capabilities><session-id>{self.session_id}</session-id></hello>"
        )
        messages = self._messages()
        try:
            hello = await messages.__anext__()
        except StopAsyncIteration:
            return
        client_11 = "base:1.1" in hello
        self._chunked = client_11 and not device.base10_only
        try:
            async for text in messages:
                device.requests.append(text)
                root = ET.fromstring(text)
                message_id = root.get("message-id", "")
                operation = root[0]
                body, closing = self._handle(operation)
                await self._send(
                    f'<rpc-reply xmlns="{BASE_NS}" message-id="{message_id}">{body}</rpc-reply>'
                )
                if closing:
                    break
        finally:
            self._end_session()
            await self._to_client.put(b"")

    def _end_session(self) -> None:
        device = self.device
        for name, owner in list(device.locks.items()):
            if owner == self.session_id:
                del device.locks[name]
        pending = device.pending
        if pending is not None and not pending.persist and pending.session == self.session_id:
            device._rollback()

    def _error(self, tag: str, message: str = "") -> tuple[str, bool]:
        return (
            "<rpc-error><error-type>application</error-type>"
            f"<error-tag>{tag}</error-tag><error-severity>error</error-severity>"
            f"<error-message>{message or tag}</error-message></rpc-error>",
            False,
        )

    def _datastore(self, node: ET.Element | None) -> str:
        if node is None or not len(node):
            return ""
        return _local(node[0].tag)

    def _handle(self, op: ET.Element) -> tuple[str, bool]:
        device = self.device
        name = _local(op.tag)
        ok = ("<ok/>", False)
        if name == "close-session":
            return ("<ok/>", True)
        if name in ("lock", "unlock"):
            target = self._datastore(op.find(f"{{{BASE_NS}}}target"))
            owner = device.locks.get(target)
            if name == "lock":
                if owner is not None and owner != self.session_id:
                    return self._error("lock-denied", f"{target} is locked by session {owner}")
                device.locks[target] = self.session_id
            elif owner == self.session_id:
                del device.locks[target]
            return ok
        if name == "discard-changes":
            device.candidate = copy.deepcopy(device.running)
            device.candidate_cli = device.running_cli
            return ok
        if name == "get-config":
            source = self._datastore(op.find(f"{{{BASE_NS}}}source"))
            store = {
                "running": device.running,
                "candidate": device.candidate,
                "startup": device.startup,
            }[source]
            # A subtree filter keeps the top-level nodes it names.
            subtree = op.find(f"{{{BASE_NS}}}filter")
            if subtree is not None and len(subtree):
                wanted = {item.tag for item in subtree}
                store = [item for item in store if item.tag in wanted]
            return (f"<data>{_xml(store)}</data>", False)
        if name == "get":
            return (f"<data>{_xml(device.running)}<state>up</state></data>", False)
        if name == "edit-config":
            if device.fail_edit:
                return self._error(device.fail_edit, "edit refused")
            target = self._datastore(op.find(f"{{{BASE_NS}}}target"))
            default = op.findtext(f"{{{BASE_NS}}}default-operation") or "merge"
            config_node = op.find(f"{{{BASE_NS}}}config")
            new: list[ET.Element] = list(config_node) if config_node is not None else []
            store = device.candidate if target == "candidate" else device.running
            updated: list[ET.Element] = (
                copy.deepcopy(new) if default == "replace" else _merge(store, new)
            )
            if target == "candidate":
                device.candidate = updated
            else:
                device.running = updated
                device.candidate = copy.deepcopy(updated)
            return ok
        if name == "validate":
            if any(_local(item.tag) == "invalid" for item in device.candidate):
                return self._error("invalid-value", "candidate does not validate")
            return ok
        if name == "commit":
            if device.fail_commit:
                return self._error(device.fail_commit, "commit refused")
            persist_id = op.findtext(f"{{{BASE_NS}}}persist-id")
            confirmed = op.find(f"{{{BASE_NS}}}confirmed") is not None
            if persist_id is not None:
                if device.pending is None or device.pending.persist != persist_id:
                    return self._error("invalid-value", "no confirmed commit with that persist-id")
                device.pending = None
                return ok
            if confirmed:
                if device.pending is None:
                    device.pending = Pending(
                        backup=copy.deepcopy(device.running),
                        backup_cli=device.running_cli,
                        persist=op.findtext(f"{{{BASE_NS}}}persist") or "",
                        session=self.session_id,
                    )
            elif device.pending is not None and not device.pending.persist:
                # A plain commit in the confirming session confirms.
                device.pending = None
            device.running = copy.deepcopy(device.candidate)
            device.running_cli = device.candidate_cli
            return ok
        if name == "cancel-commit":
            persist_id = op.findtext(f"{{{BASE_NS}}}persist-id")
            if device.pending is None or (persist_id or "") != device.pending.persist:
                return self._error("invalid-value", "no confirmed commit to cancel")
            device._rollback()
            return ok
        if name == "save-config":
            device.saved += 1
            return (f'<result xmlns="{CISCO_IA_NS}">Save running-config successful</result>', False)
        if name == "copy-config":
            device.startup = copy.deepcopy(device.running)
            return ok
        if name == "config-ios-cli-trans":
            clis = op.findtext(f"{{{CLI_RPC_NS}}}clis") or ""
            operation = op.findtext(f"{{{CLI_RPC_NS}}}operation") or "merge"
            if "bogus" in clis:
                line = next(i for i, text in enumerate(clis.splitlines(), 1) if "bogus" in text)
                return (
                    f'<result xmlns="{CLI_RPC_NS}">failure</result>'
                    f'<error-message xmlns="{CLI_RPC_NS}">% Invalid input at line {line}: bogus'
                    "</error-message>",
                    False,
                )
            text = clis.strip() + "\n"
            if operation == "merge":
                text = device.candidate_cli.rstrip("\n") + "\n" + text
            device.candidate_cli = text
            return (
                f'<result xmlns="{CLI_RPC_NS}">Configuration applied successfully</result>',
                False,
            )
        if name == "get-modelled-config-clis":
            store = op.findtext(f"{{{CLI_RPC_NS}}}datastore") or "running"
            text = device.candidate_cli if store == "candidate" else device.running_cli
            escaped = text.replace("&", "&amp;").replace("<", "&lt;")
            return (f'<result xmlns="{CLI_RPC_NS}">{escaped}</result>', False)
        return self._error("operation-not-supported", f"{name} is not supported")


class FakeServices:
    """``HandlerServices`` with ``open_netconf`` served by fake devices, by device name."""

    def __init__(self, devices: dict[str, FakeNetconfDevice], step_outputs: dict | None = None):
        self.devices = devices
        self.step_outputs = step_outputs or {}
        self.opened: list[tuple[str, dict[str, Any]]] = []
        self.attachments: list[dict[str, Any]] = []

    async def open_netconf(self, device: dict[str, Any], **kwargs: Any) -> FakeChannel:
        self.opened.append((device["name"], kwargs))
        return await self.devices[device["name"]].open()

    async def fetch_run_step_outputs(self, run_id: str) -> dict:
        return self.step_outputs

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        return self.attachments
