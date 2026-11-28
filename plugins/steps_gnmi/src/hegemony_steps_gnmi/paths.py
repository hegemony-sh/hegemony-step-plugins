# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""gNMI path strings: ``/interfaces/interface[name=Ethernet1]/config``.

The text form follows the gNMI path conventions (openconfig
``gnmi-path-conventions.md``):

- elements are separated by ``/``; a leading ``/`` is optional;
- an element may carry keys, each ``[name=value]``;
- inside a key value ``/`` needs no escape, and ``]`` and ``\\`` are written
  ``\\]`` and ``\\\\``; in an element name ``/``, ``[``, ``]``, ``=`` and ``\\``
  are escaped the same way;
- a key value may instead be a JSON string in double quotes
  (``[name="Ethernet1/1"]``), which is what ``{{ value | tojson }}`` renders:
  inside the quotes JSON's escapes apply, so a rendered value cannot end the
  key early or add elements;
- an origin is written before the path as ``origin:/path``
  (``openconfig:/interfaces``). ``/oc-if:interfaces`` is an element with a
  module prefix, not an origin, because the text starts with ``/``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from . import messages

#: Longest path text a step accepts.
MAX_PATH_CHARS = 4096


_JSON = json.JSONDecoder()


class PathError(ValueError):
    """A path string that is not a valid gNMI path."""


@dataclass(frozen=True)
class GnmiPath:
    """A parsed path: its origin and its elements with their keys."""

    origin: str = ""
    elems: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = field(default=())

    def to_proto(self) -> Any:
        path = messages.Path()
        if self.origin:
            path.origin = self.origin
        for name, keys in self.elems:
            elem = path.elem.add()
            elem.name = name
            for key, value in keys:
                elem.key[key] = value
        return path

    def __str__(self) -> str:
        return format_path(self)


def parse_path(text: str) -> GnmiPath:
    """Parse ``text`` into a :class:`GnmiPath`. Raises :class:`PathError`."""
    if not isinstance(text, str):
        raise PathError("a path must be text")
    raw = text.strip()
    if not raw:
        raise PathError("a path is empty; write / for the root")
    if len(raw) > MAX_PATH_CHARS:
        raise PathError(f"a path is longer than {MAX_PATH_CHARS} characters")
    origin = ""
    if not raw.startswith("/"):
        head, sep, rest = raw.partition(":/")
        if sep and head and all(ch not in head for ch in "/[]\\=") and _is_origin(head):
            origin, raw = head, "/" + rest
    elems: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    position = 0
    length = len(raw)
    if raw.startswith("/"):
        position = 1
    while position < length:
        name, position = _read_name(raw, position)
        keys: dict[str, str] = {}
        while position < length and raw[position] == "[":
            key, value, position = _read_key(raw, position, name)
            if key in keys:
                raise PathError(f"element {name!r} names key {key!r} twice")
            keys[key] = value
        if not name:
            raise PathError("a path has an empty element (two slashes in a row)")
        elems.append((name, tuple(sorted(keys.items()))))
        if position < length:
            if raw[position] != "/":
                raise PathError(f"unexpected {raw[position]!r} after element {name!r}")
            position += 1  # a trailing slash ends the loop here
    return GnmiPath(origin=origin, elems=tuple(elems))


def _is_origin(head: str) -> bool:
    return all(ch.isalnum() or ch in "-_." for ch in head)


def _read_name(raw: str, position: int) -> tuple[str, int]:
    out: list[str] = []
    while position < len(raw):
        ch = raw[position]
        if ch == "\\":
            if position + 1 >= len(raw):
                raise PathError("a path ends with a lone backslash")
            out.append(raw[position + 1])
            position += 2
            continue
        if ch in "/[":
            break
        if ch == "]":
            raise PathError("a ']' without its '[' (escape it as \\])")
        if ch.isspace():
            raise PathError(f"element {''.join(out)!r} is followed by a space")
        out.append(ch)
        position += 1
    return "".join(out).strip(), position


def _read_key(raw: str, position: int, elem: str) -> tuple[str, str, int]:
    position += 1  # the "["
    key: list[str] = []
    while True:
        if position >= len(raw):
            raise PathError(f"a key of element {elem!r} has no '=' or ']'")
        ch = raw[position]
        if ch == "=":
            position += 1
            break
        if ch in "[]/":
            raise PathError(f"a key of element {elem!r} has no '=value'")
        key.append(ch)
        position += 1
    if position < len(raw) and raw[position] == '"':
        try:
            decoded, end = _JSON.raw_decode(raw, position)
        except json.JSONDecodeError:
            raise PathError(
                f"the quoted value of key {''.join(key).strip()!r} of element {elem!r} "
                "is not a JSON string"
            ) from None
        if not isinstance(decoded, str):  # pragma: no cover - a '"' starts a string
            raise PathError(f"the value of key {''.join(key).strip()!r} is not a string")
        if end >= len(raw) or raw[end] != "]":
            raise PathError(
                f"the quoted value of key {''.join(key).strip()!r} of element {elem!r} "
                "must be followed by ']'"
            )
        name = "".join(key).strip()
        if not name:
            raise PathError(f"a key of element {elem!r} has no name")
        return name, decoded, end + 1
    value: list[str] = []
    while True:
        if position >= len(raw):
            raise PathError(f"the key {''.join(key)!r} of element {elem!r} has no closing ']'")
        ch = raw[position]
        if ch == "\\":
            if position + 1 >= len(raw):
                raise PathError("a path ends with a lone backslash")
            value.append(raw[position + 1])
            position += 2
            continue
        if ch == "]":
            position += 1
            break
        value.append(ch)
        position += 1
    name = "".join(key).strip()
    if not name:
        raise PathError(f"a key of element {elem!r} has no name")
    return name, "".join(value), position


def _escape_name(name: str) -> str:
    for ch in "\\/[]=":
        name = name.replace(ch, "\\" + ch)
    return name


def _escape_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("]", "\\]")


def format_path(path: GnmiPath) -> str:
    """The text form of ``path``; :func:`parse_path` reads it back unchanged."""
    parts = []
    for name, keys in path.elems:
        text = _escape_name(name)
        for key, value in keys:
            text += f"[{key}={_escape_value(value)}]"
        parts.append(text)
    body = "/" + "/".join(parts)
    return f"{path.origin}:{body}" if path.origin else body


def path_from_proto(path: object, *, prefix: object | None = None) -> str:
    """The text form of a received ``gnmi.Path``, ``prefix`` joined in front."""
    origin = ""
    elems: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    for part in (prefix, path):
        if part is None:
            continue
        origin = getattr(part, "origin", "") or origin
        proto_elems = list(getattr(part, "elem", ()))
        if proto_elems:
            for elem in proto_elems:
                elems.append((elem.name, tuple(sorted(dict(elem.key).items()))))
        else:
            # Very old devices send the deprecated string elements.
            elems.extend((name, ()) for name in getattr(part, "element", ()))
    return format_path(GnmiPath(origin=origin, elems=tuple(elems)))


def split_assignment(line: str) -> tuple[str, str]:
    """Split ``PATH = VALUE`` at the first ``=`` outside the path's keys.

    A ``=`` inside ``[...]``, inside a quoted key value, inside a ``{{ }}``
    template or after a backslash belongs to the path. Raises
    :class:`PathError` when the line has no such ``=``.
    """
    depth = 0
    position = 0
    length = len(line)
    while position < length:
        if line.startswith("{{", position):
            end = line.find("}}", position + 2)
            position = length if end < 0 else end + 2
            continue
        ch = line[position]
        if ch == "\\":
            position += 2
            continue
        if depth and ch == '"':
            try:
                _, position = _JSON.raw_decode(line, position)
            except json.JSONDecodeError:
                position += 1
            continue
        if ch == "[":
            depth += 1
        elif ch == "]" and depth:
            depth -= 1
        elif ch == "=" and not depth:
            path, value = line[:position].strip(), line[position + 1 :].strip()
            if not path:
                raise PathError("a line has a value but no path before '='")
            if not value:
                raise PathError(f"{path}: no value after '='")
            return path, value
        position += 1
    raise PathError("a line has no '= value' after its path")
