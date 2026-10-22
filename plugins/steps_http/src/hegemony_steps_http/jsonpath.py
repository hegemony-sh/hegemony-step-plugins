# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""A small path language into parsed JSON: ``a.b[0].c``, optionally ``$.``-prefixed.

Deliberately not JSONPath: no wildcards, filters or recursion. A path names
one value. Segments are dot-separated keys, ``[n]`` list indexes (negative
counts from the end), and ``["key"]`` / ``['key']`` for keys holding dots,
brackets, quotes or spaces. ``$`` alone (or an empty path after ``$``) names
the whole document.
"""

from __future__ import annotations

import re
from typing import Any

#: One path segment after the first: ``.key``, ``[3]``, ``[-1]``, ``["a.b"]``.
_SEGMENT_RE = re.compile(
    r"""\.(?P<key>[^.\[\]'"\s]+)"""
    r"""|\[(?P<index>-?\d+)\]"""
    r"""|\[(?P<quote>["'])(?P<quoted>.*?)(?P=quote)\]"""
)

PathPart = str | int


class PathError(ValueError):
    """A path that does not parse."""


def parse_path(path: str) -> tuple[PathPart, ...]:
    """The keys and indexes ``path`` names, outermost first.

    Raises :class:`PathError` for a malformed path.
    """
    if not isinstance(path, str):
        raise PathError("a path must be a string")
    text = path.strip()
    if not text:
        raise PathError("the path is empty")
    if text.startswith("$"):
        text = text[1:]
    elif not text.startswith((".", "[")):
        text = "." + text
    parts: list[PathPart] = []
    position = 0
    while position < len(text):
        match = _SEGMENT_RE.match(text, position)
        if match is None:
            raise PathError(
                f"path {path!r} is not valid at {text[position:]!r}: use keys separated by "
                'dots, [n] for list items, and ["key"] for keys with special characters'
            )
        if match.group("key") is not None:
            parts.append(match.group("key"))
        elif match.group("index") is not None:
            parts.append(int(match.group("index")))
        else:
            parts.append(match.group("quoted"))
        position = match.end()
    return tuple(parts)


def _step(current: Any, part: PathPart) -> tuple[bool, Any]:
    """``(found, value)`` one segment below ``current``."""
    if isinstance(current, dict):
        if isinstance(part, str) and part in current:
            return True, current[part]
        return False, None
    if isinstance(current, list):
        index: int | None = None
        if isinstance(part, int):
            index = part
        elif re.fullmatch(r"-?\d+", part):
            index = int(part)
        if index is not None and -len(current) <= index < len(current):
            return True, current[index]
    return False, None


def get_path(data: Any, parts: tuple[PathPart, ...]) -> Any:
    """The value at ``parts`` in ``data``, or None when any segment is missing."""
    current = data
    for part in parts:
        found, current = _step(current, part)
        if not found:
            return None
    return current


def replace_at(data: Any, parts: tuple[PathPart, ...], value: Any) -> Any:
    """``data`` with the value at ``parts`` replaced by ``value`` (in place); returns the root.

    The path must exist (raises :class:`PathError` otherwise); an empty path
    replaces the whole document.
    """
    if not parts:
        return value
    parent = data
    for part in parts[:-1]:
        found, parent = _step(parent, part)
        if not found:
            raise PathError("the path does not exist in the document")
    last = parts[-1]
    if isinstance(parent, dict) and isinstance(last, str) and last in parent:
        parent[last] = value
        return data
    if isinstance(parent, list):
        found, _ = _step(parent, last)
        if found:
            parent[int(last)] = value
            return data
    raise PathError("the path does not exist in the document")


__all__ = ["PathError", "get_path", "parse_path", "replace_at"]
