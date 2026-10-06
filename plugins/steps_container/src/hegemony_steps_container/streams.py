# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Reading a Docker client's output for a step's live log.

``container.run`` and ``container.build`` read their client's output with
:func:`read_lines` until it ends: a pipe nobody reads fills up and blocks
the container. The live log takes that output through a :class:`LiveOutput`,
which stops it at :data:`MAX_LIVE_OUTPUT_BYTES`; the step still reads the
rest, and keeps what its evidence has room for.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

#: Output is read in chunks of this size, and a line longer than this comes in
#: pieces (asyncio's line reader raises on a line longer than 64 KiB).
READ_CHUNK_BYTES = 64 * 1024
#: The most of a step's output its live log shows.
MAX_LIVE_OUTPUT_BYTES = 5 * 1024 * 1024
#: How long to wait for a killed Docker client to be reaped. asyncio's
#: ``wait()`` also waits for the client's pipes to close, which a pipe left
#: full when its reader stopped never does.
KILL_WAIT_SECONDS = 10.0


async def read_lines(stream: asyncio.StreamReader) -> AsyncIterator[bytes]:
    """The stream's lines with their newline; a very long line comes in pieces."""
    pending = b""
    while chunk := await stream.read(READ_CHUNK_BYTES):
        *lines, pending = (pending + chunk).split(b"\n")
        for line in lines:
            yield line + b"\n"
        while len(pending) >= READ_CHUNK_BYTES:
            yield pending[:READ_CHUNK_BYTES]
            pending = pending[READ_CHUNK_BYTES:]
    if pending:
        yield pending


def size_text(size: int) -> str:
    """``size`` bytes as the docs write it: ``5 MB``, ``2.5 MB``."""
    return f"{size / (1024 * 1024):g} MB"


class LiveOutput:
    """What of a step's output still goes to its live log.

    Pieces pass until :data:`MAX_LIVE_OUTPUT_BYTES` of them have; the piece
    that would go past it is replaced by ``notice`` (once), and later pieces
    by nothing. Pieces are counted as the UTF-8 the log receives, not as the
    bytes read: decoding turns each invalid byte into a three-byte U+FFFD.
    """

    def __init__(self, notice: str, limit: int = MAX_LIVE_OUTPUT_BYTES) -> None:
        self._left = limit
        self._notice = notice
        self._line_start = True
        self.stopped = False

    def admit(self, text: str) -> str:
        """What the live log shows of the decoded output piece ``text``."""
        if self.stopped:
            return ""
        size = len(text.encode("utf-8"))
        if size <= self._left:
            self._left -= size
            if text:
                self._line_start = text.endswith("\n")
            return text
        self.stopped = True
        return ("" if self._line_start else "\n") + self._notice + "\n"


__all__ = [
    "KILL_WAIT_SECONDS",
    "MAX_LIVE_OUTPUT_BYTES",
    "READ_CHUNK_BYTES",
    "LiveOutput",
    "read_lines",
    "size_text",
]
