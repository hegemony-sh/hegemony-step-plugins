# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Reading a Docker client's output for a step's live log.

``container.run`` and ``container.build`` read their client's output with
:func:`read_lines` until it ends: a pipe nobody reads fills up and blocks
the container.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

#: Output is read in chunks of this size, and a line longer than this comes in
#: pieces (asyncio's line reader raises on a line longer than 64 KiB).
READ_CHUNK_BYTES = 64 * 1024
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


__all__ = ["KILL_WAIT_SECONDS", "READ_CHUNK_BYTES", "read_lines"]
