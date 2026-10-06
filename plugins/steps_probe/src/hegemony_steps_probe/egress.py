# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The flow egress check, run off the step's event loop.

``services.enforce_egress`` is a coroutine in the SDK contract, but the
platform's gate resolves a host name, and every ``service:port`` rule of the
policy, with a blocking ``getaddrinfo`` inside it. Awaited on the step's
loop, each check would stall the worker's event loop: the requests of the
other targets, and every other step on that worker, while DNS answers.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any


async def enforce_egress_off_loop(
    enforce: Callable[..., Awaitable[Any]],
    host: str,
    port: int | None,
    *,
    proto: str,
    kind: str,
) -> None:
    """Await ``enforce(host, port, proto=..., kind=...)`` in a worker thread.

    The coroutine runs to completion on an event loop of its own in that
    thread. ``asyncio.to_thread`` copies the context, so the gate still sees
    the step's egress policy, which the platform binds in a context variable.
    A denial raises here as the gate raised it.
    """

    async def _gate() -> None:
        await enforce(host, port, proto=proto, kind=kind)

    def _run_gate() -> None:
        asyncio.run(_gate())

    await asyncio.to_thread(_run_gate)
