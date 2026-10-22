# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Bounded per-device concurrency for multi-device handlers.

Handlers that iterate target devices can opt into parallel processing via a
``max_parallel_devices`` config value (default 1 = strictly sequential, the
classic loop, unless the handler passes its own default to
:func:`max_parallel_from_config`). :func:`for_each_target_device` bounds
concurrency with a semaphore and returns results in device order, so
aggregation stays deterministic regardless of completion order. Live output from concurrent
devices interleaves in the Logs tab, where lines are already labelled with
``attrs.device_name``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, TypeVar

R = TypeVar("R")

#: Upper bound for ``max_parallel_devices`` — matches the default executor
#: thread pool headroom the blocking (netmiko) transport runs in.
MAX_PARALLEL_DEVICES_LIMIT = 32


def max_parallel_from_config(config: Mapping[str, Any], *, default: int = 1) -> int:
    """Read ``max_parallel_devices`` from a step config, clamped and safe.

    A missing or empty value means ``default``: 1 (sequential) unless the
    handler declares another default for its field. Anything unparsable
    degrades to 1 (sequential) rather than failing the step over a
    display-level knob.
    """
    value = config.get("max_parallel_devices")
    if value is None or value == "":
        value = default
    try:
        value = int(value)
    except (TypeError, ValueError):
        return 1
    return max(1, min(value, MAX_PARALLEL_DEVICES_LIMIT))


async def for_each_target_device(
    devices: Sequence[dict[str, Any]],
    worker: Callable[[dict[str, Any]], Awaitable[R]],
    *,
    max_parallel: int = 1,
) -> list[R]:
    """Run ``await worker(device)`` for every device with bounded concurrency.

    ``max_parallel <= 1`` runs strictly sequentially — identical semantics to
    the classic per-device loop, including early visibility of each device's
    progress before the next starts. Above 1, at most ``max_parallel``
    workers run at once and results are returned in device order.

    Workers are expected to handle their own per-device errors (the
    sequential loops always did); an exception escaping a worker propagates
    and cancels the remaining concurrent workers (``asyncio.gather`` alone
    would leave them running, so cancellation is explicit here).
    """
    if max_parallel <= 1:
        return [await worker(device) for device in devices]

    semaphore = asyncio.Semaphore(max_parallel)

    async def _bounded(device: dict[str, Any]) -> R:
        async with semaphore:
            return await worker(device)

    tasks = [asyncio.ensure_future(_bounded(device)) for device in devices]
    try:
        return list(await asyncio.gather(*tasks))
    except BaseException:
        for task in tasks:
            task.cancel()
        # Reap every task so cancellations complete and nothing leaks into
        # the event loop's unhandled-exception hook.
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
