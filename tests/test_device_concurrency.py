# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Per-device concurrency: the SDK helper and handler wiring.

Pins ``for_each_target_device`` (strictly sequential at the default of 1,
bounded overlap above it, results in device order), the tolerant
``max_parallel_from_config`` parsing, and that a multi-device handler
actually overlaps device work when ``max_parallel_devices`` is raised.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

from hegemony_step_sdk import (
    MAX_PARALLEL_DEVICES_LIMIT,
    HandlerContext,
    HandlerServices,
    for_each_target_device,
    max_parallel_from_config,
)


class _ConcurrencyProbe:
    """Track how many workers run at once and the peak overlap."""

    def __init__(self) -> None:
        self.active = 0
        self.peak = 0
        self.started: list[str] = []

    async def work(self, device: dict[str, Any]) -> str:
        self.started.append(device["name"])
        self.active += 1
        self.peak = max(self.peak, self.active)
        await asyncio.sleep(0.01)
        self.active -= 1
        return device["name"]


def _devices(count: int) -> list[dict[str, Any]]:
    return [{"name": f"dev-{i}"} for i in range(count)]


class TestForEachTargetDevice:
    async def test_default_is_strictly_sequential(self):
        probe = _ConcurrencyProbe()
        results = await for_each_target_device(_devices(4), probe.work, max_parallel=1)
        assert probe.peak == 1
        assert results == ["dev-0", "dev-1", "dev-2", "dev-3"]
        assert probe.started == ["dev-0", "dev-1", "dev-2", "dev-3"]

    async def test_parallelism_is_bounded_and_order_preserved(self):
        probe = _ConcurrencyProbe()
        results = await for_each_target_device(_devices(8), probe.work, max_parallel=3)
        assert 1 < probe.peak <= 3
        # gather preserves device order regardless of completion order.
        assert results == [f"dev-{i}" for i in range(8)]

    async def test_worker_exception_propagates(self):
        async def _boom(device):
            raise RuntimeError(device["name"])

        try:
            await for_each_target_device(_devices(2), _boom, max_parallel=2)
        except RuntimeError as exc:
            assert str(exc).startswith("dev-")
        else:  # pragma: no cover - the call must raise
            raise AssertionError("expected the worker exception to propagate")


class TestMaxParallelFromConfig:
    def test_default_and_clamping(self):
        assert max_parallel_from_config({}) == 1
        assert max_parallel_from_config({"max_parallel_devices": 4}) == 4
        assert max_parallel_from_config({"max_parallel_devices": 0}) == 1
        assert (
            max_parallel_from_config({"max_parallel_devices": 10_000}) == MAX_PARALLEL_DEVICES_LIMIT
        )

    def test_garbage_degrades_to_sequential(self):
        assert max_parallel_from_config({"max_parallel_devices": "lots"}) == 1
        assert max_parallel_from_config({"max_parallel_devices": None}) == 1


class TestHandlerParallelism:
    """netcli.execute overlaps device work when the config asks for it."""

    def _ctx(self, recorder: list, devices: list[dict], **config) -> HandlerContext:
        async def _record(message, device_id, attrs):
            recorder.append((message, device_id, attrs))
            return True

        return HandlerContext(
            run_id="r",
            flow_id="f",
            step_run_id="sr",
            step_id="s",
            phase="EXECUTE",
            kind="ACTION",
            config={"commands": ["show version"], **config},
            target_roles=["primary"],
            target_devices_by_role={"primary": devices},
            services=cast(HandlerServices, self._services()),
            _emit_progress=_record,
        )

    def _services(self):
        probe = _ConcurrencyProbe()

        class _Result:
            command = "show version"
            output = "IOS XE"
            exit_code = 0
            error = None
            latency_ms = 1.0

        class _Transport:
            async def execute_commands(self, commands):
                await probe.work({"name": "x"})
                return [_Result()]

        class _Services:
            concurrency_probe = probe

            def connect(self, device, *, platform=None, **kwargs):
                return _Transport()

        return _Services()

    async def test_default_runs_devices_sequentially(self):
        from hegemony_steps_netcli.execute import ExecuteCLIActionHandler

        devices = [{"id": None, "name": f"sw{i}", "mgmt_host": f"192.0.2.{i}"} for i in range(1, 5)]
        events: list = []
        ctx = self._ctx(events, devices)
        result = await ExecuteCLIActionHandler().execute(ctx)
        assert result.success is True
        services = cast(Any, ctx.services)
        assert services.concurrency_probe.peak == 1

    async def test_max_parallel_devices_overlaps_device_work(self):
        from hegemony_steps_netcli.execute import ExecuteCLIActionHandler

        devices = [{"id": None, "name": f"sw{i}", "mgmt_host": f"192.0.2.{i}"} for i in range(1, 7)]
        events: list = []
        ctx = self._ctx(events, devices, max_parallel_devices=3)
        result = await ExecuteCLIActionHandler().execute(ctx)
        assert result.success is True
        services = cast(Any, ctx.services)
        assert 1 < services.concurrency_probe.peak <= 3
        # Every device still produced its output events.
        outputs = [e for e in events if e[2] and e[2].get("milestone") == "output"]
        assert len(outputs) == 6
