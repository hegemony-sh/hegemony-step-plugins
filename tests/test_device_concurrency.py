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

    async def test_worker_exception_cancels_inflight_siblings(self):
        first_started = asyncio.Event()
        cancelled: list[str] = []

        async def _worker(device: dict[str, Any]) -> str:
            if device["name"] == "dev-1":
                await first_started.wait()
                raise RuntimeError("boom")
            first_started.set()
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                cancelled.append(device["name"])
                raise
            return device["name"]  # pragma: no cover - always cancelled

        try:
            await asyncio.wait_for(
                for_each_target_device(_devices(2), _worker, max_parallel=2), timeout=5
            )
        except RuntimeError as exc:
            assert str(exc) == "boom"
        else:  # pragma: no cover - the call must raise
            raise AssertionError("expected the worker exception to propagate")
        # The still-running sibling was cancelled, not left dangling.
        assert cancelled == ["dev-0"]

    async def test_staggered_completion_still_returns_device_order(self):
        async def _work(device: dict[str, Any]) -> str:
            # Later devices finish first — results must stay in device order.
            index = int(device["name"].split("-")[1])
            await asyncio.sleep(0.03 - index * 0.01)
            return device["name"]

        results = await for_each_target_device(_devices(3), _work, max_parallel=3)
        assert results == ["dev-0", "dev-1", "dev-2"]


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
        assert max_parallel_from_config({"max_parallel_devices": ""}) == 1

    def test_a_handler_default_fills_only_an_unset_value(self):
        assert max_parallel_from_config({}, default=10) == 10
        assert max_parallel_from_config({"max_parallel_devices": None}, default=10) == 10
        assert max_parallel_from_config({"max_parallel_devices": ""}, default=10) == 10
        assert max_parallel_from_config({"max_parallel_devices": 2}, default=10) == 2
        assert max_parallel_from_config({"max_parallel_devices": 0}, default=10) == 1
        assert max_parallel_from_config({"max_parallel_devices": "lots"}, default=10) == 1
        assert max_parallel_from_config({}, default=100) == MAX_PARALLEL_DEVICES_LIMIT


class TestHandlerParallelism:
    """netcli.execute overlaps device work when the config asks for it."""

    def _ctx(
        self, recorder: list, devices: list[dict], services: Any = None, **config
    ) -> HandlerContext:
        async def _record(message, device_id, attrs):
            recorder.append((message, device_id, attrs))
            return True

        return HandlerContext(
            run_id="r",
            flow_id="f",
            step_run_id="sr",
            step_id="s",
            config={"commands": ["show version"], **config},
            target_roles=["primary"],
            target_devices_by_role={"primary": devices},
            services=cast(HandlerServices, services if services is not None else self._services()),
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

    async def test_parallel_aggregation_preserves_device_order(self):
        """Evidence/stdout follow device order even when completion order differs.

        Workers collect into per-device results that are merged after the
        fan-out, so the first-configured device leads the artifact list and
        the chained stdout even when it finishes last.
        """
        from hegemony_steps_netcli.execute import ExecuteCLIActionHandler

        class _Result:
            def __init__(self, name: str) -> None:
                self.command = "show version"
                self.output = f"version {name}"
                self.exit_code = 0
                self.error = None
                self.latency_ms = 1.0

        class _Transport:
            def __init__(self, name: str, delay: float) -> None:
                self._name = name
                self._delay = delay

            async def execute_commands(self, commands):
                await asyncio.sleep(self._delay)
                return [_Result(self._name)]

        class _Services:
            def connect(self, device, *, platform=None, **kwargs):
                index = int(device["name"].removeprefix("sw"))
                # Earlier devices are slowest — completion order is reversed.
                return _Transport(device["name"], 0.03 - index * 0.01)

        devices = [{"id": None, "name": f"sw{i}", "mgmt_host": f"192.0.2.{i}"} for i in range(3)]
        events: list = []
        ctx = self._ctx(events, devices, services=_Services(), max_parallel_devices=3)
        result = await ExecuteCLIActionHandler().execute(ctx)
        assert result.success is True
        assert [e["content_json"]["device_name"] for e in result.evidence] == ["sw0", "sw1", "sw2"]
        assert (result.output or {}).get("stdout", "").splitlines() == [
            "version sw0",
            "version sw1",
            "version sw2",
        ]
