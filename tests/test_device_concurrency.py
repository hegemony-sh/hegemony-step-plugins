# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Per-device concurrency: the SDK helper and handler wiring.

Pins ``for_each_target_device`` (strictly sequential at the default of 1,
bounded overlap above it, results in device order), the tolerant
``max_parallel_from_config`` parsing, and that a multi-device handler
actually overlaps device work when ``max_parallel_devices`` is raised. The
probe handlers check their targets in parallel by default.
"""

from __future__ import annotations

import asyncio
from typing import Any, cast

import httpx
import pytest

from hegemony_step_sdk import (
    MAX_PARALLEL_DEVICES_LIMIT,
    HandlerContext,
    HandlerServices,
    ProbeResult,
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


_IPS = [f"192.0.2.{i}" for i in range(1, 7)]


class _InFlight:
    """Count overlapping checks; earlier targets take longest."""

    def __init__(self) -> None:
        self.active = 0
        self.peak = 0

    async def hold(self, index: int) -> None:
        self.active += 1
        self.peak = max(self.peak, self.active)
        try:
            # Target 1 waits longest, so completion order is reversed.
            await asyncio.sleep(0.05 - index * 0.005)
        finally:
            self.active -= 1


def _index(address: str) -> int:
    return int(address.rsplit(".", 1)[1])


def _probe_ctx(config: dict[str, Any], services: Any, ips: list[str] = _IPS) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        step_target_ips=ips,
        services=cast(HandlerServices, services),
    )


class _Denied(Exception):
    """Stands in for the host's egress-denial error."""


class TestProbeHandlerParallelism:
    """The probe handlers check targets concurrently and merge in target order."""

    @pytest.mark.parametrize(("config", "peak"), [({}, 6), ({"max_parallel_devices": 1}, 1)])
    async def test_connectivity_defaults_to_ten_at_once(self, config, peak):
        from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

        flight = _InFlight()

        class _Services:
            async def run_probe(self, check_type, address, options):
                await flight.hold(_index(address))
                return ProbeResult(ok=True, metrics={"connect_ms": 1.0})

        result = await ConnectivityCheckHandler().execute(_probe_ctx(config, _Services()))
        assert result.success is True, result.error
        assert flight.peak == peak

    async def test_connectivity_keeps_target_order(self):
        from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

        flight = _InFlight()

        class _Services:
            async def run_probe(self, check_type, address, options):
                await flight.hold(_index(address))
                ok = address != _IPS[0]
                return ProbeResult(ok=ok, metrics={"connect_ms": 1.0}, error_detail="refused")

        ctx = _probe_ctx({"max_parallel_devices": 3}, _Services())
        result = await ConnectivityCheckHandler().execute(ctx)
        assert 1 < flight.peak <= 3
        assert result.success is False
        assert [e["content_json"]["host"] for e in result.evidence] == _IPS
        assert list(result.metrics) == [f"{ip}_ms" for ip in _IPS[1:]]
        assert result.error == "Failed: 192.0.2.1 (refused)"

    async def test_connectivity_unknown_check_type_still_fails_cleanly(self):
        from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

        class _Services:
            async def run_probe(self, check_type, address, options):
                await asyncio.sleep(0)
                raise KeyError(check_type)

        ctx = _probe_ctx({"check_type": "tls_handshake"}, _Services())
        result = await ConnectivityCheckHandler().execute(ctx)
        assert result.success is False
        assert result.error == "Check type 'tls_handshake' is not available on this worker"
        assert result.summary == "Unsupported check type: tls_handshake"

    async def test_connectivity_egress_denial_still_raises(self):
        from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

        stopped: list[str] = []

        class _Services:
            async def run_probe(self, check_type, address, options):
                if address == _IPS[2]:
                    raise _Denied(f"probe to {address} refused by the flow egress policy")
                try:
                    await asyncio.sleep(30)
                except asyncio.CancelledError:
                    stopped.append(address)
                    raise
                return ProbeResult(ok=True)  # pragma: no cover - always cancelled

        with pytest.raises(_Denied):
            await asyncio.wait_for(
                ConnectivityCheckHandler().execute(_probe_ctx({}, _Services())), timeout=5
            )
        # The checks still running were stopped, not left behind.
        assert sorted(stopped) == sorted(ip for ip in _IPS if ip != _IPS[2])

    async def test_http_requests_targets_concurrently_in_order(self, monkeypatch):
        from hegemony_steps_probe import http_check
        from hegemony_steps_probe.http_check import HttpProbeHandler

        flight = _InFlight()

        async def answer(request: httpx.Request) -> httpx.Response:
            await flight.hold(_index(request.url.host))
            return httpx.Response(200)

        real_client = httpx.AsyncClient

        def client_with_mock_transport(**kwargs):
            kwargs["transport"] = httpx.MockTransport(answer)
            return real_client(**kwargs)

        monkeypatch.setattr(http_check.httpx, "AsyncClient", client_with_mock_transport)
        ctx = _probe_ctx({"max_parallel_devices": 4}, type("_Services", (), {})())
        result = await HttpProbeHandler().execute(ctx)
        assert result.success is True, result.error
        assert 1 < flight.peak <= 4
        assert [e["content_json"]["url"] for e in result.evidence] == [
            f"http://{ip}/" for ip in _IPS
        ]
        assert list(result.metrics) == [f"{ip}_ms" for ip in _IPS]

    async def test_http_egress_denial_still_raises(self, monkeypatch):
        from hegemony_steps_probe import http_check
        from hegemony_steps_probe.http_check import HttpProbeHandler

        async def answer(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(0.01)
            return httpx.Response(200)

        real_client = httpx.AsyncClient

        def client_with_mock_transport(**kwargs):
            kwargs["transport"] = httpx.MockTransport(answer)
            return real_client(**kwargs)

        monkeypatch.setattr(http_check.httpx, "AsyncClient", client_with_mock_transport)

        class _Services:
            async def enforce_egress(self, host, port, *, proto, kind):
                if host == _IPS[3]:
                    raise _Denied(f"{kind} to {host} refused by the flow egress policy")

        with pytest.raises(_Denied):
            await HttpProbeHandler().execute(_probe_ctx({}, _Services()))

    async def test_dns_looks_targets_up_concurrently_in_order(self, monkeypatch):
        from hegemony_steps_probe import dns_check
        from hegemony_steps_probe.dns_check import DnsProbeHandler

        flight = _InFlight()

        async def fake_resolve(query_name, record_type, *, resolver_ip="", timeout_sec=5.0):
            index = int(query_name.split(".")[0].removeprefix("r"))
            await flight.hold(index)
            return [f"192.0.2.{index}"]

        monkeypatch.setattr(dns_check, "resolve_records", fake_resolve)
        devices = [
            {"id": None, "name": f"r{i}", "hostname": f"r{i}.example.com", "mgmt_host": ip}
            for i, ip in enumerate(_IPS, start=1)
        ]
        ctx = HandlerContext(
            run_id="r",
            flow_id="f",
            step_run_id="sr",
            step_id="s",
            config={"max_parallel_devices": 3},
            target_roles=["primary"],
            target_devices_by_role={"primary": devices},
        )
        result = await DnsProbeHandler().execute(ctx)
        assert result.success is True, result.error
        assert 1 < flight.peak <= 3
        assert [e["content_json"]["answers"] for e in result.evidence] == [[ip] for ip in _IPS]
        assert list(result.metrics) == [f"r{i}_ms" for i in range(1, 7)]

    async def test_wait_reachable_polls_a_round_concurrently(self):
        from hegemony_steps_probe.wait_reachable import WaitReachableHandler

        flight = _InFlight()

        class _Services:
            async def run_probe(self, check_type, address, options):
                await flight.hold(_index(address))
                return ProbeResult(ok=True)

        config = {"max_wait_seconds": 10, "stable_seconds": 1, "poll_interval": 1}
        ctx = _probe_ctx({**config, "max_parallel_devices": 3}, _Services())
        result = await WaitReachableHandler().execute(ctx)
        assert result.success is True, result.error
        assert 1 < flight.peak <= 3
        assert [e["content_json"]["host"] for e in result.evidence] == _IPS

    async def test_wait_reachable_keeps_its_deadline(self):
        """Six hanging targets, two at a time, a 5 s connect timeout: the step
        still ends at its 2 s deadline instead of after 6 x 5 s."""
        from hegemony_steps_probe.wait_reachable import WaitReachableHandler

        timeouts_ms: list[int] = []

        class _Services:
            async def run_probe(self, check_type, address, options):
                timeouts_ms.append(options["timeout_ms"])
                await asyncio.sleep(30)  # ignores its timeout: the cap must hold
                return ProbeResult(ok=True)  # pragma: no cover - always cut off

        config = {
            "max_wait_seconds": 2,
            "stable_seconds": 1,
            "poll_interval": 1,
            "connect_timeout_seconds": 5,
            "max_parallel_devices": 2,
        }
        loop = asyncio.get_running_loop()
        started = loop.time()
        result = await WaitReachableHandler().execute(_probe_ctx(config, _Services()))
        assert loop.time() - started < 2.5
        assert result.success is False
        assert (result.error or "").startswith("Timeout waiting for targets")
        assert timeouts_ms and max(timeouts_ms) <= 2000
