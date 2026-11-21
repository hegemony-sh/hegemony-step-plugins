# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""probe.wait_unreachable: wait until targets stop answering."""

from __future__ import annotations

from typing import Any, cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices, InvalidConfigError, ProbeResult
from hegemony_step_sdk.docs import load_docs_bundle
from hegemony_steps_probe.wait_unreachable import WaitUnreachableConfig, WaitUnreachableHandler

UP = ProbeResult(ok=True)
DOWN = ProbeResult(ok=False, error_kind="timeout", error_detail="no answer")
REFUSED = ProbeResult(ok=False, error_kind="connection_refused", error_detail="refused")
PROXY_BROKEN = ProbeResult(ok=False, error_kind="socks_error", error_detail="proxy refused us")


class _Script:
    """services.run_probe stand-in: each address answers from its own list,
    repeating the last answer once the list runs out."""

    def __init__(self, answers: dict[str, list[ProbeResult]]) -> None:
        self.answers = answers
        self.calls: dict[str, int] = dict.fromkeys(answers, 0)

    async def run_probe(self, check_type, address, options):
        script = self.answers[address]
        answer = script[min(self.calls[address], len(script) - 1)]
        self.calls[address] += 1
        return answer


def _ctx(config: dict[str, Any], services: _Script) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"poll_interval_seconds": 1, **config},
        step_target_ips=list(services.answers),
        services=cast(HandlerServices, services),
    )


async def test_a_target_that_stops_answering_went_down():
    probes = _Script({"192.0.2.7": [UP, DOWN]})
    result = await WaitUnreachableHandler().execute(
        _ctx({"stable_seconds": 0, "max_wait_seconds": 10}, probes)
    )
    assert result.success is True, result.error
    assert result.output["went_down"] == ["192.0.2.7"]
    assert result.output["already_down"] == []
    assert result.output["still_up"] == []
    assert result.evidence[0]["content_json"]["answered_first"] is True
    assert "1 went down, 0 already down" in (result.summary or "")


async def test_a_target_down_from_the_first_poll_is_already_down():
    probes = _Script({"192.0.2.7": [REFUSED]})
    result = await WaitUnreachableHandler().execute(
        _ctx({"stable_seconds": 0, "max_wait_seconds": 10}, probes)
    )
    assert result.success is True, result.error
    assert result.output["already_down"] == ["192.0.2.7"]
    assert result.output["went_down"] == []
    assert probes.calls["192.0.2.7"] == 1


async def test_a_down_target_stays_down_while_the_others_catch_up():
    """A quick reload can bring a device back before a slower one goes down."""
    probes = _Script({"192.0.2.7": [DOWN, UP], "192.0.2.8": [UP, UP, DOWN]})
    result = await WaitUnreachableHandler().execute(
        _ctx({"stable_seconds": 0, "max_wait_seconds": 10}, probes)
    )
    assert result.success is True, result.error
    assert sorted(result.output["went_down"] + result.output["already_down"]) == [
        "192.0.2.7",
        "192.0.2.8",
    ]
    # Confirmed down on its first poll, so never polled again.
    assert probes.calls["192.0.2.7"] == 1


async def test_one_lost_poll_is_not_a_reload():
    probes = _Script({"192.0.2.7": [DOWN, UP]})
    result = await WaitUnreachableHandler().execute(
        _ctx({"stable_seconds": 2, "max_wait_seconds": 4}, probes)
    )
    assert result.success is False
    assert "still answering: 192.0.2.7" in (result.error or "")
    assert result.summary == "Targets still reachable after 4s"
    assert result.output["still_up"] == ["192.0.2.7"]


async def test_a_broken_proxy_never_counts_as_down():
    probes = _Script({"192.0.2.7": [PROXY_BROKEN]})
    result = await WaitUnreachableHandler().execute(
        _ctx({"stable_seconds": 0, "max_wait_seconds": 2}, probes)
    )
    assert result.success is False
    assert "the check could not run: 192.0.2.7 (proxy refused us)" in (result.error or "")


async def test_a_misconfigured_check_fails_at_once():
    probes = _Script({"192.0.2.7": [ProbeResult(ok=False, error_kind="config_error")]})
    result = await WaitUnreachableHandler().execute(
        _ctx({"stable_seconds": 0, "max_wait_seconds": 10}, probes)
    )
    assert result.success is False
    assert probes.calls["192.0.2.7"] == 1
    assert "cannot run against" in (result.error or "")


def test_the_down_window_must_be_shorter_than_the_wait():
    with pytest.raises(InvalidConfigError):
        WaitUnreachableHandler().parse_config(
            {"stable_seconds": 30, "max_wait_seconds": 30}, WaitUnreachableConfig
        )


def test_the_form_names_the_down_window_for_what_it_is():
    props = WaitUnreachableConfig.model_json_schema()["properties"]
    assert props["stable_seconds"]["title"] == "Down For (sec)"
    assert props["stable_seconds"]["default"] == 10
    assert "x_legacy_keys" not in props["max_wait_seconds"]


@pytest.mark.parametrize("answers", [[UP, DOWN], [UP]])
async def test_the_declared_output_fields_are_the_keys_the_step_outputs(answers):
    probes = _Script({"192.0.2.7": answers})
    result = await WaitUnreachableHandler().execute(
        _ctx({"stable_seconds": 0, "max_wait_seconds": 2}, probes)
    )
    declared = {field.name for field in WaitUnreachableHandler.output_fields}
    assert declared == set(result.output)


def test_the_docs_page_names_every_declared_output_field():
    text = load_docs_bundle("hegemony_steps_probe")[WaitUnreachableHandler.handler_id]
    for field in WaitUnreachableHandler.output_fields:
        assert f"output.{field.name}`" in text, field.name


class _Slow:
    """run_probe stand-in that answers after ``delay`` seconds."""

    def __init__(self, answer: ProbeResult, delay: float = 0.0) -> None:
        self.answer, self.delay, self.calls = answer, delay, 0

    async def run_probe(self, check_type, address, options):
        import asyncio

        self.calls += 1
        await asyncio.sleep(self.delay)
        return self.answer


def _config(**fields: Any) -> WaitUnreachableConfig:
    return WaitUnreachableConfig.model_validate(
        {"stable_seconds": 0, "max_wait_seconds": 30, **fields}
    )


async def test_a_poll_past_the_deadline_is_skipped():
    import asyncio

    from hegemony_steps_probe.waiting import poll_target

    probes = _Slow(DOWN)
    deadline = asyncio.get_running_loop().time() - 1
    result = await poll_target(
        cast(HandlerServices, probes), _config(), {"mgmt_host": "192.0.2.7"}, deadline
    )
    assert result is None
    assert probes.calls == 0


async def test_a_failed_poll_the_deadline_cut_short_proves_nothing():
    import asyncio

    from hegemony_steps_probe.waiting import poll_target

    deadline = asyncio.get_running_loop().time() + 0.5
    device = {"mgmt_host": "192.0.2.7"}
    failed = await poll_target(cast(HandlerServices, _Slow(DOWN)), _config(), device, deadline)
    assert failed is None
    answered = await poll_target(cast(HandlerServices, _Slow(UP)), _config(), device, deadline)
    assert answered is UP


async def test_a_probe_with_no_answer_in_its_full_time_is_a_timeout():
    import asyncio

    from hegemony_steps_probe.waiting import poll_target

    deadline = asyncio.get_running_loop().time() + 30
    result = await poll_target(
        cast(HandlerServices, _Slow(UP, delay=5)),
        _config(connect_timeout_seconds=1),
        {"mgmt_host": "192.0.2.7"},
        deadline,
    )
    assert result is not None
    assert result.ok is False and result.error_kind == "timeout"


async def test_through_a_proxy_a_poll_that_runs_out_is_inconclusive():
    """The probe gets a little less time, so it can blame the proxy or the
    target itself; a poll that still runs out cannot say which stalled."""
    import asyncio

    from hegemony_steps_probe.waiting import poll_target

    class _Recording(_Slow):
        options: dict[str, Any] = {}

        async def run_probe(self, check_type, address, options):
            self.options = dict(options)
            return await super().run_probe(check_type, address, options)

    probes = _Recording(UP, delay=5)
    deadline = asyncio.get_running_loop().time() + 30
    result = await poll_target(
        cast(HandlerServices, probes),
        _config(connect_timeout_seconds=1, socks_proxy="socks5://127.0.0.1:1080"),
        {"mgmt_host": "192.0.2.7"},
        deadline,
        proxy_stage=True,
    )
    assert probes.options["timeout_ms"] == 750
    assert result is not None
    assert result.error_kind == "socks_error"
