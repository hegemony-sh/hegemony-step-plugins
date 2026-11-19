# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""general.noop, general.sleep and flow.notify declare that they output nothing."""

from __future__ import annotations

import pytest

from hegemony_step_sdk import HandlerContext
from hegemony_steps_flow.notify import SendNotificationHandler
from hegemony_steps_general import sleep as sleep_module
from hegemony_steps_general.noop import NoOpHandler
from hegemony_steps_general.sleep import SleepHandler


def _ctx(config: dict) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        target_roles=[],
        target_devices_by_role={},
    )


def test_handlers_without_output_declare_no_fields():
    for handler in (NoOpHandler, SleepHandler, SendNotificationHandler):
        assert handler.output_fields == (), handler.handler_id


@pytest.mark.parametrize(
    ("handler", "config"),
    [(NoOpHandler, {}), (SleepHandler, {"duration_seconds": 1})],
)
async def test_handlers_without_output_put_nothing_in_it(handler, config, monkeypatch):
    async def _no_wait(_seconds: float) -> None:
        return None

    monkeypatch.setattr(sleep_module.asyncio, "sleep", _no_wait)
    result = await handler().execute(_ctx(config))

    assert result.success is True, result.error
    assert result.output == {}
