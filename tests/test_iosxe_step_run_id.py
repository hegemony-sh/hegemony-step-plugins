# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Every IOS-XE upgrade step opens its device sessions under its step run.

``services.connect(..., step_run_id=...)`` registers the session for
cancellation, so cancelling the run closes it instead of leaving a long
install or transfer running on the device.
"""

from __future__ import annotations

import pytest

from hegemony_steps_cisco_iosxe.upgrade.handlers import verify as verify_module
from hegemony_steps_cisco_iosxe.upgrade.handlers.cleanup import UpgradeCleanupHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.install import UpgradeInstallHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.preflight import UpgradePreflightHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.stage import UpgradeStageHandler
from hegemony_steps_cisco_iosxe.upgrade.handlers.verify import UpgradeVerifyHandler
from tests.iosxe_fakes import (
    UNREACHABLE,
    FakeServices,
    InstantClock,
    Result,
    ScriptedTransport,
    make_ctx,
)

STEPS = [
    ("preflight", UpgradePreflightHandler, {}),
    (
        "stage",
        UpgradeStageHandler,
        {"source_url": "https://repo.example/i.bin", "dest_filename": "i.bin"},
    ),
    ("install", UpgradeInstallHandler, {"image_name": "i.bin"}),
    # retry_interval: the name steps saved before poll_interval_seconds still use.
    ("verify", UpgradeVerifyHandler, {"max_wait_seconds": 60, "retry_interval": 5}),
    ("cleanup", UpgradeCleanupHandler, {}),
]


@pytest.fixture(autouse=True)
def _instant_verify_wait(monkeypatch):
    monkeypatch.setattr(verify_module, "asyncio", InstantClock())


@pytest.mark.parametrize(("handler", "config"), [s[1:] for s in STEPS], ids=[s[0] for s in STEPS])
async def test_connect_gets_the_step_run_id(handler, config):
    services = FakeServices(
        lambda: ScriptedTransport({"show clock": Result("10:00:00 UTC")}, default=UNREACHABLE)
    )
    await handler().execute(make_ctx(config, services, step_run_id="step-run-42"))
    assert services.connect_calls
    assert all(call.get("step_run_id") == "step-run-42" for call in services.connect_calls)
