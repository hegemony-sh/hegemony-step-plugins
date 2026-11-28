# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The ``napalm.*`` steps against an in-memory NAPALM device.

The fake session keeps a running configuration (a list of lines), a loaded
candidate and a pending confirmed commit, so the tests see what a step
changed on the device, not only what it called.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_step_sdk.docs import load_docs_bundle
from hegemony_steps_napalm import ALL_HANDLERS
from hegemony_steps_napalm.config import NapalmConfigConfig, NapalmConfigHandler
from hegemony_steps_napalm.get import NapalmGetConfig, NapalmGetHandler
from hegemony_steps_napalm.rollback import NapalmRollbackHandler


class FakeDevice:
    """One device's configuration state, shared by every session to it."""

    def __init__(self, name: str, *, driver: str = "eos") -> None:
        self.name = name
        self.driver = driver
        self.running: list[str] = [f"hostname {name}"]
        self.before_commit: list[str] | None = None
        self.pending = False
        self.reachable_after_commit = True
        self.timer_fires_before_check = False
        self.rollbacks_by_timer = False
        self.timer_fires_after_check = False
        self.rollback_calls = 0
        self.startup = list(self.running)
        self.big_result = 0
        self.commits = 0
        self.facts = {"hostname": name, "os_version": "4.30"}

    def diff(self, candidate: list[str]) -> str:
        removed = [f"-{line}" for line in self.running if line not in candidate]
        added = [f"+{line}" for line in candidate if line not in self.running]
        return "\n".join(removed + added)


class FakeSession:
    def __init__(self, device: FakeDevice) -> None:
        self.device = device
        self.driver = device.driver
        self.candidate: list[str] | None = None
        self.closed = False

    async def get(self, getter: str) -> Any:
        if getter == "facts":
            return self.device.facts
        if getter == "config":
            return {"running": "\n".join(self.device.running) + "!" * 20000}
        if getter == "vlans":
            raise NotImplementedError("get_vlans is not implemented for this driver")
        if getter == "interfaces" and self.device.big_result:
            return {"description": "x" * self.device.big_result}
        return {getter: True}

    async def load_config(self, config: str, *, replace: bool = False) -> None:
        lines = [line for line in config.splitlines() if line.strip()]
        if any(line.startswith("bad") for line in lines):
            raise RuntimeError("MergeConfigException: % Invalid input detected")
        self.candidate = (
            lines
            if replace
            else self.device.running + [line for line in lines if line not in self.device.running]
        )

    async def compare_config(self) -> str:
        assert self.candidate is not None
        return self.device.diff(self.candidate)

    async def discard_config(self) -> None:
        self.candidate = None

    async def commit_config(self, *, message: str = "", revert_in: int | None = None) -> None:
        assert self.candidate is not None
        if revert_in is not None and self.driver == "nxos_ssh":
            raise NotImplementedError("Commit confirm has not been implemented on this platform.")
        self.device.before_commit = list(self.device.running)
        self.device.running = self.candidate
        self.device.pending = revert_in is not None
        if self.device.pending and self.device.timer_fires_before_check:
            # The device's own timer reverts before the step checks.
            self.device.running = list(self.device.before_commit)
            self.device.pending = False
            self.device.rollbacks_by_timer = True
        self.device.commits += 1
        self.candidate = None

    async def has_pending_commit(self) -> bool:
        pending = self.device.pending
        if pending and self.device.timer_fires_after_check:
            # The race: the timer fires right after the step sees "pending".
            self.device.running = list(self.device.before_commit or self.device.running)
            self.device.pending = False
        return pending

    async def cancel_pending_commit(self) -> None:
        # Like "configure session X abort" / "configure revert now": only the
        # pending commit is undone, and nothing happens when none is pending.
        if self.device.pending:
            self.device.running = list(self.device.before_commit or self.device.running)
            self.device.pending = False

    async def confirm_commit(self) -> None:
        assert self.device.pending
        self.device.pending = False

    async def rollback(self) -> None:
        self.device.rollback_calls += 1
        if self.device.before_commit is None:
            raise RuntimeError("ReplaceConfigException: rollback file does not exist")
        self.device.running = self.device.before_commit
        self.device.pending = False

    async def close(self) -> None:
        self.closed = True


class FakeServices:
    def __init__(self, *devices: FakeDevice) -> None:
        self.devices = {device.name: device for device in devices}
        self.sessions: list[FakeSession] = []
        self.opened: list[tuple[str, dict[str, Any]]] = []

    async def open_napalm(self, device: dict[str, Any], **kwargs: Any) -> FakeSession:
        self.opened.append((device["name"], kwargs))
        state = self.devices[device["name"]]
        if state.rollbacks_by_timer:
            raise TimeoutError("the device does not answer")
        if state.driver == "none":
            raise NotImplementedError("NAPALM steps do not support the device platform 'junos'")
        if state.pending and not state.reachable_after_commit:
            raise TimeoutError("the device does not answer")
        session = FakeSession(state)
        self.sessions.append(session)
        return session

    async def emit_run_event(self, *args: Any, **kwargs: Any) -> None:
        return None


def _ctx(config: dict[str, Any], services: Any, names: tuple[str, ...] = ("r1",)) -> HandlerContext:
    return HandlerContext(
        attempt=1,
        run_id="run-1",
        flow_id="flow-1",
        step_run_id="sr-1",
        step_id="change",
        config=config,
        target_devices_by_role={
            "core": [{"id": f"id-{name}", "name": name, "mgmt_host": "192.0.2.1"} for name in names]
        },
        target_roles=["core"],
        services=cast(HandlerServices, services),
    )


# --- napalm.get ----------------------------------------------------------------------------


async def test_get_reads_each_getter_into_output_and_evidence():
    services = FakeServices(FakeDevice("r1"), FakeDevice("r2", driver="ios"))
    ctx = _ctx({"getters": ["facts", "get_bgp_neighbors"]}, services, ("r1", "r2"))

    result = await NapalmGetHandler().execute(ctx)

    assert result.success, result.error
    r1 = result.output["devices"]["r1"]
    assert r1["driver"] == "eos"
    assert r1["data"]["facts"]["os_version"] == "4.30"
    assert r1["data"]["bgp_neighbors"] == {"bgp_neighbors": True}
    assert result.output["devices"]["r2"]["driver"] == "ios"
    names = sorted(item["name"] for item in result.evidence)
    assert names == ["r1:bgp_neighbors", "r1:facts", "r2:bgp_neighbors", "r2:facts"]
    facts = next(item for item in result.evidence if item["name"] == "r1:facts")
    # The getter name is the command, as evidence.assert looks it up.
    assert facts["content_json"]["command"] == "facts"
    assert '"os_version": "4.30"' in facts["content_text"]
    assert all(session.closed for session in services.sessions)


async def test_a_large_result_stays_in_the_evidence_only():
    services = FakeServices(FakeDevice("r1"))

    result = await NapalmGetHandler().execute(_ctx({"getters": ["config", "facts"]}, services))

    entry = result.output["devices"]["r1"]
    assert entry["omitted"] == ["config"]
    assert set(entry["data"]) == {"facts"}
    config = next(item for item in result.evidence if item["name"] == "r1:config")
    assert len(config["content_text"]) > 16 * 1024


def test_get_refuses_getters_that_return_credentials_or_do_not_exist():
    for getter in ("users", "get_snmp_information", "route_to", "nonsense"):
        with pytest.raises(ValueError, match="unknown getter"):
            NapalmGetConfig(getters=[getter])
    assert NapalmGetConfig(getters=[" get_facts ", "facts", ""]).getters == ["facts"]


async def test_a_device_without_a_driver_or_getter_fails_alone():
    services = FakeServices(FakeDevice("r1"), FakeDevice("r2", driver="none"))
    ctx = _ctx({"getters": ["facts", "vlans"]}, services, ("r1", "r2"))

    result = await NapalmGetHandler().execute(ctx)

    assert not result.success
    assert "r2 (NAPALM steps do not support the device platform 'junos')" in (result.error or "")
    assert "r1 (not supported on this device: get_vlans" in (result.error or "")


async def test_a_platform_without_open_napalm_fails_the_step_clearly():
    class OldServices:
        async def emit_run_event(self, *args: Any, **kwargs: Any) -> None:
            return None

    result = await NapalmGetHandler().execute(_ctx({}, OldServices()))

    assert not result.success
    assert "cannot open NAPALM sessions" in (result.error or "")


async def test_connection_settings_reach_the_platform():
    services = FakeServices(FakeDevice("r1"))
    config = {"connect_timeout_seconds": 7, "command_timeout_seconds": 9, "allow_legacy_ssh": True}

    await NapalmGetHandler().execute(_ctx(config, services))

    assert services.opened == [
        ("r1", {"connect_timeout": 7.0, "command_timeout": 9.0, "allow_legacy_ssh": True})
    ]


# --- napalm.config -------------------------------------------------------------------------


async def test_a_merge_commits_the_difference():
    device = FakeDevice("r1")
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(
        _ctx({"config": "interface Loopback100\n"}, services)
    )

    assert result.success, result.error
    entry = result.output["devices"]["r1"]
    assert entry["diff"] == "+interface Loopback100"
    assert entry["changed"] and entry["committed"] and not entry["confirmed"]
    assert device.running == ["hostname r1", "interface Loopback100"]
    assert [item["name"] for item in result.evidence] == ["r1:napalm diff"]
    assert "1/1 devices ok, 1 changed" in result.summary


async def test_a_dry_run_records_the_difference_and_changes_nothing():
    device = FakeDevice("r1")
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(
        _ctx({"config": "interface Loopback100", "dry_run": True}, services)
    )

    assert result.success
    assert result.output["devices"]["r1"]["diff"] == "+interface Loopback100"
    assert not result.output["devices"]["r1"]["committed"]
    assert device.running == ["hostname r1"] and device.commits == 0
    assert services.sessions[0].candidate is None
    assert "would change" in result.summary


async def test_nothing_to_change_commits_nothing():
    device = FakeDevice("r1")
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(_ctx({"config": "hostname r1"}, services))

    assert result.success
    entry = result.output["devices"]["r1"]
    assert entry["diff"] == "" and not entry["changed"] and not entry["committed"]
    assert device.commits == 0
    assert result.evidence[0]["content_text"] == "(no difference)"


async def test_replace_removes_what_the_text_leaves_out():
    device = FakeDevice("r1")
    device.running.append("ntp server 192.0.2.9")
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(
        _ctx({"config": "hostname r1", "mode": "replace"}, services)
    )

    assert result.output["devices"]["r1"]["diff"] == "-ntp server 192.0.2.9"
    assert device.running == ["hostname r1"]


async def test_a_refused_candidate_is_discarded_and_fails_the_device():
    device = FakeDevice("r1")
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(_ctx({"config": "bad line"}, services))

    assert not result.success
    assert "Invalid input" in (result.error or "")
    assert device.commits == 0
    assert services.sessions[0].candidate is None and services.sessions[0].closed


async def test_a_confirmed_commit_is_confirmed_after_a_new_session_succeeds():
    device = FakeDevice("r1")
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(
        _ctx({"config": "interface Loopback100", "revert_in_seconds": 120}, services)
    )

    assert result.success, result.error
    entry = result.output["devices"]["r1"]
    assert entry["committed"] and entry["confirmed"]
    assert not device.pending
    # The change session and the proof session.
    assert len(services.opened) == 2
    assert all(session.closed for session in services.sessions)


async def test_a_confirmed_commit_that_cuts_the_device_off_is_rolled_back():
    device = FakeDevice("r1")
    device.reachable_after_commit = False
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(
        _ctx({"config": "interface Loopback100", "revert_in_seconds": 120}, services)
    )

    assert not result.success
    assert "a new session after the commit failed" in (result.error or "")
    assert "rolled back now" in (result.error or "")
    entry = result.output["devices"]["r1"]
    assert entry["committed"] and not entry["confirmed"] and entry["rolled_back"]
    assert device.running == ["hostname r1"] and not device.pending


async def test_a_driver_without_confirmed_commit_fails_and_changes_nothing():
    device = FakeDevice("r1", driver="nxos_ssh")
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(
        _ctx({"config": "interface Loopback100", "revert_in_seconds": 60}, services)
    )

    assert not result.success
    assert "not supported on this device" in (result.error or "")
    assert device.running == ["hostname r1"]


@pytest.mark.parametrize("seconds", [30, 90, 24 * 3600, 24 * 3600 + 60])
def test_confirm_within_takes_whole_minutes_in_range(seconds):
    with pytest.raises(ValueError):
        NapalmConfigConfig(config="x", revert_in_seconds=seconds)
    assert NapalmConfigConfig(config="x", revert_in_seconds=0).revert_in_seconds == 0
    assert NapalmConfigConfig(config="x", revert_in_seconds=300).revert_in_seconds == 300


async def test_one_device_failing_leaves_the_others_changed():
    good, bad = FakeDevice("r1"), FakeDevice("r2", driver="none")
    services = FakeServices(good, bad)

    result = await NapalmConfigHandler().execute(
        _ctx({"config": "interface Loopback100", "max_parallel_devices": 2}, services, ("r1", "r2"))
    )

    assert not result.success
    assert result.output["devices"]["r1"]["committed"]
    assert not result.output["devices"]["r2"]["ok"]
    assert good.running[-1] == "interface Loopback100"


# --- napalm.rollback -----------------------------------------------------------------------


async def test_rollback_returns_to_the_configuration_before_the_last_commit():
    device = FakeDevice("r1")
    services = FakeServices(device)
    await NapalmConfigHandler().execute(_ctx({"config": "interface Loopback100"}, services))
    assert device.running[-1] == "interface Loopback100"

    result = await NapalmRollbackHandler().execute(_ctx({}, services))

    assert result.success, result.error
    assert device.running == ["hostname r1"]
    assert result.output["devices"]["r1"]["driver"] == "eos"


async def test_rollback_without_a_saved_configuration_fails_with_the_drivers_reason():
    result = await NapalmRollbackHandler().execute(_ctx({}, FakeServices(FakeDevice("r1"))))

    assert not result.success
    assert "rollback file does not exist" in (result.error or "")


# --- registration and docs -----------------------------------------------------------------


def test_the_wheel_registers_its_three_handlers_with_docs():
    ids = sorted(handler.handler_id for handler in ALL_HANDLERS)
    assert ids == ["napalm.config", "napalm.get", "napalm.rollback"]
    bundle = load_docs_bundle("hegemony_steps_napalm")
    assert sorted(bundle) == ids


async def test_no_targets_fails_every_step():
    for handler in (NapalmGetHandler(), NapalmConfigHandler(), NapalmRollbackHandler()):
        ctx = _ctx({"config": "x"}, FakeServices(), names=())
        result = await handler.execute(ctx)
        assert not result.success and result.error == "No target devices configured"


async def test_a_commit_the_device_already_reverted_is_not_rolled_back_again():
    # On EOS a rollback after the timer fired would replace running with the
    # startup copy taken at commit time, dropping unsaved changes.
    device = FakeDevice("r1")
    device.timer_fires_before_check = True
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(
        _ctx({"config": "interface Loopback100", "revert_in_seconds": 120}, services)
    )

    assert not result.success
    assert "the device already rolled it back" in (result.error or "")
    assert device.rollback_calls == 0
    assert result.output["devices"]["r1"]["rolled_back"] is True
    assert device.running == ["hostname r1"]


async def test_results_read_before_a_failing_getter_are_kept():
    services = FakeServices(FakeDevice("r1"))

    result = await NapalmGetHandler().execute(_ctx({"getters": ["facts", "vlans"]}, services))

    assert not result.success
    entry = result.output["devices"]["r1"]
    assert entry["data"]["facts"]["os_version"] == "4.30"
    assert [item["name"] for item in result.evidence] == ["r1:facts"]


async def test_getter_data_shares_one_output_budget_across_devices():
    names = tuple(f"r{n}" for n in range(1, 7))
    devices = [FakeDevice(name) for name in names]
    for device in devices:
        device.big_result = 15000
    services = FakeServices(*devices)

    result = await NapalmGetHandler().execute(
        _ctx({"getters": ["interfaces"], "max_parallel_devices": 6}, services, names)
    )

    assert result.success, result.error
    kept = [name for name, entry in result.output["devices"].items() if entry["data"]]
    omitted = [name for name, entry in result.output["devices"].items() if entry["omitted"]]
    # 64 KiB of output fits four 15000-character results, not six.
    assert len(kept) == 4 and len(omitted) == 2
    assert len(result.evidence) == 6


async def test_a_cancel_while_logging_the_open_still_closes_the_session(monkeypatch):
    import asyncio

    from hegemony_steps_napalm import common

    real_log = common.log_line

    async def cancel_on_open(ctx: Any, device: Any, line: str) -> None:
        if line.startswith("NAPALM session open"):
            raise asyncio.CancelledError
        await real_log(ctx, device, line)

    monkeypatch.setattr(common, "log_line", cancel_on_open)
    services = FakeServices(FakeDevice("r1"))

    with pytest.raises(asyncio.CancelledError):
        await NapalmGetHandler().execute(_ctx({}, services))

    assert services.sessions and services.sessions[0].closed


async def test_the_timer_firing_after_the_pending_check_changes_nothing_more():
    # Unsaved running changes predate the step; startup does not have them.
    device = FakeDevice("r1")
    device.running.append("ntp server 192.0.2.9")
    device.timer_fires_after_check = True
    device.reachable_after_commit = False
    services = FakeServices(device)

    result = await NapalmConfigHandler().execute(
        _ctx({"config": "interface Loopback100", "revert_in_seconds": 120}, services)
    )

    assert not result.success
    # No NAPALM rollback(), which would restore the startup copy.
    assert device.rollback_calls == 0
    assert device.running == ["hostname r1", "ntp server 192.0.2.9"]
