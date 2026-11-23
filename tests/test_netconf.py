# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The ``netconf.*`` steps against the in-process NETCONF device (``netconf_fakes``).

Every test runs the real client over a byte channel: hello, end-of-message
and chunked framing, message ids and rpc-errors.
"""

from __future__ import annotations

import random
from typing import Any, cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_step_sdk.docs import load_docs_bundle
from hegemony_steps_netconf import ALL_HANDLERS
from hegemony_steps_netconf.client import (
    NetconfError,
    NetconfSession,
    RpcFailed,
    RpcTimeout,
    check_fragment,
    element_content,
    parse_xml,
    pretty,
)
from hegemony_steps_netconf.commit import NetconfCancelCommitHandler, NetconfCommitHandler
from hegemony_steps_netconf.edit_config import NetconfEditConfigHandler
from hegemony_steps_netconf.get import NetconfGetHandler
from hegemony_steps_netconf.rpc import NetconfRpcHandler
from tests.netconf_fakes import ALL_CAPABILITIES, FakeNetconfDevice, FakeServices, Pending

NATIVE = "urn:example:native"
BASE = f'<native xmlns="{NATIVE}"><hostname>r1</hostname><domain>lab</domain></native>'


def _device(name: str = "r1") -> dict[str, Any]:
    return {"id": f"id-{name}", "name": name, "mgmt_host": "192.0.2.1"}


def _ctx(config: dict[str, Any], services: Any, names: tuple[str, ...] = ("r1",)) -> HandlerContext:
    return HandlerContext(
        run_id="run-1",
        flow_id="flow-1",
        step_run_id="sr-1",
        step_id="change",
        config=config,
        target_devices_by_role={"core": [_device(name) for name in names]},
        target_roles=["core"],
        services=cast(HandlerServices, services),
    )


def _hostname(value: str) -> str:
    return f'<native xmlns="{NATIVE}"><hostname>{value}</hostname></native>'


def _running_hostname(device: FakeNetconfDevice) -> str:
    return device.running[0].findtext(f"{{{NATIVE}}}hostname") or ""


# --- The client ---------------------------------------------------------------


@pytest.mark.parametrize("base10_only", [False, True], ids=["chunked", "end-of-message"])
async def test_the_client_speaks_both_framings(base10_only):
    device = FakeNetconfDevice.with_config(BASE, base10_only=base10_only)
    session = NetconfSession(await device.open(), timeout=5)
    await session.hello()
    assert session.session_id == "1"
    assert session._chunked is not base10_only
    reply = await session.get_config("running")
    assert "<hostname>r1</hostname>" in reply.data().replace("ns0:", "")
    await session.close()


async def test_framing_follows_what_both_peers_advertise():
    capabilities = tuple(c for c in ALL_CAPABILITIES if not c.endswith("base:1.1"))
    device = FakeNetconfDevice.with_config(BASE, capabilities=capabilities)
    session = NetconfSession(await device.open(), timeout=5)
    await session.hello()
    assert session._chunked is False
    assert "<hostname>r1</hostname>" in (await session.get_config("running")).data().replace(
        "ns0:", ""
    )
    await session.close()


async def test_only_the_confirming_session_settles_a_commit_without_persist_id():
    device = FakeNetconfDevice.with_config(BASE)
    owner = NetconfSession(await device.open(), timeout=5)
    await owner.hello()
    await owner.edit_config("candidate", _hostname("r2"))
    await owner.commit(confirmed=True, confirm_timeout=60)
    other = NetconfSession(await device.open(), timeout=5)
    await other.hello()
    with pytest.raises(RpcFailed, match="another session's"):
        await other.commit()
    with pytest.raises(RpcFailed, match="another session's"):
        await other.cancel_commit()
    assert device.pending is not None
    await owner.commit()
    assert device.pending is None and _running_hostname(device) == "r2"
    await other.close()
    await owner.close()


class _SplitReads:
    """A channel whose reads return 1 to ``most`` bytes at a time, at random (fixed seed)."""

    def __init__(self, inner: Any, *, seed: int, most: int) -> None:
        self._inner = inner
        self._random = random.Random(seed)
        self._most = most
        self._pending = b""

    async def write(self, data: bytes) -> None:
        await self._inner.write(data)

    async def read(self, max_bytes: int = 65536) -> bytes:
        if not self._pending:
            self._pending = await self._inner.read(max_bytes)
            if not self._pending:
                return b""
        size = min(self._random.randint(1, self._most), max_bytes)
        data, self._pending = self._pending[:size], self._pending[size:]
        return data

    async def close(self) -> None:
        await self._inner.close()


@pytest.mark.parametrize("base10_only", [False, True], ids=["chunked", "end-of-message"])
@pytest.mark.parametrize("most", [1, 7, 64])
async def test_replies_split_into_small_reads_are_reassembled(base10_only, most):
    big = "".join(f"<item{n}>value {n}</item{n}>" for n in range(300))
    device = FakeNetconfDevice.with_config(
        BASE + f'<other xmlns="urn:example:other">{big}</other>', base10_only=base10_only
    )
    session = NetconfSession(_SplitReads(await device.open(), seed=133, most=most), timeout=5)
    await session.hello()
    assert session._chunked is not base10_only
    for _ in range(3):
        data = (await session.get_config("running")).data()
        assert "<hostname>r1</hostname>" in data.replace("ns0:", "")
        assert "value 299" in data
    await session.close()


async def test_a_timed_out_request_leaves_the_session_unusable():
    device = FakeNetconfDevice.with_config(BASE, stall=frozenset({"get-config"}))
    channel = await device.open()
    session = NetconfSession(channel, timeout=5)
    await session.hello()
    with pytest.raises(RpcTimeout, match="no reply within"):
        await session.rpc("<get-config><source><running/></source></get-config>", timeout=0.05)
    # The reply may still arrive half-read: the session does not guess its place.
    with pytest.raises(NetconfError, match="session is unusable"):
        await session.lock("running")
    sent = len(device.requests)
    await session.close()
    assert channel.closed
    assert len(device.requests) == sent  # no close-session sent on a broken session


async def test_an_rpc_error_names_the_tag_and_message():
    device = FakeNetconfDevice.with_config(BASE)
    session = NetconfSession(await device.open(), timeout=5)
    await session.hello()
    with pytest.raises(RpcFailed) as error:
        await session.rpc("<frobnicate/>")
    assert error.value.has_tag("operation-not-supported")
    assert "frobnicate is not supported" in str(error.value)
    await session.close()


def test_replies_with_a_doctype_or_entity_are_refused():
    with pytest.raises(NetconfError, match="DOCTYPE or an entity"):
        parse_xml('<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>', what="reply")


def test_fragments_must_be_elements_only():
    assert len(check_fragment("<a/><b/>", what="x")) == 2
    with pytest.raises(NetconfError, match="text outside"):
        check_fragment("<a/>stray", what="x")
    with pytest.raises(NetconfError, match="well-formed"):
        check_fragment("<a>", what="x")


def test_data_content_keeps_the_device_prefixes():
    reply = '<nc:rpc-reply xmlns:nc="b"><nc:data><x:a xmlns:x="u">1</x:a></nc:data></nc:rpc-reply>'
    assert element_content(reply, "data") == '<x:a xmlns:x="u">1</x:a>'
    assert element_content("<rpc-reply><data/></rpc-reply>", "data") == ""
    assert pretty('<a xmlns="u"><b>1</b></a>') == '<a xmlns="u">\n  <b>1</b>\n</a>\n'


# --- netconf.get ----------------------------------------------------------------


async def test_get_reads_running_and_records_evidence():
    services = FakeServices({"r1": FakeNetconfDevice.with_config(BASE)})
    result = await NetconfGetHandler().execute(_ctx({}, services))
    assert result.success, result.error
    data = result.output["devices"]["r1"]["data"]
    assert "hostname>r1<" in data
    assert result.evidence[0]["kind"] == "cli_output"
    assert result.evidence[0]["content_json"]["device_name"] == "r1"
    assert services.opened == [("r1", {"port": 830, "connect_timeout": 15.0})]
    assert set(result.output) == {field.name for field in NetconfGetHandler.output_fields}


async def test_get_state_and_a_missing_datastore():
    device = FakeNetconfDevice.with_config(
        BASE, capabilities=tuple(c for c in ALL_CAPABILITIES if "startup" not in c)
    )
    services = FakeServices({"r1": device})
    state = await NetconfGetHandler().execute(_ctx({"source": "state"}, services))
    # The fake's <state> inherits the reply's default (base) namespace, and keeps it.
    assert ">up</state>" in state.output["devices"]["r1"]["data"]
    startup = await NetconfGetHandler().execute(_ctx({"source": "startup"}, services))
    assert not startup.success
    assert "no startup datastore" in (startup.error or "")


async def test_get_refuses_a_filter_that_is_not_xml():
    errors = NetconfGetHandler().validate_config({"filter": "<interfaces"})
    assert any("not well-formed" in error for error in errors)


async def test_long_data_is_cut_in_the_output_and_kept_in_the_evidence(monkeypatch):
    monkeypatch.setattr("hegemony_steps_netconf.common.MAX_OUTPUT_TEXT_CHARS", 40)
    services = FakeServices({"r1": FakeNetconfDevice.with_config(BASE)})
    result = await NetconfGetHandler().execute(_ctx({}, services))
    assert result.output["truncated"] == ["r1.data"]
    assert result.output["devices"]["r1"]["data"].endswith("in the step's evidence]")
    assert "domain" in result.evidence[0]["content_text"]


# --- netconf.edit_config ----------------------------------------------------------


async def test_edit_confirms_after_a_second_session_and_reports_the_diff():
    device = FakeNetconfDevice.with_config(BASE)
    services = FakeServices({"r1": device})
    result = await NetconfEditConfigHandler().execute(_ctx({"config": _hostname("r2")}, services))

    assert result.success, result.error
    entry = result.output["devices"]["r1"]
    assert entry["changed"] and entry["committed"] and not entry["pending"]
    assert entry["validated"] is True
    assert "-  <ns0:hostname>r1</ns0:hostname>" in entry["diff"]
    assert "+  <ns0:hostname>r2</ns0:hostname>" in entry["diff"]
    assert _running_hostname(device) == "r2"
    assert device.pending is None
    # The change session, then the "still manageable" check, which opens after
    # the confirmed commit put r2 in running.
    assert device.sessions_opened == 2
    assert "r1" in device.running_at_open[0] and "r2" not in device.running_at_open[0]
    assert ">r2<" in device.running_at_open[1]
    assert not device.locks
    names = [item["name"] for item in result.evidence]
    assert names == ["r1:netconf diff", "r1:netconf before", "r1:netconf candidate"]
    assert result.summary == "netconf edit-config: 1 changed, 1 committed of 1 devices"


async def test_a_change_that_changes_nothing_commits_nothing():
    device = FakeNetconfDevice.with_config(BASE)
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r1")}, FakeServices({"r1": device}))
    )
    entry = result.output["devices"]["r1"]
    assert result.success and not entry["changed"] and not entry["committed"]
    assert not any("<commit" in request for request in device.requests)
    assert result.evidence == []


async def test_a_dry_run_shows_the_diff_and_discards_it():
    device = FakeNetconfDevice.with_config(BASE)
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r9"), "dry_run": True}, FakeServices({"r1": device}))
    )
    entry = result.output["devices"]["r1"]
    assert result.success and entry["changed"] and not entry["committed"]
    assert "r9" in entry["diff"]
    assert _running_hostname(device) == "r1"
    assert device.candidate[0].findtext(f"{{{NATIVE}}}hostname") == "r1"


async def test_when_the_second_session_fails_the_commit_is_rolled_back():
    device = FakeNetconfDevice.with_config(BASE, accept_sessions=1)
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2")}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert "did not accept a second NETCONF session" in (result.error or "")
    assert _running_hostname(device) == "r1"
    assert device.pending is None


async def test_without_confirmed_commit_1_1_ending_the_session_rolls_back():
    capabilities = tuple(c for c in ALL_CAPABILITIES if "confirmed-commit:1.1" not in c)
    device = FakeNetconfDevice.with_config(BASE, capabilities=capabilities, accept_sessions=1)
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2")}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert not any("cancel-commit" in request for request in device.requests)
    assert _running_hostname(device) == "r1"


async def test_a_refused_edit_discards_the_candidate_and_unlocks():
    device = FakeNetconfDevice.with_config(BASE, fail_edit="invalid-value")
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2")}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert "invalid-value: edit refused" in (result.error or "")
    assert sum("<discard-changes" in request for request in device.requests) == 2
    assert not device.locks


async def test_a_candidate_that_does_not_validate_is_not_committed():
    device = FakeNetconfDevice.with_config(BASE)
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": '<invalid xmlns="urn:x"/>'}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert "candidate does not validate" in (result.error or "")
    assert not any("<commit" in request for request in device.requests)


async def test_a_locked_datastore_fails_the_device():
    device = FakeNetconfDevice.with_config(BASE)
    device.locks["candidate"] = 99
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2")}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert "lock-denied" in (result.error or "")


async def test_commit_directly_and_save_to_startup():
    device = FakeNetconfDevice.with_config(BASE)
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r2"), "commit_mode": "direct", "save_config": True},
            FakeServices({"r1": device}),
        )
    )
    entry = result.output["devices"]["r1"]
    assert result.success and entry["committed"] and entry["saved"] == "save-config"
    assert device.saved == 1
    assert device.sessions_opened == 1


async def test_running_datastore_applies_at_once():
    capabilities = tuple(c for c in ALL_CAPABILITIES if "candidate" not in c)
    device = FakeNetconfDevice.with_config(BASE, capabilities=capabilities)
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2")}, FakeServices({"r1": device}))
    )
    entry = result.output["devices"]["r1"]
    assert result.success and entry["datastore"] == "running" and entry["committed"]
    assert _running_hostname(device) == "r2"
    assert any("rollback-on-error" in request for request in device.requests)


async def test_replace_removes_what_the_configuration_leaves_out():
    device = FakeNetconfDevice.with_config(BASE)
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r2"), "default_operation": "replace", "commit_mode": "direct"},
            FakeServices({"r1": device}),
        )
    )
    assert result.success
    assert "domain" in result.output["devices"]["r1"]["diff"]
    assert "domain" not in device.running_xml()


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({}, "'config' is required"),
        ({"config": "<native>"}, "not well-formed"),
        ({"config": _hostname("r2"), "target": "running", "dry_run": True}, "dry run needs"),
        ({"config": _hostname("r2"), "confirm_timeout_seconds": 5}, "confirm_timeout_seconds"),
    ],
)
def test_edit_settings_are_checked(config, message):
    errors = NetconfEditConfigHandler().validate_config(config)
    assert any(message in error for error in errors), errors


# --- Confirm in a later step ----------------------------------------------------


async def _pending_change(device: FakeNetconfDevice) -> tuple[Any, FakeServices]:
    services = FakeServices({"r1": device})
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "later"}, services)
    )
    assert result.success, result.error
    services.step_outputs = {"change": {"success": True, "output": result.output}}
    return result, services


async def test_a_later_step_confirms_the_pending_commit():
    device = FakeNetconfDevice.with_config(BASE)
    result, services = await _pending_change(device)
    entry = result.output["devices"]["r1"]
    assert entry["pending"] and entry["persist_id"] and not entry["committed"]
    assert device.pending is not None and device.pending.persist == entry["persist_id"]
    # Ending the change session leaves a persisted commit pending.
    assert _running_hostname(device) == "r2"

    confirmed = await NetconfCommitHandler().execute(
        _ctx({"change_step": "change", "save_config": True}, services)
    )
    assert confirmed.success, confirmed.error
    assert confirmed.output["devices"]["r1"]["confirmed"] is True
    assert confirmed.output["devices"]["r1"]["persist_id"] == entry["persist_id"]
    assert device.pending is None and device.saved == 1
    device.expire()
    assert _running_hostname(device) == "r2"


async def test_a_later_step_cancels_the_pending_commit():
    device = FakeNetconfDevice.with_config(BASE)
    _, services = await _pending_change(device)
    cancelled = await NetconfCancelCommitHandler().execute(
        _ctx({"change_step": "change"}, services)
    )
    assert cancelled.success, cancelled.error
    assert _running_hostname(device) == "r1"


async def test_the_device_rolls_back_when_nobody_confirms():
    device = FakeNetconfDevice.with_config(BASE)
    _, services = await _pending_change(device)
    device.expire()
    assert _running_hostname(device) == "r1"
    late = await NetconfCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert not late.success
    assert "rolled back when its confirm timeout ran out" in (late.error or "")


async def test_save_to_startup_waits_for_the_later_confirmation():
    device = FakeNetconfDevice.with_config(BASE)
    services = FakeServices({"r1": device})
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r2"), "commit_mode": "later", "save_config": True},
            services,
        )
    )
    assert result.success, result.error
    entry = result.output["devices"]["r1"]
    assert entry["pending"] and entry["save_requested"] and not entry["saved"]
    assert device.saved == 0
    services.step_outputs = {"change": {"output": result.output}}
    # The confirming step's own Save to startup is off: the change step's request holds.
    confirmed = await NetconfCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert confirmed.success, confirmed.error
    assert confirmed.output["devices"]["r1"]["saved"] == "save-config"
    assert device.saved == 1


async def test_confirming_refuses_edits_another_session_staged():
    # RFC 6241 7.5: the candidate lock is refused while it holds uncommitted edits.
    device = FakeNetconfDevice.with_config(BASE)
    _, services = await _pending_change(device)
    other = NetconfSession(await device.open(), timeout=5)
    await other.hello()
    await other.edit_config("candidate", _hostname("rogue"))
    result = await NetconfCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert not result.success
    assert "has changes staged in it" in (result.error or "")
    assert device.pending is not None
    assert _running_hostname(device) == "r2"
    await other.close()


async def test_confirming_compares_the_candidate_where_the_lock_is_granted_anyway():
    # A server that grants the lock over staged edits: the comparison refuses.
    device = FakeNetconfDevice.with_config(BASE, lenient_locks=True)
    _, services = await _pending_change(device)
    other = NetconfSession(await device.open(), timeout=5)
    await other.hello()
    await other.edit_config("candidate", _hostname("rogue"))
    result = await NetconfCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert not result.success
    assert "not part of the pending commit" in (result.error or "")
    assert device.pending is not None
    assert _running_hostname(device) == "r2"
    assert "candidate" not in device.locks or device.locks["candidate"] == other.session_id
    await other.close()


async def test_confirming_refuses_while_another_session_holds_the_candidate():
    device = FakeNetconfDevice.with_config(BASE)
    _, services = await _pending_change(device)
    other = NetconfSession(await device.open(), timeout=5)
    await other.hello()
    await other.lock("candidate")
    result = await NetconfCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert not result.success
    assert "another session holds it" in (result.error or "")
    assert device.pending is not None
    await other.close()


async def test_a_shared_name_never_gets_another_devices_persist_id():
    device = FakeNetconfDevice.with_config(BASE)
    services = FakeServices({"edge": device})
    services.step_outputs = {
        "change": {
            "output": {
                "devices": {
                    "edge": {"ok": True, "pending": True, "persist_id": "first"},
                    "edge #2": {"ok": True, "pending": True, "persist_id": "second"},
                }
            }
        }
    }
    ctx = HandlerContext(
        run_id="run-1",
        flow_id="flow-1",
        step_run_id="sr-2",
        step_id="confirm",
        config={"change_step": "change"},
        target_devices_by_role={"core": [{"name": "edge", "mgmt_host": "192.0.2.9"}]},
        target_roles=["core"],
        services=cast(HandlerServices, services),
    )
    result = await NetconfCommitHandler().execute(ctx)
    assert not result.success
    assert "several devices are named 'edge'" in (result.error or "")
    assert services.opened == []


async def test_confirm_later_needs_confirmed_commit_1_1():
    capabilities = tuple(c for c in ALL_CAPABILITIES if "confirmed-commit:1.1" not in c)
    device = FakeNetconfDevice.with_config(BASE, capabilities=capabilities)
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "later"}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert ":confirmed-commit:1.1" in (result.error or "")
    assert not device.locks


async def test_settling_needs_a_change_step_with_a_pending_commit():
    services = FakeServices({"r1": FakeNetconfDevice.with_config(BASE)})
    missing = await NetconfCommitHandler().execute(_ctx({"change_step": "nope"}, services))
    assert not missing.success and "has no output" in (missing.error or "")
    services.step_outputs = {
        "change": {"output": {"devices": {"r2": {"pending": True, "device_id": "id-r2"}}}}
    }
    none = await NetconfCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert not none.success and "has no result for this device" in (none.error or "")
    services.step_outputs = {
        "change": {"output": {"devices": {"r1": {"pending": False, "device_id": "id-r1"}}}}
    }
    nothing = await NetconfCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert nothing.success and nothing.output["devices"]["r1"]["skipped"] is True
    unset = await NetconfCommitHandler().execute(_ctx({}, services))
    assert not unset.success and "'change_step' is required" in (unset.error or "")


# --- netconf.rpc -----------------------------------------------------------------


async def test_rpc_sends_the_operation_and_keeps_the_reply():
    device = FakeNetconfDevice.with_config(BASE)
    result = await NetconfRpcHandler().execute(
        _ctx(
            {"rpc": '<save-config xmlns="http://cisco.com/yang/cisco-ia"/>'},
            FakeServices({"r1": device}),
        )
    )
    assert result.success, result.error
    assert "Save running-config successful" in result.output["devices"]["r1"]["reply"]
    assert device.saved == 1
    assert result.summary == "netconf save-config: 1/1 devices"


@pytest.mark.parametrize(
    ("rpc", "message"),
    [
        ("", "'rpc' is required"),
        ("<a/><b/>", "exactly one"),
        ("<close-session/>", "cannot be sent"),
        ("<a>", "not well-formed"),
    ],
)
def test_rpc_settings_are_checked(rpc, message):
    errors = NetconfRpcHandler().validate_config({"rpc": rpc})
    assert any(message in error for error in errors), errors


# --- Every step ----------------------------------------------------------------


async def test_a_platform_without_netconf_fails_clearly():
    class _Old:
        pass

    result = await NetconfGetHandler().execute(_ctx({}, _Old()))
    assert not result.success
    assert "cannot open NETCONF sessions" in (result.error or "")


async def test_no_targets_fails():
    result = await NetconfGetHandler().execute(_ctx({}, FakeServices({}), names=()))
    assert not result.success and result.summary == "Missing targets"


async def test_legacy_ssh_is_passed_only_when_on():
    services = FakeServices({"r1": FakeNetconfDevice.with_config(BASE)})
    await NetconfGetHandler().execute(_ctx({"allow_legacy_ssh": True, "port": 2830}, services))
    assert services.opened[0][1] == {
        "port": 2830,
        "connect_timeout": 15.0,
        "allow_legacy_ssh": True,
    }


@pytest.mark.parametrize("handler", ALL_HANDLERS, ids=lambda cls: cls.handler_id)
def test_the_docs_page_names_every_declared_output_field(handler):
    text = load_docs_bundle("hegemony_steps_netconf")[handler.handler_id]
    for field in handler.output_fields:
        assert f"output.{field.name}`" in text, field.name


# --- Review fixes ------------------------------------------------------------


async def test_a_diff_filter_that_hides_the_change_still_commits_it():
    device = FakeNetconfDevice.with_config(BASE + '<other xmlns="urn:example:other"/>')
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r2"), "diff_filter": '<other xmlns="urn:example:other"/>'},
            FakeServices({"r1": device}),
        )
    )
    entry = result.output["devices"]["r1"]
    assert result.success, result.error
    assert entry["diff"] == "" and entry["committed"]
    # Unknown outside the filter, so counted as changed, never as "0 changed".
    assert entry["changed"] is True
    assert "1 changed" in result.summary
    assert any("covers only part of the configuration" in note for note in entry["notes"])
    assert _running_hostname(device) == "r2"


async def test_settling_skips_devices_the_change_left_unchanged():
    changed = FakeNetconfDevice.with_config(BASE)
    unchanged = FakeNetconfDevice.with_config(BASE)
    services = FakeServices({"r1": changed, "r2": unchanged})
    # r2 already holds the configuration the step asks for.
    unchanged = FakeNetconfDevice.with_config(
        _hostname("r2").replace("</native>", "<domain>lab</domain></native>")
    )
    services.devices["r2"] = unchanged
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "later"}, services, names=("r1", "r2"))
    )
    assert result.output["devices"]["r1"]["pending"]
    assert not result.output["devices"]["r2"]["changed"]
    services.step_outputs = {"change": {"output": result.output}}

    confirmed = await NetconfCommitHandler().execute(
        _ctx({"change_step": "change"}, services, names=("r1", "r2"))
    )
    assert confirmed.success, confirmed.error
    assert confirmed.output["devices"]["r1"]["confirmed"] is True
    assert confirmed.output["devices"]["r2"]["skipped"] is True
    assert unchanged.sessions_opened == 1  # only the change step's session


async def test_settling_fails_a_device_the_change_step_failed_on():
    services = FakeServices({"r1": FakeNetconfDevice.with_config(BASE)})
    services.step_outputs = {
        "change": {"output": {"devices": {"r1": {"ok": False, "error": "x", "device_id": "id-r1"}}}}
    }
    result = await NetconfCancelCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert not result.success
    assert "failed on this device" in (result.error or "")


def test_prefixes_declared_above_the_data_are_kept():
    reply = (
        '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:m="urn:example:m" '
        'message-id="1"><data xmlns:n="urn:example:n"><m:system><n:x>1</n:x></m:system>'
        "</data></rpc-reply>"
    )
    from hegemony_steps_netconf.client import Reply, inherited_prefixes

    assert inherited_prefixes(reply, "rpc-reply", "data") == {
        "m": "urn:example:m",
        "n": "urn:example:n",
        "": "urn:ietf:params:xml:ns:netconf:base:1.0",
    }
    text = Reply(parse_xml(reply, what="reply"), reply).pretty_data()
    assert 'xmlns:m="urn:example:m"' in text and 'xmlns:n="urn:example:n"' in text
    # The fragment stands on its own: it is valid edit_config input.
    assert check_fragment(text, what="data")


def test_a_default_namespace_declared_above_the_data_is_kept():
    from hegemony_steps_netconf.client import Reply

    def data(namespace: str) -> str:
        reply = (
            f'<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">'
            f'<nc:data xmlns="{namespace}"><top><leaf>1</leaf></top></nc:data></nc:rpc-reply>'
        )
        return Reply(parse_xml(reply, what="reply"), reply).pretty_data()

    text = data("urn:example:a")
    assert text.startswith("<top ") and 'xmlns="urn:example:a"' in text.splitlines()[0]
    [top] = check_fragment(text, what="data")
    assert top.tag == "{urn:example:a}top"
    # Same text, other namespace: a different configuration, so a different diff.
    assert data("urn:example:b") != text
    # A top element with its own default declaration keeps it unchanged.
    own = (
        '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">'
        '<data><top xmlns="urn:example:c"/></data></rpc-reply>'
    )
    assert (
        Reply(parse_xml(own, what="reply"), own).pretty_data() == '<top xmlns="urn:example:c"/>\n'
    )


async def test_the_check_is_bounded_by_the_confirm_timeout(monkeypatch):
    import asyncio

    from hegemony_steps_netconf import transaction

    monkeypatch.setattr(transaction, "CONFIRM_MARGIN_SECONDS", 0.2)
    device = FakeNetconfDevice.with_config(BASE)
    session = NetconfSession(await device.open(), timeout=5)
    await session.hello()

    async def slow_check() -> None:
        await asyncio.sleep(5)

    async def read(source: str) -> str:
        return (await session.get_config(source)).pretty_data()

    async def apply() -> None:
        await session.edit_config("candidate", _hostname("r2"))

    with pytest.raises(transaction.CheckFailed, match="confirm timeout of 1 s"):
        await transaction.change_candidate(
            session,
            apply=apply,
            read=read,
            options=transaction.ChangeOptions(confirm_timeout_seconds=1),
            check=slow_check,
        )
    # Cancelled, never confirmed with a plain commit.
    commits = [r for r in device.requests if "<commit" in r]
    assert len(commits) == 1 and "<confirmed/>" in commits[0]
    assert _running_hostname(device) == "r1"
    await session.close()


async def test_a_stalled_write_times_out_and_close_still_returns():
    import asyncio

    class _Stalled:
        closed = False

        async def write(self, data: bytes) -> None:
            await asyncio.sleep(60)

        async def read(self, max_bytes: int = 65536) -> bytes:
            await asyncio.sleep(60)
            return b""

        async def close(self) -> None:
            self.closed = True

    channel = _Stalled()
    session = NetconfSession(channel, timeout=0.2)
    with pytest.raises(NetconfError, match="did not accept the request"):
        await session.rpc("<get/>")
    await asyncio.wait_for(session.close(), timeout=5)
    assert channel.closed


# --- Copilot review fixes ---------------------------------------------------


def test_a_blank_leaf_value_is_data_not_indentation():
    one = pretty('<a xmlns="u"><d> </d></a>')
    two = pretty('<a xmlns="u"><d>  </d></a>')
    assert one != two
    assert "<d> </d>" in one


async def test_a_policy_refusal_keeps_the_devices_done_before_it():
    class _RefusesR2(FakeServices):
        async def open_netconf(self, device: dict[str, Any], **kwargs: Any) -> Any:
            if device["name"] == "r2":
                raise PermissionError("egress to 192.0.2.1:830/tcp denied by the flow's policy")
            return await super().open_netconf(device, **kwargs)

    services = _RefusesR2(
        {"r1": FakeNetconfDevice.with_config(BASE), "r2": FakeNetconfDevice.with_config(BASE)}
    )
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "later"}, services, names=("r1", "r2"))
    )
    assert not result.success
    assert result.output["devices"]["r1"]["pending"] is True
    assert result.output["devices"]["r1"]["persist_id"]
    assert "denied by the flow's policy" in result.output["devices"]["r2"]["error"]


async def test_the_log_names_the_failure_kind_not_the_device_text(caplog):
    device = FakeNetconfDevice.with_config(BASE, fail_edit="invalid-value")
    with caplog.at_level("INFO", logger="hegemony_steps_netconf.common"):
        await NetconfEditConfigHandler().execute(
            _ctx({"config": _hostname("r2")}, FakeServices({"r1": device}))
        )
    records = [r for r in caplog.records if r.getMessage() == "netconf step failed on a device"]
    assert records and records[0].__dict__["error_type"] == "RpcFailed"
    assert "edit refused" not in repr(records[0].__dict__)


async def test_a_failed_save_keeps_the_committed_change():
    capabilities = tuple(c for c in ALL_CAPABILITIES if "cisco-ia" not in c)
    device = FakeNetconfDevice.with_config(BASE, capabilities=capabilities)
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r2"), "commit_mode": "direct", "save_config": True},
            FakeServices({"r1": device}),
        )
    )
    entry = result.output["devices"]["r1"]
    assert not result.success
    assert entry["committed"] and "no way to save" in entry["save_error"]
    assert "the change was made, but saving it to startup failed" in (result.error or "")
    assert [item["name"] for item in result.evidence][0] == "r1:netconf diff"
    assert _running_hostname(device) == "r2"


async def test_a_failed_save_after_confirming_keeps_confirmed():
    capabilities = tuple(c for c in ALL_CAPABILITIES if "cisco-ia" not in c)
    device = FakeNetconfDevice.with_config(BASE, capabilities=capabilities)
    _, services = await _pending_change(device)
    result = await NetconfCommitHandler().execute(
        _ctx({"change_step": "change", "save_config": True}, services)
    )
    entry = result.output["devices"]["r1"]
    assert not result.success
    assert entry["confirmed"] is True and entry["persist_id"]
    assert "confirmed, but saving it to startup failed" in (result.error or "")
    assert device.pending is None


async def test_running_with_a_diff_filter_counts_the_change_as_made():
    capabilities = tuple(c for c in ALL_CAPABILITIES if "candidate" not in c)
    device = FakeNetconfDevice.with_config(
        BASE + '<other xmlns="urn:example:other"/>', capabilities=capabilities
    )
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {
                "config": _hostname("r2"),
                "diff_filter": '<other xmlns="urn:example:other"/>',
                "save_config": True,
            },
            FakeServices({"r1": device}),
        )
    )
    entry = result.output["devices"]["r1"]
    assert result.success, result.error
    assert entry["committed"] and entry["saved"] == "save-config"
    assert entry["changed"] is True
    assert "1 changed" in result.summary
    assert device.saved == 1


async def test_xpath_filters_declare_their_namespaces():
    from hegemony_steps_netconf.client import filter_xml

    body = filter_xml(
        "xpath", "/if:interfaces", {"if": "urn:ietf:params:xml:ns:yang:ietf-interfaces"}
    )
    root = parse_xml(body, what="filter")
    assert root.get("select") == "/if:interfaces"
    assert 'xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces"' in body

    device = FakeNetconfDevice.with_config(BASE)
    result = await NetconfGetHandler().execute(
        _ctx(
            {
                "filter_type": "xpath",
                "filter": "/n:native",
                "namespaces": {"n": NATIVE},
            },
            FakeServices({"r1": device}),
        )
    )
    assert result.success, result.error
    request = next(r for r in device.requests if "get-config" in r)
    assert f'xmlns:n="{NATIVE}"' in request
    sent = parse_xml(request, what="request").find(
        ".//{urn:ietf:params:xml:ns:netconf:base:1.0}filter"
    )
    assert sent is not None
    assert (sent.get("type"), sent.get("select")) == ("xpath", "/n:native")
    errors = NetconfGetHandler().validate_config(
        {"filter_type": "xpath", "filter": "/a", "namespaces": {"1bad": "u"}}
    )
    assert any("not a usable namespace prefix" in error for error in errors)


async def test_close_closes_the_channel_even_when_cancelled():
    import asyncio

    class _Slow:
        closed = False

        async def write(self, data: bytes) -> None:
            await asyncio.sleep(60)

        async def read(self, max_bytes: int = 65536) -> bytes:
            await asyncio.sleep(60)
            return b""

        async def close(self) -> None:
            self.closed = True

    channel = _Slow()
    session = NetconfSession(channel, timeout=30)
    task = asyncio.ensure_future(session.close())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert channel.closed


async def test_an_omitted_operation_is_a_config_error():
    assert any("'rpc' is required" in e for e in NetconfRpcHandler().validate_config({}))
    result = await NetconfRpcHandler().execute(
        _ctx({}, FakeServices({"r1": FakeNetconfDevice.with_config(BASE)}))
    )
    assert not result.success and "'rpc' is required" in (result.error or "")


async def test_running_without_rollback_on_error_says_a_failed_edit_may_be_partial():
    capabilities = tuple(
        c for c in ALL_CAPABILITIES if "candidate" not in c and "rollback-on-error" not in c
    )
    device = FakeNetconfDevice.with_config(
        BASE, capabilities=capabilities, fail_edit="invalid-value"
    )
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2")}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert "edit refused" in (result.error or "")
    assert "may have applied in part" in (result.error or "")

    ok_device = FakeNetconfDevice.with_config(BASE, capabilities=capabilities)
    ok = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2")}, FakeServices({"r1": ok_device}))
    )
    assert ok.success, ok.error
    assert not any("rollback-on-error" in note for note in ok.output["devices"]["r1"]["notes"])


async def test_confirming_compares_the_datastores_in_canonical_form():
    device = FakeNetconfDevice.with_config(BASE, reformat_candidate=True)
    _, services = await _pending_change(device)
    result = await NetconfCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert result.success, result.error
    assert device.pending is None and _running_hostname(device) == "r2"


async def test_the_persist_id_is_the_same_on_every_attempt():
    first = FakeNetconfDevice.with_config(BASE)
    second = FakeNetconfDevice.with_config(BASE)
    config = {"config": _hostname("r2"), "commit_mode": "later"}
    one = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": first})))
    two = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": second})))
    persist_id = one.output["devices"]["r1"]["persist_id"]
    assert persist_id.startswith("hegemony-")
    assert two.output["devices"]["r1"]["persist_id"] == persist_id
    other_run = HandlerContext(
        run_id="run-2",
        flow_id="flow-1",
        step_run_id="sr-1",
        step_id="change",
        config=config,
        target_devices_by_role={"core": [_device("r1")]},
        target_roles=["core"],
        services=cast(HandlerServices, FakeServices({"r1": FakeNetconfDevice.with_config(BASE)})),
    )
    three = await NetconfEditConfigHandler().execute(other_run)
    assert three.output["devices"]["r1"]["persist_id"] != persist_id


async def test_a_retried_step_finds_the_commit_an_earlier_attempt_left_pending():
    device = FakeNetconfDevice.with_config(BASE)
    config = {"config": _hostname("r2"), "commit_mode": "later", "save_config": True}
    first = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": device})))
    assert first.success, first.error
    persist_id = first.output["devices"]["r1"]["persist_id"]
    assert device.pending is not None and device.pending.extended == 0

    # The worker crashed after the commit: the activity runs the step again.
    retry = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": device})))
    assert retry.success, retry.error
    entry = retry.output["devices"]["r1"]
    assert entry["pending"] is True and entry["persist_id"] == persist_id
    assert entry["save_requested"] is True
    assert any("earlier attempt" in note for note in entry["notes"])
    assert device.pending is not None and device.pending.extended == 1

    services = FakeServices({"r1": device})
    services.step_outputs = {"change": {"output": retry.output}}
    confirmed = await NetconfCommitHandler().execute(_ctx({"change_step": "change"}, services))
    assert confirmed.success, confirmed.error
    assert device.pending is None and _running_hostname(device) == "r2" and device.saved == 1


async def test_an_unchanged_retry_with_nothing_pending_reports_nothing_pending():
    device = FakeNetconfDevice.with_config(_hostname("r2"))
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "later"}, FakeServices({"r1": device}))
    )
    assert result.success, result.error
    entry = result.output["devices"]["r1"]
    assert entry["pending"] is False and entry["persist_id"] == ""
    assert any("nothing committed" in note for note in entry["notes"])
    assert device.pending is None


async def test_a_final_commit_without_a_reply_says_it_may_have_happened():
    device = FakeNetconfDevice.with_config(BASE, stall=frozenset({"commit"}))
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r2"), "commit_mode": "direct", "rpc_timeout_seconds": 1},
            FakeServices({"r1": device}),
        )
    )
    assert not result.success
    assert "may already have committed" in (result.error or "")


async def test_a_confirmation_without_a_reply_says_it_may_have_happened():
    device = FakeNetconfDevice.with_config(BASE)
    _, services = await _pending_change(device)
    device.stall = frozenset({"commit"})
    result = await NetconfCommitHandler().execute(
        _ctx({"change_step": "change", "rpc_timeout_seconds": 1}, services)
    )
    assert not result.success
    assert "may already have confirmed" in (result.error or "")


async def test_saving_after_confirming_holds_the_candidate_lock():
    device = FakeNetconfDevice.with_config(BASE)
    _, services = await _pending_change(device)
    confirmed = await NetconfCommitHandler().execute(
        _ctx({"change_step": "change", "save_config": True}, services)
    )
    assert confirmed.success, confirmed.error
    assert device.saved_while_locked == [True]
    assert not device.locks


def _settle_ctx(services: FakeServices, device: dict[str, Any]) -> HandlerContext:
    return HandlerContext(
        run_id="run-1",
        flow_id="flow-1",
        step_run_id="sr-2",
        step_id="confirm",
        config={"change_step": "change"},
        target_devices_by_role={"core": [device]},
        target_roles=["core"],
        services=cast(HandlerServices, services),
    )


async def test_a_device_is_matched_by_its_id_not_by_a_display_key():
    # Device a is named "edge"; another device, b, is named "edge (a)".
    device = FakeNetconfDevice.with_config(BASE)
    device.pending = Pending(backup=device.snapshot(), persist="p-a", session=99)
    services = FakeServices({"edge": device})
    services.step_outputs = {
        "change": {
            "output": {
                "devices": {
                    "edge": {"ok": True, "pending": True, "persist_id": "p-a", "device_id": "a"},
                    "edge (a)": {"ok": True, "pending": False, "device_id": "b"},
                }
            }
        }
    }
    result = await NetconfCommitHandler().execute(
        _settle_ctx(services, {"id": "a", "name": "edge", "mgmt_host": "192.0.2.9"})
    )
    assert result.success, result.error
    assert result.output["devices"]["edge"]["persist_id"] == "p-a"
    assert device.pending is None


async def test_a_result_recorded_for_another_device_is_never_settled():
    services = FakeServices({"edge": FakeNetconfDevice.with_config(BASE)})
    services.step_outputs = {
        "change": {
            "output": {
                "devices": {
                    "edge": {"ok": True, "pending": True, "persist_id": "p", "device_id": "old"}
                }
            }
        }
    }
    result = await NetconfCommitHandler().execute(
        _settle_ctx(services, {"id": "new", "name": "edge", "mgmt_host": "192.0.2.9"})
    )
    assert not result.success
    assert "recorded for another device" in (result.error or "")
    assert services.opened == []


async def test_a_lost_commit_reply_keeps_the_persist_id_for_a_cancel():
    device = FakeNetconfDevice.with_config(BASE, stall=frozenset({"commit"}))
    services = FakeServices({"r1": device})
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r2"), "commit_mode": "later", "rpc_timeout_seconds": 1},
            services,
        )
    )
    assert not result.success
    entry = result.output["devices"]["r1"]
    assert entry["commit_uncertain"] is True and entry["persist_id"]
    assert "may be pending" in (result.error or "")
    # The device did take the commit: a cancel step finds and rolls it back.
    assert device.pending is not None and device.pending.persist == entry["persist_id"]
    device.stall = frozenset()
    services.step_outputs = {"change": {"output": result.output}}
    cancelled = await NetconfCancelCommitHandler().execute(
        _ctx({"change_step": "change"}, services)
    )
    assert cancelled.success, cancelled.error
    assert device.pending is None and _running_hostname(device) == "r1"


async def test_a_persisted_commit_is_followed_up_only_with_its_persist_id():
    device = FakeNetconfDevice.with_config(BASE)
    await _pending_change(device)
    other = NetconfSession(await device.open(), timeout=5)
    await other.hello()
    await other.edit_config("candidate", _hostname("r3"))
    with pytest.raises(RpcFailed, match="give persist-id"):
        await other.commit()
    assert device.pending is not None and _running_hostname(device) == "r2"
    await other.close()


async def test_a_locked_datastore_refuses_another_sessions_edit_and_commit():
    device = FakeNetconfDevice.with_config(BASE)
    owner = NetconfSession(await device.open(), timeout=5)
    other = NetconfSession(await device.open(), timeout=5)
    await owner.hello()
    await other.hello()
    await owner.lock("candidate")
    with pytest.raises(RpcFailed, match="in-use"):
        await other.edit_config("candidate", _hostname("rogue"))
    with pytest.raises(RpcFailed, match="in-use"):
        await other.commit()
    await owner.edit_config("candidate", _hostname("r2"))
    await owner.commit()
    assert _running_hostname(device) == "r2"
    await owner.unlock("candidate")
    await other.close()
    await owner.close()
