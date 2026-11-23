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


def _ctx(
    config: dict[str, Any], services: Any, names: tuple[str, ...] = ("r1",), attempt: int = 1
) -> HandlerContext:
    return HandlerContext(
        attempt=attempt,
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
    elements = check_fragment(state.output["devices"]["r1"]["data"], what="data")
    [up] = [element for element in elements if element.tag.endswith("}state")]
    assert up.tag == "{urn:ietf:params:xml:ns:netconf:base:1.0}state" and up.text == "up"
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
    session._negotiated = True  # as after a hello: close() sends close-session
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
    retry = await NetconfEditConfigHandler().execute(
        _ctx(config, FakeServices({"r1": device}), attempt=2)
    )
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
    # The confirmed commit itself (persist, no persist-id) gets no reply.
    device = FakeNetconfDevice.with_config(
        BASE, stall=frozenset({"commit"}), only_if="</persist></commit>"
    )
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


def test_escaped_namespace_values_are_not_escaped_twice():
    from hegemony_steps_netconf.client import Reply

    reply = (
        '<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" '
        'xmlns:p="urn:p?a=1&amp;b=2" message-id="1">'
        '<nc:data xmlns="urn:d?x=&quot;y&quot;"><top><p:leaf>1</p:leaf></top></nc:data>'
        "</nc:rpc-reply>"
    )
    [top] = check_fragment(Reply(parse_xml(reply, what="reply"), reply).pretty_data(), what="d")
    assert top.tag == '{urn:d?x="y"}top'
    assert top[0].tag == "{urn:p?a=1&b=2}leaf"


def _canonical(fragment: str) -> str | None:
    from hegemony_steps_netconf.client import canonical_xml

    return canonical_xml(fragment)


def test_the_canonical_form_keeps_what_a_value_means():
    # Layout and prefix spelling do not count.
    assert _canonical('<a xmlns="urn:x"><b>1</b></a>') == _canonical(
        '<n:a xmlns:n="urn:x">\n  <n:b>1</n:b>\n</n:a>'
    )
    # A leaf's spaces are its value.
    assert _canonical('<a xmlns="urn:x"><b> hello </b></a>') != _canonical(
        '<a xmlns="urn:x"><b>hello</b></a>'
    )
    # A prefix:name value keeps its text and the namespace its prefix names:
    # a rebinding counts, and without the schema another spelling counts too
    # (a string such as a description is not equated by namespace).
    one = '<a xmlns="urn:x" xmlns:i="urn:one"><k>i:foo</k></a>'
    two = '<a xmlns="urn:x" xmlns:i="urn:two"><k>i:foo</k></a>'
    spelled = '<a xmlns="urn:x" xmlns:j="urn:one"><k>j:foo</k></a>'
    assert _canonical(one) != _canonical(two)
    assert _canonical(one) != _canonical(spelled)
    i_foo = '<d xmlns="urn:x" xmlns:i="urn:x" xmlns:j="urn:x">i:foo</d>'
    j_foo = '<d xmlns="urn:x" xmlns:i="urn:x" xmlns:j="urn:x">j:foo</d>'
    assert _canonical(i_foo) != _canonical(j_foo)
    assert _canonical("<a>") is None


async def test_a_dropped_session_after_the_commit_keeps_the_persist_id():
    device = FakeNetconfDevice.with_config(
        BASE, drop_after=frozenset({"commit"}), only_if="</persist></commit>"
    )
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "later"}, FakeServices({"r1": device}))
    )
    assert not result.success
    entry = result.output["devices"]["r1"]
    assert entry["commit_uncertain"] is True and entry["persist_id"]
    assert device.pending is not None and device.pending.persist == entry["persist_id"]


async def test_a_closed_session_error_says_why_when_the_host_knows():
    from hegemony_steps_netconf.client import NetconfError, NetconfSession

    class Closed:
        disconnect_reason = "Too many sessions"

        async def write(self, data: bytes) -> None:
            pass

        async def read(self, max_bytes: int = 65536) -> bytes:
            return b""

        async def close(self) -> None:
            pass

    session = NetconfSession(cast(Any, Closed()))
    with pytest.raises(NetconfError, match="closed the NETCONF session: Too many sessions"):
        await session._fill()


async def test_a_retry_recovers_a_pending_commit_although_running_cannot_be_locked():
    # A device refuses to lock running while a confirmed commit is pending
    # (RFC 6241 7.5): the retry checks under the candidate lock alone.
    device = FakeNetconfDevice.with_config(BASE)
    config = {"config": _hostname("r2"), "commit_mode": "later"}
    first = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": device})))
    persist_id = first.output["devices"]["r1"]["persist_id"]
    retry = await NetconfEditConfigHandler().execute(
        _ctx(config, FakeServices({"r1": device}), attempt=2)
    )
    assert retry.success, retry.error
    entry = retry.output["devices"]["r1"]
    assert entry["pending"] is True and entry["persist_id"] == persist_id
    assert not any("<running/></target></lock>" in r for r in device.requests[-12:])


async def test_an_uncertain_commit_keeps_the_save_request():
    device = FakeNetconfDevice.with_config(
        BASE, drop_after=frozenset({"commit"}), only_if="</persist></commit>"
    )
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r2"), "commit_mode": "later", "save_config": True},
            FakeServices({"r1": device}),
        )
    )
    entry = result.output["devices"]["r1"]
    assert entry["commit_uncertain"] is True and entry["save_requested"] is True
    assert device.saved == 0


def test_tags_inside_comments_and_quoted_values_are_not_tags():
    from hegemony_steps_netconf.client import element_content, inherited_prefixes

    reply = (
        '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">'
        '<!-- <data xmlns:p="urn:wrong"/> --><data xmlns:p="urn:right">'
        '<p:top><data label="a>b"/><p:x/></p:top></data></rpc-reply>'
    )
    assert inherited_prefixes(reply, "rpc-reply", "data")["p"] == "urn:right"
    assert element_content(reply, "data") == '<p:top><data label="a>b"/><p:x/></p:top>'


def test_only_the_data_child_of_the_reply_is_read():
    # A warning's error-info may hold an element named data before the real one.
    from hegemony_steps_netconf.client import element_content, inherited_prefixes

    reply = (
        '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">'
        "<rpc-error><error-type>application</error-type><error-tag>operation-failed"
        "</error-tag><error-severity>warning</error-severity><error-info>"
        '<x:data xmlns:x="urn:x" xmlns:p="urn:wrong"/></error-info></rpc-error>'
        '<data xmlns:p="urn:right"><p:top/></data></rpc-reply>'
    )
    assert element_content(reply, "data") == "<p:top/>"
    assert inherited_prefixes(reply, "rpc-reply", "data")["p"] == "urn:right"


async def test_a_first_attempt_sends_no_pending_check():
    # A first attempt cannot have left a commit pending, so it does not ask:
    # its outcome never depends on how a server answers an unknown persist id.
    device = FakeNetconfDevice.with_config(BASE)
    config = {"config": _hostname("r2"), "commit_mode": "later"}
    result = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": device})))
    assert result.success, result.error
    assert not any("<persist-id>" in request for request in device.requests)
    assert _running_hostname(device) == "r2"


async def test_a_retry_adds_its_change_to_the_commit_left_pending():
    # The pending commit does not hold this change: it is added under the
    # same persist id, so the commit still rolls back as a whole.
    device = FakeNetconfDevice.with_config(BASE)
    first = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "later"}, FakeServices({"r1": device}))
    )
    persist_id = first.output["devices"]["r1"]["persist_id"]
    retry = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r3"), "commit_mode": "later"},
            FakeServices({"r1": device}),
            attempt=2,
        )
    )
    assert retry.success, retry.error
    entry = retry.output["devices"]["r1"]
    assert entry["pending"] is True and entry["changed"] is True
    assert entry["persist_id"] == persist_id
    assert any("added to it" in note for note in entry["notes"])
    assert _running_hostname(device) == "r3"
    assert device.pending is not None and device.pending.extended == 2
    device.restore(device.pending.backup)  # what a cancel or the timeout does
    assert _running_hostname(device) == "r1"


async def test_a_refused_follow_up_keeps_the_persist_id_of_the_pending_commit():
    device = FakeNetconfDevice.with_config(BASE)
    first = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "later"}, FakeServices({"r1": device}))
    )
    persist_id = first.output["devices"]["r1"]["persist_id"]
    # The check finds the commit; the follow-up adding this change is refused.
    device.fail_commit = "operation-failed"
    device.fail_commit_after = 1
    retry = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r3"), "commit_mode": "later"},
            FakeServices({"r1": device}),
            attempt=2,
        )
    )
    assert not retry.success
    entry = retry.output["devices"]["r1"]
    assert entry["commit_uncertain"] is True and entry["persist_id"] == persist_id
    assert device.pending is not None and _running_hostname(device) == "r2"


async def test_a_retry_whose_check_gets_no_answer_keeps_the_persist_id():
    device = FakeNetconfDevice.with_config(BASE)
    config = {"config": _hostname("r2"), "commit_mode": "later", "rpc_timeout_seconds": 1}
    first = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": device})))
    assert first.success, first.error
    persist_id = first.output["devices"]["r1"]["persist_id"]
    device.stall = frozenset({"commit"})
    retry = await NetconfEditConfigHandler().execute(
        _ctx(config, FakeServices({"r1": device}), attempt=2)
    )
    assert not retry.success
    entry = retry.output["devices"]["r1"]
    assert entry["commit_uncertain"] is True and entry["persist_id"] == persist_id
    assert "earlier attempt" in (retry.error or "")


async def test_a_persist_id_confirmation_waits_for_another_sessions_lock():
    # Only the candidate: no session can lock running while the confirmed
    # commit is pending (RFC 6241 7.5), and the fake refuses it.
    locked = "candidate"
    device = FakeNetconfDevice.with_config(BASE)
    first, _ = await _pending_change(device)
    persist_id = first.output["devices"]["r1"]["persist_id"]
    holder = NetconfSession(await device.open(), timeout=5)
    other = NetconfSession(await device.open(), timeout=5)
    await holder.hello()
    await other.hello()
    await holder.lock(locked)
    with pytest.raises(RpcFailed, match="in-use"):
        await other.commit(persist_id=persist_id)
    assert device.pending is not None and _running_hostname(device) == "r2"
    await holder.unlock(locked)
    await other.commit(persist_id=persist_id)
    assert device.pending is None and _running_hostname(device) == "r2"
    device.expire()
    assert _running_hostname(device) == "r2"
    await other.close()
    await holder.close()


async def test_a_retry_refused_for_another_reason_keeps_the_persist_id():
    device = FakeNetconfDevice.with_config(BASE)
    config = {"config": _hostname("r2"), "commit_mode": "later"}
    first = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": device})))
    persist_id = first.output["devices"]["r1"]["persist_id"]
    device.fail_commit = "operation-failed"
    retry = await NetconfEditConfigHandler().execute(
        _ctx(config, FakeServices({"r1": device}), attempt=2)
    )
    assert not retry.success
    entry = retry.output["devices"]["r1"]
    assert entry["commit_uncertain"] is True and entry["persist_id"] == persist_id


async def test_a_retry_refused_over_another_parameter_keeps_the_persist_id():
    # invalid-value about the confirm timeout says nothing about the persist id.
    device = FakeNetconfDevice.with_config(BASE)
    config = {"config": _hostname("r2"), "commit_mode": "later"}
    first = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": device})))
    persist_id = first.output["devices"]["r1"]["persist_id"]
    device.fail_commit = "invalid-value"
    device.fail_commit_path = "/rpc/commit/confirm-timeout"
    retry = await NetconfEditConfigHandler().execute(
        _ctx(config, FakeServices({"r1": device}), attempt=2)
    )
    assert not retry.success
    entry = retry.output["devices"]["r1"]
    assert entry["commit_uncertain"] is True and entry["persist_id"] == persist_id


class _ChannelFailsAfterCommit:
    """A channel whose read raises (not end of stream) once a commit was sent."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._committed = False

    async def write(self, data: bytes) -> None:
        # The confirmed commit (persist, no persist-id), not the pending check.
        self._committed = self._committed or (
            b"<commit>" in data and b"<persist>" in data and b"<persist-id>" not in data
        )
        await self._inner.write(data)

    async def read(self, max_bytes: int = 65536) -> bytes:
        if self._committed:
            raise OSError("connection reset by peer")
        return await self._inner.read(max_bytes)

    async def close(self) -> None:
        await self._inner.close()


async def test_a_channel_error_after_the_commit_keeps_the_persist_id():
    fake = FakeNetconfDevice.with_config(BASE)

    class Services(FakeServices):
        async def open_netconf(self, device: dict[str, Any], **kwargs: Any) -> Any:
            return _ChannelFailsAfterCommit(await super().open_netconf(device, **kwargs))

    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "later"}, Services({"r1": fake}))
    )
    assert not result.success
    entry = result.output["devices"]["r1"]
    assert entry["commit_uncertain"] is True and entry["persist_id"]
    assert fake.pending is not None and fake.pending.persist == entry["persist_id"]


def test_the_data_ends_at_its_own_end_tag():
    reply = (
        '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">'
        "<data><top/><!-- </data> --><x><data>in</data></x></data><!-- </data> -->"
        "</rpc-reply>"
    )
    assert element_content(reply, "data") == "<top/><!-- </data> --><x><data>in</data></x>"


def test_the_canonical_form_fails_closed_on_namespaces_a_value_may_use():
    # An unprefixed identityref takes the default namespace.
    assert _canonical('<m:mode xmlns:m="urn:m" xmlns="urn:a">active</m:mode>') != _canonical(
        '<m:mode xmlns:m="urn:m" xmlns="urn:b">active</m:mode>'
    )
    # An instance identifier's steps use their prefixes' bindings.
    one = '<p xmlns="urn:x" xmlns:i="urn:one">/i:root/i:item</p>'
    two = '<p xmlns="urn:x" xmlns:i="urn:two">/i:root/i:item</p>'
    assert _canonical(one) != _canonical(two)
    # Mixed content keeps its text.
    assert _canonical('<p xmlns="urn:x">allow<rule/></p>') != _canonical(
        '<p xmlns="urn:x">deny<rule/></p>'
    )
    # Indentation in element-only content still does not count.
    assert _canonical('<p xmlns="urn:x"><r>1</r></p>') == _canonical(
        '<p xmlns="urn:x">\n  <r>1</r>\n</p>'
    )
    # Whitespace without a line break may be data: it counts.
    assert _canonical('<p xmlns="urn:x"><rule/> </p>') != _canonical('<p xmlns="urn:x"><rule/></p>')
    # In mixed content whitespace is data too.
    assert _canonical('<p xmlns="urn:x">allow<rule/> </p>') != _canonical(
        '<p xmlns="urn:x">allow<rule/></p>'
    )


def test_a_non_ascii_prefix_declared_above_the_data_is_kept():
    from hegemony_steps_netconf.client import inherited_prefixes

    reply = (
        '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:\u00e9="urn:e" '
        'message-id="1"><data><\u00e9:top/></data></rpc-reply>'
    )
    assert inherited_prefixes(reply, "rpc-reply", "data")["\u00e9"] == "urn:e"


def test_non_ascii_prefixes_on_the_enclosing_tags_are_read():
    from hegemony_steps_netconf.client import canonical_xml, inherited_prefixes

    def reply(uri: str) -> str:
        return (
            '<\u00e9:rpc-reply xmlns:\u00e9="urn:ietf:params:xml:ns:netconf:base:1.0" '
            f'xmlns:\u03b1="{uri}" message-id="1"><\u00e9:data><\u03b1:top/></\u00e9:data>'
            "</\u00e9:rpc-reply>"
        )

    found = inherited_prefixes(reply("urn:a"), "rpc-reply", "data")
    assert found["\u03b1"] == "urn:a"
    one = canonical_xml("<\u03b1:top/>", inherited_prefixes(reply("urn:a"), "rpc-reply", "data"))
    two = canonical_xml("<\u03b1:top/>", inherited_prefixes(reply("urn:b"), "rpc-reply", "data"))
    assert one is not None and two is not None and one != two


def test_a_gt_inside_an_attribute_value_does_not_end_the_tag():
    from hegemony_steps_netconf.client import element_content, inherited_prefixes

    reply = (
        '<nc:rpc-reply xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" '
        'xmlns:a="urn:metadata" a:note="a>b/>c" xmlns:p="urn:model:a" message-id="1">'
        "<nc:data a:x='1>2'><p:top/></nc:data></nc:rpc-reply>"
    )
    assert inherited_prefixes(reply, "rpc-reply", "data")["p"] == "urn:model:a"
    assert element_content(reply, "data") == "<p:top/>"


def test_only_namespace_declarations_bind_inherited_prefixes():
    from hegemony_steps_netconf.client import inherited_prefixes

    # notxmlns:p is an attribute in another namespace, and text inside a
    # value is not an attribute: neither rebinds p.
    reply = (
        '<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">'
        '<nc:data xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:p="urn:model:a" '
        'xmlns:notxmlns="urn:metadata" notxmlns:p="urn:override" '
        "notxmlns:q='a xmlns:p=\"urn:in-a-value\"'><p:top/></nc:data></rpc-reply>"
    )
    found = inherited_prefixes(reply, "rpc-reply", "data")
    assert found["p"] == "urn:model:a"
    assert found[""] == "urn:ietf:params:xml:ns:netconf:base:1.0"


async def test_a_filtered_retry_finds_the_commit_an_earlier_attempt_left_pending():
    device = FakeNetconfDevice.with_config(BASE + '<other xmlns="urn:example:other"/>')
    config = {
        "config": _hostname("r2"),
        "commit_mode": "later",
        "diff_filter": '<other xmlns="urn:example:other"/>',
    }
    first = await NetconfEditConfigHandler().execute(_ctx(config, FakeServices({"r1": device})))
    assert first.success, first.error
    persist_id = first.output["devices"]["r1"]["persist_id"]
    retry = await NetconfEditConfigHandler().execute(
        _ctx(config, FakeServices({"r1": device}), attempt=2)
    )
    assert retry.success, retry.error
    entry = retry.output["devices"]["r1"]
    assert entry["pending"] is True and entry["persist_id"] == persist_id
    # A filtered diff cannot show the pending commit holds the change: it is
    # added again under the same persist id (the check, then the follow-up).
    assert device.pending is not None and device.pending.extended == 2
    assert _running_hostname(device) == "r2"


@pytest.mark.parametrize("target", ["candidate", "running"])
async def test_a_retry_saves_what_an_earlier_attempt_applied_but_could_not_save(target):
    capabilities = (
        ALL_CAPABILITIES
        if target == "candidate"
        else tuple(c for c in ALL_CAPABILITIES if "candidate" not in c)
    )
    device = FakeNetconfDevice.with_config(_hostname("r2"), capabilities=capabilities)
    result = await NetconfEditConfigHandler().execute(
        _ctx(
            {"config": _hostname("r2"), "commit_mode": "direct", "save_config": True},
            FakeServices({"r1": device}),
            attempt=2,
        )
    )
    assert result.success, result.error
    assert result.output["devices"]["r1"]["changed"] is False
    assert result.output["devices"]["r1"]["saved"] and device.saved == 1


async def test_a_refused_confirmation_says_to_save_when_a_save_was_asked():
    device = FakeNetconfDevice.with_config(BASE)
    _, services = await _pending_change(device)
    device.pending = None  # confirmed (or rolled back) by an earlier attempt
    result = await NetconfCommitHandler().execute(
        _ctx({"change_step": "change", "save_config": True}, services)
    )
    assert not result.success
    assert "running is not saved yet" in (result.error or "")


async def test_close_before_the_hello_sends_no_close_session():
    device = FakeNetconfDevice.with_config(BASE)
    channel = await device.open()
    written: list[bytes] = []

    class Recording:
        async def write(self, data: bytes) -> None:
            written.append(data)
            await channel.write(data)

        async def read(self, max_bytes: int = 65536) -> bytes:
            return await channel.read(max_bytes)

        async def close(self) -> None:
            await channel.close()

    session = NetconfSession(Recording(), timeout=5)
    await session.close()
    assert channel.closed
    assert written == []  # not even a close-session: the hello never happened


async def test_a_final_commit_whose_session_drops_says_it_may_have_happened():
    device = FakeNetconfDevice.with_config(BASE, drop_after=frozenset({"commit"}))
    result = await NetconfEditConfigHandler().execute(
        _ctx({"config": _hostname("r2"), "commit_mode": "direct"}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert "may already have committed" in (result.error or "")
