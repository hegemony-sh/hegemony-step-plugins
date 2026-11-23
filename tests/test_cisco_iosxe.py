# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``cisco.iosxe.config_replace`` (ACR) and ``cisco.iosxe.get_config`` against the fake device."""

from __future__ import annotations

from typing import Any, cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_step_sdk.docs import load_docs_bundle
from hegemony_steps_cisco_iosxe import ALL_HANDLERS
from hegemony_steps_cisco_iosxe.acr import MAX_CLIS_CHARS
from hegemony_steps_cisco_iosxe.handlers import ConfigReplaceHandler, GetConfigHandler
from hegemony_steps_netconf.commit import NetconfCommitHandler
from tests.cisco_iosxe_fakes import ALL_CAPABILITIES, CLI_RPC_NS, FakeIosXeDevice, FakeServices
from tests.netconf_fakes import FakeNetconfDevice

RUNNING = "hostname r1\n!\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"
TARGET = "hostname r1-new\n!\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255\n"


def _ctx(config: dict[str, Any], services: Any, names: tuple[str, ...] = ("r1",)) -> HandlerContext:
    return HandlerContext(
        run_id="run-1",
        flow_id="flow-1",
        step_run_id="sr-1",
        step_id="acr",
        config=config,
        target_devices_by_role={
            "edge": [{"id": f"id-{n}", "name": n, "mgmt_host": "192.0.2.1"} for n in names]
        },
        target_roles=["edge"],
        services=cast(HandlerServices, services),
    )


def _device(**kwargs: Any) -> FakeIosXeDevice:
    return FakeIosXeDevice(running_cli=RUNNING, **kwargs)


async def test_full_replace_shows_the_diff_and_confirms_after_the_check():
    device = _device()
    result = await ConfigReplaceHandler().execute(
        _ctx({"config": TARGET}, FakeServices({"r1": device}))
    )

    assert result.success, result.error
    entry = result.output["devices"]["r1"]
    assert entry["operation"] == "full-replace"
    assert entry["changed"] and entry["committed"] and entry["validated"]
    assert "-hostname r1\n" in entry["diff"] and "+hostname r1-new\n" in entry["diff"]
    assert device.running_cli == TARGET
    assert device.pending is None
    sent = next(r for r in device.requests if "config-ios-cli-trans" in r)
    assert "<operation>full-replace</operation><do-commit>false</do-commit>" in sent
    assert [item["name"] for item in result.evidence] == [
        "r1:running-config diff",
        "r1:running-config before",
        "r1:running-config candidate",
        "r1:acr result",
    ]
    assert result.summary == "ACR full-replace: 1 changed, 1 committed of 1 devices"


async def test_a_dry_run_leaves_running_and_candidate_as_they_were():
    device = _device()
    result = await ConfigReplaceHandler().execute(
        _ctx({"config": TARGET, "dry_run": True}, FakeServices({"r1": device}))
    )
    entry = result.output["devices"]["r1"]
    assert result.success and entry["changed"] and not entry["committed"]
    assert device.running_cli == RUNNING and device.candidate_cli == RUNNING


async def test_acr_rejecting_a_line_fails_and_discards():
    device = _device()
    result = await ConfigReplaceHandler().execute(
        _ctx({"config": "hostname r1\nbogus command\n"}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert "ACR refused the configuration: % Invalid input at line 2: bogus" in (result.error or "")
    assert device.running_cli == RUNNING and device.candidate_cli == RUNNING
    assert not device.locks


async def test_cli_text_is_escaped_in_the_rpc():
    device = _device()
    text = "banner motd ^C Authorized <staff> & partners ^C\n"
    result = await ConfigReplaceHandler().execute(
        _ctx({"config": text, "commit_mode": "direct"}, FakeServices({"r1": device}))
    )
    assert result.success, result.error
    assert device.running_cli == text
    assert "&lt;staff&gt; &amp; partners" in next(
        r for r in device.requests if "config-ios-cli-trans" in r
    )


async def test_missing_prerequisites_are_named():
    capabilities = tuple(c for c in ALL_CAPABILITIES if CLI_RPC_NS not in c)
    device = _device(capabilities=capabilities)
    result = await ConfigReplaceHandler().execute(
        _ctx({"config": TARGET}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert "Cisco-IOS-XE-cli-rpc" in (result.error or "")
    assert "yang-interfaces feature atomic-config" in (result.error or "")


async def test_each_device_gets_its_own_attached_file():
    devices: dict[str, FakeNetconfDevice] = {"r1": _device(), "r2": _device()}
    services = FakeServices(devices)
    services.attachments = [
        {"filename": "configs/r1.cfg", "content": "hostname r1-a\n"},
        {"filename": "configs/r2.cfg", "content": "hostname r2-a\n"},
    ]
    result = await ConfigReplaceHandler().execute(
        _ctx({"config_attachment": "configs/{device}.cfg"}, services, names=("r1", "r2"))
    )
    assert result.success, result.error
    assert devices["r1"].running_cli == "hostname r1-a\n"
    assert devices["r2"].running_cli == "hostname r2-a\n"


async def test_a_missing_attachment_fails_that_device():
    services = FakeServices({"r1": _device()})
    result = await ConfigReplaceHandler().execute(
        _ctx({"config_attachment": "configs/{device}.cfg"}, services)
    )
    assert not result.success
    assert "no attachment 'configs/r1.cfg'" in (result.error or "")


async def test_a_pending_replace_is_confirmed_by_netconf_commit():
    device = _device()
    services = FakeServices({"r1": device})
    result = await ConfigReplaceHandler().execute(
        _ctx({"config": TARGET, "commit_mode": "later", "confirm_timeout_seconds": 300}, services)
    )
    assert result.success and result.output["devices"]["r1"]["pending"]
    # A first attempt makes the confirmed commit without a pending check.
    assert not any("<persist-id>" in request for request in device.requests)
    services.step_outputs = {"acr": {"output": result.output}}
    confirmed = await NetconfCommitHandler().execute(_ctx({"change_step": "acr"}, services))
    assert confirmed.success, confirmed.error
    device.expire()
    assert device.running_cli == TARGET


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({}, "exactly one of 'config' and 'config_attachment'"),
        ({"config": "x", "config_attachment": "a.cfg"}, "exactly one"),
        ({"config_attachment": "../etc/passwd"}, "relative path"),
        ({"config": "x", "operation": "overwrite"}, "operation"),
    ],
)
def test_replace_settings_are_checked(config, message):
    errors = ConfigReplaceHandler().validate_config(config)
    assert any(message in error for error in errors), errors


async def test_get_config_reads_cli_text_for_git_backups():
    services = FakeServices({"r1": _device()})
    result = await GetConfigHandler().execute(_ctx({}, services))
    assert result.success, result.error
    assert result.output["devices"]["r1"]["config"] == RUNNING
    (evidence,) = result.evidence
    assert evidence["kind"] == "cli_output"
    assert evidence["name"] == "r1:running-config"
    assert evidence["content_text"] == RUNNING
    assert evidence["content_json"]["command"] == "running-config"
    assert evidence["content_json"]["device_name"] == "r1"


@pytest.mark.parametrize("handler", ALL_HANDLERS, ids=lambda cls: cls.handler_id)
def test_the_docs_page_names_every_declared_output_field(handler):
    text = load_docs_bundle("hegemony_steps_cisco_iosxe")[handler.handler_id]
    for field in handler.output_fields:
        assert f"output.{field.name}`" in text, field.name


async def test_an_empty_attachment_is_never_sent_as_a_full_replace():
    device = _device()
    services = FakeServices({"r1": device})
    services.attachments = [{"filename": "configs/r1.cfg", "content": "  \n"}]
    result = await ConfigReplaceHandler().execute(
        _ctx({"config_attachment": "configs/{device}.cfg"}, services)
    )
    assert not result.success
    assert "is empty" in (result.error or "")
    assert device.sessions_opened == 0
    assert device.running_cli == RUNNING


async def test_two_devices_never_share_one_per_device_file():
    device = _device()
    services = FakeServices({"r/1": device, "r_1": device})
    services.attachments = [{"filename": "configs/r_1.cfg", "content": TARGET}]
    result = await ConfigReplaceHandler().execute(
        _ctx({"config_attachment": "configs/{device}.cfg"}, services, names=("r/1", "r_1"))
    )
    assert not result.success
    assert "both resolve to the attachment 'configs/r_1.cfg'" in (result.error or "")
    assert device.sessions_opened == 0
    assert device.running_cli == RUNNING


async def test_acr_success_is_never_read_from_the_result_text():
    refused = _device(trans_result="Configuration unsuccessful")
    result = await ConfigReplaceHandler().execute(
        _ctx({"config": TARGET + "bogus\n"}, FakeServices({"r1": refused}))
    )
    assert not result.success
    assert "% Invalid input" in (result.error or "")

    device = _device(trans_result="Configuration applied, 3 lines")
    applied = await ConfigReplaceHandler().execute(
        _ctx({"config": TARGET}, FakeServices({"r1": device}))
    )
    assert applied.success, applied.error
    assert applied.output["devices"]["r1"]["acr_result"] == "Configuration applied, 3 lines"
    acr = [item for item in applied.evidence if item["name"] == "r1:acr result"]
    assert acr and acr[0]["content_text"] == "Configuration applied, 3 lines"


async def test_an_empty_modelled_diff_still_commits_the_replace():
    # Modelled CLI leaves out wireless, app-hosting and telemetry: equal modelled
    # text does not show that the replace changes nothing.
    device = _device()
    result = await ConfigReplaceHandler().execute(
        _ctx({"config": RUNNING, "commit_mode": "direct"}, FakeServices({"r1": device}))
    )
    assert result.success, result.error
    entry = result.output["devices"]["r1"]
    assert entry["diff"] == "" and entry["committed"] and entry["changed"]
    assert any("covers only part of the configuration" in note for note in entry["notes"])
    assert any("<commit>" in request or "<commit/>" in request for request in device.requests)


def test_the_configuration_is_limited_in_characters_not_bytes():
    handler = ConfigReplaceHandler()
    at_limit = "\u00e9" * MAX_CLIS_CHARS  # two bytes each in UTF-8
    assert not handler.validate_config({"config": at_limit})
    errors = handler.validate_config({"config": at_limit + "x"})
    assert any(f"at most {MAX_CLIS_CHARS}" in error for error in errors), errors


async def test_a_release_without_the_operation_leaf_needs_17_15():
    device = _device(operation_leaf=False)
    result = await ConfigReplaceHandler().execute(
        _ctx({"config": TARGET}, FakeServices({"r1": device}))
    )
    assert not result.success
    assert "needs IOS XE 17.15 or later" in (result.error or "")
    assert device.running_cli == RUNNING


async def test_the_model_listed_only_in_the_yang_library_is_found():
    device = _device(cli_rpc_in_hello=False)
    assert not any(CLI_RPC_NS in capability for capability in device.capabilities)
    services = FakeServices({"r1": device})
    result = await ConfigReplaceHandler().execute(_ctx({"config": TARGET}, services))
    assert result.success, result.error
    assert device.running_cli == TARGET
    read = await GetConfigHandler().execute(_ctx({}, services))
    assert read.success, read.error
    assert read.output["devices"]["r1"]["config"] == TARGET
