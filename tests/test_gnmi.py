# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The ``gnmi.*`` steps against an in-process gNMI device over real gRPC (``gnmi_fakes``).

Every step test runs the real client: TLS with certificate checks (mutual
TLS included), the login metadata, Capabilities, Get and Set, gRPC statuses.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

import grpc
import pytest

import hegemony_steps_gnmi
from hegemony_step_sdk import DeviceCredentials, HandlerContext, HandlerServices
from hegemony_step_sdk.docs import load_docs_bundle
from hegemony_steps_gnmi import _descriptors, client, messages
from hegemony_steps_gnmi.get import GnmiGetConfig, GnmiGetHandler
from hegemony_steps_gnmi.paths import (
    PathError,
    format_path,
    parse_path,
    path_from_proto,
    split_assignment,
)
from hegemony_steps_gnmi.set_config import GnmiSetConfig, GnmiSetHandler
from hegemony_steps_gnmi.values import decode_value, encode_value
from tests.gnmi_fakes import FakeGnmiDevice, FakeGnmiServer, FakeServices, Pki

PROTO_DIR = Path(hegemony_steps_gnmi.__file__).parent / "proto"

ETH1 = "interface[name=Ethernet1]"


def _tree() -> dict[str, Any]:
    return {
        "system": {"config": {"hostname": "r1", "domain-name": "lab"}},
        "interfaces": {
            ETH1: {"config": {"description": "old", "mtu": 1500, "enabled": True}},
            "interface[name=Ethernet2]": {"config": {"description": "spare"}},
        },
    }


@pytest.fixture(scope="module")
def pki() -> Pki:
    return Pki.make()


@pytest.fixture
def allow_loopback(monkeypatch):
    """The fake device listens on 127.0.0.1, which the steps refuse in production."""
    monkeypatch.setattr(client, "blocked_address_reason", lambda address: None)


@pytest.fixture
async def device(pki, allow_loopback):
    server = await FakeGnmiServer(FakeGnmiDevice(tree=_tree()), pki=pki).start()
    yield server
    await server.stop()


def _device(name: str = "r1", host: str = "127.0.0.1", **extra: Any) -> dict[str, Any]:
    return {"id": f"id-{name}", "name": name, "mgmt_host": host, **extra}


class _Log:
    def __init__(self) -> None:
        self.lines: list[str] = []

    async def __call__(self, message: str, device_id: str | None, attrs: Any) -> bool:
        self.lines.append(message)
        return True


def _ctx(
    config: dict[str, Any],
    services: Any,
    devices: list[dict[str, Any]] | None = None,
    log: _Log | None = None,
) -> HandlerContext:
    ctx = HandlerContext(
        run_id="run-1",
        flow_id="flow-1",
        step_run_id="sr-1",
        step_id="gnmi",
        config=config,
        target_devices_by_role={"core": devices if devices is not None else [_device()]},
        target_roles=["core"],
        services=cast(HandlerServices, services),
    )
    if log is not None:
        ctx._emit_progress = log
    return ctx


def _config(server: FakeGnmiServer, **extra: Any) -> dict[str, Any]:
    return {"port": server.port, **extra}


# --- Paths and values ------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "origin", "elems"),
    [
        ("/", "", ()),
        ("/a/b/", "", (("a", ()), ("b", ()))),
        ("a/b", "", (("a", ()), ("b", ()))),
        (
            "openconfig:/interfaces/interface[name=Ethernet1/1]/config",
            "openconfig",
            (("interfaces", ()), ("interface", (("name", "Ethernet1/1"),)), ("config", ())),
        ),
        ("/oc-if:interfaces", "", (("oc-if:interfaces", ()),)),
        ("/a[k=x\\]y][j=1]/b", "", (("a", (("j", "1"), ("k", "x]y"))), ("b", ()))),
        ('/i[name="Eth]/1=\\"x\\""]/c', "", (("i", (("name", 'Eth]/1="x"'),)), ("c", ()))),
    ],
)
def test_paths_parse_and_format_back(text, origin, elems):
    path = parse_path(text)
    assert (path.origin, path.elems) == (origin, elems)
    assert parse_path(format_path(path)) == path


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "empty"),
        ("//a", "empty element"),
        ("/a[k]", "no '=value'"),
        ("/a[k=1", "no closing"),
        ("/a]", "without its '['"),
        ("/a b", "followed by a space"),
        ('/a[name="x"y]', "followed by ']'"),
        ("/a[k=1][k=2]", "twice"),
        ("/a\\", "lone backslash"),
    ],
)
def test_bad_paths_are_refused(text, message):
    with pytest.raises(PathError, match=re.escape(message)):
        parse_path(text)


def test_a_path_goes_to_the_wire_and_back():
    path = parse_path("openconfig:/interfaces/interface[name=Ethernet1]/config")
    proto = path.to_proto()
    assert proto.origin == "openconfig"
    assert [elem.name for elem in proto.elem] == ["interfaces", "interface", "config"]
    assert dict(proto.elem[1].key) == {"name": "Ethernet1"}
    prefix = parse_path("/interfaces").to_proto()
    tail = parse_path("/interface[name=Ethernet1]").to_proto()
    assert path_from_proto(tail, prefix=prefix) == "/interfaces/interface[name=Ethernet1]"


def test_assignments_split_at_the_first_equals_outside_keys():
    assert split_assignment('/i[name="a=b"]/config = {"x": 1}') == (
        '/i[name="a=b"]/config',
        '{"x": 1}',
    )
    assert split_assignment("/i[k=v]/d = 1 = 2") == ("/i[k=v]/d", "1 = 2")
    with pytest.raises(PathError, match=re.escape("no '= value'")):
        split_assignment("/i[k=v]/d")
    with pytest.raises(PathError, match="no value"):
        split_assignment("/i/d =")


def test_values_decode_from_every_kind():
    typed = messages.TypedValue
    assert decode_value(typed(json_ietf_val=b'{"a": 1}')) == {"a": 1}
    assert decode_value(typed(json_val=b'"x"')) == "x"
    assert decode_value(typed(string_val="s")) == "s"
    assert decode_value(typed(int_val=-3)) == -3
    assert decode_value(typed(uint_val=3)) == 3
    assert decode_value(typed(bool_val=True)) is True
    assert decode_value(typed(double_val=float("nan"))) == "nan"
    assert decode_value(typed(bytes_val=b"\x00\x01")) == base64.b64encode(b"\x00\x01").decode()
    assert decode_value(typed(decimal_val=messages.Decimal64(digits=1234, precision=2))) == 12.34
    leaflist = typed()
    leaflist.leaflist_val.element.add(string_val="a")
    leaflist.leaflist_val.element.add(int_val=2)
    assert decode_value(leaflist) == ["a", 2]
    assert decode_value(typed()) is None
    assert json.loads(encode_value({"mtu": 9000}, "json_ietf").json_ietf_val) == {"mtu": 9000}
    assert json.loads(encode_value("x", "json").json_val) == "x"


def test_the_descriptors_match_the_proto_files():
    """``_descriptors.py`` was compiled from exactly these files (scripts/gen_gnmi_descriptors.py)."""
    for name, digest in _descriptors.SOURCE_SHA256.items():
        assert hashlib.sha256((PROTO_DIR / name).read_bytes()).hexdigest() == digest, name
    assert messages.SetRequest.DESCRIPTOR.full_name == "gnmi.SetRequest"
    # The private pool leaves protobuf's default pool alone.
    from google.protobuf import descriptor_pool

    with pytest.raises(KeyError):
        descriptor_pool.Default().FindMessageTypeByName("gnmi.SetRequest")


def test_blocked_addresses_are_the_http_steps_ones():
    for address in (
        "127.0.0.1",
        "::1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::ffff:127.0.0.1",
    ):
        assert client.blocked_address_reason(address), address
    for address in ("192.0.2.1", "10.0.0.1", "2001:db8::1"):
        assert client.blocked_address_reason(address) is None, address


# --- Templates --------------------------------------------------------------------


def test_get_paths_take_templates_only_as_tojson_key_values():
    handler = GnmiGetHandler()
    good = {"paths": ["/interfaces/interface[name={{ inputs.ifname | tojson }}]/state"]}
    assert handler.template_errors(good) == []
    for bad in (
        "/interfaces/interface[name={{ inputs.ifname }}]/state",
        "/{{ inputs.root | tojson }}/state",
        '/interfaces/interface[name="{{ inputs.ifname | tojson }}"]',
        "/interfaces/interface[name=Eth{{ inputs.n | tojson }}]",
        "/a{% if x %}/b{% endif %}",
    ):
        assert handler.template_errors({"paths": [bad]}), bad


def test_set_values_take_templates_only_as_tojson_json_values():
    handler = GnmiSetHandler()
    good = {
        "updates": [
            "/interfaces/interface[name={{ inputs.ifname | tojson }}]/config = "
            '{"description": {{ inputs.description | tojson }}, "mtu": {{ inputs.mtu | tojson }}}'
        ],
        "deletes": ["/interfaces/interface[name={{ inputs.old | tojson }}]"],
    }
    assert handler.template_errors(good) == []
    for bad in (
        '/system/config/hostname = "{{ inputs.name | tojson }}"',
        '/system/config/hostname = "{{ inputs.name }}"',
        "/system/config/hostname = {{ inputs.name }}",
        '/system/config = {"hostname": "x{{ inputs.name | tojson }}"}',
        "/system/config/{{ inputs.leaf | tojson }} = 1",
    ):
        assert handler.template_errors({"updates": [bad]}), bad


def test_a_rendered_key_value_cannot_add_elements():
    """``tojson`` output is one quoted key value, whatever it holds."""
    rendered = "/interfaces/interface[name=" + json.dumps("x]/evil[a=b") + "]/config"
    path = parse_path(rendered)
    assert path.elems[1] == ("interface", (("name", "x]/evil[a=b"),))
    assert len(path.elems) == 3


# --- Settings ----------------------------------------------------------------------


def test_settings_are_checked_before_a_run():
    handler = GnmiGetHandler()
    assert handler.validate_config({"paths": ["/a"]}) == []
    assert handler.validate_config({"paths": ["/a["]})
    assert handler.validate_config({"paths": ["/a"], "credentials": "step"})  # no username
    assert handler.validate_config({"paths": ["/a"], "use_tls": False})  # login in clear
    assert (
        handler.validate_config({"paths": ["/a"], "use_tls": False, "allow_insecure_auth": True})
        == []
    )
    assert handler.validate_config({"paths": ["/a"], "client_certificate": "x"})  # no key
    assert handler.validate_config(
        {"paths": ["/a"], "client_certificate": "vault://c", "client_key": "-----BEGIN"}
    )  # a literal key
    assert handler.validate_config({"paths": ["/a"], "ca_bundle": "not a pem"})
    set_handler = GnmiSetHandler()
    assert set_handler.validate_config({"updates": ["/a/b = not json"]})
    assert set_handler.validate_config({"updates": ["/a/b = 1"]}) == []
    assert set_handler.validate_config({"updates": ["# a comment", "/a/b = 1"]}) == []


def test_the_models_document_their_defaults():
    get = GnmiGetConfig()
    assert (get.port, get.credentials, get.use_tls, get.max_parallel_devices) == (
        9339,
        "device",
        True,
        10,
    )
    change = GnmiSetConfig()
    assert (change.dry_run, change.read_back, change.max_parallel_devices) == (False, True, 1)


# --- gnmi.get ------------------------------------------------------------------------


async def test_get_reads_paths_with_the_device_login_over_verified_tls(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    log = _Log()
    config = _config(device, paths=["/system/config", f"/interfaces/{ETH1}/config/mtu"])
    result = await GnmiGetHandler().execute(_ctx(config, services, log=log))
    assert result.success, result.error
    entry = result.output["devices"]["r1"]
    assert entry["values"] == {
        "/system/config": {"hostname": "r1", "domain-name": "lab"},
        "/interfaces/interface[name=Ethernet1]/config/mtu": 1500,
    }
    assert json.loads(entry["data"]) == entry["values"]
    assert entry["encoding"] == "json_ietf"
    assert set(result.output) == {spec.name for spec in GnmiGetHandler.output_fields}
    assert result.summary == "gnmi get all: 1/1 devices"
    [evidence] = result.evidence
    assert evidence["kind"] == "cli_output"
    assert evidence["name"] == "r1:gnmi get all"
    assert json.loads(evidence["content_text"]) == entry["values"]
    # The login went as call metadata; the egress policy saw the address dialled.
    _, _, metadata = device.device.requests[-1]
    assert (metadata["username"], metadata["password"]) == ("admin", "s3cret-pass")
    assert ("127.0.0.1", device.port, "gnmi") in services.egress
    assert [name for name, _, _ in device.device.requests] == ["Capabilities", "Get"]
    # The log names requests, never values or the login.
    text = "\n".join(log.lines)
    assert "Capabilities: ok" in text and "Get: ok" in text
    assert "s3cret-pass" not in text and "1500" not in text


async def test_get_asks_the_policy_about_a_name_and_its_addresses(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    ctx = _ctx(_config(device, paths=["/system"]), services, [_device(host="localhost")])
    # The certificate names device.test and 127.0.0.1, not localhost.
    config = {**ctx.config, "tls_server_name": "device.test"}
    ctx.config = config
    result = await GnmiGetHandler().execute(ctx)
    assert result.success, result.error
    hosts = [host for host, _, _ in services.egress]
    assert hosts[0] == "localhost"
    assert set(hosts[1:]) <= {"127.0.0.1", "::1"} and hosts[1:]


async def test_get_without_the_org_ca_fails_the_certificate_check(device):
    result = await GnmiGetHandler().execute(
        _ctx(_config(device, paths=["/system"]), FakeServices())
    )
    assert not result.success
    error = result.output["devices"]["r1"]["error"]
    assert "Capabilities failed (UNAVAILABLE" in error


async def test_a_ca_bundle_pins_the_device_certificate(device, pki):
    services = FakeServices(secrets={"ca": pki.ca_pem.decode()})
    config = _config(device, paths=["/system"], ca_bundle="vault://orgs/acme/secrets/gnmi/ca")
    assert (await GnmiGetHandler().execute(_ctx(config, services))).success
    # Another CA, even with the org's right one trusted, is refused: the bundle pins.
    other = Pki.make()
    services = FakeServices(org_ca_pem=pki.ca_pem)
    config = _config(device, paths=["/system"], ca_bundle=other.ca_pem.decode())
    assert not (await GnmiGetHandler().execute(_ctx(config, services))).success


async def test_the_certificate_must_carry_the_checked_name(pki, allow_loopback):
    only_dns = Pki.make(server_names=("device.test",))
    server = await FakeGnmiServer(FakeGnmiDevice(tree=_tree()), pki=only_dns).start()
    try:
        services = FakeServices(org_ca_pem=only_dns.ca_pem)
        config = _config(server, paths=["/system"])
        assert not (await GnmiGetHandler().execute(_ctx(config, services))).success
        config["tls_server_name"] = "device.test"
        assert (await GnmiGetHandler().execute(_ctx(config, services))).success
    finally:
        await server.stop()


async def test_mutual_tls_presents_the_client_certificate(pki, allow_loopback):
    fake = FakeGnmiDevice(tree=_tree(), require_login=False)
    server = await FakeGnmiServer(fake, pki=pki, require_client_cert=True).start()
    try:
        services = FakeServices(
            org_ca_pem=pki.ca_pem, secrets={"client-key": pki.client_key_pem.decode()}
        )
        base = _config(server, paths=["/system"], credentials="none")
        assert not (await GnmiGetHandler().execute(_ctx(base, services))).success
        config = {
            **base,
            "client_certificate": pki.client_cert_pem.decode(),
            "client_key": "vault://orgs/acme/secrets/gnmi/client-key",
        }
        result = await GnmiGetHandler().execute(_ctx(config, services))
        assert result.success, result.error
        _, _, metadata = fake.requests[-1]
        assert "username" not in metadata
    finally:
        await server.stop()


async def test_the_step_login_comes_from_a_secret(device, pki):
    device.device.username, device.device.password = "robot", "robot-pass"
    services = FakeServices(org_ca_pem=pki.ca_pem, secrets={"gnmi/password": "robot-pass"})
    config = _config(
        device,
        paths=["/system"],
        credentials="step",
        username="robot",
        password="vault://orgs/acme/secrets/gnmi/password",
    )
    result = await GnmiGetHandler().execute(_ctx(config, services))
    assert result.success, result.error
    assert "gnmi.password" in services.resolved


async def test_a_refused_login_is_named(device, pki):
    services = FakeServices(
        org_ca_pem=pki.ca_pem, credentials=DeviceCredentials(username="admin", password="wrong!")
    )
    result = await GnmiGetHandler().execute(_ctx(_config(device, paths=["/system"]), services))
    assert not result.success
    assert "refused the login (UNAUTHENTICATED: bad username or password)" in str(result.error)


async def test_a_device_with_only_an_ssh_key_needs_the_step_login(device, pki):
    services = FakeServices(
        org_ca_pem=pki.ca_pem, credentials=DeviceCredentials(username="admin", private_key="k")
    )
    result = await GnmiGetHandler().execute(_ctx(_config(device, paths=["/system"]), services))
    assert "has no password" in result.output["devices"]["r1"]["error"]


async def test_a_missing_path_fails_with_the_device_status(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    config = _config(device, paths=["/system/nothing"])
    result = await GnmiGetHandler().execute(_ctx(config, services))
    assert not result.success
    assert "Get failed (NOT_FOUND: nothing does not exist)" in str(result.error)


async def test_auto_encoding_falls_back_to_json(device, pki):
    device.device.encodings = ("JSON",)
    services = FakeServices(org_ca_pem=pki.ca_pem)
    result = await GnmiGetHandler().execute(_ctx(_config(device, paths=["/system"]), services))
    assert result.success, result.error
    assert result.output["devices"]["r1"]["encoding"] == "json"


async def test_one_device_failing_keeps_the_others(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem, denied={"192.0.2.9"})
    devices = [_device("r1"), _device("r2", host="192.0.2.9"), _device("r3", jump_host=None)]
    devices[2]["access_config"] = {"jump_host": {"host": "bastion"}}
    result = await GnmiGetHandler().execute(
        _ctx(_config(device, paths=["/system"]), services, devices)
    )
    assert not result.success
    out = result.output["devices"]
    assert out["r1"]["ok"] and out["r1"]["values"]
    assert "egress policy denies 192.0.2.9" in out["r2"]["error"]
    assert "jump host" in out["r3"]["error"]


async def test_loopback_is_refused_in_production(pki):
    """Without the test fixture's exemption, a loopback device is never dialled."""
    server = await FakeGnmiServer(FakeGnmiDevice(tree=_tree()), pki=pki).start()
    try:
        services = FakeServices(org_ca_pem=pki.ca_pem)
        result = await GnmiGetHandler().execute(_ctx(_config(server, paths=["/s"]), services))
        assert "it is a loopback address" in result.output["devices"]["r1"]["error"]
        assert server.device.requests == []
    finally:
        await server.stop()


async def test_no_egress_gate_means_no_connection(device):
    class Old:
        pass

    result = await GnmiGetHandler().execute(_ctx(_config(device, paths=["/system"]), Old()))
    assert not result.success
    assert result.summary == "gNMI unavailable"
    assert device.device.requests == []


async def test_an_unreachable_port_is_reported(pki, allow_loopback):
    server = await FakeGnmiServer(FakeGnmiDevice(), pki=pki).start()
    port = server.port
    await server.stop()
    services = FakeServices(org_ca_pem=pki.ca_pem)
    result = await GnmiGetHandler().execute(
        _ctx({"port": port, "paths": ["/a"], "connect_timeout_seconds": 3}, services)
    )
    assert not result.success
    error = result.output["devices"]["r1"]["error"]
    assert "UNAVAILABLE" in error or "did not answer" in error


async def test_plaintext_needs_the_explicit_opt_in(allow_loopback):
    server = await FakeGnmiServer(FakeGnmiDevice(tree=_tree())).start()
    try:
        config = _config(server, paths=["/system"], use_tls=False)
        refused = await GnmiGetHandler().execute(_ctx(config, FakeServices()))
        assert not refused.success and "allow_insecure_auth" in str(refused.error)
        config["allow_insecure_auth"] = True
        result = await GnmiGetHandler().execute(_ctx(config, FakeServices()))
        assert result.success, result.error
    finally:
        await server.stop()


async def test_get_without_targets_or_paths_fails_early(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    assert (await GnmiGetHandler().execute(_ctx({"paths": ["/a"]}, services, []))).summary == (
        "Missing targets"
    )
    assert (await GnmiGetHandler().execute(_ctx({"paths": []}, services))).summary == (
        "Missing paths"
    )


# --- gnmi.set ------------------------------------------------------------------------


def _set_config(server: FakeGnmiServer, **extra: Any) -> dict[str, Any]:
    return _config(
        server,
        deletes=["/interfaces/interface[name=Ethernet2]"],
        replaces=[f'/interfaces/{ETH1}/config = {{"description": "uplink", "mtu": 9000}}'],
        updates=['/system/config/hostname = "r1-new"', "# a comment"],
        **extra,
    )


async def test_set_applies_one_transaction_and_reads_before_and_after(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    result = await GnmiSetHandler().execute(_ctx(_set_config(device), services))
    assert result.success, result.error
    tree = device.device.tree
    assert tree["system"]["config"] == {"hostname": "r1-new", "domain-name": "lab"}
    assert tree["interfaces"] == {ETH1: {"config": {"description": "uplink", "mtu": 9000}}}
    entry = result.output["devices"]["r1"]
    assert entry["applied"] is True
    assert entry["results"] == ["delete", "replace", "update"]
    assert entry["before"]["/system/config/hostname"] == "r1"
    assert entry["after"]["/system/config/hostname"] == "r1-new"
    assert "/interfaces/interface[name=Ethernet2]" in entry["before"]
    assert entry["changed"] == sorted(
        [
            "/interfaces/interface[name=Ethernet1]/config",
            "/interfaces/interface[name=Ethernet2]",
            "/system/config/hostname",
        ]
    )
    assert [op["op"] for op in entry["operations"]] == ["delete", "replace", "update"]
    assert set(result.output) == {spec.name for spec in GnmiSetHandler.output_fields}
    assert result.output["dry_run"] is False
    assert result.summary == "gnmi set applied: 1/1 devices"
    names = [item["name"] for item in result.evidence]
    assert names == ["r1:gnmi set before", "r1:gnmi set request", "r1:gnmi set after"]
    [set_request] = [request for name, request, _ in device.device.requests if name == "Set"]
    assert json.loads(set_request.update[0].val.json_ietf_val) == "r1-new"


async def test_a_dry_run_reads_and_sends_nothing(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    before = json.dumps(device.device.tree, sort_keys=True)
    result = await GnmiSetHandler().execute(_ctx(_set_config(device, dry_run=True), services))
    assert result.success, result.error
    assert json.dumps(device.device.tree, sort_keys=True) == before
    assert device.device.count("Set") == 0
    entry = result.output["devices"]["r1"]
    assert entry["applied"] is False and entry["before"]
    assert result.summary == "gnmi set dry run: 1/1 devices"
    assert result.output["dry_run"] is True


async def test_a_refused_change_leaves_the_device_unchanged(device, pki):
    device.device.fail_set = (grpc.StatusCode.INVALID_ARGUMENT, "mtu out of range")
    services = FakeServices(org_ca_pem=pki.ca_pem)
    before = json.dumps(device.device.tree, sort_keys=True)
    result = await GnmiSetHandler().execute(_ctx(_set_config(device), services))
    assert not result.success
    entry = result.output["devices"]["r1"]
    assert entry["applied"] is False
    assert "Set failed (INVALID_ARGUMENT: mtu out of range)" in entry["error"]
    assert json.dumps(device.device.tree, sort_keys=True) == before


async def test_a_new_path_is_missing_before_and_present_after(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    config = _config(device, updates=['/interfaces/interface[name=Loopback9]/config = {"mtu": 1}'])
    result = await GnmiSetHandler().execute(_ctx(config, services))
    assert result.success, result.error
    entry = result.output["devices"]["r1"]
    assert entry["missing"] == ["/interfaces/interface[name=Loopback9]/config"]
    assert entry["after"] == {"/interfaces/interface[name=Loopback9]/config": {"mtu": 1}}


async def test_a_failed_read_back_says_the_change_was_applied(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    config = _config(device, updates=['/system/config/hostname = "x"'])
    device.device.fail_get_after = (1, grpc.StatusCode.INTERNAL, "boom")
    result = await GnmiSetHandler().execute(_ctx(config, services))
    assert not result.success
    entry = result.output["devices"]["r1"]
    assert entry["applied"] is True
    assert "the change was applied, but reading it back failed" in entry["error"]
    assert device.device.tree["system"]["config"]["hostname"] == "x"


async def test_set_without_read_back_sends_only_the_change(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    config = _config(device, updates=['/system/config/hostname = "x"'], read_back=False)
    result = await GnmiSetHandler().execute(_ctx(config, services))
    assert result.success, result.error
    assert [name for name, _, _ in device.device.requests] == ["Capabilities", "Set"]


async def test_set_with_nothing_to_change_fails_early(device, pki):
    services = FakeServices(org_ca_pem=pki.ca_pem)
    result = await GnmiSetHandler().execute(_ctx(_config(device), services))
    assert result.summary == "Missing operations"
    assert device.device.requests == []


async def test_a_rendered_value_with_quotes_stays_one_value(device, pki):
    """What the host renders from ``{{ x | tojson }}`` is one JSON value in its slot."""
    services = FakeServices(org_ca_pem=pki.ca_pem)
    evil = 'x", "enabled": false, "a": "'
    line = f"/interfaces/{ETH1}/config = " + '{"description": ' + json.dumps(evil) + "}"
    result = await GnmiSetHandler().execute(_ctx(_config(device, updates=[line]), services))
    assert result.success, result.error
    config = device.device.tree["interfaces"][ETH1]["config"]
    assert config["description"] == evil and config["enabled"] is True


# --- Registration and docs ------------------------------------------------------------


def test_the_wheel_registers_and_documents_both_handlers():
    ids = {cls.handler_id for cls in hegemony_steps_gnmi.ALL_HANDLERS}
    assert ids == {"gnmi.get", "gnmi.set"}
    bundle = load_docs_bundle("hegemony_steps_gnmi")
    assert set(bundle) == ids
    for cls in hegemony_steps_gnmi.ALL_HANDLERS:
        for spec in cls.output_fields:
            assert f"steps.NODE_ID.output.{spec.name}" in bundle[cls.handler_id]
        assert set(cls.raw_config_keys) == {
            "password",
            "ca_bundle",
            "client_certificate",
            "client_key",
        }
