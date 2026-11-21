# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``probe.snmp``: read-only SNMP GET and walk against a real in-process agent.

The agent is pysnmp's own command responder on 127.0.0.1, serving its
default SNMPv2-MIB system group to an SNMPv2c community and an SNMPv3 user.
The credentials are synthetic.
"""

from __future__ import annotations

import warnings
from typing import Any, cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_step_sdk.docs import load_docs_bundle
from hegemony_steps_probe.snmp_check import (
    DEFAULT_OIDS,
    MAX_OUTPUT_VALUE_BYTES,
    SnmpProbeConfig,
    SnmpProbeHandler,
    render_value,
)

COMMUNITY = "synthetic-community"
USER = "alice"
AUTH_KEY = "synthetic-auth-key"
PRIV_KEY = "synthetic-priv-key"
SECRETS = {
    "vault://orgs/acme/secrets/snmp/community": COMMUNITY,
    "vault://orgs/acme/secrets/snmp/auth": AUTH_KEY,
    "vault://orgs/acme/secrets/snmp/priv": PRIV_KEY,
    "vault://orgs/acme/secrets/snmp/wrong": "wrong-auth-key",
    "vault://orgs/acme/secrets/snmp/short": "abc",
}
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYSTEM = "1.3.6.1.2.1.1"


@pytest.fixture
async def agent_port():
    """Start an SNMP agent on a free UDP port of 127.0.0.1; yields the port."""
    warnings.simplefilter("ignore", DeprecationWarning)
    from pysnmp.carrier.asyncio.dgram import udp
    from pysnmp.entity import config, engine
    from pysnmp.entity.rfc3413 import cmdrsp, context

    snmp_engine = engine.SnmpEngine()
    config.add_transport(
        snmp_engine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(("127.0.0.1", 0)),
    )
    transport = snmp_engine.transport_dispatcher.get_transport(udp.DOMAIN_NAME)
    await transport._lport
    port = transport.transport.get_extra_info("sockname")[1]
    config.add_v1_system(snmp_engine, "lab", COMMUNITY)
    config.add_v3_user(
        snmp_engine,
        USER,
        config.USM_AUTH_HMAC192_SHA256,
        AUTH_KEY,
        config.USM_PRIV_CFB128_AES,
        PRIV_KEY,
    )
    config.add_vacm_user(snmp_engine, 2, "lab", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
    config.add_vacm_user(snmp_engine, 3, USER, "authPriv", (1, 3, 6), (1, 3, 6))
    snmp_context = context.SnmpContext(snmp_engine)
    cmdrsp.GetCommandResponder(snmp_engine, snmp_context)
    cmdrsp.NextCommandResponder(snmp_engine, snmp_context)
    cmdrsp.BulkCommandResponder(snmp_engine, snmp_context)
    try:
        yield port
    finally:
        snmp_engine.close_dispatcher()


class _Services:
    """Resolves the synthetic secrets and records every egress question."""

    def __init__(self, *, deny: bool = False) -> None:
        self.deny = deny
        self.egress: list[tuple[str, int | None, str | None, str]] = []
        self.resolved: list[str] = []

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        assert ref is not None
        self.resolved.append(source)
        for path, value in SECRETS.items():
            if path in ref:
                return value
        return ""

    async def enforce_egress(self, host, port=None, *, proto=None, kind="connection"):
        self.egress.append((host, port, proto, kind))
        if self.deny:
            raise PermissionError(f"egress to {host}:{port}/{proto} denied by policy")


def _ctx(config: dict[str, Any], services: Any, ips: list[str] | None = None) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        step_target_ips=ips if ips is not None else ["127.0.0.1"],
        services=cast(HandlerServices, services),
    )


def _v2c(port: int, **extra: Any) -> dict[str, Any]:
    return {
        "community": "vault://orgs/acme/secrets/snmp/community",
        "port": port,
        "attempt_timeout_seconds": 1,
        "attempts": 1,
        **extra,
    }


def _v3(port: int, **extra: Any) -> dict[str, Any]:
    return {
        "version": "v3",
        "username": USER,
        "auth_secret": "vault://orgs/acme/secrets/snmp/auth",
        "priv_secret": "{{ secret('vault://orgs/acme/secrets/snmp/priv') }}",
        "port": port,
        "attempt_timeout_seconds": 1,
        "attempts": 1,
        **extra,
    }


async def test_v2c_get_reads_the_default_system_values(agent_port):
    services = _Services()
    result = await SnmpProbeHandler().execute(_ctx(_v2c(agent_port), services))

    assert result.success, result.error
    target = result.output["targets"]["127.0.0.1"]
    assert target["ok"] is True
    assert set(target["values"]) == set(DEFAULT_OIDS)
    assert target["values"]["1.3.6.1.2.1.1.1.0"].startswith("PySNMP engine")
    assert target["values"]["1.3.6.1.2.1.1.2.0"] == "1.3.6.1.4.1.20408"
    assert isinstance(target["values"]["1.3.6.1.2.1.1.3.0"], int)
    assert target["types"]["1.3.6.1.2.1.1.3.0"] == "TimeTicks"
    assert target["address"] == "127.0.0.1"
    assert result.output["omitted"] == []
    assert result.metrics["values_read"] == 4
    assert services.egress == [("127.0.0.1", agent_port, "udp", "snmp query")]


async def test_the_credentials_stay_out_of_output_evidence_and_errors(agent_port):
    result = await SnmpProbeHandler().execute(_ctx(_v3(agent_port), _Services()))

    assert result.success, result.error
    text = repr((result.output, result.evidence, result.summary, result.error))
    for secret in (COMMUNITY, AUTH_KEY, PRIV_KEY):
        assert secret not in text


async def test_v3_auth_priv_walk_stops_at_max_rows(agent_port):
    config = _v3(agent_port, operation="walk", oids=[SYSTEM], max_rows=3)
    result = await SnmpProbeHandler().execute(_ctx(config, _Services()))

    assert result.success, result.error
    target = result.output["targets"]["127.0.0.1"]
    assert len(target["values"]) == 3
    assert all(oid.startswith(SYSTEM + ".") for oid in target["values"])
    assert target["truncated"] == [SYSTEM]


async def test_a_walk_under_its_limit_is_not_truncated(agent_port):
    # sysORTable is empty on pysnmp's agent, so walk the 9 system scalars.
    config = _v2c(agent_port, operation="walk", oids=[SYSTEM], max_rows=1000)
    result = await SnmpProbeHandler().execute(_ctx(config, _Services()))

    assert result.success, result.error
    target = result.output["targets"]["127.0.0.1"]
    assert target["truncated"] == []
    assert SYS_NAME in target["values"]


async def test_a_wrong_v3_key_fails_the_target(agent_port):
    config = _v3(agent_port, auth_secret="vault://orgs/acme/secrets/snmp/wrong")
    result = await SnmpProbeHandler().execute(_ctx(config, _Services()))

    assert not result.success
    assert "Wrong SNMP PDU digest" in (result.error or "")
    assert result.output["targets"]["127.0.0.1"]["ok"] is False


async def test_an_unknown_v3_user_fails_the_target(agent_port):
    result = await SnmpProbeHandler().execute(_ctx(_v3(agent_port, username="bob"), _Services()))

    assert not result.success
    assert "Unknown USM user" in (result.error or "")


async def test_a_missing_oid_fails_the_target_and_names_it(agent_port):
    config = _v2c(agent_port, oids=[SYS_NAME, "1.3.6.1.4.1.99999.1.0"])
    result = await SnmpProbeHandler().execute(_ctx(config, _Services()))

    assert not result.success
    target = result.output["targets"]["127.0.0.1"]
    assert SYS_NAME in target["values"]
    assert target["missing"] == {"1.3.6.1.4.1.99999.1.0": "noSuchObject"}
    assert "1.3.6.1.4.1.99999.1.0 (noSuchObject)" in (result.error or "")


async def test_a_walk_with_nothing_under_the_oid_fails(agent_port):
    config = _v2c(agent_port, operation="walk", oids=["1.3.6.1.4.1.99999"])
    result = await SnmpProbeHandler().execute(_ctx(config, _Services()))

    assert not result.success
    assert result.output["targets"]["127.0.0.1"]["missing"] == {
        "1.3.6.1.4.1.99999": "no values under this OID"
    }


async def test_an_agent_that_does_not_answer_times_out(agent_port):
    # A wrong SNMPv2c community gets no answer at all.
    services = _Services()
    config = _v2c(agent_port, community="vault://orgs/acme/secrets/snmp/auth")
    result = await SnmpProbeHandler().execute(_ctx(config, services))

    assert not result.success
    assert "No SNMP response" in (result.error or "")
    assert result.output["targets"]["127.0.0.1"]["latency_ms"] is None


async def test_a_denied_destination_fails_the_step_before_any_query():
    services = _Services(deny=True)
    with pytest.raises(PermissionError, match="denied by policy"):
        await SnmpProbeHandler().execute(_ctx(_v2c(161), services))
    assert services.egress == [("127.0.0.1", 161, "udp", "snmp query")]


async def test_without_the_egress_gate_the_step_refuses_to_run():
    class _NoGate:
        async def resolve_secret_ref(self, ref, *, source):
            return COMMUNITY

    result = await SnmpProbeHandler().execute(_ctx(_v2c(161), _NoGate()))
    assert not result.success
    assert "network policy" in (result.error or "")


async def test_a_short_secret_is_refused():
    config = _v2c(161, community="vault://orgs/acme/secrets/snmp/short")
    result = await SnmpProbeHandler().execute(_ctx(config, _Services()))
    assert not result.success
    assert "shorter than 4" in (result.error or "")


async def test_no_targets_fails():
    result = await SnmpProbeHandler().execute(_ctx(_v2c(161), _Services(), ips=[]))
    assert not result.success
    assert result.summary == "Missing targets"


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"community": "public"}, "'community' must be a secret reference"),
        ({}, "'community' is required"),
        ({"community": "vault://a/b", "oids": ["sysName.0"]}, "must be numeric"),
        ({"community": "vault://a/b", "oids": ["1.3.6.1"] * 65}, "at most 64"),
        ({"version": "v3", "auth_secret": "vault://a/b"}, "'username' is required"),
        ({"version": "v3", "username": "u", "priv_secret": "vault://a/c"}, "'auth_secret'"),
        (
            {"version": "v3", "username": "u", "auth_protocol": "none", "priv_secret": "x://y"},
            "privacy needs authentication",
        ),
        (
            {"version": "v3", "username": "u", "auth_secret": "x://a", "priv_protocol": "aes128"},
            "'priv_secret' is required",
        ),
        ({"community": "vault://a/b", "auth_protocol": "md5"}, "auth_protocol"),
    ],
)
def test_invalid_settings_are_refused(config, message):
    errors = SnmpProbeHandler().validate_config(config)
    assert any(message in error for error in errors), errors


def test_valid_settings_pass_and_a_leading_dot_is_dropped():
    handler = SnmpProbeHandler()
    config = {"community": "{{ secret('vault://a/b') }}", "oids": [".1.3.6.1.2.1.1.5.0", " "]}
    assert handler.validate_config(config) == []
    parsed = handler.parse_config(config, SnmpProbeConfig)
    assert parsed.oids == [SYS_NAME]
    assert (
        handler.validate_config(
            {"version": "v3", "username": "u", "auth_protocol": "none", "priv_protocol": "none"}
        )
        == []
    )


def test_values_render_as_plain_json():
    from pysnmp.proto import rfc1902

    assert render_value(rfc1902.Counter64(2**40)) == ("Counter64", 2**40)
    assert render_value(rfc1902.IpAddress("192.0.2.1")) == ("IpAddress", "192.0.2.1")
    assert render_value(rfc1902.OctetString(b"\x00\x1b\x21")) == ("OctetString", "0x001b21")
    assert render_value(rfc1902.OctetString("r1.example")) == ("OctetString", "r1.example")
    assert render_value(rfc1902.OctetString("München\tlab".encode())) == (
        "OctetString",
        "München\tlab",
    )
    assert render_value(rfc1902.OctetString(b"a\x07b")) == ("OctetString", "0x610762")
    kind, long_text = render_value(rfc1902.OctetString("x" * 5000))
    assert len(long_text) == 1024 and long_text.endswith("\u2026")


async def test_values_past_the_output_budget_stay_in_the_evidence(agent_port, monkeypatch):
    monkeypatch.setattr("hegemony_steps_probe.snmp_check.MAX_OUTPUT_VALUE_BYTES", 150)
    config = _v2c(agent_port, oids=["1.3.6.1.2.1.1.1.0"])
    result = await SnmpProbeHandler().execute(
        _ctx(config, _Services(), ips=["127.0.0.1", "127.0.0.1"])
    )

    assert result.success, result.error
    assert len(result.output["omitted"]) == 1
    omitted = result.output["omitted"][0]
    assert result.output["targets"][omitted]["values"] == {}
    assert all(item["content_json"]["values"] for item in result.evidence)
    assert MAX_OUTPUT_VALUE_BYTES == 48 * 1024


async def test_the_declared_output_fields_are_the_keys_the_step_outputs(agent_port):
    result = await SnmpProbeHandler().execute(_ctx(_v2c(agent_port), _Services()))
    declared = [field.name for field in SnmpProbeHandler.output_fields]
    assert set(declared) == set(result.output)


def test_the_docs_page_names_every_declared_output_field():
    text = load_docs_bundle("hegemony_steps_probe")["probe.snmp"]
    for field in SnmpProbeHandler.output_fields:
        assert f"output.{field.name}`" in text, field.name
