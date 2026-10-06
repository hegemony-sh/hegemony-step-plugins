# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Registration and metadata smoke tests for the handler wheels.

Deep behavioral coverage for these handlers lives in the platform repo (which
exercises them through the installed wheels with host-bound services); this
suite pins what the wheels themselves own: per-wheel handler sets, namespace
discipline, metadata, and config schemas.
"""

import asyncio
import json
from typing import Any, cast

import pytest

import hegemony_steps_cisco_iosxe
import hegemony_steps_container
import hegemony_steps_evidence
import hegemony_steps_flow
import hegemony_steps_general
import hegemony_steps_http
import hegemony_steps_monitor
import hegemony_steps_netcli
import hegemony_steps_probe
import hegemony_steps_secret
import hegemony_steps_shell
from hegemony_step_sdk import BaseHandler, HandlerContext, HandlerServices, ProbeResult, StepKind

# module, claimed namespace prefix (= entry-point name), expected handler ids
WHEELS = [
    (hegemony_steps_general, "general", {"general.noop", "general.sleep"}),
    (
        hegemony_steps_probe,
        "probe",
        {"probe.connectivity", "probe.wait_reachable", "probe.http", "probe.dns", "probe.tls"},
    ),
    (
        hegemony_steps_netcli,
        "netcli",
        {"netcli.execute", "netcli.collect_evidence"},
    ),
    (hegemony_steps_evidence, "evidence", {"evidence.assert", "evidence.compare"}),
    (hegemony_steps_container, "container", {"container.run", "container.build"}),
    (hegemony_steps_shell, "shell", {"shell.execute"}),
    (hegemony_steps_flow, "flow", {"flow.run", "flow.notify"}),
    (
        hegemony_steps_cisco_iosxe,
        "cisco.iosxe",
        {
            "cisco.iosxe.upgrade.preflight",
            "cisco.iosxe.upgrade.stage",
            "cisco.iosxe.upgrade.install",
            "cisco.iosxe.upgrade.verify",
            "cisco.iosxe.upgrade.cleanup",
        },
    ),
    (hegemony_steps_monitor, "monitor", {"monitor.connectivity"}),
    (hegemony_steps_http, "http", {"http.request"}),
    (hegemony_steps_secret, "secret", {"secret.write"}),
]

HIDDEN_IDS = {"general.noop"}


class RecordingRegistry:
    api_version = 1

    def __init__(self) -> None:
        # list[Any]: the protocol's parameter type is plain ``type`` (duck-typed).
        self.registered: list[Any] = []

    def register_handler_type(self, handler_class: type) -> None:
        self.registered.append(handler_class)


@pytest.mark.parametrize(("module", "namespace", "expected_ids"), WHEELS)
def test_register_registers_declared_handlers(module, namespace, expected_ids):
    registry = RecordingRegistry()
    module.register(registry)
    ids = {cls.handler_id for cls in registry.registered}
    assert ids == expected_ids
    assert len(registry.registered) == len(expected_ids)


@pytest.mark.parametrize(("module", "namespace", "expected_ids"), WHEELS)
def test_all_ids_stay_inside_the_claimed_namespace(module, namespace, expected_ids):
    for cls in module.ALL_HANDLERS:
        assert cls.handler_id.startswith(namespace + "."), cls.handler_id


@pytest.mark.parametrize(("module", "namespace", "expected_ids"), WHEELS)
def test_handlers_are_well_formed(module, namespace, expected_ids):
    for cls in module.ALL_HANDLERS:
        assert issubclass(cls, BaseHandler), cls
        assert cls.supported_kinds, cls
        assert all(isinstance(kind, StepKind) for kind in cls.supported_kinds), cls
        model = cls.config_model
        assert model is not None, cls.handler_id
        json.dumps(model.model_json_schema())
        if cls.handler_id in HIDDEN_IDS:
            assert cls.hidden, cls.handler_id
        else:
            assert not cls.hidden, cls.handler_id
            assert cls.display_name and cls.display_name != cls.handler_id, cls.handler_id
            assert cls.description, cls.handler_id
            assert cls.category, cls.handler_id


def test_no_duplicate_ids_across_wheels():
    all_ids: list[str] = []
    for module, _ns, _expected in WHEELS:
        all_ids += [cls.handler_id for cls in module.ALL_HANDLERS]
    assert len(all_ids) == len(set(all_ids)) == 24


def test_connectivity_check_type_is_registry_driven():
    """check_type is a plain string marked for host enum injection, not a static Literal."""
    from hegemony_steps_probe.connectivity import ConnectivityCheckConfig

    prop = ConnectivityCheckConfig.model_json_schema()["properties"]["check_type"]
    assert prop.get("type") == "string"
    assert "enum" not in prop  # the host injects options from the probe registry
    assert prop["x_options_source"] == "probes"


async def test_connectivity_probe_runs_through_services_run_probe():
    """probe.connectivity delegates each check to the host's shared probe registry."""
    from hegemony_step_sdk import ProbeResult
    from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

    calls: list[tuple[str, str, dict[str, Any]]] = []

    class _Services:
        async def run_probe(self, check_type, address, options):
            calls.append((check_type, address, options))
            return ProbeResult(ok=True, metrics={"connect_ms": 1.2})

    handler = ConnectivityCheckHandler()
    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"check_type": "tcp_connect", "port": 443, "timeout_sec": 3},
        target_roles=["primary"],
        target_devices_by_role={"primary": [{"id": "d1", "name": "r1", "mgmt_host": "192.0.2.1"}]},
        services=cast(HandlerServices, _Services()),
    )
    result = await handler.execute(ctx)
    assert result.success is True
    assert calls == [("tcp_connect", "192.0.2.1", {"timeout_ms": 3000, "port": 443})]


async def test_connectivity_probe_forwards_socks_proxy():
    """The socks_proxy option rides the existing config path into run_probe."""
    from hegemony_step_sdk import ProbeResult
    from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

    calls: list[tuple[str, str, dict[str, Any]]] = []

    class _Services:
        async def run_probe(self, check_type, address, options):
            calls.append((check_type, address, options))
            return ProbeResult(ok=True, metrics={"connect_ms": 1.2})

    handler = ConnectivityCheckHandler()
    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={
            "check_type": "tcp_connect",
            "port": 22,
            "timeout_sec": 3,
            "socks_proxy": "socks5://jump:pw@dind:1080",
        },
        target_roles=["primary"],
        target_devices_by_role={"primary": [{"id": "d1", "name": "r1", "mgmt_host": "192.0.2.1"}]},
        services=cast(HandlerServices, _Services()),
    )
    result = await handler.execute(ctx)
    assert result.success is True
    assert calls[0][2]["socks_proxy"] == "socks5://jump:pw@dind:1080"


async def test_connectivity_probe_reports_unsupported_check_type():
    """A known-but-unregistered check type surfaces as a clean failure, not a crash."""
    from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

    class _Services:
        async def run_probe(self, check_type, address, options):
            raise KeyError(check_type)

    handler = ConnectivityCheckHandler()
    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"check_type": "tls_handshake", "port": 443},
        target_roles=["primary"],
        target_devices_by_role={"primary": [{"id": "d1", "name": "r1", "mgmt_host": "192.0.2.1"}]},
        services=cast(HandlerServices, _Services()),
    )
    result = await handler.execute(ctx)
    assert result.success is False
    assert "not available" in (result.error or "")


def _ip_target_ctx(handler_config: dict[str, Any], ips: list[str], services=None, **kwargs):
    """A ctx targeted purely by direct-IP selectors — no devices, no roles."""
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=handler_config,
        step_target_ips=ips,
        services=cast(HandlerServices, services) if services is not None else None,
        **kwargs,
    )


async def test_connectivity_probe_accepts_direct_ip_targets():
    """A probe aims at addresses, not at inventory: IP selectors alone are a
    complete targeting — this exact shape used to fail 'No target devices
    configured' while the monitor handler accepted it."""
    from hegemony_step_sdk import ProbeResult
    from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

    calls: list[str] = []

    class _Services:
        async def run_probe(self, check_type, address, options):
            calls.append(address)
            return ProbeResult(ok=True, metrics={"rtt_ms": 2.5})

    handler = ConnectivityCheckHandler()
    ctx = _ip_target_ctx(
        {"check_type": "icmp_ping", "timeout_sec": 3},
        ["192.0.2.7", "192.0.2.8"],
        services=_Services(),
    )
    result = await handler.execute(ctx)
    assert result.success is True, result.error
    assert calls == ["192.0.2.7", "192.0.2.8"]
    assert result.summary == "icmp_ping: 2/2 targets OK"
    # No inventory identity: the evidence must not invent one — the artifact
    # column behind device_id is a UUID and an address would not survive it.
    assert [e["device_id"] for e in result.evidence] == [None, None]
    assert result.metrics == {"192.0.2.7_ms": 2.5, "192.0.2.8_ms": 2.5}


async def test_connectivity_probe_unions_devices_and_ips():
    """Devices and direct IPs are one target list, devices first."""
    from hegemony_step_sdk import ProbeResult
    from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

    calls: list[str] = []

    class _Services:
        async def run_probe(self, check_type, address, options):
            calls.append(address)
            return ProbeResult(ok=True, metrics={"connect_ms": 1.0})

    handler = ConnectivityCheckHandler()
    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"check_type": "tcp_connect", "port": 443},
        target_roles=["primary"],
        target_devices_by_role={"primary": [{"id": "d1", "name": "r1", "mgmt_host": "192.0.2.1"}]},
        step_target_ips=["198.51.100.9"],
        services=cast(HandlerServices, _Services()),
    )
    result = await handler.execute(ctx)
    assert result.success is True, result.error
    assert calls == ["192.0.2.1", "198.51.100.9"]
    assert result.summary == "tcp_connect: 2/2 targets OK"


async def test_connectivity_port_defaults_by_check_type():
    """An empty Port is 80 for HTTP Health, and 22 for the others as it always was."""
    from hegemony_step_sdk import ProbeResult
    from hegemony_steps_probe.connectivity import (
        ConnectivityCheckConfig,
        ConnectivityCheckHandler,
    )

    calls: list[tuple[str, int | None]] = []

    class _Services:
        async def run_probe(self, check_type, address, options):
            calls.append((check_type, options.get("port")))
            return ProbeResult(ok=True)

    handler = ConnectivityCheckHandler()
    # A new step starts without a port, so the check's own default applies.
    assert "port" not in handler.default_config
    assert ConnectivityCheckConfig().port is None
    configs: list[dict[str, Any]] = [
        {},
        {"check_type": "http_health"},
        {"check_type": "http_health", "port": None},
        {"check_type": "http_health", "port": 8080},
        {"check_type": "tcp_connect", "port": 443},
    ]
    for config in configs:
        result = await handler.execute(_ip_target_ctx(config, ["192.0.2.7"], services=_Services()))
        assert result.success is True, (config, result.error)
    assert calls == [
        ("tcp_connect", 22),
        ("http_health", 80),
        ("http_health", 80),
        ("http_health", 8080),
        ("tcp_connect", 443),
    ]


async def test_probe_handlers_fail_the_same_way_without_any_target():
    """All four probe handlers speak with one voice when nothing is targeted."""
    from hegemony_steps_probe.connectivity import ConnectivityCheckHandler
    from hegemony_steps_probe.dns_check import DnsProbeHandler
    from hegemony_steps_probe.http_check import HttpProbeHandler
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    for handler in (
        ConnectivityCheckHandler(),
        DnsProbeHandler(),
        HttpProbeHandler(),
        WaitReachableHandler(),
    ):
        result = await handler.execute(_ip_target_ctx({}, []))
        assert result.success is False, handler.handler_id
        assert result.error == "No target devices or IPs configured", handler.handler_id


async def test_dns_probe_refuses_a_bare_ip_target_without_a_query_name(monkeypatch):
    """An IP literal is not a DNS question. Without a Name to Resolve the
    target fails with a pointed message instead of a baffling NXDOMAIN; with
    one, the IP target is simply where the question came from."""
    from hegemony_steps_probe import dns_check
    from hegemony_steps_probe.dns_check import DnsProbeHandler

    handler = DnsProbeHandler()
    result = await handler.execute(_ip_target_ctx({}, ["192.0.2.7"]))
    assert result.success is False
    assert "IP target needs a Name to Resolve" in (result.error or "")

    async def fake_resolve(query_name, record_type, *, resolver_ip="", timeout_sec=5.0):
        assert query_name == "device.example.com"
        return ["192.0.2.7"]

    monkeypatch.setattr(dns_check, "resolve_records", fake_resolve)
    result = await handler.execute(
        _ip_target_ctx({"query_name": "device.example.com"}, ["192.0.2.7"])
    )
    assert result.success is True, result.error


async def test_dns_probe_puts_a_chosen_resolver_through_the_egress_gate(monkeypatch):
    """A chosen nameserver is a destination the policy must see, on UDP and TCP."""
    from hegemony_steps_probe import dns_check
    from hegemony_steps_probe.dns_check import DnsProbeHandler

    gated: list[tuple[str, int, str, str]] = []
    asked: list[str] = []

    class _Services:
        async def enforce_egress(self, host, port, *, proto, kind):
            gated.append((host, port, proto, kind))

    async def fake_resolve(query_name, record_type, *, resolver_ip="", timeout_sec=5.0):
        asked.append(resolver_ip)
        return ["192.0.2.7"]

    monkeypatch.setattr(dns_check, "resolve_records", fake_resolve)
    config = {"query_name": "device.example.com", "resolver": "2001:db8::53"}
    ctx = _ip_target_ctx(config, ["192.0.2.7"], services=_Services())
    result = await DnsProbeHandler().execute(ctx)
    assert result.success is True, result.error
    assert gated == [
        ("2001:db8::53", 53, "udp", "dns query"),
        ("2001:db8::53", 53, "tcp", "dns query"),
    ]
    assert asked == ["2001:db8::53"]


async def test_dns_probe_does_not_ask_a_resolver_the_policy_denies(monkeypatch):
    from hegemony_steps_probe import dns_check
    from hegemony_steps_probe.dns_check import DnsProbeHandler

    class _Denied(Exception):
        pass

    class _Services:
        async def enforce_egress(self, host, port, *, proto, kind):
            raise _Denied(f"{kind} to {host} refused by the flow egress policy")

    async def fail_resolve(*args, **kwargs):
        raise AssertionError("the denied resolver was asked")

    monkeypatch.setattr(dns_check, "resolve_records", fail_resolve)
    config = {"query_name": "device.example.com", "resolver": "198.51.100.53"}
    ctx = _ip_target_ctx(config, ["192.0.2.7"], services=_Services())
    with pytest.raises(_Denied):
        await DnsProbeHandler().execute(ctx)


async def test_dns_probe_refuses_a_resolver_when_no_gate_can_check_it(monkeypatch):
    """Fail closed: a host without enforce_egress cannot apply the policy."""
    from hegemony_steps_probe import dns_check
    from hegemony_steps_probe.dns_check import DnsProbeHandler

    async def fail_resolve(*args, **kwargs):
        raise AssertionError("an unchecked resolver was asked")

    monkeypatch.setattr(dns_check, "resolve_records", fail_resolve)
    config = {"query_name": "device.example.com", "resolver": "192.0.2.53"}
    for services in (None, type("_Services", (), {})()):
        result = await DnsProbeHandler().execute(
            _ip_target_ctx(config, ["192.0.2.7"], services=services)
        )
        assert result.success is False
        assert "cannot apply the flow's network policy" in (result.error or "")


@pytest.mark.parametrize(
    "resolver", ["dns.google", "1.2.3.4:53", "https://dns.google/dns-query", "tls://1.1.1.1"]
)
async def test_dns_probe_refuses_a_resolver_that_is_not_an_ip(monkeypatch, resolver):
    from hegemony_steps_probe import dns_check
    from hegemony_steps_probe.dns_check import DnsProbeConfig, DnsProbeHandler

    async def fail_resolve(*args, **kwargs):
        raise AssertionError("an invalid resolver was asked")

    monkeypatch.setattr(dns_check, "resolve_records", fail_resolve)
    config = {"query_name": "device.example.com", "resolver": resolver}
    assert DnsProbeHandler().validate_config(config)
    with pytest.raises(ValueError):
        DnsProbeConfig.model_validate(config)
    result = await DnsProbeHandler().execute(_ip_target_ctx(config, ["192.0.2.7"]))
    assert result.success is False
    assert "must be a nameserver IP address" in (result.error or "")


class _FakeProbes:
    """services.run_probe stand-in: records each call and gives one answer."""

    def __init__(self, answer: ProbeResult | BaseException | None = None) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.answer = answer if answer is not None else ProbeResult(ok=True)

    async def run_probe(self, check_type, address, options):
        self.calls.append((check_type, address, dict(options)))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


#: A wait that succeeds on the second poll, about a second in.
_QUICK_WAIT = {"max_wait_seconds": 10, "stable_seconds": 1, "poll_interval": 1}


def _device_and_ip_ctx(config: dict[str, Any], services: Any) -> HandlerContext:
    """One device with an inventory mgmt_port, and one direct-IP target."""
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config=config,
        target_roles=["primary"],
        target_devices_by_role={
            "primary": [{"id": "d1", "name": "r1", "mgmt_host": "192.0.2.1", "mgmt_port": 2222}]
        },
        step_target_ips=["2001:db8::7"],
        services=cast(HandlerServices, services),
    )


async def test_wait_reachable_accepts_ip_targets():
    """Reachability needs an address, not a device record."""
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    probes = _FakeProbes()
    ctx = _ip_target_ctx(dict(_QUICK_WAIT), ["192.0.2.7"], services=probes)
    result = await WaitReachableHandler().execute(ctx)
    assert result.success is True, result.error
    assert {call[1] for call in probes.calls} == {"192.0.2.7"}
    assert [e["device_id"] for e in result.evidence] == [None]
    assert "target(s) stable" in (result.summary or "")


def test_wait_reachable_declares_its_connect_timeout():
    """connect_timeout was read but never declared, so nothing validated it."""
    from hegemony_steps_probe.wait_reachable import WaitReachableConfig, WaitReachableHandler

    prop = WaitReachableConfig.model_json_schema()["properties"]["connect_timeout_seconds"]
    assert (prop["default"], prop["minimum"], prop["maximum"]) == (5, 1, 60)
    # Steps saved with the old key keep their value.
    assert WaitReachableConfig.model_validate({"connect_timeout": "7"}).connect_timeout_seconds == 7
    assert WaitReachableHandler().validate_config({"connect_timeout": "abc"})
    assert WaitReachableHandler().validate_config({"connect_timeout_seconds": 61})


@pytest.mark.parametrize(
    ("config", "expected_ms"),
    [({"connect_timeout_seconds": 3}, 3000), ({"connect_timeout": "2"}, 2000)],
)
async def test_wait_reachable_polls_with_the_validated_connect_timeout(config, expected_ms):
    """A string timeout used to reach asyncio.wait_for, whose TypeError the
    check swallowed: every target stayed "unreachable" until the deadline."""
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    probes = _FakeProbes()
    ctx = _ip_target_ctx({**_QUICK_WAIT, **config}, ["192.0.2.7"], services=probes)
    result = await WaitReachableHandler().execute(ctx)
    assert result.success is True, result.error
    assert {call[2]["timeout_ms"] for call in probes.calls} == {expected_ms}


async def test_wait_reachable_refuses_an_invalid_config():
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    ctx = _ip_target_ctx({"connect_timeout": "soon"}, ["192.0.2.7"])
    result = await WaitReachableHandler().execute(ctx)
    assert result.success is False
    assert "Invalid probe.wait_reachable config" in (result.error or "")


def test_wait_reachable_check_type_is_registry_driven():
    from hegemony_steps_probe.wait_reachable import WaitReachableConfig

    props = WaitReachableConfig.model_json_schema()["properties"]
    assert props["check_type"]["default"] == "tcp_connect"
    assert "enum" not in props["check_type"]  # the host injects the probe ids
    assert props["check_type"]["x_options_source"] == "probes"
    assert props["port"]["x_hide_when"] == {"field": "check_type", "value": "icmp_ping"}
    assert props["socks_proxy"]["default"] == ""


async def test_wait_reachable_defaults_poll_tcp_on_the_management_port():
    """Without the new settings a poll is today's TCP connect: a device on
    its inventory mgmt_port, a direct IP (IPv6 too) on 22."""
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    probes = _FakeProbes()
    result = await WaitReachableHandler().execute(_device_and_ip_ctx(dict(_QUICK_WAIT), probes))
    assert result.success is True, result.error
    first_round = probes.calls[:2]
    assert first_round == [
        ("tcp_connect", "192.0.2.1", {"timeout_ms": 5000, "port": 2222}),
        ("tcp_connect", "2001:db8::7", {"timeout_ms": 5000, "port": 22}),
    ]
    assert [
        (e["content_json"]["check_type"], e["content_json"]["port"]) for e in result.evidence
    ] == [
        ("tcp_connect", 2222),
        ("tcp_connect", 22),
    ]


@pytest.mark.parametrize(
    ("config", "device_options", "ip_options"),
    [
        ({"port": 443}, {"port": 443}, {"port": 443}),
        ({"check_type": "http_health"}, {"port": 80}, {"port": 80}),
        ({"check_type": "icmp_ping", "port": 443}, {"count": 1}, {"count": 1}),
        (
            {"socks_proxy": " socks5://jump:pw@dind:1080 "},
            {"port": 2222, "socks_proxy": "socks5://jump:pw@dind:1080"},
            {"port": 22, "socks_proxy": "socks5://jump:pw@dind:1080"},
        ),
    ],
)
async def test_wait_reachable_polls_with_the_check_type_port_and_proxy(
    config, device_options, ip_options
):
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    probes = _FakeProbes()
    ctx = _device_and_ip_ctx({**_QUICK_WAIT, **config}, probes)
    result = await WaitReachableHandler().execute(ctx)
    assert result.success is True, result.error
    check_type = config.get("check_type", "tcp_connect")
    assert probes.calls[:2] == [
        (check_type, "192.0.2.1", {"timeout_ms": 5000, **device_options}),
        (check_type, "2001:db8::7", {"timeout_ms": 5000, **ip_options}),
    ]
    ports = [e["content_json"]["port"] for e in result.evidence]
    assert ports == [device_options.get("port"), ip_options.get("port")]


async def test_wait_reachable_fails_on_the_first_poll_of_a_denied_target():
    """run_probe applies the egress gate; a denial ends the wait at once."""
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    class _Denied(Exception):
        pass

    probes = _FakeProbes(_Denied("probe to 192.0.2.7 refused by the flow egress policy"))
    ctx = _ip_target_ctx({"max_wait_seconds": 300}, ["192.0.2.7"], services=probes)
    with pytest.raises(_Denied):
        await asyncio.wait_for(WaitReachableHandler().execute(ctx), timeout=5)
    assert len(probes.calls) == 1


@pytest.mark.parametrize(
    ("answer", "error"),
    [
        (KeyError("tcp_connect"), "Check type 'tcp_connect' is not available on this worker"),
        (
            ProbeResult(
                ok=False,
                error_kind="config_error",
                error_detail="icmp_ping cannot use socks_proxy",
            ),
            "tcp_connect cannot run against 192.0.2.7: icmp_ping cannot use socks_proxy",
        ),
    ],
)
async def test_wait_reachable_fails_at_once_when_the_check_cannot_run(answer, error):
    """An unknown check type or refused options fail every poll the same
    way, so the step says so instead of polling until the deadline."""
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    probes = _FakeProbes(answer)
    ctx = _ip_target_ctx({"max_wait_seconds": 300}, ["192.0.2.7"], services=probes)
    result = await asyncio.wait_for(WaitReachableHandler().execute(ctx), timeout=5)
    assert result.success is False
    assert result.error == error
    assert len(probes.calls) == 1


@pytest.mark.parametrize("check_type", ["tcp_connect", "http_health"])
async def test_wait_reachable_stops_at_once_on_an_invalid_proxy(check_type):
    """The bundled probes report a SOCKS5 Proxy that is no socks5:// URL as
    a config_error, so the wait ends on the first poll instead of polling a
    setting that cannot work until Max Wait (sec)."""
    from hegemony_probe_net.http_health import HttpHealthProbe
    from hegemony_probe_net.tcp_connect import TcpConnectProbe
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    probes = {"tcp_connect": TcpConnectProbe(), "http_health": HttpHealthProbe()}

    class _BundledProbes(_FakeProbes):
        async def run_probe(self, check_type, address, options):
            self.calls.append((check_type, address, dict(options)))
            return await probes[check_type].execute(address, options)

    services = _BundledProbes()
    config = {"check_type": check_type, "max_wait_seconds": 300, "socks_proxy": "socks5://dind"}
    ctx = _ip_target_ctx(config, ["192.0.2.7"], services=services)
    result = await asyncio.wait_for(WaitReachableHandler().execute(ctx), timeout=5)
    assert result.success is False
    assert result.error == (
        f"{check_type} cannot run against 192.0.2.7: socks_proxy requires host and port "
        "(e.g. socks5://user:pass@dind:1080)"
    )
    assert len(services.calls) == 1


async def test_wait_reachable_measures_each_target_up_to_its_own_answer():
    """A slow poll of one target must not count toward another's window.

    Polled one after another, both targets answer at 0 s. In the second
    round 192.0.2.7 answers at 1 s and 192.0.2.8 at 2.5 s. The round ends
    2.5 s after the first answers, but 192.0.2.7's answers span only 1 s of
    the 2 s window, so the wait needs a third round.
    """
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    class _SlowSecondPoll(_FakeProbes):
        async def run_probe(self, check_type, address, options):
            polls = sum(1 for call in self.calls if call[1] == address)
            if address == "192.0.2.8" and polls == 1:
                await asyncio.sleep(1.5)
            return await super().run_probe(check_type, address, options)

    probes = _SlowSecondPoll()
    config = {
        "max_wait_seconds": 10,
        "stable_seconds": 2,
        "poll_interval": 1,
        "max_parallel_devices": 1,
    }
    ctx = _ip_target_ctx(config, ["192.0.2.7", "192.0.2.8"], services=probes)
    result = await WaitReachableHandler().execute(ctx)
    assert result.success is True, result.error
    assert result.metrics["attempts"] == 3


async def test_http_probe_brackets_ipv6_literals_and_gates_every_hop(monkeypatch):
    """IPv6 authorities are bracketed, and each request walks the egress gate."""
    import httpx

    from hegemony_steps_probe import http_check
    from hegemony_steps_probe.http_check import HttpProbeHandler

    seen_urls: list[str] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        """Record each URL the client actually sends and answer 200."""
        seen_urls.append(str(request.url))
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(transport_handler)
    real_client = httpx.AsyncClient

    def client_with_mock_transport(**kwargs):
        """The handler's own client, rerouted through the mock transport."""
        kwargs["transport"] = transport
        return real_client(**kwargs)

    monkeypatch.setattr(http_check.httpx, "AsyncClient", client_with_mock_transport)

    gated: list[tuple[str, int]] = []

    class _Services:
        async def enforce_egress(self, host, port, *, proto, kind):
            gated.append((host, port))

    handler = HttpProbeHandler()
    ctx = _ip_target_ctx(
        {"scheme": "http", "path": "/health", "port": 8080},
        ["2001:db8::7"],
        services=_Services(),
    )
    result = await handler.execute(ctx)
    assert result.success is True, result.error
    assert seen_urls == ["http://[2001:db8::7]:8080/health"]
    # The gate saw the unbracketed host with the effective port.
    assert gated == [("2001:db8::7", 8080)]


async def test_http_probe_fails_only_the_target_whose_request_cannot_be_made(monkeypatch):
    """Only an IPv6 address is bracketed, and a URL that does not parse, or a
    request that raises something other than an httpx.HTTPError, fails that
    target alone: the others are still requested and keep their evidence."""
    import httpx

    from hegemony_steps_probe import http_check
    from hegemony_steps_probe.http_check import HttpProbeHandler

    sent: list[str] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        """Answer 200, except for the host whose transport breaks."""
        if request.url.host == "192.0.2.66":
            raise ValueError("transport broke")
        sent.append(str(request.url))
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(transport_handler)
    real_client = httpx.AsyncClient

    def client_with_mock_transport(**kwargs):
        """The handler's own client, rerouted through the mock transport."""
        kwargs["transport"] = transport
        return real_client(**kwargs)

    monkeypatch.setattr(http_check.httpx, "AsyncClient", client_with_mock_transport)

    hosts = {
        "v4": "192.0.2.1",
        "v6": "2001:db8::7",
        "bracketed": "[2001:db8::8]",
        "host_port": "192.0.2.5:8443",
        "broken": "192.0.2.66",
    }
    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"path": "/health", "port": 8080, "max_parallel_devices": 5},
        target_roles=["primary"],
        target_devices_by_role={
            "primary": [{"name": name, "mgmt_host": host} for name, host in hosts.items()]
        },
        services=cast(HandlerServices, type("_Services", (), {})()),
    )
    result = await HttpProbeHandler().execute(ctx)

    assert result.success is False
    assert sorted(sent) == [
        "http://192.0.2.1:8080/health",
        "http://[2001:db8::7]:8080/health",
        "http://[2001:db8::8]:8080/health",
    ]
    assert result.error == (
        "Failed: host_port (invalid URL http://192.0.2.5:8443:8080/health: "
        "Invalid port: '8443:8080'), broken (ValueError: transport broke)"
    )
    assert result.summary == "http GET /health: 3/5 targets OK"
    assert [e["name"] for e in result.evidence] == [f"http_{name}" for name in hosts]
    assert [e["content_json"]["success"] for e in result.evidence] == [
        True,
        True,
        True,
        False,
        False,
    ]


async def test_http_probe_refuses_a_redirect_to_a_denied_destination(monkeypatch):
    """A redirect must not launder a denied destination through an allowed
    first hop: the request hook walks every hop past the gate, and the denial
    propagates as the policy's reason instead of a failed check."""
    import httpx

    from hegemony_steps_probe import http_check
    from hegemony_steps_probe.http_check import HttpProbeHandler

    sent: list[str] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        """First hop redirects to a host the policy denies."""
        sent.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://198.51.100.99/steal"})

    transport = httpx.MockTransport(transport_handler)
    real_client = httpx.AsyncClient

    def client_with_mock_transport(**kwargs):
        """The handler's own client, rerouted through the mock transport."""
        kwargs["transport"] = transport
        return real_client(**kwargs)

    monkeypatch.setattr(http_check.httpx, "AsyncClient", client_with_mock_transport)

    class _Denied(Exception):
        pass

    class _Services:
        async def enforce_egress(self, host, port, *, proto, kind):
            if host == "198.51.100.99":
                raise _Denied(f"{kind} to {host} refused by the flow egress policy")

    handler = HttpProbeHandler()
    ctx = _ip_target_ctx(
        {"scheme": "http", "path": "/", "follow_redirects": True},
        ["192.0.2.1"],
        services=_Services(),
    )
    with pytest.raises(_Denied):
        await handler.execute(ctx)
    # The redirected request was never sent — only the allowed first hop was.
    assert sent == ["http://192.0.2.1/"]


async def test_execute_cli_connects_with_the_device_platform():
    """netcli.execute forwards each device's platform to services.connect.

    Transports pick their driver from the spec's platform (scrapli especially),
    so falling back to the ios-xe default for every device — the old behavior —
    would drive non-IOS-XE devices with the wrong driver.
    """
    from hegemony_steps_netcli.execute import ExecuteCLIActionHandler

    class _Result:
        command = "show version"
        output = "ok"
        exit_code = 0
        error = None
        latency_ms = 1.0

    class _Transport:
        async def execute_commands(self, commands):
            return [_Result() for _ in commands]

    connects: list[str | None] = []

    class _Services:
        def connect(self, device, *, platform=None, **kwargs):
            connects.append(platform)
            return _Transport()

    handler = ExecuteCLIActionHandler()
    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"commands": ["show version"]},
        target_roles=["primary"],
        target_devices_by_role={
            "primary": [{"id": "d1", "name": "eos1", "mgmt_host": "192.0.2.1", "platform": "eos"}]
        },
        services=cast(HandlerServices, _Services()),
    )
    result = await handler.execute(ctx)
    assert result.success is True
    assert connects == ["eos"]


def _netcli_ctx(services: Any, **config: Any) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"commands": ["show version"], **config},
        target_roles=["primary"],
        target_devices_by_role={"primary": [{"id": "d1", "name": "r1", "mgmt_host": "192.0.2.1"}]},
        services=cast(HandlerServices, services),
    )


class _RecordingConnects:
    """services.connect stand-in recording its keyword arguments."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def connect(self, device, **kwargs):
        self.calls.append(kwargs)

        class _Result:
            command = "show version"
            output = "ok"
            exit_code = 0
            error = None
            latency_ms = 1.0

        class _Transport:
            async def execute_commands(self, commands):
                return [_Result() for _ in commands]

        return _Transport()


def _netcli_handlers() -> list[BaseHandler]:
    from hegemony_steps_netcli.collect_evidence import CollectEvidenceHandler
    from hegemony_steps_netcli.execute import ExecuteCLIActionHandler

    return [ExecuteCLIActionHandler(), CollectEvidenceHandler()]


@pytest.mark.parametrize("handler", _netcli_handlers(), ids=lambda h: h.handler_id)
async def test_netcli_sessions_register_for_cancellation(handler: BaseHandler):
    """The step run id reaches services.connect, so cancelling the run closes
    the device session instead of leaving it running."""
    services = _RecordingConnects()
    result = await handler.execute(_netcli_ctx(services))
    assert result.success is True, result.error
    assert [call["step_run_id"] for call in services.calls] == ["sr"]


@pytest.mark.parametrize("handler", _netcli_handlers(), ids=lambda h: h.handler_id)
def test_netcli_steps_target_roles_only(handler: BaseHandler):
    # A device session needs the login details only inventory devices carry,
    # so the editor offers no additional-IP list for these steps.
    assert handler.targeting.roles is True and handler.targeting.ips is False


@pytest.mark.parametrize("handler", _netcli_handlers(), ids=lambda h: h.handler_id)
@pytest.mark.parametrize(
    ("config", "expected"), [({}, 30.0), ({"command_timeout_seconds": 600}, 600.0)]
)
async def test_netcli_command_timeout_reaches_connect(
    handler: BaseHandler, config: dict[str, Any], expected: float
):
    services = _RecordingConnects()
    result = await handler.execute(_netcli_ctx(services, **config))
    assert result.success is True, result.error
    assert [call["command_timeout"] for call in services.calls] == [expected]


@pytest.mark.parametrize("handler", _netcli_handlers(), ids=lambda h: h.handler_id)
def test_netcli_command_timeout_is_bounded(handler: BaseHandler):
    config = {"commands": ["show version"]}
    assert handler.validate_config({**config, "command_timeout_seconds": 3600}) == []
    assert handler.validate_config({**config, "command_timeout_seconds": 0})
    assert handler.validate_config({**config, "command_timeout_seconds": 3601})
