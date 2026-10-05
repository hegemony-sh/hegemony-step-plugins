# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Registration and metadata smoke tests for the handler wheels.

Deep behavioral coverage for these handlers lives in the platform repo (which
exercises them through the installed wheels with host-bound services); this
suite pins what the wheels themselves own: per-wheel handler sets, namespace
discipline, metadata, and config schemas.
"""

import json
from typing import Any, cast

import pytest

import hegemony_steps_cisco_iosxe
import hegemony_steps_container
import hegemony_steps_evidence
import hegemony_steps_flow
import hegemony_steps_general
import hegemony_steps_monitor
import hegemony_steps_netcli
import hegemony_steps_probe
import hegemony_steps_shell
from hegemony_step_sdk import BaseHandler, HandlerContext, HandlerServices, StepKind

# module, claimed namespace prefix (= entry-point name), expected handler ids
WHEELS = [
    (hegemony_steps_general, "general", {"general.noop", "general.sleep"}),
    (
        hegemony_steps_probe,
        "probe",
        {"probe.connectivity", "probe.wait_reachable", "probe.http", "probe.dns"},
    ),
    (
        hegemony_steps_netcli,
        "netcli",
        {"netcli.execute", "netcli.collect_evidence"},
    ),
    (hegemony_steps_evidence, "evidence", {"evidence.assert", "evidence.compare"}),
    (hegemony_steps_container, "container", {"container.run", "container.build"}),
    (hegemony_steps_shell, "shell", {"shell.execute"}),
    (hegemony_steps_flow, "flow", {"flow.run", "flow.notify", "flow.git_sync"}),
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
    (
        hegemony_steps_monitor,
        "monitor",
        {"monitor.connectivity", "monitor.start", "monitor.stop"},
    ),
]

HIDDEN_IDS = {"general.noop", "flow.git_sync", "monitor.start", "monitor.stop"}


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


async def test_wait_reachable_accepts_ip_targets(monkeypatch):
    """Reachability needs an address, not a device record."""
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    handler = WaitReachableHandler()

    async def always_up(host, port, timeout):
        assert host == "192.0.2.7"
        return True

    monkeypatch.setattr(handler, "_check_tcp", always_up)
    # Bare services: no enforce_egress bound, as in a host without the gate.
    # stable_seconds stays within the config model's ge=1 bound so the test
    # exercises a config real step validation would accept.
    ctx = _ip_target_ctx(
        {"max_wait_seconds": 10, "stable_seconds": 1, "poll_interval": 1},
        ["192.0.2.7"],
        services=type("_Services", (), {})(),
    )
    result = await handler.execute(ctx)
    assert result.success is True, result.error
    assert [e["device_id"] for e in result.evidence] == [None]
    assert "target(s) stable" in (result.summary or "")


async def test_check_tcp_handles_an_ipv6_literal_without_raising():
    """An IPv6 direct target is a reachability question, not a crash.

    The old AF_INET socket raised on a v6 literal before the connect ever
    ran; the family-agnostic path must return a plain bool even on hosts
    whose kernel lacks IPv6 entirely.
    """
    from hegemony_steps_probe.wait_reachable import WaitReachableHandler

    handler = WaitReachableHandler()
    reachable = await handler._check_tcp("2001:db8::7", 22, 0.2)
    assert reachable is False


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
