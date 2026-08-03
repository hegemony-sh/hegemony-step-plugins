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
        {"netcli.execute", "netcli.collect_evidence", "netcli.poll_until"},
    ),
    (hegemony_steps_evidence, "evidence", {"evidence.assert", "evidence.compare"}),
    (hegemony_steps_container, "container", {"container.run"}),
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
        phase="VERIFY",
        kind="CHECK",
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
        phase="VERIFY",
        kind="CHECK",
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
        phase="VERIFY",
        kind="CHECK",
        config={"check_type": "tls_handshake", "port": 443},
        target_roles=["primary"],
        target_devices_by_role={"primary": [{"id": "d1", "name": "r1", "mgmt_host": "192.0.2.1"}]},
        services=cast(HandlerServices, _Services()),
    )
    result = await handler.execute(ctx)
    assert result.success is False
    assert "not available" in (result.error or "")


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
        phase="EXECUTE",
        kind="ACTION",
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
