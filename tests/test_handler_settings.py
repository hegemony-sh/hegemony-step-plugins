# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Step settings: one source for names, defaults and time limits.

A handler's ``config_model`` is what the editor shows and the reference docs
list, so the handler must run with the model's values: its defaults, the old
names a renamed field still accepts, and the field the platform reads for the
handler's own time limit (``run_timeout_field``).
"""

from __future__ import annotations

import ast
import asyncio
import importlib.metadata
import inspect
from types import SimpleNamespace
from typing import Any, cast, get_args

import pytest
from pydantic import AliasChoices, BaseModel
from pydantic_core import PydanticUndefined

from hegemony_step_sdk import (
    STEP_HANDLER_ENTRY_POINT_GROUP,
    BaseHandler,
    HandlerContext,
    HandlerServices,
    ProbeResult,
)


class _Registry:
    api_version = 1

    def __init__(self) -> None:
        self.handlers: list[type[BaseHandler]] = []

    def register_handler_type(self, handler_class: type) -> None:
        assert issubclass(handler_class, BaseHandler)
        self.handlers.append(handler_class)


def _all_handlers() -> list[type[BaseHandler]]:
    registry = _Registry()
    for entry_point in importlib.metadata.entry_points(group=STEP_HANDLER_ENTRY_POINT_GROUP):
        entry_point.load()(registry)
    return sorted(registry.handlers, key=lambda cls: cls.handler_id)


HANDLERS = _all_handlers()
MODELLED = [cls for cls in HANDLERS if cls.config_model is not None]


def _model(cls: type[BaseHandler]) -> type[BaseModel]:
    assert cls.config_model is not None
    return cls.config_model


def _accepted_names(field: Any) -> list[str]:
    alias = field.validation_alias
    if isinstance(alias, AliasChoices):
        return [choice for choice in alias.choices if isinstance(choice, str)]
    return [alias] if isinstance(alias, str) else []


def _legacy_fields() -> list[tuple[str, type[BaseModel], str, str]]:
    found = []
    for cls in MODELLED:
        model = _model(cls)
        for name, field in model.model_fields.items():
            extra = field.json_schema_extra if isinstance(field.json_schema_extra, dict) else {}
            for legacy in cast(list[str], extra.get("x_legacy_keys") or []):
                found.append((cls.handler_id, model, name, legacy))
    return found


def test_every_handler_wheel_is_scanned():
    ids = {cls.handler_id for cls in HANDLERS}
    assert {"general.sleep", "shell.execute", "tf.apply", "ansible.playbook"} <= ids


@pytest.mark.parametrize(
    ("handler_id", "model", "name", "legacy"),
    _legacy_fields(),
    ids=[f"{h}:{legacy}" for h, _, _, legacy in _legacy_fields()],
)
def test_a_legacy_key_the_editor_shows_is_one_the_handler_reads(handler_id, model, name, legacy):
    """The editor shows a step saved under ``legacy`` in field ``name``; the handler must agree."""
    default = model.model_fields[name].default
    value = default + 1 if isinstance(default, int) and not isinstance(default, bool) else 7
    parsed = model.model_validate({legacy: value})
    assert getattr(parsed, name) == value
    # Both present: the current name wins.
    both = model.model_validate({legacy: value, name: default})
    assert getattr(both, name) == default


@pytest.mark.parametrize("cls", MODELLED, ids=lambda cls: cls.handler_id)
def test_the_schema_names_each_field_by_its_current_name(cls):
    model = _model(cls)
    properties = model.model_json_schema()["properties"]
    assert set(properties) == set(model.model_fields)
    for name, field in model.model_fields.items():
        names = _accepted_names(field)
        if names:
            # The platform reads raw step config by the field's name.
            assert names[0] == name, f"{cls.handler_id}.{name}: {names}"


@pytest.mark.parametrize("cls", MODELLED, ids=lambda cls: cls.handler_id)
def test_a_new_step_is_seeded_with_current_names(cls):
    model = _model(cls)
    assert set(cls.default_config) <= set(model.model_fields), cls.handler_id


EXPECTED_RUN_TIMEOUT_FIELDS = {
    "ansible.playbook": "timeout_seconds",
    "cisco.iosxe.upgrade.verify": "max_wait_seconds",
    "container.run": "timeout_seconds",
    "general.noop": "delay_seconds",
    "general.sleep": "duration_seconds",
    "probe.wait_reachable": "max_wait_seconds",
    "tf.apply": "timeout_seconds",
    "tf.plan": "timeout_seconds",
}


def test_handlers_that_enforce_their_own_limit_declare_it():
    declared = {cls.handler_id: cls.run_timeout_field for cls in HANDLERS if cls.run_timeout_field}
    assert declared == EXPECTED_RUN_TIMEOUT_FIELDS


@pytest.mark.parametrize(
    "cls", [cls for cls in HANDLERS if cls.run_timeout_field], ids=lambda cls: cls.handler_id
)
def test_a_run_timeout_field_is_a_number_of_seconds_in_the_model(cls):
    field = _model(cls).model_fields[cast(str, cls.run_timeout_field)]
    kinds = set(get_args(field.annotation)) or {field.annotation}
    assert kinds - {type(None)} <= {int, float}, field.annotation
    margin = cls.run_timeout_margin_seconds
    assert isinstance(margin, int) and not isinstance(margin, bool) and margin >= 0


def _model_default(model: type[BaseModel], key: str) -> tuple[bool, Any]:
    """Whether ``key`` names a field with a default, and that default."""
    for name, field in model.model_fields.items():
        if key == name or key in _accepted_names(field):
            if field.default_factory is not None:
                return True, cast(Any, field.default_factory)()
            # A required field has no default for a fallback to disagree with.
            return field.default is not PydanticUndefined, field.default
    return False, None


def _literal(node: ast.expr) -> tuple[bool, Any]:
    try:
        return True, ast.literal_eval(node)
    except ValueError:
        return False, None


def _config_get_fallbacks(source: str) -> list[tuple[int, str, ast.expr]]:
    """``config.get("key", fallback)`` and ``config.get("key") or fallback`` calls."""

    def config_get_key(node: ast.AST) -> str | None:
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            return None
        owner = node.func.value
        if (isinstance(owner, ast.Attribute) and owner.attr == "config") or (
            isinstance(owner, ast.Name) and owner.id == "config"
        ):
            return node.args[0].value
        return None

    found = []
    for node in ast.walk(ast.parse(source)):
        key = config_get_key(node)
        if key is not None and isinstance(node, ast.Call) and len(node.args) > 1:
            found.append((node.lineno, key, node.args[1]))
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
            key = config_get_key(node.values[0])
            if key is not None:
                found.append((node.lineno, key, node.values[-1]))
    return found


@pytest.mark.parametrize("cls", MODELLED, ids=lambda cls: cls.handler_id)
def test_a_handler_falls_back_to_its_model_defaults(cls):
    """A raw-config fallback that differs from the model runs with a value the editor never shows."""
    model = _model(cls)
    module = inspect.getmodule(cls)
    assert module is not None
    source = inspect.getsource(module)
    wrong = []
    for line, key, fallback in _config_get_fallbacks(source):
        has_default, default = _model_default(model, key)
        is_literal, value = _literal(fallback)
        if has_default and is_literal and value != default and not (value is None and not default):
            wrong.append(
                f"line {line}: {key!r} falls back to {value!r}, the model says {default!r}"
            )
    assert not wrong, f"{cls.handler_id}: {wrong}"


# --- general ----------------------------------------------------------------


def _ctx(config: dict[str, Any], **kwargs: Any) -> HandlerContext:
    return HandlerContext(
        run_id="run-1",
        flow_id="flow-1",
        step_run_id="sr-1",
        step_id="step",
        config=config,
        **kwargs,
    )


@pytest.fixture
def slept(monkeypatch) -> list[float]:
    import hegemony_steps_general.noop as noop_module
    import hegemony_steps_general.sleep as sleep_module

    calls: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        calls.append(seconds)

    fake = SimpleNamespace(sleep=fake_sleep)
    monkeypatch.setattr(sleep_module, "asyncio", fake)
    monkeypatch.setattr(noop_module, "asyncio", fake)
    return calls


@pytest.mark.parametrize(
    ("config", "seconds", "summary"),
    [
        # The editor's default, not a failure, when the duration is left out.
        ({}, 30, "Sleeping for 30 seconds"),
        ({"duration_seconds": "5"}, 5, "Sleeping for 5 seconds"),
        # The name steps saved before the rename carry.
        ({"seconds": 12, "message": "settle"}, 12, "settle"),
        ({"duration_seconds": 3, "message": ""}, 3, "Sleeping for 3 seconds"),
    ],
)
async def test_sleep_runs_with_the_model_values(slept, config, seconds, summary):
    from hegemony_steps_general.sleep import SleepHandler

    result = await SleepHandler().execute(_ctx(config))
    assert result.success is True, result.error
    assert slept == [seconds]
    assert result.summary == summary
    assert result.metrics == {"sleep_seconds": seconds}


@pytest.mark.parametrize("config", [{"duration_seconds": 0}, {"seconds": "soon"}])
async def test_sleep_refuses_a_duration_it_cannot_use(slept, config):
    from hegemony_steps_general.sleep import SleepHandler

    result = await SleepHandler().execute(_ctx(config))
    assert result.success is False
    assert (result.error or "").startswith("Invalid general.sleep config:")
    assert slept == []


async def test_noop_takes_a_rendered_delay(slept):
    from hegemony_steps_general.noop import NoOpHandler

    result = await NoOpHandler().execute(_ctx({"delay_seconds": "2"}))
    assert result.success is True
    assert slept == [2]


# --- shell.execute ----------------------------------------------------------


class _Shell:
    def __init__(self, delay: float = 0.0) -> None:
        self.delay = delay
        self.runs: list[tuple[str, float | None]] = []

    async def run(self, command: str, *, timeout: float | None = None) -> Any:
        self.runs.append((command, timeout))
        if self.delay:
            await asyncio.sleep(self.delay)
        return SimpleNamespace(command=command, exit_code=0, stdout="ok", stderr="")

    async def close(self) -> None:
        return None


def _shell_ctx(config: dict[str, Any], shell: _Shell, *, timeout: int = 300) -> HandlerContext:
    class _Services:
        async def open_shell(self, device, **kwargs):
            return shell

    return _ctx(
        config,
        target_roles=["hosts"],
        target_devices_by_role={"hosts": [{"id": "d1", "name": "h1", "mgmt_host": "192.0.2.1"}]},
        services=cast(HandlerServices, _Services()),
        timeout_seconds=timeout,
    )


@pytest.mark.parametrize(
    ("config", "limit"),
    [
        ({}, 60),
        ({"command_timeout_seconds": 120}, 120),
        ({"command_timeout_sec": 90}, 90),
    ],
)
async def test_shell_gives_each_command_its_limit(config, limit):
    from hegemony_steps_shell.execute import ShellExecuteHandler

    shell = _Shell()
    result = await ShellExecuteHandler().execute(
        _shell_ctx({"commands": ["uptime"], **config}, shell)
    )
    assert result.success is True, result.error
    assert [timeout for _, timeout in shell.runs] == [pytest.approx(limit)]


async def test_shell_cuts_a_command_limit_to_the_step_timeout():
    from hegemony_steps_shell.execute import REPORT_MARGIN_SECONDS, ShellExecuteHandler

    shell = _Shell()
    ctx = _shell_ctx({"commands": ["uptime"], "command_timeout_seconds": 600}, shell, timeout=40)
    result = await ShellExecuteHandler().execute(ctx)
    assert result.success is True, result.error
    ((_, timeout),) = shell.runs
    assert (
        timeout is not None
        and 40 - REPORT_MARGIN_SECONDS - 1 < timeout <= 40 - REPORT_MARGIN_SECONDS
    )


async def test_shell_does_not_start_a_command_once_the_step_timeout_is_near():
    from hegemony_steps_shell.execute import REPORT_MARGIN_SECONDS, ShellExecuteHandler

    shell = _Shell()
    ctx = _shell_ctx({"commands": ["one", "two"]}, shell, timeout=REPORT_MARGIN_SECONDS)
    result = await ShellExecuteHandler().execute(ctx)
    assert result.success is False
    assert shell.runs == []
    assert "the step's timeout ran out before 'one'" in (result.error or "")


async def test_shell_takes_a_number_as_an_environment_value():
    from hegemony_steps_shell.execute import ShellExecuteHandler

    shell = _Shell()
    ctx = _shell_ctx({"commands": ['echo "$PORT"'], "env": {"PORT": 8080}}, shell)
    result = await ShellExecuteHandler().execute(ctx)
    assert result.success is True, result.error
    assert shell.runs[0][0] == 'export PORT=8080; echo "$PORT"'


# --- probes and the monitor ---------------------------------------------------


class _Probes:
    def __init__(self) -> None:
        self.options: list[dict[str, Any]] = []

    async def run_probe(self, check_type: str, address: str, options: dict[str, Any]) -> Any:
        self.options.append(options)
        return ProbeResult(ok=True)


def _probe_ctx(config: dict[str, Any], services: Any) -> HandlerContext:
    return _ctx(
        config,
        target_roles=["core"],
        target_devices_by_role={"core": [{"id": "d1", "name": "r1", "mgmt_host": "192.0.2.9"}]},
        services=cast(HandlerServices, services),
    )


@pytest.mark.parametrize(
    ("config", "timeout_ms"),
    [({}, 10_000), ({"attempt_timeout_seconds": 3}, 3_000), ({"timeout_sec": "4"}, 4_000)],
)
async def test_connectivity_probe_reads_its_attempt_timeout(config, timeout_ms):
    from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

    probes = _Probes()
    result = await ConnectivityCheckHandler().execute(_probe_ctx(config, probes))
    assert result.success is True, result.error
    assert [options["timeout_ms"] for options in probes.options] == [timeout_ms]


async def test_connectivity_probe_requests_health_for_an_empty_url_path():
    from hegemony_steps_probe.connectivity import ConnectivityCheckHandler

    probes = _Probes()
    config = {"check_type": "http_health", "url_path": ""}
    await ConnectivityCheckHandler().execute(_probe_ctx(config, probes))
    assert probes.options[0]["url_path"] == "/health"


async def test_dns_probe_reads_its_attempt_timeout(monkeypatch):
    import hegemony_steps_probe.dns_check as dns_module

    budgets: list[float] = []

    async def fake_resolve(query_name, record_type, *, resolver_ip="", timeout_sec=5.0):
        budgets.append(timeout_sec)
        return ["192.0.2.10"]

    monkeypatch.setattr(dns_module, "resolve_records", fake_resolve)
    config = {"query_name": "svc.example", "timeout_sec": 7, "expected_values": ["192.0.2.10"]}
    result = await dns_module.DnsProbeHandler().execute(_probe_ctx(config, _Probes()))
    assert result.success is True, result.error
    assert budgets == [7.0]


def test_http_probe_reads_a_rendered_switch_and_its_old_timeout_name():
    from hegemony_steps_probe.http_check import HttpProbeConfig, HttpProbeHandler

    config = {"verify_tls": "false", "timeout_sec": 4, "expected_status": 200}
    parsed = HttpProbeHandler().parse_config(config, HttpProbeConfig)
    assert parsed.verify_tls is False
    assert parsed.attempt_timeout_seconds == 4
    assert parsed.expected_status == "200"


@pytest.mark.parametrize(
    ("config", "max_wait", "poll"),
    [
        ({}, 300, 5),
        ({"max_wait": 900, "check_interval": 10}, 900, 10),
        ({"max_wait_seconds": 60, "poll_interval": 2}, 60, 2),
        ({"poll_interval_seconds": 3, "poll_interval": 9}, 300, 3),
    ],
)
def test_wait_reachable_reads_every_name_the_editor_shows(config, max_wait, poll):
    from hegemony_steps_probe.wait_reachable import WaitReachableConfig

    parsed = WaitReachableConfig.model_validate(config)
    assert (parsed.max_wait_seconds, parsed.poll_interval_seconds) == (max_wait, poll)


def test_wait_reachable_no_longer_shows_a_stability_count_as_seconds():
    from hegemony_steps_probe.wait_reachable import WaitReachableConfig

    prop = WaitReachableConfig.model_json_schema()["properties"]["stable_seconds"]
    assert "x_legacy_keys" not in prop
    assert WaitReachableConfig.model_validate({"stability_checks": 3}).stable_seconds == 30


class _Monitors:
    def __init__(self) -> None:
        self.configs: list[dict[str, Any]] = []

    def is_check_registered(self, check_id: str) -> bool:
        return True

    async def start_monitor(self, config, resolved_targets, **kwargs) -> str:
        self.configs.append(config)
        return "db-1"


@pytest.mark.parametrize(
    "config",
    [
        {"schedule_mode": "duration", "duration_seconds": 120, "attempt_timeout_seconds": 3},
        {"schedule_mode": "duration", "duration_sec": 120, "timeout_sec": 3},
    ],
)
async def test_monitor_reads_current_and_old_names(config):
    from hegemony_steps_monitor.handlers import ConnectivityMonitorHandler

    monitors = _Monitors()
    result = await ConnectivityMonitorHandler().execute(_probe_ctx(config, monitors))
    assert result.success is True, result.error
    (started,) = monitors.configs
    assert started["schedule"] == {
        "schedule_mode": "duration",
        "interval_ms": 5000,
        "duration_s": 120,
    }
    assert started["options"]["timeout_ms"] == 3000


async def test_monitor_refuses_an_invalid_setting():
    from hegemony_steps_monitor.handlers import ConnectivityMonitorHandler

    monitors = _Monitors()
    result = await ConnectivityMonitorHandler().execute(_probe_ctx({"interval_ms": 10}, monitors))
    assert result.success is False
    assert (result.error or "").startswith("Invalid monitor.connectivity config: interval_ms")
    assert monitors.configs == []


def test_verify_reads_its_old_retry_interval_name():
    from hegemony_steps_cisco_iosxe.upgrade.handlers.verify import UpgradeVerifyConfig

    assert UpgradeVerifyConfig.model_validate({"retry_interval": 45}).poll_interval_seconds == 45


# --- container-backed steps ---------------------------------------------------


@pytest.mark.parametrize(
    ("requested", "step_timeout", "expected"),
    [(None, 300, 300), (120, 300, 120), (900, 960, 900), (900, 300, 300), (0, 300, 300)],
)
def test_a_container_never_runs_past_the_step_timeout(requested, step_timeout, expected):
    from hegemony_steps_container.runner import step_container_timeout

    ctx = _ctx({}, timeout_seconds=step_timeout)
    assert step_container_timeout(ctx, requested) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), ("", None), (600, 600), ("600", 600), ("{{ x }}", None), (True, None)],
)
def test_requested_timeout_reads_validated_values(value, expected):
    from hegemony_steps_container.runner import requested_timeout

    assert requested_timeout(value) == expected


async def test_a_cut_timeout_is_reported_in_the_step_events():
    from hegemony_steps_container.runner import report_timeout_cut

    events: list[tuple[str, dict[str, Any] | None]] = []

    async def emit(message, device_id=None, attrs=None):
        events.append((message, attrs))
        return True

    ctx = _ctx({}, timeout_seconds=300, _emit_progress=emit)
    await report_timeout_cut(ctx, 300, 300)
    await report_timeout_cut(ctx, None, 300)
    assert events == []
    await report_timeout_cut(ctx, 900, 300)
    ((message, attrs),) = events
    assert "900 s" in message and "300 s" in message
    assert attrs == {"milestone": "timeout_cut", "requested_seconds": 900, "timeout_seconds": 300}


@pytest.mark.parametrize(
    ("value", "valid"),
    [(None, True), ("", True), (60, True), ("60", True), (0, False), ("soon", False)],
)
def test_container_run_checks_its_timeout(value, valid):
    from hegemony_steps_container.run import RunContainerHandler

    errors = RunContainerHandler().validate_config({"image": "alpine:3", "timeout_seconds": value})
    assert (not errors) is valid, errors


@pytest.mark.parametrize(
    ("model_path", "field"),
    [
        ("hegemony_steps_container.run:RunContainerConfig", "timeout_seconds"),
        ("hegemony_steps_container.runner:ContainerExecutionConfig", "timeout_seconds"),
    ],
)
def test_an_empty_container_timeout_means_the_step_timeout(model_path, field):
    module_name, _, class_name = model_path.partition(":")
    model = getattr(__import__(module_name, fromlist=[class_name]), class_name)
    assert model.model_fields[field].default is None
