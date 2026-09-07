# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SDK contract surface tests.

Pins the public API plugin authors rely on; the host keeps a mirror parity
test so the duck-typed platform registry and this SDK stay in lock-step.
"""

import inspect

import hegemony_step_sdk as sdk


def test_public_surface():
    for name in (
        "BaseHandler",
        "CommandResult",
        "ContainerRuntime",
        "HandlerContext",
        "HandlerResult",
        "HandlerServices",
        "HandlerTargeting",
        "StepHandlerRegistry",
        "StepKind",
        "Transport",
        "ShellResult",
        "ShellTransport",
        "BaseProbe",
        "ProbeResult",
        "ProbeRegistry",
        "MAX_CHAIN_OUTPUT_CHARS",
        "DEFAULT_DEVICE_PLATFORM",
        "SDK_ABI_VERSION",
        "STEP_HANDLER_ENTRY_POINT_GROUP",
        "PROBE_ENTRY_POINT_GROUP",
        "resolve_target_devices_for_roles",
    ):
        assert hasattr(sdk, name), name


def test_entry_point_group_and_abi():
    assert sdk.STEP_HANDLER_ENTRY_POINT_GROUP == "hegemony.step_handlers"
    assert sdk.PROBE_ENTRY_POINT_GROUP == "hegemony.probes"
    assert sdk.SDK_ABI_VERSION == 1


def test_handler_services_declares_run_probe():
    assert list(inspect.signature(sdk.HandlerServices.run_probe).parameters) == [
        "self",
        "check_type",
        "address",
        "options",
    ]


def test_handler_services_declares_monitor_methods():
    for name in ("is_check_registered", "start_monitor", "stop_monitor"):
        assert hasattr(sdk.HandlerServices, name), name
    assert list(inspect.signature(sdk.HandlerServices.start_monitor).parameters) == [
        "self",
        "config",
        "resolved_targets",
        "run_id",
        "step_id",
        "step_run_id",
        "phase",
    ]


def test_probe_registry_protocol_shape():
    assert list(inspect.signature(sdk.ProbeRegistry.register_probe).parameters) == [
        "self",
        "probe_class",
    ]


def test_device_connection_spec_repr_hides_secrets():
    spec = sdk.DeviceConnectionSpec(host="h", username="u", password="pw", enable_secret="en")
    rendered = repr(spec)
    assert "pw" not in rendered
    assert "en" not in rendered
    assert "u" in rendered  # username stays visible for debugging


def test_step_kind_values():
    assert {kind.value for kind in sdk.StepKind} == {
        "CHECK",
        "ACTION",
        "WAIT",
        "TRANSFER",
        "EXECUTE",
    }
    # str-enum: values compare equal to plain strings across enum copies
    assert sdk.StepKind.CHECK == "CHECK"


def test_handler_context_binds_services():
    ctx = sdk.HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        phase="EXECUTE",
        kind="ACTION",
    )
    try:
        ctx.require_services()
    except RuntimeError as exc:
        assert "services" in str(exc)
    else:
        raise AssertionError("require_services must fail when unbound")


def test_handler_context_carries_the_step_tags():
    """Handlers read the step's tags off the context; the map defaults to empty.

    The host feature-detects this field before passing it, so it must be a
    real dataclass field with a default rather than a property.
    """
    import dataclasses

    names = {f.name for f in dataclasses.fields(sdk.HandlerContext)}
    assert "tags" in names

    bare = sdk.HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        phase="",
        kind="",
    )
    assert bare.tags == {}

    tagged = sdk.HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        phase="VERIFY",
        kind="CHECK",
        tags={"phase": "VERIFY", "kind": "CHECK", "env": "prod"},
    )
    assert tagged.tags["env"] == "prod"
    # Each context gets its own map: a handler mutating one never leaks into another.
    bare.tags["leak"] = "no"
    assert (
        "leak"
        not in sdk.HandlerContext(
            run_id="r", flow_id="f", step_run_id="sr", step_id="s", phase="", kind=""
        ).tags
    )


def test_handler_context_keeps_positional_bindings():
    """``tags`` is declared last so a positional caller binds nothing differently.

    Regression for the field being inserted mid-list, which would have handed
    ``target_devices_by_role`` to ``tags`` for anyone building the context
    positionally.
    """
    by_role = {"core": [{"id": "d1"}]}
    positional = sdk.HandlerContext(
        "r", "f", "sr", "s", "VERIFY", "CHECK", "Flow", "Run", by_role, ["core"]
    )
    assert positional.target_devices_by_role is by_role
    assert positional.target_roles == ["core"]
    assert positional.tags == {}
    assert positional.get_target_devices() == [{"id": "d1"}]
    assert [f.name for f in __import__("dataclasses").fields(sdk.HandlerContext)][-1] == "tags"


def test_registry_protocol_shape():
    signature = inspect.signature(sdk.StepHandlerRegistry.register_handler_type)
    assert list(signature.parameters) == ["self", "handler_class"]


def test_base_handler_validates_with_config_model():
    from pydantic import BaseModel

    class Config(BaseModel):
        name: str

    class Handler(sdk.BaseHandler):
        handler_id = "test.handler"
        supported_kinds = [sdk.StepKind.ACTION]
        config_model = Config

        async def execute(self, ctx):  # pragma: no cover - not executed
            return sdk.HandlerResult(success=True)

    handler = Handler()
    assert handler.validate_config({"name": "x"}) == []
    errors = handler.validate_config({})
    assert errors and errors[0].startswith("name:")


def test_command_label_shortens_script_shaped_commands():
    """Artifact display names derived from commands stay one line and bounded."""
    from hegemony_step_sdk import command_label

    assert command_label("show version") == "show version"
    # First non-empty line only
    assert command_label("uname -a\nid\nuptime") == "uname -a"
    # Long one-liners get ellipsized within the cap
    long_cmd = 'FAIL=0; for t in 10.101.1.10 10.104.1.10; do ping -c 3 -W 2 "$t" || FAIL=1; done; exit $FAIL'
    label = command_label(long_cmd)
    assert len(label) <= 80
    assert label.endswith("…")
    assert label.startswith("FAIL=0; for t in")
    assert command_label("   ") == ""
