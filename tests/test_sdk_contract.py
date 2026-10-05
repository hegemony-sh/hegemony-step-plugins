# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SDK contract surface tests.

Pins the public API plugin authors rely on; the host keeps a mirror parity
test so the duck-typed platform registry and this SDK stay in lock-step.
"""

import dataclasses
import inspect
from typing import Any

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
        "DeviceCredentials",
        "StateBackendAccess",
        "ImageCache",
        "ImageBuild",
        "BUILD_NETWORK_DEFAULT",
        "BUILD_NETWORK_NONE",
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


def test_handler_services_declares_resolve_device_credentials():
    assert list(inspect.signature(sdk.HandlerServices.resolve_device_credentials).parameters) == [
        "self",
        "device",
    ]


def test_device_credentials_keep_secrets_out_of_repr():
    creds = sdk.DeviceCredentials(
        username="admin",
        password="pw-value",
        private_key="KEY-VALUE",
        enable_password="enable-value",
        jump_host=sdk.JumpHostSpec(host="bastion", password="jump-pw"),
    )
    text = repr(creds)
    assert "admin" in text
    for secret in ("pw-value", "KEY-VALUE", "enable-value", "jump-pw"):
        assert secret not in text


def test_container_backed_defaults_off():
    assert sdk.BaseHandler.container_backed is False
    assert sdk.BaseHandler.platform_api_access is False
    assert sdk.BaseHandler.node_scoped_state is False
    assert sdk.BaseHandler.builds_images is False


def test_handler_services_declares_open_state_backend():
    parameters = inspect.signature(sdk.HandlerServices.open_state_backend).parameters
    assert list(parameters) == ["self", "name", "ttl_seconds", "hold_until_apply"]
    # Added later: optional, so a host implementing only the first three still fits.
    assert parameters["hold_until_apply"].default is False
    assert parameters["hold_until_apply"].kind is inspect.Parameter.KEYWORD_ONLY


def test_state_backend_access_keeps_the_token_out_of_repr():
    access = sdk.StateBackendAccess(
        address="http://api:8000/tf-states/core/state",
        lock_address="http://api:8000/tf-states/core/lock",
        unlock_address="http://api:8000/tf-states/core/lock",
        username="run",
        password="hgm_run_secret-value",
    )
    assert "secret-value" not in repr(access)
    assert (access.lock_method, access.unlock_method) == ("POST", "DELETE")


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
    ctx = sdk.HandlerContext(run_id="r", flow_id="f", step_run_id="sr", step_id="s")
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
    names = {f.name for f in dataclasses.fields(sdk.HandlerContext)}
    assert "tags" in names

    bare = sdk.HandlerContext(run_id="r", flow_id="f", step_run_id="sr", step_id="s")
    assert bare.tags == {}

    tagged = sdk.HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        tags={"phase": "VERIFY", "kind": "CHECK", "env": "prod"},
    )
    assert tagged.tags["env"] == "prod"
    # phase and kind are read the way every other tag is.
    assert tagged.tags.get("phase", "") == "VERIFY"
    assert bare.tags.get("phase", "") == ""
    # Each context gets its own map: a handler mutating one never leaks into another.
    bare.tags["leak"] = "no"
    assert (
        "leak"
        not in sdk.HandlerContext(run_id="r", flow_id="f", step_run_id="sr", step_id="s").tags
    )


def test_handler_context_has_no_phase_or_kind_field():
    """``phase`` and ``kind`` exist only as keys of ``tags``.

    The context declares no field for either, so a handler still reading
    ``ctx.phase`` fails loudly instead of seeing a second, possibly stale,
    copy of the tag.
    """
    names = {f.name for f in dataclasses.fields(sdk.HandlerContext)}
    assert "phase" not in names
    assert "kind" not in names


def test_handler_context_keeps_positional_bindings():
    """A positional caller binds the run ids, then the two names, then the targets.

    Regression for a field sliding in ahead of ``target_devices_by_role``,
    which would hand the device map to the wrong attribute for anyone
    building the context positionally.
    """
    by_role = {"core": [{"id": "d1"}]}
    positional = sdk.HandlerContext("r", "f", "sr", "s", "Flow", "Run", by_role, ["core"])
    assert positional.step_id == "s"
    assert positional.flow_name == "Flow"
    assert positional.run_name == "Run"
    assert positional.target_devices_by_role is by_role
    assert positional.target_roles == ["core"]
    assert positional.tags == {}
    assert positional.get_target_devices() == [{"id": "d1"}]


def test_container_runtime_requires_the_sandbox_daemon():
    """``docker_host`` has no default: a host must name the sandbox daemon.

    The old empty default meant "inherit the worker's environment", which is
    the worker's own Docker daemon. ``container.run`` refuses that now, so a
    host that leaves the field out gets a TypeError naming ``docker_host``
    where it constructs the runtime, and a type checker flags the call,
    instead of handing the plugin an empty value to refuse.
    """
    field = next(f for f in dataclasses.fields(sdk.ContainerRuntime) if f.name == "docker_host")
    assert field.default is dataclasses.MISSING
    assert field.default_factory is dataclasses.MISSING

    # Typed Any: leaving the argument out is the point of the call.
    construct: Any = sdk.ContainerRuntime
    try:
        construct(
            docker_bin="docker",
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
        )
    except TypeError as exc:
        assert "docker_host" in str(exc)
    else:
        raise AssertionError("ContainerRuntime must require docker_host")


def test_container_runtime_docker_config_dir_defaults_to_empty():
    """The step's Docker configuration directory is optional.

    A host older than the field constructs the runtime without it and the
    handler keeps inheriting the worker's configuration (anonymous pulls);
    only a non-empty value redirects ``DOCKER_CONFIG``.
    """
    field = next(
        f for f in dataclasses.fields(sdk.ContainerRuntime) if f.name == "docker_config_dir"
    )
    assert field.default == ""
    runtime = sdk.ContainerRuntime(
        docker_bin="docker",
        shared_workspaces_enabled=False,
        shared_workspace_root="",
        shared_workspace_volume="",
        docker_host="tcp://dind:2375",
    )
    assert runtime.docker_config_dir == ""


def test_container_runtime_image_cache_defaults_to_none():
    """The platform registry is optional and arrives as one structured value.

    A host without a registry constructs the runtime without ``image_cache``
    and every image is pulled from its own registry; a host with one passes
    an :class:`ImageCache` whose write namespace is required and whose
    read-only namespaces default to none.
    """
    field = next(f for f in dataclasses.fields(sdk.ContainerRuntime) if f.name == "image_cache")
    assert field.default is None
    runtime = sdk.ContainerRuntime(
        docker_bin="docker",
        shared_workspaces_enabled=False,
        shared_workspace_root="",
        shared_workspace_volume="",
        docker_host="tcp://dind:2375",
    )
    assert runtime.image_cache is None

    cache = sdk.ImageCache(
        registry="registry.hegemony.internal",
        api_url="http://registry.hegemony.internal",
        namespace="orgs/acme",
    )
    assert cache.read_namespaces == ()
    assert [f.name for f in dataclasses.fields(sdk.ImageCache)] == [
        "registry",
        "api_url",
        "namespace",
        "read_namespaces",
    ]
    with_cache = dataclasses.replace(runtime, image_cache=cache)
    assert with_cache.image_cache is cache


def test_container_runtime_image_build_defaults_to_none():
    """A step that may push what it builds gets one structured value; nobody else does.

    A host older than the field constructs the runtime without it, and a
    building handler then fails with a clear message instead of pushing
    somewhere it was not granted. The network defaults to none: a host that
    names no network gives the build none (fail closed). A host older than
    ``push`` served the value only with a push grant, so it defaults to True;
    one older than ``external_push`` allowed no other registry, so that
    defaults to False (fail closed).
    """
    field = next(f for f in dataclasses.fields(sdk.ContainerRuntime) if f.name == "image_build")
    assert field.default is None
    runtime = sdk.ContainerRuntime(
        docker_bin="docker",
        shared_workspaces_enabled=False,
        shared_workspace_root="",
        shared_workspace_volume="",
        docker_host="tcp://dind:2375",
    )
    assert runtime.image_build is None

    build = sdk.ImageBuild(registry="registry.hegemony.internal", namespace="orgs/acme")
    assert build.network == sdk.BUILD_NETWORK_NONE == "none"
    assert sdk.BUILD_NETWORK_DEFAULT == "default"
    assert build.push is True
    assert build.external_push is False
    assert [f.name for f in dataclasses.fields(sdk.ImageBuild)] == [
        "registry",
        "namespace",
        "network",
        "push",
        "external_push",
    ]
    with_build = dataclasses.replace(runtime, image_build=build)
    assert with_build.image_build is build


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
