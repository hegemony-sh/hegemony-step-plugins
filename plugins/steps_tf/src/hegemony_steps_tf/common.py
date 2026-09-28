# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What ``tf.plan`` and ``tf.apply`` share: engines, images, files, scripts.

OpenTofu and Terraform read the same ``.tf`` files and share plan/apply
semantics, so one namespace serves both; the engine is a config field.

A saved plan can only be applied by the same tool version, in the same working
directory (same lock file, providers installed). So the plan step keeps its
working directory in the run's shared workspace, ``/shared/tf/<plan step id>``,
and the apply step runs in it with the image the plan used.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal

from pydantic import Field

from hegemony_step_sdk import HandlerContext, StateBackendAccess
from hegemony_steps_container.run import RunContainerHandler
from hegemony_steps_container.runner import (
    OUTPUT_DIR,
    ContainerExecutionConfig,
    StagedFile,
    container_config_from,
    resolve_secret_values,
    secret_map_errors,
)

logger = logging.getLogger(__name__)

Engine = Literal["opentofu", "terraform"]
StateMode = Literal["managed", "backend", "ephemeral"]

LockTimeout = Annotated[
    str,
    Field(
        title="Lock timeout",
        description="How long to wait for the state lock (-lock-timeout), e.g. 300s or 5m.",
        json_schema_extra={"x_advanced": True},
    ),
]

#: Exact, immutable default images. OpenTofu's image has sh and bash (its docs
#: prefer copying the binary into your own image — images/opentofu-runner does
#: that); HashiCorp's has busybox sh. Both run as root.
DEFAULT_IMAGES: dict[str, str] = {
    "opentofu": "ghcr.io/opentofu/opentofu:1.12.6",
    "terraform": "hashicorp/terraform:1.16.4",
}
BINARIES: dict[str, str] = {"opentofu": "tofu", "terraform": "terraform"}

ATTACHMENTS_ROOT = "/attachments"
SHARED_ROOT = "/shared"
TF_ROOT = "/hegemony/tf"
RUN_SCRIPT = f"{TF_ROOT}/run.sh"
SECRET_ENV_FILE = f"{TF_ROOT}/secret.env"
BACKEND_OVERRIDE_FILE = f"{TF_ROOT}/zz_hegemony_backend_override.tf"
BACKEND_CONFIG_FILE = f"{TF_ROOT}/backend.hcl"
VARS_FILE = f"{TF_ROOT}/vars.tfvars.json"
SECRET_VARS_FILE = f"{TF_ROOT}/secret-vars.tfvars.json"
PLAN_FILE = "plan.tfplan"
#: Appended to a plan's summary when its readable plan could not be kept.
PLAN_TEXT_MISSING_NOTE = " (the readable plan could not be collected)"
#: Harvested as downloadable run artifacts after the container exits (the
#: runner's new-artifacts folder), for files that must outlive the run workspace.
KEEP_DIR = "/hegemony/keep"

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_VAR_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")
_BACKEND_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ADDRESS_RE = re.compile(r"^[^\s'\"]+$")

#: pbkdf2 key provider minimum (OpenTofu refuses shorter passphrases).
MIN_ENCRYPTION_PASSPHRASE = 16

#: Managed state names, as the platform accepts them.
STATE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
#: Backend overrides: ``*_override.tf`` replaces any backend (or cloud) block,
#: and works when the configuration declares none.
HTTP_BACKEND_OVERRIDE = 'terraform {\n  backend "http" {}\n}\n'
LOCAL_BACKEND_OVERRIDE = 'terraform {\n  backend "local" {}\n}\n'
#: How long state access outlives the step's own timeout (image pull, cleanup).
STATE_ACCESS_MARGIN_SECONDS = 600
#: The longest state access the platform grants (its run tokens' maximum life).
MAX_STATE_ACCESS_SECONDS = 86400
#: The longest step timeout that state access can cover, margin included.
MAX_MANAGED_STATE_TIMEOUT = MAX_STATE_ACCESS_SECONDS - STATE_ACCESS_MARGIN_SECONDS


class TfContainerConfig(ContainerExecutionConfig):
    """Fields both steps share: provider credentials and the image override."""

    secret_env: dict[str, str] = Field(
        default_factory=dict,
        title="Secret environment",
        description=(
            "NAME=secret reference, one per line, exported to the tool's process only "
            "(provider credentials such as AWS_SECRET_ACCESS_KEY). A reference is a "
            "{{ secret('...') }} template or a bare reference such as "
            "vault://orgs/acme/secrets/aws/key. Values are redacted from output and "
            "never appear in the container's metadata."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "AWS_SECRET_ACCESS_KEY=vault://orgs/acme/secrets/aws/secret-key",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )


def default_image(engine: str) -> str:
    return DEFAULT_IMAGES.get(engine, DEFAULT_IMAGES["opentofu"])


def workdir_for(step_id: str) -> str:
    """The plan step's working directory inside the run's shared workspace."""
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", step_id) or "plan"
    if not safe.strip("."):
        # "." and ".." would name /shared/tf or /shared itself, which the plan
        # script empties first.
        safe = "_" + safe
    return f"{SHARED_ROOT}/tf/{safe}"


def shared_workspace_mounted(ctx: HandlerContext) -> bool:
    """Whether the run's shared workspace is mounted into this step's container.

    The runner mounts it only for a step with shared (or explicit) execution
    affinity on a worker with shared workspaces enabled. Without it, a plan's
    working directory disappears with its container.
    """
    if not ctx.shared_workspace:
        return False
    return bool(ctx.require_services().container_runtime().shared_workspaces_enabled)


def relative_path_error(field_name: str, value: object, *, allow_empty: bool = False) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return (
            None
            if allow_empty and value in ("", None)
            else f"'{field_name}' must be a relative path"
        )
    path = value.strip()
    if path.startswith("/") or "\\" in path or "\0" in path:
        return f"'{field_name}' must be a relative path among the flow attachments"
    if ".." in path.split("/"):
        return f"'{field_name}' must not contain '..'"
    return None


def env_map_errors(field_name: str, value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, dict):
        return [f"'{field_name}' must be an object of NAME=value"]
    errors = []
    for name, raw in value.items():
        if not isinstance(name, str) or not _ENV_NAME_RE.match(name):
            errors.append(f"'{field_name}' name {name!r} is not a valid environment variable")
        elif name.startswith("HEGEMONY_") or name.startswith("TF_HTTP_"):
            errors.append(f"'{field_name}' name {name!r} is reserved")
        elif not isinstance(raw, str) or not raw.strip():
            errors.append(f"'{field_name}.{name}' must be a non-empty string")
    return errors


def variable_map_errors(field_name: str, value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, dict):
        return [f"'{field_name}' must be an object of NAME=value"]
    return [
        f"'{field_name}' name {name!r} is not a valid variable name"
        for name in value
        if not isinstance(name, str) or not _VAR_NAME_RE.match(name)
    ]


def address_list_errors(field_name: str, value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        return [f"'{field_name}' must be a list of resource addresses"]
    return [
        f"'{field_name}[{index}]' must be one resource address without spaces or quotes"
        for index, item in enumerate(value)
        if not isinstance(item, str) or not _ADDRESS_RE.match(item.strip())
    ]


def state_name_errors(value: object) -> list[str]:
    if not isinstance(value, str) or not STATE_NAME_RE.match(value.strip()):
        return [
            "'state_name' is required for managed state: 1-128 letters, digits, '.', '_' "
            "or '-', starting with a letter or digit"
        ]
    return []


def state_backend_env(access: StateBackendAccess) -> dict[str, str]:
    """The ``http`` backend settings, for the sourced env file (never container env)."""
    return {
        "TF_HTTP_ADDRESS": access.address,
        "TF_HTTP_LOCK_ADDRESS": access.lock_address,
        "TF_HTTP_UNLOCK_ADDRESS": access.unlock_address,
        "TF_HTTP_LOCK_METHOD": access.lock_method,
        "TF_HTTP_UNLOCK_METHOD": access.unlock_method,
        "TF_HTTP_USERNAME": access.username,
        "TF_HTTP_PASSWORD": access.password,
    }


def container_timeout(ctx: HandlerContext, config: ContainerExecutionConfig) -> int:
    """How long the step's container may run, resolved once for the container and its state access.

    The step's own ``timeout_seconds`` when it sets one, else the step timeout the
    host resolved (the step's policy, the flow's default, the handler's default),
    which is what the runner falls back to. The config model's own default must
    not stand in for an absent value: state access granted for that would end
    while the container still runs.
    """
    if "timeout_seconds" in config.model_fields_set:
        return config.timeout_seconds
    return ctx.timeout_seconds


@asynccontextmanager
async def managed_state_access(
    ctx: HandlerContext, name: str | None, timeout_seconds: int
) -> AsyncIterator[StateBackendAccess | None]:
    """Access to the platform-managed state ``name`` for one step (None: not managed).

    ``timeout_seconds`` is the container's own (see :func:`container_timeout`).
    """
    if not name:
        yield None
        return
    ttl = timeout_seconds + STATE_ACCESS_MARGIN_SECONDS
    if ttl > MAX_STATE_ACCESS_SECONDS:
        # The step's own timeout is validated (managed_timeout_errors); one from its
        # policy or the flow is not, and the platform refuses a longer grant.
        ttl = MAX_STATE_ACCESS_SECONDS
        message = (
            f"Managed state access for {name!r} is limited to {MAX_STATE_ACCESS_SECONDS} s; "
            f"the step may run for {timeout_seconds} s, and state access ends first"
        )
        logger.warning(message, extra={"run_id": ctx.run_id, "step_run_id": ctx.step_run_id})
        await ctx.emit_progress(message)
    async with ctx.require_services().open_state_backend(name, ttl_seconds=ttl) as access:
        yield access


def managed_timeout_errors(value: object) -> list[str]:
    """A step timeout longer than managed state access can last."""
    try:
        seconds = int(str(value))
    except (TypeError, ValueError):
        return []
    if seconds > MAX_MANAGED_STATE_TIMEOUT:
        return [
            f"'timeout_seconds' must be at most {MAX_MANAGED_STATE_TIMEOUT} with managed "
            f"state: state access lasts at most {MAX_STATE_ACCESS_SECONDS} s, including a "
            f"{STATE_ACCESS_MARGIN_SECONDS} s margin"
        ]
    return []


def secret_env_errors(value: object) -> list[str]:
    return secret_map_errors("secret_env", value) + env_map_errors("secret_env", value)


def lock_timeout_errors(value: object) -> list[str]:
    lock_timeout = str(value or "300s")
    if not lock_timeout[:-1].isdigit() or lock_timeout[-1] not in "sm":
        return ["'lock_timeout' must look like 300s or 5m"]
    return []


def common_errors(config: dict[str, Any]) -> list[str]:
    """Checks shared by both steps: lock timeout, credentials, the container half."""
    errors = lock_timeout_errors(config.get("lock_timeout"))
    errors += secret_env_errors(config.get("secret_env"))
    image = config.get("image") or default_image(str(config.get("engine") or "opentofu"))
    errors.extend(
        RunContainerHandler().validate_config(
            container_config_from(config, image=str(image), command=[])
        )
    )
    return errors


async def secret_environment(
    ctx: HandlerContext,
    secret_env: dict[str, str],
    encryption_key: str,
    access: StateBackendAccess | None = None,
) -> list[StagedFile]:
    """The sourced env file: provider credentials, managed-state access, TF_ENCRYPTION."""
    values = await resolve_secret_values(ctx, secret_env, source="tf.secret_env")
    if access is not None:
        values.update(state_backend_env(access))
    if encryption_key.strip():
        resolved = await resolve_secret_values(
            ctx, {"key": encryption_key}, source="tf.state_encryption_key"
        )
        passphrase = resolved["key"]
        if len(passphrase) < MIN_ENCRYPTION_PASSPHRASE:
            raise ValueError(
                f"the state encryption key must be at least {MIN_ENCRYPTION_PASSPHRASE} characters"
            )
        values["TF_ENCRYPTION"] = encryption_hcl(passphrase)
    return [secret_env_file(values)] if values else []


def typed_variable(value: str) -> Any:
    """A variable value as JSON when it is a JSON list/object/number/bool, else the string.

    Lets a flow pass ``["r1","r2"]`` to a ``list(string)`` variable; the tool
    converts a number or bool to a string variable on its own.
    """
    stripped = value.strip()
    if stripped[:1] in {"[", "{"} or stripped in {"true", "false"}:
        try:
            return json.loads(stripped)
        except ValueError:
            return value
    return value


def hcl_string(value: str) -> str:
    """A quoted HCL string literal with template sequences escaped."""
    return json.dumps(value).replace("${", "$${").replace("%{", "%%{")


def backend_config_file(values: dict[str, str]) -> StagedFile:
    lines = [f"{key} = {hcl_string(value)}" for key, value in sorted(values.items())]
    return StagedFile(BACKEND_CONFIG_FILE, "\n".join(lines) + "\n")


def backend_config_errors(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, dict):
        return ["'backend_config' must be an object of KEY=value"]
    return [
        f"'backend_config' key {key!r} is not a valid backend setting name"
        for key in value
        if not isinstance(key, str) or not _BACKEND_KEY_RE.match(key)
    ]


def encryption_hcl(passphrase: str) -> str:
    """``TF_ENCRYPTION`` for OpenTofu: state and saved plans encrypted, enforced."""
    return (
        'key_provider "pbkdf2" "hegemony" { passphrase = ' + hcl_string(passphrase) + " }\n"
        'method "aes_gcm" "hegemony" { keys = key_provider.pbkdf2.hegemony }\n'
        "state { method = method.aes_gcm.hegemony\n  enforced = true\n}\n"
        "plan { method = method.aes_gcm.hegemony\n  enforced = true\n}\n"
        "remote_state_data_sources { default { method = method.aes_gcm.hegemony } }\n"
    )


def secret_env_file(values: dict[str, str]) -> StagedFile:
    """Shell ``export`` lines sourced by the run script (never container env)."""
    lines = [f"export {name}={shlex.quote(value)}" for name, value in sorted(values.items())]
    return StagedFile(SECRET_ENV_FILE, "\n".join(lines) + "\n")


#: How both tools start the error for a state lock they could not take.
LOCK_ERROR_MARKER = "Error acquiring the state lock"
#: A holder line of the "Lock Info:" block the tools print after it.
_LOCK_INFO_LINE_RE = re.compile(r"^[\s│|]*(Who|Info):[ \t]*(\S.*?)\s*$", re.MULTILINE)


def lock_conflict_error(tool: str, lock_timeout: str, stdout: str, stderr: str) -> str | None:
    """The step error for a state lock held by someone else, naming the holder.

    The holder is whatever the tool printed from the lock: ``Who`` (user and
    host of the holding process) and ``Info`` (the platform fills it with the
    holding run and step for managed state).
    """
    for text in (stderr, stdout):
        start = text.find(LOCK_ERROR_MARKER)
        if start < 0:
            continue
        holder: dict[str, str] = {}
        for key, value in _LOCK_INFO_LINE_RE.findall(text[start : start + 4000]):
            holder.setdefault(key, value[:200])
        details = ", ".join(f"{key}: {holder[key]}" for key in ("Info", "Who") if key in holder)
        return (
            f"{tool} could not acquire the state lock within {lock_timeout or '300s'}"
            + (f"; it is held by {details}" if details else "")
            + "; see the container output"
        )
    return None


def tool_env() -> dict[str, str]:
    """Environment for either tool: non-interactive, no telemetry, no color."""
    return {
        "TF_IN_AUTOMATION": "1",
        "TF_INPUT": "0",
        "CHECKPOINT_DISABLE": "1",
    }


def script_header() -> list[str]:
    return [
        "#!/bin/sh",
        "# Generated by the tf step.",
        "set -eu",
        "umask 077",
        f"if [ -f {SECRET_ENV_FILE} ]; then . {SECRET_ENV_FILE}; fi",
        f"mkdir -p {OUTPUT_DIR}",
    ]
