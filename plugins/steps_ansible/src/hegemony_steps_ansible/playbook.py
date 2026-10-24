# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``ansible.playbook``: run an Ansible playbook against the step's target devices.

The inventory comes from Hegemony's own inventory — the step's target devices,
grouped by flow role, platform, site, tag, and provider — so a playbook needs no
hand-kept hosts file. Device credentials, secrets, and Ansible Vault passwords
are resolved on the worker, redacted from output, and handed to Ansible as
files inside the step's container, never as environment variables or
arguments. Results come back per device.

The playbook runs in a container on the platform's sandbox through
``container.run``'s runner, so the flow's egress policy applies to it exactly as
to any container step.
"""

from __future__ import annotations

import json
import posixpath
import re
import shlex
import time
from typing import Any, Literal

from pydantic import Field

from hegemony_step_sdk import (
    BaseHandler,
    DeviceCredentials,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)
from hegemony_steps_container.run import RunContainerHandler
from hegemony_steps_container.runner import (
    OUTPUT_DIR,
    SECRET_NAME_RE,
    ContainerExecutionConfig,
    ContainerJob,
    StagedFile,
    container_config_from,
    deadline_shell_lines,
    resolve_secret_values,
    run_container_job,
    secret_map_errors,
    step_container_timeout,
)

from .inventory import (
    DEVICE_ANSIBLE_VARS_ALLOWED,
    GROUP_DIMENSIONS,
    GroupDimension,
    Inventory,
    InventoryHost,
    build_inventory,
    is_plain_host,
    literal,
    management_address,
)
from .results import (
    CALLBACK_NAME,
    CALLBACK_SOURCE,
    EXIT_CODE_MEANINGS,
    RESULTS_FILE,
    PlaybookResults,
    parse_results,
    render_host_report,
)

#: First-party execution image: ansible-core, libssh, sshpass, and the common
#: network collections. Built from images/ansible-runner in this repository; the
#: Images workflow publishes it for every release as X.Y.Z and X.Y, and the tag
#: here names this release's minor version (scripts/set_version.py moves it).
DEFAULT_IMAGE = "ghcr.io/hegemony-sh/ansible-runner:0.33"

ATTACHMENTS_ROOT = "/attachments"
ANSIBLE_ROOT = "/hegemony/ansible"
INVENTORY_DIR = f"{ANSIBLE_ROOT}/inventory"
INVENTORY_FILE = f"{INVENTORY_DIR}/hosts.json"
CALLBACK_DIR = f"{ANSIBLE_ROOT}/callback_plugins"
EXTRA_VARS_FILE = f"{ANSIBLE_ROOT}/extra_vars.json"
SECRETS_FILE = f"{ANSIBLE_ROOT}/secrets.json"
VAULT_DIR = f"{ANSIBLE_ROOT}/vault"
KEYS_STAGE_DIR = f"{ANSIBLE_ROOT}/keys"
RUN_SCRIPT = f"{ANSIBLE_ROOT}/run.sh"
# Written by run.sh as the container's own user: OpenSSH ignores a private key
# that another user could read, and staged files are root-owned 0644.
PRIVATE_DIR = "/tmp/hegemony-ansible"
KEYS_DIR = f"{PRIVATE_DIR}/keys"
KNOWN_HOSTS_FILE = f"{PRIVATE_DIR}/known_hosts"

#: Largest step output kept whole; bigger fleets lose the per-host map first.
MAX_OUTPUT_BYTES = 48 * 1024
MAX_OUTPUT_HOST_NAMES = 500

_GROUP_SECRET_KEY_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):([A-Za-z_][A-Za-z0-9_]*)$")
_VAULT_LABEL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_ANSIBLE_TAG_RE = re.compile(r"^[^\s,]+$")
# Jump host fields end up in a ProxyCommand that OpenSSH and libssh run through
# /bin/sh, and they come from device records (an inventory source can set them):
# only plain host names, IP addresses (is_plain_host) and user names are accepted.
_JUMP_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._@+-]{0,63}$")

HostKeyChecking = Literal["accept_new", "strict", "off"]


class AnsiblePlaybookConfig(ContainerExecutionConfig):
    """Config for ``ansible.playbook``."""

    playbook: str = Field(
        min_length=1,
        title="Playbook",
        description=(
            "Path of the playbook among the flow attachments, e.g. site.yml or "
            "ansible/site.yml. It runs from its own folder, so roles/, group_vars/ "
            "and ansible.cfg next to it are picked up."
        ),
        json_schema_extra={"x_placeholder": "site.yml"},
    )
    limit: str = Field(
        default="",
        title="Limit",
        description="Optional host pattern passed to --limit, e.g. a group name or host name.",
        json_schema_extra={"x_placeholder": "site_emea"},
    )
    check_mode: bool = Field(
        default=False,
        title="Check mode (dry run)",
        description=(
            "Run with --check: report what would change without changing anything. "
            "Combine with Show differences to review changes before approving a real run."
        ),
    )
    diff: bool = Field(
        default=False,
        title="Show differences",
        description="Run with --diff so changed files and configuration show before/after.",
    )
    tags: list[str] = Field(
        default_factory=list,
        title="Tags",
        description="Only run tasks with these tags (--tags), one per line.",
        json_schema_extra={"x_widget": "commands", "x_rows": 2, "x_advanced": True},
    )
    skip_tags: list[str] = Field(
        default_factory=list,
        title="Skip tags",
        description="Skip tasks with these tags (--skip-tags), one per line.",
        json_schema_extra={"x_widget": "commands", "x_rows": 2, "x_advanced": True},
    )
    extra_vars: dict[str, str] = Field(
        default_factory=dict,
        title="Extra variables",
        description=(
            "NAME=value, one per line, passed as extra variables (highest precedence). "
            "Values may use templates such as {{ inputs.service }}; Ansible reads the "
            "result as plain text and does not template it again."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "service_name={{ inputs.service_name }}",
            "x_rows": 3,
            "x_col_span": 2,
        },
    )
    secrets: dict[str, str] = Field(
        default_factory=dict,
        title="Secrets",
        description=(
            "NAME=secret reference, one per line: a {{ secret('...') }} template or a "
            "bare reference such as vault://orgs/acme/secrets/db/password. Each becomes "
            "the Ansible variable NAME, passed from a file (never an environment "
            "variable or argument) and redacted from output."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "db_password=vault://orgs/acme/secrets/db/password",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    group_secrets: dict[str, str] = Field(
        default_factory=dict,
        title="Group secrets",
        description=(
            "GROUP:NAME=secret reference, one per line: the variable NAME for hosts in "
            "inventory group GROUP only, e.g. site_emea:api_key=vault://…"
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "site_emea:api_key=vault://orgs/acme/secrets/emea/api-key",
            "x_rows": 2,
            "x_col_span": 2,
            "x_advanced": True,
        },
    )
    vault_password: str = Field(
        default="",
        title="Ansible Vault password",
        description=(
            "Secret reference holding the password for files encrypted with "
            "ansible-vault, so existing repositories run unchanged."
        ),
        json_schema_extra={
            "x_placeholder": "vault://orgs/acme/secrets/ansible/vault-password",
            "x_advanced": True,
            "x_col_span": 2,
        },
    )
    vault_ids: dict[str, str] = Field(
        default_factory=dict,
        title="Ansible Vault IDs",
        description=(
            "LABEL=secret reference, one per line, for playbooks that use several "
            "vault IDs (--vault-id LABEL@…)."
        ),
        json_schema_extra={"x_widget": "env-vars", "x_rows": 2, "x_advanced": True},
    )
    inventory_scope: Literal["step", "run"] = Field(
        default="step",
        title="Inventory scope",
        description=(
            "'step' puts the step's target devices in the inventory; 'run' puts every "
            "device the run targets, grouped by role, so plays can reach other roles."
        ),
        json_schema_extra={"x_advanced": True},
    )
    group_by: list[GroupDimension] = Field(
        default_factory=lambda: list(GROUP_DIMENSIONS),
        title="Inventory groups",
        description=(
            "Which groups to derive: role (the flow's role names), platform "
            "(platform_ios_xe), site (site_emea, site_emea_nl, …), tag "
            "(tag_env_prod), provider (provider_netbox_main)."
        ),
        json_schema_extra={"x_advanced": True},
    )
    extra_inventory: list[str] = Field(
        default_factory=list,
        title="Extra inventory files",
        description=(
            "Attachment paths of further inventory sources layered on the generated "
            "one (-i), one per line."
        ),
        json_schema_extra={"x_widget": "commands", "x_rows": 2, "x_advanced": True},
    )
    device_credentials: bool = Field(
        default=True,
        title="Use device credentials",
        description=(
            "Give Ansible each device's login from its access configuration. Turn off "
            "when the playbook brings its own credentials."
        ),
        json_schema_extra={"x_advanced": True},
    )
    host_key_checking: HostKeyChecking = Field(
        default="accept_new",
        title="Host key checking",
        description=(
            "accept_new trusts a host's key on first contact within the run and rejects "
            "a change; strict needs the keys in the image's known_hosts; off disables "
            "checking."
        ),
        json_schema_extra={"x_advanced": True},
    )
    requirements_file: str = Field(
        default="",
        title="Requirements file",
        description=(
            "Attachment path of a requirements.yml to install with ansible-galaxy before "
            "the play (roles and collections). Needs network access to the Galaxy server."
        ),
        json_schema_extra={"x_placeholder": "requirements.yml", "x_advanced": True},
    )
    forks: int | None = Field(
        default=None,
        ge=1,
        le=100,
        title="Forks",
        description=(
            "How many hosts Ansible works on in parallel (--forks). Unset, the "
            "playbook's ansible.cfg decides (Ansible's default is 5)."
        ),
        json_schema_extra={"x_placeholder": "5", "x_advanced": True},
    )
    verbosity: int = Field(
        default=0,
        ge=0,
        le=4,
        title="Verbosity",
        description="Ansible verbosity: 0 is normal, 1-4 add -v to -vvvv.",
        json_schema_extra={"x_advanced": True},
    )
    image: str = Field(
        default=DEFAULT_IMAGE,
        min_length=1,
        title="Execution image",
        description=(
            "Container image with ansible-playbook and the collections the playbook "
            "needs. Any Ansible execution environment image works."
        ),
        json_schema_extra={"x_advanced": True, "x_col_span": 2},
    )
    cache_image: bool = Field(
        default=True,
        title="Cache image",
        description=(
            "Keep a copy of the pulled image in the platform registry, under this "
            "organization, and use it on later runs. A tag is still checked against the "
            "image's registry by digest, and the copy serves when that registry is "
            "unreachable. Turn off for an image that must come straight from its registry "
            "every time. No effect when the platform runs no registry."
        ),
        json_schema_extra={"x_advanced": True},
    )


def _relative_path_error(field_name: str, value: object) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return f"'{field_name}' must be a non-empty relative path"
    path = value.strip()
    if path.startswith("/") or "\\" in path or "\0" in path:
        return f"'{field_name}' must be a relative path among the flow attachments"
    if ".." in path.split("/"):
        return f"'{field_name}' must not contain '..'"
    return None


def _host_key_ssh_args(mode: str) -> list[str]:
    """OpenSSH options for the host key mode, one argument per item."""
    if mode == "accept_new":
        return [
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            f"UserKnownHostsFile={KNOWN_HOSTS_FILE}",
        ]
    if mode == "off":
        return ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    return []


def _jump_endpoint(device: str, jump: Any) -> tuple[str, str, int]:
    """The jump host's host, user and port, refused unless each is plain."""
    host = str(jump.host or "").strip()
    if not is_plain_host(host):
        raise ValueError(
            f"device {device}: its jump host {host[:100]!r} is not a host name or IP address"
        )
    user = str(jump.username or "").strip()
    if user and not _JUMP_USER_RE.match(user):
        raise ValueError(
            f"device {device}: its jump host user name {user[:100]!r} may use only "
            "letters, digits and . _ @ + - (at most 64 characters)"
        )
    try:
        port = int(jump.port)
    except (TypeError, ValueError):
        port = 0
    if not 1 <= port <= 65535:
        raise ValueError(f"device {device}: its jump host port {jump.port!r} is not a port")
    return host, user, port


def _pem(key: str) -> str:
    return key if key.endswith("\n") else key + "\n"


def credential_host_vars(
    host: InventoryHost,
    credentials: DeviceCredentials | None,
    index: int,
    host_key_checking: str,
) -> tuple[dict[str, Any], list[StagedFile]]:
    """Connection variables for one host, and the key files they point at.

    These go into ``host_vars/<host>.json`` next to the generated inventory,
    never into the inventory document itself.
    """
    variables: dict[str, Any] = {}
    files: list[StagedFile] = []
    ssh_args = _host_key_ssh_args(host_key_checking)

    if credentials is not None:
        variables["ansible_user"] = credentials.username
        if credentials.password:
            variables["ansible_password"] = credentials.password
        if credentials.private_key:
            name = f"host-{index}.pem"
            files.append(StagedFile(f"{KEYS_STAGE_DIR}/{name}", _pem(credentials.private_key)))
            variables["ansible_ssh_private_key_file"] = f"{KEYS_DIR}/{name}"
        if credentials.enable_password and host.variables.get("ansible_network_os"):
            variables["ansible_become"] = True
            variables["ansible_become_method"] = "enable"
            variables["ansible_become_password"] = credentials.enable_password

        jump = credentials.jump_host
        if jump is not None:
            jump_host, jump_user, jump_port = _jump_endpoint(host.name, jump)
            if not jump.private_key:
                raise ValueError(
                    f"device {host.name}: its jump host {jump_host} logs in with a password "
                    "only; the Ansible step supports key-based jump hosts"
                )
            name = f"jump-{index}.pem"
            files.append(StagedFile(f"{KEYS_STAGE_DIR}/{name}", _pem(jump.private_key)))
            argv = [
                "ssh",
                "-W",
                "%h:%p",
                "-i",
                f"{KEYS_DIR}/{name}",
                "-p",
                str(jump_port),
                *_host_key_ssh_args(host_key_checking),
            ]
            if jump_user:
                argv += ["-l", jump_user]
            # Quoted for /bin/sh, which OpenSSH and libssh run it through;
            # paramiko splits it with shlex.
            proxy = shlex.join([*argv, jump_host])
            variables["ansible_libssh_proxy_command"] = proxy
            variables["ansible_paramiko_proxy_command"] = proxy
            ssh_args += ["-o", f"ProxyCommand={proxy}"]

    if ssh_args:
        # Ansible splits this with shlex before handing it to ssh.
        variables["ansible_ssh_common_args"] = shlex.join(ssh_args)
    return variables, files


def _roles_without_devices(devices_by_role: dict[str, list[dict[str, Any]]]) -> list[str]:
    """The step's target roles when none of them matched a device, else ``[]``.

    Such roles leave an inventory with no hosts: a play for them runs nowhere and
    reports nothing changed, which reads like a clean run on the devices. A play
    for localhost alone is fine, so the step reports this rather than failing.
    """
    if any(devices_by_role.values()):
        return []
    return sorted(devices_by_role)


def _ansible_env(config: AnsiblePlaybookConfig, user_env: dict[str, str]) -> dict[str, str]:
    """The ANSIBLE_* variables the step needs, and nothing more.

    Environment variables beat the repository's ``ansible.cfg``, so the step
    sets only what it cannot work without: where its results callback lives
    (added in front of any path the step's own env gives; the callback needs
    no ``callbacks_enabled`` entry, so the repository's list stands), a
    private local temp folder, the step's host key checking option, and, with
    a requirements file, writable collection and role paths.
    """
    callback_paths = [CALLBACK_DIR]
    user_paths = user_env.get("ANSIBLE_CALLBACK_PLUGINS", "")
    callback_paths.extend(item.strip() for item in user_paths.split(":") if item.strip())
    env = {
        "ANSIBLE_CALLBACK_PLUGINS": ":".join(dict.fromkeys(callback_paths)),
        "ANSIBLE_LOCAL_TEMP": f"{PRIVATE_DIR}/tmp",
    }
    checking = config.host_key_checking
    auto_add = "True" if checking == "accept_new" else "False"
    env["ANSIBLE_HOST_KEY_CHECKING"] = "False" if checking == "off" else "True"
    env["ANSIBLE_LIBSSH_HOST_KEY_AUTO_ADD"] = auto_add
    env["ANSIBLE_PARAMIKO_HOST_KEY_AUTO_ADD"] = auto_add
    env["ANSIBLE_HOST_KEY_AUTO_ADD"] = auto_add
    if config.requirements_file.strip():
        env["ANSIBLE_COLLECTIONS_PATH"] = (
            f"{PRIVATE_DIR}/collections:~/.ansible/collections:/usr/share/ansible/collections"
        )
        env["ANSIBLE_ROLES_PATH"] = (
            f"{PRIVATE_DIR}/roles:~/.ansible/roles:/usr/share/ansible/roles:/etc/ansible/roles"
        )
    return env


def build_run_script(
    config: AnsiblePlaybookConfig,
    *,
    has_extra_vars: bool,
    has_secrets: bool,
    vault_files: dict[str, str],
    deadline: int | None = None,
) -> str:
    """The container's entry script: key setup, optional Galaxy install, the play.

    With a ``deadline`` (a Unix time), the Galaxy install and the play stop by
    then, even when the worker that should stop the container is gone.
    """
    playbook = config.playbook.strip()
    playbook_dir = posixpath.join(ATTACHMENTS_ROOT, posixpath.dirname(playbook)).rstrip("/")
    args = ["ansible-playbook", "-i", INVENTORY_FILE]
    for source in config.extra_inventory:
        args += ["-i", posixpath.join(ATTACHMENTS_ROOT, source.strip())]
    if config.limit.strip():
        args += ["--limit", config.limit.strip()]
    if config.tags:
        args += ["--tags", ",".join(tag.strip() for tag in config.tags if tag.strip())]
    if config.skip_tags:
        args += ["--skip-tags", ",".join(tag.strip() for tag in config.skip_tags if tag.strip())]
    if config.check_mode:
        args.append("--check")
    if config.diff:
        args.append("--diff")
    if config.forks is not None:
        # Only when the step sets it: otherwise ansible.cfg's forks applies.
        args += ["--forks", str(config.forks)]
    if config.verbosity:
        args.append("-" + "v" * config.verbosity)
    if has_extra_vars:
        args += ["-e", f"@{EXTRA_VARS_FILE}"]
    if has_secrets:
        args += ["-e", f"@{SECRETS_FILE}"]
    for label, path in vault_files.items():
        args += (
            ["--vault-password-file", path] if label == "" else ["--vault-id", f"{label}@{path}"]
        )
    args.append(posixpath.basename(playbook))

    lines = [
        "#!/bin/sh",
        "# Generated by the ansible.playbook step.",
        "set -eu",
        "umask 077",
        f"mkdir -p {KEYS_DIR} {PRIVATE_DIR}/tmp {OUTPUT_DIR}",
        f"for key in {KEYS_STAGE_DIR}/*; do",
        '  if [ -f "$key" ]; then',
        f'    cp "$key" {KEYS_DIR}/',
        f'    chmod 600 "{KEYS_DIR}/$(basename "$key")"',
        "  fi",
        "done",
        f"cd {shlex.quote(playbook_dir)}",
    ]
    run = "exec "
    if deadline is not None:
        lines += deadline_shell_lines(deadline)
        run = "bounded "
    if config.requirements_file.strip():
        requirements = posixpath.join(ATTACHMENTS_ROOT, config.requirements_file.strip())
        galaxy = f"ansible-galaxy install -r {shlex.quote(requirements)}"
        lines.append(galaxy if deadline is None else f"bounded {galaxy}")
    lines.append(run + " ".join(shlex.quote(arg) for arg in args))
    return "\n".join(lines) + "\n"


def _parse_group_secrets(raw: dict[str, str]) -> dict[str, dict[str, str]]:
    grouped: dict[str, dict[str, str]] = {}
    for key, value in raw.items():
        match = _GROUP_SECRET_KEY_RE.match(key)
        if match is None:
            raise ValueError(f"group secret key {key!r} must be GROUP:NAME")
        grouped.setdefault(match.group(1), {})[match.group(2)] = value
    return grouped


def _json_file(path: str, payload: Any) -> StagedFile:
    return StagedFile(path, json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")


def _bounded_output(output: dict[str, Any]) -> dict[str, Any]:
    """Keep the step output small enough to chain into later steps."""
    for key in ("changed_hosts", "failed_hosts", "unreachable_hosts"):
        names = output.get(key, [])
        if len(names) > MAX_OUTPUT_HOST_NAMES:
            output[key] = names[:MAX_OUTPUT_HOST_NAMES]
            output[f"{key}_truncated"] = True
    if len(json.dumps(output, default=str)) > MAX_OUTPUT_BYTES:
        output.pop("hosts", None)
        output["hosts_truncated"] = True
    if len(json.dumps(output, default=str)) > MAX_OUTPUT_BYTES:
        output.pop("stats", None)
        output["stats_truncated"] = True
    return output


#: Host names an error lists before it abbreviates; the evidence has them all.
MAX_ERROR_HOST_NAMES = 5
MAX_ERROR_MESSAGE_CHARS = 300


def _host_list(names: list[str]) -> str:
    shown = ", ".join(names[:MAX_ERROR_HOST_NAMES])
    more = len(names) - MAX_ERROR_HOST_NAMES
    return f"{shown}, … {more} more" if more > 0 else shown


def _failure_detail(results: PlaybookResults, failed: list[str], unreachable: list[str]) -> str:
    """Which hosts failed or were unreachable, from the play recap.

    With a single failed host, its first failed task and message are added,
    so the run graph shows the cause without opening the evidence.
    """
    parts: list[str] = []
    if failed:
        part = f"{len(failed)} host(s) failed ({_host_list(failed)})"
        if len(failed) == 1:
            first = next(
                (t for t in results.tasks_for(failed[0]) if t.get("status") == "failed"), None
            )
            if first is not None:
                part += f"; task {str(first.get('task', ''))!r} failed"
                message = " ".join(str(first.get("msg") or "").split())
                if message:
                    if len(message) > MAX_ERROR_MESSAGE_CHARS:
                        message = message[: MAX_ERROR_MESSAGE_CHARS - 1] + "…"
                    part += f": {message}"
        parts.append(part)
    if unreachable:
        parts.append(f"{len(unreachable)} unreachable ({_host_list(unreachable)})")
    return "; ".join(parts)


def _explain_default_image_pull_failure(
    config: AnsiblePlaybookConfig, result: HandlerResult
) -> HandlerResult:
    """Say how to get the default image when the sandbox could not pull it."""
    if config.image.strip() != DEFAULT_IMAGE or not (result.summary or "").startswith(
        "Failed to pull image"
    ):
        return result
    result.error = (
        f"The default execution image {DEFAULT_IMAGE} could not be pulled. The release "
        "publishes it on ghcr.io: check that the sandbox's Docker daemon can reach "
        "ghcr.io (directly or through its proxy), or build it from images/ansible-runner "
        "in hegemony-step-plugins, push it to a registry the sandbox can pull from, and "
        f"set Execution image to that tag. {result.error or ''}"
    ).strip()
    return result


class AnsiblePlaybookHandler(BaseHandler):
    """Run an Ansible playbook against the step's targets, inventory generated."""

    handler_id = "ansible.playbook"
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE, StepKind.CHECK]
    display_name = "Ansible Playbook"
    description = (
        "Run an Ansible playbook against the step's target devices, with the inventory "
        "and credentials generated from Hegemony's inventory."
    )
    category = "Actions"
    targeting = HandlerTargeting(roles=True, ips=False, multi_role=True)
    container_backed = True
    # Secret references reach the handler as written (see resolve_secret_values).
    raw_config_keys = frozenset({"secrets", "group_secrets", "vault_password", "vault_ids"})
    default_timeout_seconds = 1800
    config_model = AnsiblePlaybookConfig
    default_config = {"playbook": "site.yml", "timeout_seconds": 1800}
    run_timeout_field = "timeout_seconds"

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        errors = super().validate_config(config)
        if errors:
            return errors
        for field_name in ("playbook",):
            error = _relative_path_error(field_name, config.get(field_name))
            if error:
                errors.append(error)
        requirements = config.get("requirements_file")
        if isinstance(requirements, str) and requirements.strip():
            error = _relative_path_error("requirements_file", requirements)
            if error:
                errors.append(error)
        for index, source in enumerate(config.get("extra_inventory") or []):
            error = _relative_path_error(f"extra_inventory[{index}]", source)
            if error:
                errors.append(error)
        for field_name in ("tags", "skip_tags"):
            for index, tag in enumerate(config.get(field_name) or []):
                if not isinstance(tag, str) or not _ANSIBLE_TAG_RE.match(tag.strip()):
                    errors.append(
                        f"'{field_name}[{index}]' must be one tag without spaces or commas"
                    )
        errors.extend(secret_map_errors("secrets", config.get("secrets")))
        for key in config.get("group_secrets") or {}:
            if not isinstance(key, str) or not _GROUP_SECRET_KEY_RE.match(key):
                errors.append(f"'group_secrets' key {key!r} must be GROUP:NAME")
        for label in config.get("vault_ids") or {}:
            if not isinstance(label, str) or not _VAULT_LABEL_RE.match(label):
                errors.append(f"'vault_ids' label {label!r} must use letters, digits, '_.-'")
        extra_vars = config.get("extra_vars") or {}
        for name in extra_vars:
            if not isinstance(name, str) or not SECRET_NAME_RE.match(name):
                errors.append(f"'extra_vars' name {name!r} is not a valid variable name")
        # The container half: image reference, env keys, egress rules.
        errors.extend(
            RunContainerHandler().validate_config(
                container_config_from(
                    config, image=str(config.get("image") or DEFAULT_IMAGE), command=[]
                )
            )
        )
        return errors

    def _devices_by_role(self, ctx: HandlerContext, scope: str) -> dict[str, list[dict[str, Any]]]:
        roles = list(ctx.target_devices_by_role) if scope == "run" else list(ctx.target_roles)
        return {role: list(ctx.target_devices_by_role.get(role, [])) for role in roles}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        errors = self.validate_config(ctx.config)
        if errors:
            return HandlerResult(
                success=False,
                error=f"Invalid Ansible step config: {'; '.join(errors)}",
                summary="Config validation failed",
            )
        config = AnsiblePlaybookConfig.model_validate(ctx.config)
        services = ctx.require_services()

        devices_by_role = self._devices_by_role(ctx, config.inventory_scope)
        unmatched_roles = _roles_without_devices(devices_by_role)
        if unmatched_roles:
            await ctx.emit_progress(
                "No device matched the target roles "
                f"({', '.join(unmatched_roles)}); the inventory has no hosts"
            )
        try:
            inventory = build_inventory(devices_by_role, group_by=config.group_by)
            files, inventory, left_out = await self._staged_files(ctx, config, inventory, services)
        except ValueError as exc:
            return HandlerResult(
                success=False,
                error=str(exc),
                summary="Could not prepare the Ansible run",
            )

        user_env = dict(ctx.config.get("env") or {})
        job = ContainerJob(
            config=container_config_from(
                ctx.config,
                image=config.image,
                command=[f"exec sh {RUN_SCRIPT}"],
                entrypoint="/bin/sh",
                env=_ansible_env(config, user_env),
                working_dir="/workspace",
            ),
            files=files,
            collect=[OUTPUT_DIR],
            handler_id=self.handler_id,
        )
        outcome = await run_container_job(ctx, job)
        if isinstance(outcome, HandlerResult):
            return _explain_default_image_pull_failure(config, outcome)

        return self._result(ctx, config, inventory, outcome, left_out)

    async def _staged_files(
        self,
        ctx: HandlerContext,
        config: AnsiblePlaybookConfig,
        inventory: Inventory,
        services: Any,
    ) -> tuple[list[StagedFile], Inventory, dict[str, str]]:
        """The files to stage, the inventory they describe, and the hosts left out.

        A device of one of the step's own target roles must have usable
        credentials, and a management address (when it has one) that is a
        host name or IP address. One that is in the inventory only through
        inventory scope ``run`` is left out instead (host name -> reason), so
        devices that other steps reach some other way do not block the play.
        """
        files: list[StagedFile] = [
            StagedFile(f"{CALLBACK_DIR}/{CALLBACK_NAME}.py", CALLBACK_SOURCE),
        ]
        targeted_roles = set(ctx.target_roles)
        left_out: dict[str, str] = {}
        for index, host in enumerate(inventory.hosts):
            credentials: DeviceCredentials | None = None
            try:
                address = management_address(host.device)
                if address and not is_plain_host(address):
                    raise ValueError(
                        f"device {host.name}: its management address {address[:100]!r} "
                        "is not a host name or IP address"
                    )
                if config.device_credentials:
                    try:
                        credentials = await services.resolve_device_credentials(host.device)
                    except ValueError as exc:
                        raise ValueError(f"device {host.name}: {exc}") from exc
                variables, key_files = credential_host_vars(
                    host, credentials, index, config.host_key_checking
                )
            except ValueError as exc:
                if host.roles & targeted_roles:
                    raise
                left_out[host.name] = str(exc).removeprefix(f"device {host.name}: ")
                continue
            files.extend(key_files)
            if variables:
                # Logins and passwords are data: escaped so Ansible never runs them.
                files.append(
                    _json_file(f"{INVENTORY_DIR}/host_vars/{host.name}.json", literal(variables))
                )
        if left_out:
            inventory = inventory.without(set(left_out))
        files.insert(0, _json_file(INVENTORY_FILE, inventory.document()))

        secrets = await resolve_secret_values(
            ctx, config.secrets, source="ansible.playbook.secrets"
        )
        for group, names in _parse_group_secrets(config.group_secrets).items():
            values = await resolve_secret_values(
                ctx, names, source="ansible.playbook.group_secrets"
            )
            files.append(_json_file(f"{INVENTORY_DIR}/group_vars/{group}.json", literal(values)))

        vault_secrets: dict[str, str] = {}
        if config.vault_password.strip():
            vault_secrets[""] = config.vault_password
        vault_secrets.update(config.vault_ids)
        vault_files: dict[str, str] = {}
        for index, (label, reference) in enumerate(vault_secrets.items()):
            resolved = await resolve_secret_values(
                ctx, {"vault": reference}, source="ansible.playbook.vault"
            )
            path = f"{VAULT_DIR}/password-{index}"
            # Non-executable on purpose: an executable vault file is run as a script.
            files.append(StagedFile(path, resolved["vault"] + "\n", mode=0o644))
            vault_files[label] = path

        if config.extra_vars:
            # Extra variables are data too: by now the platform has rendered
            # their templates, so a value can carry a run input or another
            # step's output, and Ansible must not template that text again.
            files.append(_json_file(EXTRA_VARS_FILE, literal(config.extra_vars)))
        if secrets:
            # Secret values are data: escaped so Ansible never runs them.
            files.append(_json_file(SECRETS_FILE, literal(secrets)))
        files.append(
            StagedFile(
                RUN_SCRIPT,
                build_run_script(
                    config,
                    has_extra_vars=bool(config.extra_vars),
                    has_secrets=bool(secrets),
                    vault_files=vault_files,
                    # The runner stops the container at this time too.
                    deadline=int(time.time()) + step_container_timeout(ctx, config.timeout_seconds),
                ),
                mode=0o755,
            )
        )
        return files, inventory, left_out

    def _result(
        self,
        ctx: HandlerContext,
        config: AnsiblePlaybookConfig,
        inventory: Inventory,
        outcome: Any,
        left_out: dict[str, str] | None = None,
    ) -> HandlerResult:
        results = parse_results(outcome.collected.get(RESULTS_FILE))
        collect_error = outcome.collect_errors.get(RESULTS_FILE) or outcome.collect_errors.get(
            OUTPUT_DIR
        )
        if collect_error and RESULTS_FILE not in outcome.collected:
            # Not "the callback wrote nothing": the copy out of the container failed.
            results.problem = (
                f"the results could not be copied out of the container ({collect_error})"
            )
        by_name = inventory.host_by_name()
        evidence: list[dict[str, Any]] = list(outcome.evidence)
        evidence.append(
            {
                "kind": "step_result",
                "name": f"ansible_inventory_{ctx.step_id}",
                "content_json": inventory.document(),
                "content_text": json.dumps(inventory.document(), indent=2, default=str) + "\n",
            }
        )
        for host_name in sorted(results.hosts):
            counts = results.hosts[host_name]
            tasks = results.tasks_for(host_name)
            item: dict[str, Any] = {
                "kind": "step_result",
                "name": f"ansible_{host_name}",
                "content_text": render_host_report(host_name, counts, tasks),
                "content_json": {"host": host_name, "counts": counts, "tasks": tasks},
            }
            host = by_name.get(host_name)
            if host is not None and host.device_id:
                item["device_id"] = host.device_id
            evidence.append(item)
        if results.problem:
            evidence.append(
                {
                    "kind": "step_result",
                    "name": f"ansible_results_missing_{ctx.step_id}",
                    "content_text": f"No structured results: {results.problem}.\n",
                }
            )
        if left_out:
            evidence.append(
                {
                    "kind": "step_result",
                    "name": f"ansible_hosts_left_out_{ctx.step_id}",
                    "content_text": (
                        "Left out of the inventory: in it only through inventory scope "
                        "'run', not a target of this step, and without usable credentials "
                        "or with a management address that is not a host name or IP "
                        "address.\n"
                        + "".join(f"- {name}: {why}\n" for name, why in sorted(left_out.items()))
                    ),
                }
            )
        ignored = [
            f"{host.name}: {', '.join(host.ignored_vars)}"
            for host in inventory.hosts
            if host.ignored_vars
        ]
        if ignored:
            evidence.append(
                {
                    "kind": "step_result",
                    "name": f"ansible_vars_ignored_{ctx.step_id}",
                    "content_text": (
                        "Warning: these keys of the devices' ansible_vars attribute were "
                        "ignored. Connection, login, become, ssh-argument, proxy and "
                        "executable variables come from Hegemony only; of the ansible_* "
                        f"variables, only {', '.join(sorted(DEVICE_ANSIBLE_VARS_ALLOWED))} "
                        "may be set there, and no value may contain template syntax "
                        "({{, {% or {#).\n" + "".join(f"- {line}\n" for line in ignored)
                    ),
                }
            )
        if results.trimmed:
            evidence.append(
                {
                    "kind": "step_result",
                    "name": f"ansible_results_trimmed_{ctx.step_id}",
                    "content_text": (
                        "The structured results were too large and left out: "
                        f"{', '.join(results.trimmed)}. The play recap is complete; "
                        "the full task output is in the container output.\n"
                    ),
                }
            )

        changed = results.hosts_where("changed")
        failed = results.hosts_where("failures")
        unreachable = results.hosts_where("unreachable")
        exit_code = outcome.exit_code
        raw_output: dict[str, Any] = {
            "exit_code": exit_code,
            "check_mode": config.check_mode,
            # Unknown (null), never a guessed "no changes", without the recap: a
            # check-mode gate branching on it must not skip an approval.
            "changed": bool(changed) if results.completed else None,
            "hosts": results.hosts,
            "changed_hosts": changed,
            "failed_hosts": failed,
            "unreachable_hosts": unreachable,
            "stats": results.custom,
        }
        if results.trimmed:
            raw_output["results_trimmed"] = results.trimmed
        output = _bounded_output(raw_output)
        mode = " (check mode)" if config.check_mode else ""
        meaning = EXIT_CODE_MEANINGS.get(exit_code, "unexpected exit code")
        error: str | None = None
        if exit_code != 0:
            detail = _failure_detail(results, failed, unreachable) if results.completed else ""
            error = f"ansible-playbook exited with code {exit_code}" + (
                f": {detail}" if detail else f" ({meaning})"
            )
        elif not results.completed:
            error = (
                "ansible-playbook exited with code 0, but the step has no results from it: "
                f"{results.problem or 'the play did not finish'}. Whether any host changed "
                "is unknown, so the step fails instead of reporting no changes."
            )
        success = error is None
        if results.completed:
            summary = (
                f"{config.playbook}{mode}: {len(results.hosts)} host(s), {len(changed)} changed, "
                f"{len(failed)} failed, {len(unreachable)} unreachable"
            )
        else:
            summary = f"{config.playbook}{mode}: ansible-playbook exited with code {exit_code}"
        devices_by_role = self._devices_by_role(ctx, config.inventory_scope)
        if unmatched_roles := _roles_without_devices(devices_by_role):
            summary += f" (no device matched the target roles: {', '.join(unmatched_roles)})"
        return HandlerResult(
            success=success,
            summary=summary,
            error=error,
            metrics={
                "exit_code": exit_code,
                "target_devices": sum(len(devices) for devices in devices_by_role.values()),
                "duration_seconds": outcome.duration_seconds,
                "image": outcome.image,
                "image_digest": outcome.image_digest,
                "image_served": outcome.image_served,
                "image_source": outcome.image_source,
                "image_cached": outcome.image_cached,
                "hosts": len(results.hosts),
                "changed": len(changed),
                "failed": len(failed),
                "unreachable": len(unreachable),
                "skipped_artifacts": outcome.skipped_artifacts,
            },
            evidence=evidence,
            output=output,
        )
