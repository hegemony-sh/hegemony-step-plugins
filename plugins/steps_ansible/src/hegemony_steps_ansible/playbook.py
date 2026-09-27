# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
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
    resolve_secret_values,
    run_container_job,
    secret_map_errors,
)

from .inventory import (
    GROUP_DIMENSIONS,
    GroupDimension,
    Inventory,
    InventoryHost,
    build_inventory,
)
from .results import (
    CALLBACK_NAME,
    CALLBACK_SOURCE,
    EXIT_CODE_MEANINGS,
    RESULTS_FILE,
    parse_results,
    render_host_report,
)

#: First-party execution image: ansible-core, libssh, sshpass, and the common
#: network collections (built from images/ansible-runner in this repository).
DEFAULT_IMAGE = "ghcr.io/hegemony-sh/ansible-runner:0.5"

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
            "Values may use templates such as {{ inputs.service }}."
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
    forks: int = Field(
        default=5,
        ge=1,
        le=100,
        title="Forks",
        description="How many hosts Ansible works on in parallel (--forks).",
        json_schema_extra={"x_advanced": True},
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
    if mode == "accept_new":
        return [
            "-o StrictHostKeyChecking=accept-new",
            f"-o UserKnownHostsFile={KNOWN_HOSTS_FILE}",
        ]
    if mode == "off":
        return ["-o StrictHostKeyChecking=no", "-o UserKnownHostsFile=/dev/null"]
    return []


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
            if not jump.private_key:
                raise ValueError(
                    f"device {host.name}: its jump host {jump.host} logs in with a password "
                    "only; the Ansible step supports key-based jump hosts"
                )
            name = f"jump-{index}.pem"
            files.append(StagedFile(f"{KEYS_STAGE_DIR}/{name}", _pem(jump.private_key)))
            proxy = " ".join(
                [
                    "ssh -W %h:%p",
                    f"-i {KEYS_DIR}/{name}",
                    f"-p {jump.port}",
                    *_host_key_ssh_args(host_key_checking),
                    f"{jump.username}@{jump.host}",
                ]
            )
            variables["ansible_libssh_proxy_command"] = proxy
            variables["ansible_paramiko_proxy_command"] = proxy
            ssh_args.append(f'-o ProxyCommand="{proxy}"')

    if ssh_args:
        variables["ansible_ssh_common_args"] = " ".join(ssh_args)
    return variables, files


def _ansible_env(config: AnsiblePlaybookConfig, user_env: dict[str, str]) -> dict[str, str]:
    callbacks = [CALLBACK_NAME]
    user_callbacks = user_env.get("ANSIBLE_CALLBACKS_ENABLED", "")
    callbacks.extend(item.strip() for item in user_callbacks.split(",") if item.strip())
    env = {
        "ANSIBLE_CALLBACK_PLUGINS": CALLBACK_DIR,
        "ANSIBLE_CALLBACKS_ENABLED": ",".join(dict.fromkeys(callbacks)),
        "ANSIBLE_NOCOLOR": "1",
        "ANSIBLE_FORCE_COLOR": "0",
        "ANSIBLE_RETRY_FILES_ENABLED": "0",
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
) -> str:
    """The container's entry script: key setup, optional Galaxy install, the play."""
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
    if config.requirements_file.strip():
        requirements = posixpath.join(ATTACHMENTS_ROOT, config.requirements_file.strip())
        lines.append(f"ansible-galaxy install -r {shlex.quote(requirements)}")
    lines.append("exec " + " ".join(shlex.quote(arg) for arg in args))
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
    default_timeout_seconds = 1800
    config_model = AnsiblePlaybookConfig
    default_config = {"playbook": "site.yml", "timeout_seconds": 1800}

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

        inventory = build_inventory(
            self._devices_by_role(ctx, config.inventory_scope), group_by=config.group_by
        )

        try:
            files = await self._staged_files(ctx, config, inventory, services)
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
                command=[f"sh {RUN_SCRIPT}"],
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
            return outcome

        return self._result(ctx, config, inventory, outcome)

    async def _staged_files(
        self,
        ctx: HandlerContext,
        config: AnsiblePlaybookConfig,
        inventory: Inventory,
        services: Any,
    ) -> list[StagedFile]:
        files: list[StagedFile] = [
            _json_file(INVENTORY_FILE, inventory.document()),
            StagedFile(f"{CALLBACK_DIR}/{CALLBACK_NAME}.py", CALLBACK_SOURCE),
        ]
        for index, host in enumerate(inventory.hosts):
            credentials: DeviceCredentials | None = None
            if config.device_credentials:
                try:
                    credentials = await services.resolve_device_credentials(host.device)
                except ValueError as exc:
                    raise ValueError(f"device {host.name}: {exc}") from exc
            variables, key_files = credential_host_vars(
                host, credentials, index, config.host_key_checking
            )
            files.extend(key_files)
            if variables:
                files.append(_json_file(f"{INVENTORY_DIR}/host_vars/{host.name}.json", variables))

        secrets = await resolve_secret_values(
            ctx, config.secrets, source="ansible.playbook.secrets"
        )
        for group, names in _parse_group_secrets(config.group_secrets).items():
            values = await resolve_secret_values(
                ctx, names, source="ansible.playbook.group_secrets"
            )
            files.append(_json_file(f"{INVENTORY_DIR}/group_vars/{group}.json", values))

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
            files.append(_json_file(EXTRA_VARS_FILE, config.extra_vars))
        if secrets:
            files.append(_json_file(SECRETS_FILE, secrets))
        files.append(
            StagedFile(
                RUN_SCRIPT,
                build_run_script(
                    config,
                    has_extra_vars=bool(config.extra_vars),
                    has_secrets=bool(secrets),
                    vault_files=vault_files,
                ),
                mode=0o755,
            )
        )
        return files

    def _result(
        self,
        ctx: HandlerContext,
        config: AnsiblePlaybookConfig,
        inventory: Inventory,
        outcome: Any,
    ) -> HandlerResult:
        results = parse_results(outcome.collected.get(RESULTS_FILE))
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

        changed = results.hosts_where("changed")
        failed = results.hosts_where("failures")
        unreachable = results.hosts_where("unreachable")
        exit_code = outcome.exit_code
        output = _bounded_output(
            {
                "exit_code": exit_code,
                "check_mode": config.check_mode,
                "changed": bool(changed),
                "hosts": results.hosts,
                "changed_hosts": changed,
                "failed_hosts": failed,
                "unreachable_hosts": unreachable,
                "stats": results.custom,
            }
        )
        success = exit_code == 0
        mode = " (check mode)" if config.check_mode else ""
        if results.completed:
            summary = (
                f"{config.playbook}{mode}: {len(results.hosts)} host(s), {len(changed)} changed, "
                f"{len(failed)} failed, {len(unreachable)} unreachable"
            )
        else:
            summary = f"{config.playbook}{mode}: ansible-playbook exited with code {exit_code}"
        meaning = EXIT_CODE_MEANINGS.get(exit_code, "unexpected exit code")
        return HandlerResult(
            success=success,
            summary=summary,
            error=None if success else f"ansible-playbook exited with code {exit_code} ({meaning})",
            metrics={
                "exit_code": exit_code,
                "duration_seconds": outcome.duration_seconds,
                "image": outcome.image,
                "hosts": len(results.hosts),
                "changed": len(changed),
                "failed": len(failed),
                "unreachable": len(unreachable),
                "skipped_artifacts": outcome.skipped_artifacts,
            },
            evidence=evidence,
            output=output,
        )
