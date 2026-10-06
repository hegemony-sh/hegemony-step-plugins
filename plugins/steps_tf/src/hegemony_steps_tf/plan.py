# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``tf.plan``: init, validate, and plan an OpenTofu or Terraform configuration.

The configuration comes from the flow's attachments. The step saves the plan in
its working directory under the run's shared workspace, keeps the readable plan
as evidence, and reports what would change — counts and resource addresses,
never resource values — so a later branch or approval can act on it and
``tf.apply`` can apply exactly that plan. A scheduled plan-only flow is drift
detection.
"""

from __future__ import annotations

import json
import posixpath
import shlex
from typing import Any

from pydantic import Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StateBackendAccess,
    StepKind,
)
from hegemony_steps_container.runner import (
    KILL_AFTER_SECONDS,
    OUTPUT_DIR,
    ContainerJob,
    ContainerJobResult,
    StagedFile,
    container_config_from,
    resolve_secret_values,
    run_container_job,
    secret_map_errors,
)

from .common import (
    ATTACHMENTS_ROOT,
    BACKEND_CONFIG_FILE,
    BACKEND_OVERRIDE_FILE,
    BINARIES,
    HTTP_BACKEND_OVERRIDE,
    LOCAL_BACKEND_OVERRIDE,
    PLAN_FILE,
    PLAN_TEXT_MISSING_NOTE,
    RUN_SCRIPT,
    SECRET_VARS_FILE,
    VARS_FILE,
    Engine,
    LockTimeout,
    StateMode,
    TfContainerConfig,
    address_list_errors,
    backend_config_errors,
    backend_config_file,
    collect_failure,
    common_errors,
    container_timeout,
    default_image,
    lock_conflict_error,
    managed_state_access,
    managed_timeout_errors,
    public_outputs,
    relative_path_error,
    script_header,
    secret_environment,
    shared_workspace_mounted,
    state_name_errors,
    tool_deadline,
    tool_env,
    tool_kill_after,
    typed_variable,
    variable_map_errors,
    workdir_for,
)
from .summary import plan_line, summarize_plan

PLAN_EXIT_FILE = f"{OUTPUT_DIR}/plan-exitcode"
PLAN_TEXT_FILE = f"{OUTPUT_DIR}/plan.txt"
#: The JSON plan is by far the largest file, and collection shares one byte
#: budget in the order of ``collect``: it comes from its own folder, last, so
#: it can never crowd out the exit code or the readable plan.
PLAN_JSON_DIR = "/hegemony/plan-json"
PLAN_JSON_FILE = f"{PLAN_JSON_DIR}/plan.json"
#: ``output -json`` of the state the plan was made against, collected before
#: the JSON plan and after the plan itself.
PLAN_OUTPUTS_DIR = "/hegemony/plan-outputs"
PLAN_OUTPUTS_FILE = f"{PLAN_OUTPUTS_DIR}/outputs.json"
#: Local working directory when the step has no shared workspace (plan only).
LOCAL_WORKDIR = "/workspace/tf"

#: Exit code the run script uses when "backend" state has no backend block.
EXIT_NO_BACKEND = 3
NO_BACKEND_MESSAGE = (
    "State is set to backend, but the configuration declares no backend block; "
    "add one, or choose managed or ephemeral state."
)


class TfPlanConfig(TfContainerConfig):
    """Config for ``tf.plan``."""

    engine: Engine = Field(
        default="opentofu",
        title="Engine",
        description="opentofu (default) or terraform. The apply step uses the same one.",
    )
    source_dir: str = Field(
        default="",
        title="Configuration folder",
        description=(
            "Folder among the flow attachments holding the .tf files, e.g. terraform/network. "
            "Leave empty for the attachments root. Commit its .terraform.lock.hcl."
        ),
        json_schema_extra={"x_placeholder": "terraform/network"},
    )
    state: StateMode = Field(
        default="managed",
        title="State",
        description=(
            "managed: Hegemony stores the state (encrypted, locked, versioned) under the "
            "state name; any backend block in the configuration is replaced. backend: the "
            "configuration's own backend block (S3, Azure, GCS, Consul, PostgreSQL, …), "
            "required. ephemeral: local state that lives only for this run, for tests and "
            "demos."
        ),
    )
    state_name: str = Field(
        default="",
        title="State name",
        description=(
            "Name of the managed state in this organization, e.g. network-core. Every flow "
            "and laptop using the same name shares one state (and its lock)."
        ),
        json_schema_extra={
            "x_placeholder": "network-core",
            "x_show_when": {"field": "state", "value": "managed"},
        },
    )
    hold_until_apply: bool = Field(
        default=False,
        title="Hold the state until apply",
        description=(
            "Keep the managed state for this run from this plan until the run applies or "
            "ends: meanwhile other runs and people cannot lock or change it, so the plan "
            "stays valid while the run waits (for an approval, say). Every other flow using "
            "the state waits that long."
        ),
        json_schema_extra={"x_show_when": {"field": "state", "value": "managed"}},
    )
    backend_config: dict[str, str] = Field(
        default_factory=dict,
        title="Backend settings",
        description=(
            "KEY=value, one per line, for a partial backend block (for example "
            "bucket=…, key=…). Values may use {{ secret('...') }}; they are passed "
            "from a file, not the command line. Only for backend state."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_rows": 2,
            "x_col_span": 2,
            "x_show_when": {"field": "state", "value": "backend"},
        },
    )
    vars: dict[str, str] = Field(
        default_factory=dict,
        title="Variables",
        description=(
            "NAME=value, one per line. Values may use templates such as "
            '{{ inputs.service_name }}; a JSON list or object (["r1","r2"]) is passed '
            "as that type."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "service_name={{ inputs.service_name }}",
            "x_rows": 3,
            "x_col_span": 2,
        },
    )
    secret_vars: dict[str, str] = Field(
        default_factory=dict,
        title="Secret variables",
        description=(
            "NAME=secret reference, one per line, for sensitive variables. Always passed "
            "as strings (decode a JSON secret with jsondecode() in the configuration), from "
            "a file, and redacted from output; like every variable they are stored in the "
            "saved plan, which lives only in the run's workspace."
        ),
        json_schema_extra={"x_widget": "env-vars", "x_rows": 2, "x_col_span": 2},
    )
    var_files: list[str] = Field(
        default_factory=list,
        title="Variable files",
        description="Attachment paths of .tfvars or .tfvars.json files, one per line.",
        json_schema_extra={"x_widget": "commands", "x_rows": 2, "x_advanced": True},
    )
    destroy: bool = Field(
        default=False,
        title="Plan a destroy",
        description="Plan the destruction of every resource the state holds (-destroy).",
        json_schema_extra={"x_advanced": True},
    )
    refresh_only: bool = Field(
        default=False,
        title="Refresh only",
        description="Only reconcile state with the real infrastructure (-refresh-only).",
        json_schema_extra={"x_advanced": True},
    )
    targets: list[str] = Field(
        default_factory=list,
        title="Targets",
        description=(
            "Resource addresses to limit the plan to (-target), one per line, e.g. "
            'aws_vpc.main or aws_instance.web["blue"].'
        ),
        json_schema_extra={"x_widget": "commands", "x_rows": 2, "x_advanced": True},
    )
    replace: list[str] = Field(
        default_factory=list,
        title="Replace",
        description=(
            "Resource addresses to force-replace (-replace), one per line, e.g. "
            'aws_instance.web["blue"].'
        ),
        json_schema_extra={"x_widget": "commands", "x_rows": 2, "x_advanced": True},
    )
    lock_timeout: LockTimeout = "300s"
    state_encryption_key: str = Field(
        default="",
        title="State encryption key",
        description=(
            "OpenTofu only: secret reference of a passphrase (16+ characters). State and "
            "saved plans are then encrypted by OpenTofu before they are written anywhere."
        ),
        json_schema_extra={"x_advanced": True, "x_col_span": 2},
    )
    image: str = Field(
        default="",
        title="Image",
        description=(
            "Container image with the tool, run as root with a POSIX sh. Leave empty for "
            "the engine's default: ghcr.io/hegemony-sh/opentofu-runner:0.15 for OpenTofu, "
            "hashicorp/terraform at a pinned version for Terraform."
        ),
        json_schema_extra={
            "x_placeholder": "ghcr.io/hegemony-sh/opentofu-runner:0.15",
            "x_advanced": True,
        },
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


def build_plan_script(
    config: TfPlanConfig,
    *,
    workdir: str,
    has_vars: bool,
    has_secret_vars: bool,
    deadline: int | None = None,
    kill_after: int = KILL_AFTER_SECONDS,
) -> str:
    """Copy the configuration into the working directory, init, validate, plan.

    With a ``deadline`` (a Unix time), every tool call gets SIGTERM then, and
    SIGKILL ``kill_after`` seconds later.
    """
    tf = BINARIES[config.engine]
    run = "" if deadline is None else "bounded "
    source = posixpath.join(ATTACHMENTS_ROOT, config.source_dir.strip()).rstrip("/")
    init = [tf, "init", "-input=false", "-no-color"]
    if config.state == "backend" and config.backend_config:
        init.append(f"-backend-config={BACKEND_CONFIG_FILE}")
    plan = [
        tf,
        "plan",
        "-input=false",
        "-no-color",
        "-detailed-exitcode",
        f"-lock-timeout={config.lock_timeout.strip()}",
        f"-out={PLAN_FILE}",
    ]
    if config.destroy:
        plan.append("-destroy")
    if config.refresh_only:
        plan.append("-refresh-only")
    plan += [f"-target={target.strip()}" for target in config.targets if target.strip()]
    plan += [f"-replace={address.strip()}" for address in config.replace if address.strip()]
    plan += [
        f"-var-file={posixpath.join(ATTACHMENTS_ROOT, path.strip())}"
        for path in config.var_files
        if path.strip()
    ]
    if has_vars:
        plan.append(f"-var-file={VARS_FILE}")
    if has_secret_vars:
        plan.append(f"-var-file={SECRET_VARS_FILE}")

    quoted_workdir = shlex.quote(workdir)
    lines = [
        *script_header(deadline, kill_after),
        f"rm -rf {quoted_workdir}",
        f"mkdir -p {quoted_workdir}",
        f"cp -R {shlex.quote(source)}/. {quoted_workdir}/",
    ]
    if config.state in ("managed", "ephemeral"):
        lines.append(f"cp {BACKEND_OVERRIDE_FILE} {quoted_workdir}/")
    lines += [
        f"cd {quoted_workdir}",
        run + " ".join(shlex.quote(part) for part in init),
    ]
    if config.state == "backend":
        # Without a backend block the tool silently keeps state in the working
        # directory, which is deleted when the run ends: refuse instead.
        lines += [
            "if [ ! -f .terraform/terraform.tfstate ]; then",
            f'  echo "{NO_BACKEND_MESSAGE}" >&2',
            f"  exit {EXIT_NO_BACKEND}",
            "fi",
        ]
    lines += [
        f"{run}{tf} validate -no-color",
        "set +e",
        run + " ".join(shlex.quote(part) for part in plan),
        "code=$?",
        "set -e",
        'if [ "$code" -ne 0 ] && [ "$code" -ne 2 ]; then exit "$code"; fi',
        f'printf "%s" "$code" > {PLAN_EXIT_FILE}',
        f"{run}{tf} show -no-color {PLAN_FILE} > {PLAN_TEXT_FILE}",
        f"mkdir -p {PLAN_JSON_DIR} {PLAN_OUTPUTS_DIR}",
        f"{run}{tf} show -json {PLAN_FILE} > {PLAN_JSON_FILE}",
        # For a tf.apply with nothing to apply; the plan is made without them.
        f"if ! {run}{tf} output -json > {PLAN_OUTPUTS_FILE}; then rm -f {PLAN_OUTPUTS_FILE}; fi",
    ]
    return "\n".join(lines) + "\n"


class TfPlanHandler(BaseHandler):
    """Plan an OpenTofu/Terraform configuration and report what would change."""

    handler_id = "tf.plan"
    supported_kinds = [StepKind.CHECK, StepKind.ACTION, StepKind.EXECUTE]
    display_name = "OpenTofu/Terraform Plan"
    description = (
        "Plan an OpenTofu or Terraform configuration from the flow's attachments and "
        "report what would change; tf.apply applies the saved plan."
    )
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    container_backed = True
    platform_api_access = True
    # The plan lives in /shared/tf/<node id>; apply finds it by node id.
    node_scoped_state = True
    # Secret references reach the handler as written (see resolve_secret_values).
    raw_config_keys = frozenset({"secret_vars", "secret_env", "state_encryption_key"})
    default_timeout_seconds = 1800
    config_model = TfPlanConfig
    default_config = {"engine": "opentofu", "state": "managed", "timeout_seconds": 1800}

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        errors = super().validate_config(config)
        if errors:
            return errors
        error = relative_path_error("source_dir", config.get("source_dir"), allow_empty=True)
        if error:
            errors.append(error)
        for index, path in enumerate(config.get("var_files") or []):
            error = relative_path_error(f"var_files[{index}]", path)
            if error:
                errors.append(error)
        errors += variable_map_errors("vars", config.get("vars"))
        errors += variable_map_errors("secret_vars", config.get("secret_vars"))
        errors += secret_map_errors("secret_vars", config.get("secret_vars"))
        errors += backend_config_errors(config.get("backend_config"))
        if (config.get("state") or "managed") == "managed":
            errors += state_name_errors(config.get("state_name"))
            errors += managed_timeout_errors(config.get("timeout_seconds"))
        errors += address_list_errors("targets", config.get("targets"))
        errors += address_list_errors("replace", config.get("replace"))
        if config.get("destroy") and config.get("refresh_only"):
            errors.append("'destroy' and 'refresh_only' cannot be combined")
        if config.get("destroy") and config.get("replace"):
            errors.append("'replace' cannot be combined with 'destroy'")
        if config.get("state_encryption_key") and config.get("engine") == "terraform":
            errors.append("'state_encryption_key' needs the opentofu engine")
        errors += common_errors(config)
        return errors

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        errors = self.validate_config(ctx.config)
        if errors:
            return HandlerResult(
                success=False,
                error=f"Invalid tf.plan config: {'; '.join(errors)}",
                summary="Config validation failed",
            )
        config = TfPlanConfig.model_validate(ctx.config)
        image = config.image.strip() or default_image(config.engine)
        shared = shared_workspace_mounted(ctx)
        workdir = workdir_for(ctx.step_id) if shared else LOCAL_WORKDIR
        state_name = config.state_name.strip() if config.state == "managed" else None
        timeout = container_timeout(ctx, config)

        try:
            async with managed_state_access(
                ctx, state_name, timeout, hold_until_apply=config.hold_until_apply
            ) as access:
                files, env_files = await self._files(
                    ctx,
                    config,
                    workdir,
                    access,
                    tool_deadline(timeout, config.stop_grace_seconds),
                    tool_kill_after(timeout, config.stop_grace_seconds),
                )
                job = ContainerJob(
                    config=container_config_from(
                        {**ctx.config, "timeout_seconds": timeout},
                        image=image,
                        command=[f"exec sh {RUN_SCRIPT}"],
                        entrypoint="/bin/sh",
                        env=tool_env(),
                    ),
                    files=files + env_files,
                    collect=[OUTPUT_DIR, PLAN_OUTPUTS_DIR, PLAN_JSON_DIR],
                    handler_id=self.handler_id,
                    extra_hosts=dict(access.extra_hosts) if access else {},
                    stop_grace_seconds=config.stop_grace_seconds,
                    # tf.apply must run the same tool version: a saved plan is
                    # refused by any other, and the image's tag may move.
                    pin_image=True,
                )
                outcome = await run_container_job(ctx, job)
        except (ValueError, RuntimeError) as exc:
            return HandlerResult(
                success=False, error=str(exc), summary="Could not prepare the plan"
            )
        if isinstance(outcome, HandlerResult):
            return outcome
        return self._result(ctx, config, image, workdir, outcome)

    async def _files(
        self,
        ctx: HandlerContext,
        config: TfPlanConfig,
        workdir: str,
        access: StateBackendAccess | None,
        deadline: int,
        kill_after: int,
    ) -> tuple[list[StagedFile], list[StagedFile]]:
        files: list[StagedFile] = []
        if config.state == "managed":
            files.append(StagedFile(BACKEND_OVERRIDE_FILE, HTTP_BACKEND_OVERRIDE))
        if config.state == "ephemeral":
            files.append(StagedFile(BACKEND_OVERRIDE_FILE, LOCAL_BACKEND_OVERRIDE))
        if config.state == "backend" and config.backend_config:
            files.append(backend_config_file(config.backend_config))
        if config.vars:
            files.append(
                StagedFile(
                    VARS_FILE,
                    json.dumps({k: typed_variable(v) for k, v in config.vars.items()}, indent=2)
                    + "\n",
                )
            )
        secret_vars = await resolve_secret_values(
            ctx, config.secret_vars, source="tf.plan.secret_vars"
        )
        if secret_vars:
            files.append(
                StagedFile(
                    SECRET_VARS_FILE,
                    # Verbatim: a secret is opaque, and the most common JSON one (a
                    # cloud credentials document) is bound to a string variable.
                    json.dumps(secret_vars) + "\n",
                )
            )
        files.append(
            StagedFile(
                RUN_SCRIPT,
                build_plan_script(
                    config,
                    workdir=workdir,
                    has_vars=bool(config.vars),
                    has_secret_vars=bool(secret_vars),
                    deadline=deadline,
                    kill_after=kill_after,
                ),
                mode=0o755,
            )
        )
        env_files = await secret_environment(
            ctx, config.secret_env, config.state_encryption_key, access
        )
        return files, env_files

    def _result(
        self,
        ctx: HandlerContext,
        config: TfPlanConfig,
        image: str,
        workdir: str,
        outcome: ContainerJobResult,
    ) -> HandlerResult:
        evidence = list(outcome.evidence)
        exit_code = outcome.exit_code
        if exit_code != 0:
            tool = BINARIES[config.engine]
            reason = (
                "the configuration declares no backend block (state: backend)"
                if exit_code == EXIT_NO_BACKEND
                else f"exited with code {exit_code}"
            )
            error = lock_conflict_error(
                tool, config.lock_timeout.strip(), outcome.stdout, outcome.stderr
            )
            return HandlerResult(
                success=False,
                summary=f"{tool} plan failed",
                error=error or f"{tool} {reason}; see the container output",
                metrics={
                    "exit_code": exit_code,
                    "duration_seconds": outcome.duration_seconds,
                    "image_served": outcome.image_served,
                    "image_source": outcome.image_source,
                    "image_cached": outcome.image_cached,
                },
                evidence=evidence,
            )

        # The script exits 0 for "no changes" and for "changes" alike: only the
        # collected detailed exit code tells them apart, and collecting it is
        # best-effort. Without it, "no changes" would be a guess that makes
        # tf.apply skip a plan that has changes.
        plan_code = (
            (outcome.collected.get(PLAN_EXIT_FILE) or b"").decode("utf-8", "replace").strip()
        )
        if plan_code not in ("0", "2"):
            copy_failure = collect_failure(outcome, PLAN_EXIT_FILE)
            cause = (
                f"the copy out of the container failed ({copy_failure})"
                if copy_failure
                else f"got {plan_code[:20]!r}"
            )
            return HandlerResult(
                success=False,
                summary=f"{BINARIES[config.engine]} plan result missing",
                error=(
                    f"{BINARIES[config.engine]} plan finished, but its detailed exit code "
                    f"could not be read back from the container ({cause}), "
                    "so whether it has changes is unknown; run the step again"
                ),
                metrics={
                    "exit_code": exit_code,
                    "duration_seconds": outcome.duration_seconds,
                    "image_served": outcome.image_served,
                    "image_source": outcome.image_source,
                    "image_cached": outcome.image_cached,
                },
                evidence=evidence,
            )
        has_changes = plan_code == "2"
        plan_text = (outcome.collected.get(PLAN_TEXT_FILE) or b"").decode("utf-8", "replace")
        summary_data: dict[str, Any] = {}
        raw_json = outcome.collected.get(PLAN_JSON_FILE)
        if raw_json:
            try:
                summary_data = summarize_plan(json.loads(raw_json))
            except (ValueError, AttributeError, TypeError):
                summary_data = {}
        if plan_text:
            evidence.append(
                {
                    "kind": "step_result",
                    "name": f"plan_{ctx.step_id}.txt",
                    "content_text": plan_text,
                    "content_json": {"has_changes": has_changes, **summary_data},
                }
            )

        outputs, sensitive_outputs = public_outputs(outcome.collected.get(PLAN_OUTPUTS_FILE))
        apply_ready = workdir != LOCAL_WORKDIR
        if not apply_ready:
            evidence.append(
                {
                    "kind": "step_result",
                    "name": f"plan_only_{ctx.step_id}",
                    "content_text": (
                        "This plan cannot be applied by tf.apply: the step had no shared "
                        "workspace, so the saved plan was deleted with its container. To "
                        "apply it, give this step and the tf.apply step shared (or explicit) "
                        "execution affinity on a worker with shared workspaces enabled.\n"
                    ),
                }
            )

        line = plan_line(summary_data) if summary_data else ("changes" if has_changes else "")
        if config.refresh_only and summary_data.get("drift"):
            # A refresh-only plan changes no resource: its changes are the drift.
            line += f" ({summary_data['drift']} drifted)"
        summary = (
            f"Plan: {line}"
            if has_changes
            else "No changes: infrastructure matches the configuration"
        )
        if has_changes and not plan_text:
            # Collection is best-effort: an approver must not look for a plan
            # artifact that is not there.
            summary += PLAN_TEXT_MISSING_NOTE
        output: dict[str, Any] = {
            # tf.apply refuses a plan step output without this marker.
            "handler": self.handler_id,
            "has_changes": has_changes,
            **summary_data,
            "summary": summary,
            "engine": config.engine,
            "image": image,
            # The image by digest, which tf.apply runs; empty for an image the
            # registry never saw (built on the sandbox daemon).
            "image_digest": outcome.image_digest,
            # tf.apply pulls the plan's image the way the plan did.
            "cache_image": config.cache_image,
            "state": config.state,
            "state_name": config.state_name.strip() if config.state == "managed" else "",
            # The run holds the state until it applies or ends (managed state only).
            "state_held": config.state == "managed" and config.hold_until_apply,
            "working_dir": workdir,
            "apply_ready": apply_ready,
            "outputs": outputs,
            "sensitive_outputs": sensitive_outputs,
        }
        return HandlerResult(
            success=True,
            summary=summary,
            metrics={
                "exit_code": exit_code,
                "duration_seconds": outcome.duration_seconds,
                "image": image,
                "image_served": outcome.image_served,
                "image_source": outcome.image_source,
                "image_cached": outcome.image_cached,
                "has_changes": has_changes,
                "add": summary_data.get("add", 0),
                "change": summary_data.get("change", 0),
                "destroy": summary_data.get("destroy", 0),
            },
            evidence=evidence,
            output=output,
        )
