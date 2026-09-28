# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``tf.apply``: apply exactly the plan a ``tf.plan`` step saved in this run.

Nothing about the configuration is repeated: the apply runs in the plan step's
working directory with the same image, so the lock file, providers, backend
settings, and variables are the ones that were planned (and, typically,
approved). The tool itself refuses the saved plan if the state changed since it
was made. Only provider credentials, which are never stored in a plan, are
given again.
"""

from __future__ import annotations

import json
import shlex
from typing import Any

from pydantic import Field

from hegemony_step_sdk import BaseHandler, HandlerContext, HandlerResult, HandlerTargeting, StepKind
from hegemony_steps_container.runner import (
    OUTPUT_DIR,
    ContainerJob,
    ContainerJobResult,
    StagedFile,
    container_config_from,
    run_container_job,
)

from .common import (
    BINARIES,
    KEEP_DIR,
    PLAN_FILE,
    RUN_SCRIPT,
    LockTimeout,
    TfContainerConfig,
    common_errors,
    container_timeout,
    managed_state_access,
    script_header,
    secret_environment,
    shared_workspace_mounted,
    tool_env,
)

OUTPUTS_FILE = f"{OUTPUT_DIR}/outputs.json"
#: What became of the state when the tool could not save it: "recovered" (saved
#: again from errored.tfstate) or "kept" (only in the kept artifact).
ERRORED_STATE_FILE = f"{OUTPUT_DIR}/errored-state"
#: The artifact an unsaved state is kept as (gzip, so it is uploaded as a file
#: and never rewritten by redaction).
ERRORED_STATE_ARTIFACT = "errored.tfstate.gz"
#: Exit code the run script uses when the saved plan is gone.
EXIT_NO_PLAN = 4
#: Waits before each further attempt to save errored.tfstate (the first is immediate).
SAVE_RETRY_WAITS = (10, 30)
STALE_PLAN_MARKER = "Saved plan is stale"

#: Non-sensitive outputs larger than this are left out of the step output.
MAX_OUTPUT_VALUE_BYTES = 16 * 1024


class TfApplyConfig(TfContainerConfig):
    """Config for ``tf.apply``."""

    plan_step: str = Field(
        min_length=1,
        title="Plan step",
        description="The tf.plan step whose saved plan to apply. It must have run in this run.",
        json_schema_extra={"x_widget": "step-select", "x_step_handler_filter": "tf.plan"},
    )
    state_encryption_key: str = Field(
        default="",
        title="State encryption key",
        description=(
            "OpenTofu only: the same secret reference the plan step used, needed to read "
            "the encrypted plan and write encrypted state."
        ),
        json_schema_extra={"x_advanced": True, "x_col_span": 2},
    )
    lock_timeout: LockTimeout = "300s"


def build_apply_script(engine: str, workdir: str, lock_timeout: str) -> str:
    """Apply the saved plan in the plan step's working directory.

    When the tool changed resources but could not save the resulting state
    (the backend was unreachable, refused the write, or the token ended), it
    leaves the state in ``errored.tfstate``. That directory is deleted with the
    run, so the script saves the state again (``state push``, retried), and if
    that fails too keeps it as a run artifact instead of losing it.
    """
    tf = BINARIES[engine]
    apply = [tf, "apply", "-input=false", "-no-color", f"-lock-timeout={lock_timeout}", PLAN_FILE]
    # Without the lock: when the apply's own unlock failed too, this step still
    # holds the lock, and the platform lets the holder write without its ID.
    push = f"{tf} state push -lock=false errored.tfstate"
    quoted_workdir = shlex.quote(workdir)
    retry = [
        f"    for wait in 0 {' '.join(str(wait) for wait in SAVE_RETRY_WAITS)}; do",
        '      if [ "$wait" -gt 0 ]; then sleep "$wait"; fi',
        f"      if {push}; then saved=yes; break; fi",
        "    done",
    ]
    return (
        "\n".join(
            [
                *script_header(),
                f"if [ ! -f {quoted_workdir}/{PLAN_FILE} ]; then",
                f"  echo {shlex.quote(NO_PLAN_MESSAGE)} >&2",
                f"  exit {EXIT_NO_PLAN}",
                "fi",
                f"cd {quoted_workdir}",
                "set +e",
                " ".join(shlex.quote(part) for part in apply),
                "code=$?",
                "set -e",
                'if [ "$code" -ne 0 ]; then',
                "  if [ -f errored.tfstate ]; then",
                "    saved=no",
                *retry,
                '    if [ "$saved" = yes ]; then',
                f"      printf recovered > {ERRORED_STATE_FILE}",
                "    else",
                f"      mkdir -p {KEEP_DIR}",
                f"      gzip -c errored.tfstate > {KEEP_DIR}/{ERRORED_STATE_ARTIFACT}",
                f"      printf kept > {ERRORED_STATE_FILE}",
                "    fi",
                "  fi",
                '  exit "$code"',
                "fi",
                # The apply succeeded: a failure to read the outputs must not
                # turn it into a failed step (a retry would refuse the plan).
                f"if ! {tf} output -json > {OUTPUTS_FILE}; then rm -f {OUTPUTS_FILE}; fi",
            ]
        )
        + "\n"
    )


NO_PLAN_MESSAGE = (
    "The saved plan is gone: the run's shared workspace was removed (for example "
    "cleaned up after a worker restart while the run waited). Plan again."
)


def public_outputs(raw: bytes | None) -> tuple[dict[str, Any], list[str]]:
    """Non-sensitive output values, and the names of the sensitive ones.

    ``output -json`` prints sensitive values in clear, so they are dropped here
    and never leave the worker.
    """
    if not raw:
        return {}, []
    try:
        data = json.loads(raw)
    except ValueError:
        return {}, []
    values: dict[str, Any] = {}
    sensitive: list[str] = []
    for name, item in data.items() if isinstance(data, dict) else []:
        if not isinstance(item, dict):
            continue
        if item.get("sensitive"):
            sensitive.append(name)
        elif len(json.dumps(item.get("value"), default=str)) <= MAX_OUTPUT_VALUE_BYTES:
            values[name] = item.get("value")
    return values, sorted(sensitive)


class TfApplyHandler(BaseHandler):
    """Apply the plan a tf.plan step saved earlier in the run."""

    handler_id = "tf.apply"
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "OpenTofu/Terraform Apply"
    description = "Apply exactly the plan a tf.plan step saved earlier in the run."
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    container_backed = True
    platform_api_access = True
    # The plan lives in /shared/tf/<node id>; apply finds it by node id.
    node_scoped_state = True
    # Secret references reach the handler as written (see resolve_secret_values).
    raw_config_keys = frozenset({"secret_env", "state_encryption_key"})
    default_timeout_seconds = 3600
    config_model = TfApplyConfig
    default_config = {"timeout_seconds": 3600}

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        errors = super().validate_config(config)
        if errors:
            return errors
        return common_errors(config)

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        errors = self.validate_config(ctx.config)
        if errors:
            return HandlerResult(
                success=False,
                error=f"Invalid tf.apply config: {'; '.join(errors)}",
                summary="Config validation failed",
            )
        config = TfApplyConfig.model_validate(ctx.config)
        plan_step = config.plan_step.strip()

        outputs = await ctx.require_services().fetch_run_step_outputs(ctx.run_id)
        plan = outputs.get(plan_step) or {}
        plan_output = plan.get("output") if isinstance(plan.get("output"), dict) else {}
        if not plan_output or not plan.get("success"):
            return self._refuse(
                f"plan step {plan_step!r} has not completed successfully in this run"
            )
        if not plan_output.get("apply_ready") or not shared_workspace_mounted(ctx):
            return self._refuse(
                "the plan and apply steps must both use shared (or explicit) execution "
                "affinity on a worker with shared workspaces enabled, so the apply runs "
                "in the plan's working directory on the same worker"
            )
        engine = str(plan_output.get("engine") or "")
        if engine not in BINARIES:
            return self._refuse(f"plan step {plan_step!r} reports an unknown engine {engine!r}")
        if not plan_output.get("has_changes"):
            return HandlerResult(
                success=True,
                summary="Nothing to apply: the plan has no changes",
                output={"applied": False, "outputs": {}, "sensitive_outputs": []},
            )

        state_name: str | None = None
        if plan_output.get("state") == "managed":
            state_name = str(plan_output.get("state_name") or "")
            if not state_name:
                return self._refuse(f"plan step {plan_step!r} reports managed state with no name")

        image = str(plan_output.get("image"))
        workdir = str(plan_output.get("working_dir"))
        timeout = container_timeout(ctx, config)
        try:
            # The saved plan names the backend but not its address or credentials:
            # managed state access is opened again for this step.
            async with managed_state_access(ctx, state_name, timeout) as access:
                env_files = await secret_environment(
                    ctx, config.secret_env, config.state_encryption_key, access
                )
                job = ContainerJob(
                    config={
                        **container_config_from(
                            {**ctx.config, "timeout_seconds": timeout},
                            image=image,
                            command=[f"sh {RUN_SCRIPT}"],
                            entrypoint="/bin/sh",
                            env=tool_env(),
                        ),
                        # An unsaved state is kept here and harvested as an artifact.
                        "new_artifacts_path": KEEP_DIR,
                    },
                    files=[
                        *env_files,
                        _script_file(engine, workdir, config.lock_timeout.strip()),
                    ],
                    collect=[OUTPUT_DIR],
                    handler_id=self.handler_id,
                    extra_hosts=dict(access.extra_hosts) if access else {},
                )
                outcome = await run_container_job(ctx, job)
        except (ValueError, RuntimeError) as exc:
            return self._refuse(str(exc))
        if isinstance(outcome, HandlerResult):
            return outcome
        return self._result(engine, image, plan_output, outcome, state_name)

    @staticmethod
    def _refuse(message: str) -> HandlerResult:
        return HandlerResult(success=False, error=message, summary="Cannot apply the plan")

    def _result(
        self,
        engine: str,
        image: str,
        plan_output: dict[str, Any],
        outcome: ContainerJobResult,
        state_name: str | None = None,
    ) -> HandlerResult:
        tool = BINARIES[engine]
        metrics = {
            "exit_code": outcome.exit_code,
            "duration_seconds": outcome.duration_seconds,
            "image": image,
        }
        if outcome.exit_code != 0:
            return HandlerResult(
                success=False,
                summary=f"{tool} apply failed",
                error=apply_failure(tool, outcome, state_name),
                metrics=metrics,
                evidence=list(outcome.evidence),
            )
        planned = plan_output.get("summary") or "the saved plan"
        summary = f"Applied: {planned.removeprefix('Plan: ')}"
        raw_outputs = outcome.collected.get(OUTPUTS_FILE)
        if raw_outputs is None:
            summary += " (its outputs could not be read)"
        values, sensitive = public_outputs(raw_outputs)
        return HandlerResult(
            success=True,
            summary=summary,
            metrics=metrics,
            evidence=list(outcome.evidence),
            output={"applied": True, "outputs": values, "sensitive_outputs": sensitive},
        )


def apply_failure(tool: str, outcome: ContainerJobResult, state_name: str | None) -> str:
    """The step error for a failed apply, naming what happened to the state."""
    where = f"managed state {state_name!r}" if state_name else "the state backend"
    errored = (outcome.collected.get(ERRORED_STATE_FILE) or b"").decode("utf-8", "replace")
    if outcome.exit_code == EXIT_NO_PLAN:
        return NO_PLAN_MESSAGE
    if errored.strip() == "kept":
        return (
            f"{tool} apply changed resources but could not save the resulting state to "
            f"{where}, and saving it again failed too. The state is kept as the run "
            f"artifact {ERRORED_STATE_ARTIFACT}: it holds the state in clear (secrets "
            f"included), so download it, save it with `{tool} "
            "state push`, then delete the artifact. Plan again only after that; see the "
            "container output for the original error."
        )
    if errored.strip() == "recovered":
        return (
            f"{tool} apply failed, and the tool could not save the resulting state at "
            f"first; the step saved it to {where} afterwards. See the container output "
            "for the error, then plan again."
        )
    if STALE_PLAN_MARKER in outcome.stdout or STALE_PLAN_MARKER in outcome.stderr:
        return f"{tool} refused the saved plan: the state changed since it was made. Plan again."
    return f"{tool} apply exited with code {outcome.exit_code}; see the container output"


def _script_file(engine: str, workdir: str, lock_timeout: str) -> StagedFile:
    return StagedFile(RUN_SCRIPT, build_apply_script(engine, workdir, lock_timeout), mode=0o755)
