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
    PLAN_FILE,
    RUN_SCRIPT,
    TfContainerConfig,
    managed_state_access,
    script_header,
    shared_workspace_mounted,
    tool_env,
)
from .plan import common_errors, secret_environment

OUTPUTS_FILE = f"{OUTPUT_DIR}/outputs.json"

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
    lock_timeout: str = Field(
        default="300s",
        title="Lock timeout",
        description="How long to wait for the state lock (-lock-timeout), e.g. 300s or 5m.",
        json_schema_extra={"x_advanced": True},
    )


def build_apply_script(engine: str, workdir: str, lock_timeout: str) -> str:
    tf = BINARIES[engine]
    apply = [tf, "apply", "-input=false", "-no-color", f"-lock-timeout={lock_timeout}", PLAN_FILE]
    return (
        "\n".join(
            [
                *script_header(),
                f"cd {shlex.quote(workdir)}",
                " ".join(shlex.quote(part) for part in apply),
                f"{tf} output -json > {OUTPUTS_FILE}",
            ]
        )
        + "\n"
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
    # Secret references reach the handler as written (see resolve_secret_values).
    raw_config_keys = frozenset({"secret_env", "state_encryption_key"})
    default_timeout_seconds = 3600
    config_model = TfApplyConfig
    default_config = {"timeout_seconds": 3600}

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        errors = super().validate_config(config)
        if errors:
            return errors
        lock_timeout = str(config.get("lock_timeout") or "300s")
        if not lock_timeout[:-1].isdigit() or lock_timeout[-1] not in "sm":
            errors.append("'lock_timeout' must look like 300s or 5m")
        errors += common_errors(config)
        return errors

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
        try:
            # The saved plan names the backend but not its address or credentials:
            # managed state access is opened again for this step.
            async with managed_state_access(ctx, state_name, config.timeout_seconds) as access:
                env_files = await secret_environment(
                    ctx, config.secret_env, config.state_encryption_key, access
                )
                job = ContainerJob(
                    config=container_config_from(
                        ctx.config,
                        image=image,
                        command=[f"sh {RUN_SCRIPT}"],
                        entrypoint="/bin/sh",
                        env=tool_env(),
                    ),
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
        return self._result(engine, image, plan_output, outcome)

    @staticmethod
    def _refuse(message: str) -> HandlerResult:
        return HandlerResult(success=False, error=message, summary="Cannot apply the plan")

    def _result(
        self,
        engine: str,
        image: str,
        plan_output: dict[str, Any],
        outcome: ContainerJobResult,
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
                error=(
                    f"{tool} apply exited with code {outcome.exit_code}; see the container "
                    "output (a stale plan means the state changed since planning: plan again)"
                ),
                metrics=metrics,
                evidence=list(outcome.evidence),
            )
        values, sensitive = public_outputs(outcome.collected.get(OUTPUTS_FILE))
        planned = plan_output.get("summary") or "the saved plan"
        return HandlerResult(
            success=True,
            summary=f"Applied: {planned.removeprefix('Plan: ')}",
            metrics=metrics,
            evidence=list(outcome.evidence),
            output={"applied": True, "outputs": values, "sensitive_outputs": sensitive},
        )


def _script_file(engine: str, workdir: str, lock_timeout: str) -> StagedFile:
    return StagedFile(RUN_SCRIPT, build_apply_script(engine, workdir, lock_timeout), mode=0o755)
