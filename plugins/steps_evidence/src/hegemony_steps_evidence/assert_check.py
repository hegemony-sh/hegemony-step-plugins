# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""AssertHandler: perform inline assertions against artifacts."""

import json
import logging
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)

logger = logging.getLogger(__name__)


class AssertConfig(BaseModel):
    """Config for ``evidence.assert``.

    ``target_role`` + ``command`` are set together by the editor's compound
    evidence-output widget (one control, two config keys).
    """

    model_config = ConfigDict(extra="allow")

    artifact_step_id: str = Field(
        title="Evidence Step",
        description="Only netcli.collect_evidence steps shown",
        json_schema_extra={
            "x_widget": "step-select",
            "x_step_handler_filter": "netcli.collect_evidence",
            "x_placeholder": "Select evidence step...",
        },
    )
    operator: Literal["contains", "not_contains", "matches", "not_matches", "eq", "ne"] = Field(
        default="contains",
        title="Operator",
        json_schema_extra={
            "x_option_labels": {
                "contains": "Contains",
                "not_contains": "Does Not Contain",
                "matches": "Matches (regex)",
                "not_matches": "Does Not Match (regex)",
                "eq": "Equals (==)",
                "ne": "Not Equals (!=)",
            }
        },
    )
    match_scope: Literal["output", "lines"] = Field(
        default="output",
        title="Match Scope",
        description=(
            "'Whole output' asserts once against the entire artifact; "
            "'Every line' asserts the operator against each selected line "
            "(e.g. every OSPF neighbor row must contain 'Full')."
        ),
        json_schema_extra={
            "x_option_labels": {
                "output": "Whole output",
                "lines": "Every line",
            }
        },
    )
    line_filter: str = Field(
        default="",
        title="Line Filter (regex)",
        description=(
            "With 'Every line' scope: only lines matching this regex are "
            "asserted, so headers and blanks don't count. Empty selects every "
            "non-empty line."
        ),
        json_schema_extra={
            "x_placeholder": "Regex selecting the lines to assert",
            "x_col_span": 2,
        },
    )
    min_lines: int = Field(
        default=1,
        ge=0,
        title="Minimum Lines",
        description=(
            "With 'Every line' scope: fail unless at least this many lines "
            "were selected — an empty selection must not pass vacuously."
        ),
    )
    target_role: str = Field(
        default="",
        title="Evidence Output",
        description="Choose a target and command from the selected evidence step.",
        json_schema_extra={
            "x_widget": "evidence-output-select",
            "x_widget_role": "target",
            "x_col_span": 2,
        },
    )
    command: str = Field(
        default="",
        json_schema_extra={"x_widget": "evidence-output-select", "x_widget_role": "command"},
    )
    expected: str = Field(
        default="",
        title="Expected Value / Pattern",
        json_schema_extra={"x_placeholder": "Expected value or regex pattern", "x_col_span": 2},
    )
    message: str = Field(
        default="",
        title="Custom Message (optional)",
        json_schema_extra={
            "x_placeholder": "e.g., IOS-XE version must be 17.9 or higher",
            "x_col_span": 2,
        },
    )


class AssertHandler(BaseHandler):
    """Handler for inline assertions with expected values.

    Config:
        expression: str - JMESPath or simple field path to evaluate
        expected: Any - Expected value to compare against
        operator: str - Comparison operator (eq, ne, gt, lt, ge, le, contains,
            not_contains, matches, not_matches)
        match_scope: str - "output" asserts once against the whole artifact;
            "lines" asserts the operator against every selected line
        line_filter: str - (match_scope="lines") regex selecting which lines
            are asserted; empty selects every non-empty line
        min_lines: int - (match_scope="lines") fail unless at least this many
            lines were selected (guards against vacuous passes)
        source: str - Source of data: "params" | "evidence" | "device" | "artifact"
        artifact_step_id: str - (when source="artifact") Step ID to get artifact from
        artifact_name: str - (when source="artifact") Artifact name to check
        message: str - Custom assertion message
    """

    handler_id = "evidence.assert"
    supported_kinds = [StepKind.CHECK]
    display_name = "Assert"
    description = "Assert an expected value against evidence collected by another step."
    category = "Checks"
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = AssertConfig
    default_config = {"operator": "contains"}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Execute assertion check against artifact from a previous step."""
        expected = ctx.config.get("expected")
        operator = ctx.config.get("operator", "contains")
        match_scope = ctx.config.get("match_scope", "output")
        line_filter = ctx.config.get("line_filter", "")
        try:
            min_lines = int(ctx.config.get("min_lines", 1))
        except (TypeError, ValueError):
            min_lines = 1
        message = ctx.config.get("message", "")
        artifact_step_id = ctx.config.get("artifact_step_id")
        log_extra = {
            "run_id": ctx.run_id,
            "step_id": ctx.step_id,
            "step_run_id": ctx.step_run_id,
        }

        # Build artifact names from target_role + command. The target role is
        # resolved to device names because collect_evidence artifacts are named
        # "<device_name>:<command>".
        target_role = ctx.config.get("target_role")
        command = ctx.config.get("command")
        artifact_name = ctx.config.get("artifact_name")
        artifact_names: list[str] = []

        if target_role and command:
            role_devices = ctx.target_devices_by_role.get(target_role, [])
            if not role_devices:
                logger.warning(
                    "assert_target_not_bound",
                    extra={**log_extra, "target_role": target_role, "command": command},
                )
                return HandlerResult(
                    success=False,
                    error=f"Target '{target_role}' not bound to any device",
                    summary=f"Cannot resolve target: {target_role}",
                )
            for device in role_devices:
                device_name = device.get("name")
                if not device_name:
                    logger.error(
                        "assert_target_device_missing_name",
                        extra={
                            **log_extra,
                            "target_role": target_role,
                            "command": command,
                            "device_id": device.get("id", device.get("mgmt_host")),
                        },
                    )
                    return HandlerResult(
                        success=False,
                        error=f"Device for target '{target_role}' has no name",
                        summary=f"Invalid device configuration for target: {target_role}",
                    )
                artifact_names.append(f"{device_name}:{command}")
        elif artifact_name:
            artifact_names = [artifact_name]

        if not artifact_names:
            logger.error(
                "assert_artifact_names_unresolved",
                extra={
                    **log_extra,
                    "artifact_step_id": artifact_step_id,
                    "target_role": target_role,
                    "command": command,
                    "artifact_name": artifact_name,
                },
            )
            return HandlerResult(
                success=False,
                error="No artifact names were resolved",
                summary=f"Cannot resolve artifact names from step '{artifact_step_id}'",
            )

        assertion_evidence = []
        failed_messages = []

        for name in artifact_names:
            artifact_content = await self._get_artifact_data(ctx, artifact_step_id, name)
            if artifact_content is None:
                logger.warning(
                    "assert_artifact_fetch_failed",
                    extra={
                        **log_extra,
                        "artifact_step_id": artifact_step_id,
                        "artifact_name": name,
                    },
                )
                failed_messages.append(f"{name}: could not fetch artifact content")
                continue

            # The actual value is the artifact text content
            actual = artifact_content
            passed, comparison_msg, scope_detail = self._assert_content(
                actual, expected, operator, match_scope, line_filter, min_lines
            )
            if not passed:
                failed_messages.append(f"{name}: {comparison_msg}")

            assertion_evidence.append(
                {
                    "kind": "assertion_result",
                    "name": "assertion" if len(artifact_names) == 1 else f"assertion:{name}",
                    "content_json": {
                        "artifact_step_id": artifact_step_id,
                        "artifact_name": name,
                        "operator": operator,
                        "expected": expected,
                        "actual": actual if len(str(actual)) < 500 else f"{str(actual)[:500]}...",
                        **scope_detail,
                        "passed": passed,
                    },
                }
            )

        if not failed_messages:
            return HandlerResult(
                success=True,
                summary=message
                or f"Assertion passed for {len(artifact_names)} artifact(s): {operator} '{expected}'",
                evidence=assertion_evidence,
            )
        return HandlerResult(
            success=False,
            error=message or "; ".join(failed_messages),
            summary=f"Assertion failed for {len(failed_messages)}/{len(artifact_names)} artifact(s)",
            evidence=assertion_evidence,
        )

    async def _get_artifact_data(
        self,
        ctx: HandlerContext,
        artifact_step_id: str | None = None,
        artifact_name: str | None = None,
    ) -> str | None:
        """Get artifact content from a previous step."""
        if not artifact_step_id or not artifact_name:
            logger.error("assert requires artifact_step_id and artifact_name")
            return None
        return await self._fetch_artifact_content(ctx, artifact_step_id, artifact_name)

    async def _fetch_artifact_content(
        self, ctx: HandlerContext, step_id: str, artifact_name: str
    ) -> str | None:
        """Fetch artifact content from API."""
        run_id = ctx.run_id
        async with ctx.require_services().open_api_client(timeout=30) as client:
            try:
                # Use internal endpoint for worker-to-API calls
                response = await client.get(f"/internal/runs/{run_id}")
                if response.status_code == 404:
                    logger.warning(f"Run {run_id} not found (may have been deleted)")
                    return None
                if response.status_code != 200:
                    logger.error(f"Failed to fetch run {run_id}: {response.status_code}")
                    return None

                run_data = response.json()
                artifacts = run_data.get("artifacts", [])

                # Find matching artifact
                for artifact in artifacts:
                    if artifact.get("step_id") == step_id and artifact.get("name") == artifact_name:
                        # Prefer content_text (actual output) over content_json
                        content_text = artifact.get("content_text")
                        if content_text:
                            return content_text
                        content_json = artifact.get("content_json")
                        if content_json is None:
                            return None
                        return json.dumps(content_json, ensure_ascii=False)

                logger.error(f"Artifact '{artifact_name}' not found in step '{step_id}'")
                return None
            except Exception as e:
                logger.error(f"Failed to fetch artifact: {e}")
                return None

    def _assert_content(
        self,
        actual: Any,
        expected: Any,
        operator: str,
        match_scope: str,
        line_filter: str,
        min_lines: int,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Assert against artifact content in the configured scope.

        ``output`` scope compares once against the whole artifact (the
        original behavior); ``lines`` scope selects lines (via the optional
        ``line_filter`` regex, else every non-empty line) and requires EVERY
        selected line to satisfy the operator, with ``min_lines`` guarding
        against a vacuous pass on an empty selection. Returns
        ``(passed, failure message, detail dict for the evidence record)``.
        """
        if match_scope != "lines":
            passed, msg = self._compare_values(actual, expected, operator)
            return passed, msg, {"match_scope": "output"}

        detail: dict[str, Any] = {"match_scope": "lines", "line_filter": line_filter}
        if not isinstance(actual, str):
            return (
                False,
                f"Line-scope assertion needs text content, got {type(actual).__name__}",
                detail,
            )

        try:
            selector = re.compile(line_filter) if line_filter else None
        except re.error as exc:
            return False, f"Invalid line_filter regex: {exc}", detail

        if selector is None:
            selected = [line for line in actual.splitlines() if line.strip()]
        else:
            selected = [line for line in actual.splitlines() if selector.search(line)]
        detail["lines_selected"] = len(selected)

        if len(selected) < min_lines:
            qualifier = f" by filter '{line_filter}'" if line_filter else ""
            return (
                False,
                f"only {len(selected)} line(s) selected{qualifier}, expected at least {min_lines}",
                detail,
            )

        lines_passed = 0
        first_failed: str | None = None
        for line in selected:
            line_ok, _ = self._compare_values(line, expected, operator)
            if line_ok:
                lines_passed += 1
            elif first_failed is None:
                first_failed = line.strip()[:200]
        detail["lines_passed"] = lines_passed

        if first_failed is not None:
            detail["first_failed_line"] = first_failed
            return (
                False,
                f"{len(selected) - lines_passed}/{len(selected)} selected line(s) "
                f"failed {operator} '{expected}'; first: '{first_failed}'",
                detail,
            )
        return True, "", detail

    def _compare_values(self, actual: Any, expected: Any, operator: str) -> tuple[bool, str]:
        """Compare actual and expected values using operator."""
        try:
            if operator == "eq":
                passed = actual == expected
                msg = f"Expected {expected}, got {actual}"
            elif operator == "ne":
                passed = actual != expected
                msg = f"Expected not {expected}, got {actual}"
            elif operator in ("gt", "lt", "ge", "le"):
                # Attempt numeric coercion for ordering comparisons;
                # only use floats if *both* values convert successfully.
                try:
                    num_actual: Any = float(actual)
                    num_expected: Any = float(expected)
                except (TypeError, ValueError):
                    # Fall back to original values (string comparison)
                    num_actual = actual
                    num_expected = expected
                if operator == "gt":
                    passed = num_actual > num_expected
                    msg = f"Expected > {expected}, got {actual}"
                elif operator == "lt":
                    passed = num_actual < num_expected
                    msg = f"Expected < {expected}, got {actual}"
                elif operator == "ge":
                    passed = num_actual >= num_expected
                    msg = f"Expected >= {expected}, got {actual}"
                else:  # le
                    passed = num_actual <= num_expected
                    msg = f"Expected <= {expected}, got {actual}"
            elif operator == "contains":
                passed = expected in actual if isinstance(actual, str | list | tuple) else False
                msg = f"Expected '{actual}' to contain '{expected}'"
            elif operator == "not_contains":
                passed = expected not in actual if isinstance(actual, str | list | tuple) else False
                msg = f"Expected '{actual}' to not contain '{expected}'"
            elif operator == "matches":
                if isinstance(actual, str) and isinstance(expected, str):
                    passed = bool(re.search(expected, actual))
                else:
                    passed = False
                msg = f"Expected '{actual}' to match pattern '{expected}'"
            elif operator == "not_matches":
                if isinstance(actual, str) and isinstance(expected, str):
                    passed = not re.search(expected, actual)
                else:
                    passed = False
                msg = f"Expected '{actual}' to not match pattern '{expected}'"
            else:
                passed = False
                msg = f"Unknown operator: {operator}"
        except Exception as e:
            passed = False
            msg = f"Comparison error: {e}"

        return passed, msg
