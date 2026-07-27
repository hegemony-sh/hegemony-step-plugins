# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""CompareEvidenceHandler: compare artifacts between steps."""

import difflib
import logging
import re
from fnmatch import fnmatch
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)

from .artifacts import latest_artifact

logger = logging.getLogger(__name__)

# Guardrails for user-supplied ``ignore_patterns``: a pathological regex run via
# ``re.sub`` over large CLI output can backtrack catastrophically and block the
# worker's event loop. Compile each pattern once (not per artifact), cap how many
# run, and cap how much text they run against.
_MAX_IGNORE_PATTERNS = 50
_MAX_MASK_INPUT_CHARS = 1_000_000


class CompareEvidenceConfig(BaseModel):
    """Config for ``evidence.compare``."""

    model_config = ConfigDict(extra="allow")

    precheck_step_id: str = Field(
        default="",
        title="Precheck Step",
        description="Select the step that collected pre-change evidence",
        json_schema_extra={
            "x_widget": "step-select",
            "x_step_handler_filter": "netcli.collect_evidence",
            "x_placeholder": "Select precheck evidence step...",
        },
    )
    postcheck_step_id: str = Field(
        default="",
        title="Postcheck Step",
        description="Select the step that collected post-change evidence",
        json_schema_extra={
            "x_widget": "step-select",
            "x_step_handler_filter": "netcli.collect_evidence",
            "x_placeholder": "Select postcheck evidence step...",
        },
    )
    comparison_type: Literal["exact", "changed", "subset", "superset", "json_diff"] = Field(
        default="exact",
        title="Comparison mode",
        description=(
            "What a difference between the pre- and post-check evidence means. "
            "'exact': pass only when they are identical — a difference FAILS the "
            "step (drift / no-change checks). 'changed': pass only when they "
            "differ — a difference SUCCEEDS the step (confirm an intended change "
            "actually took effect). 'subset' / 'superset' / 'json_diff' compare "
            "structured (dict/list) evidence."
        ),
        json_schema_extra={
            "x_option_labels": {
                "exact": "Must match — a difference fails the step",
                "changed": "Must differ — a difference passes the step",
                "subset": "Postcheck contains the precheck (structured)",
                "superset": "Postcheck extends the precheck (structured)",
                "json_diff": "Structured JSON diff (must match)",
            },
        },
    )
    artifact_name: str = Field(
        default="",
        title="Only this artifact",
        description=(
            "Compare a single artifact by its exact name (e.g. "
            "'dc1-core-01:show running-config'). Leave blank to compare every "
            "artifact the two steps share."
        ),
        json_schema_extra={"x_placeholder": "device:command"},
    )
    artifact_name_pattern: str = Field(
        default="",
        title="Only artifacts matching",
        description=(
            "Glob over artifact names (e.g. '*show running-config') so volatile "
            "outputs — routing tables, neighbor tables — can be left out of the "
            "comparison. Ignored when a single artifact name is set."
        ),
        json_schema_extra={"x_placeholder": "*show running-config"},
    )
    ignore_patterns: list[str] = Field(
        default_factory=list,
        title="Mask text matching",
        description=(
            "Regular expressions; every match is removed from BOTH sides before "
            "a text comparison, so volatile output — uptimes, timers, "
            "packet/byte counters — does not register as a difference while the "
            "rest of the line is kept. Matched per line (^ and $ anchor to line "
            "boundaries), e.g. ', \\d\\d:\\d\\d:\\d\\d,' to mask route uptimes."
        ),
    )
    ignore_fields: list[str] = Field(
        default_factory=list,
        title="Ignore fields",
        description=(
            "Structured (dict) evidence only: keys removed from both sides before comparing."
        ),
    )


class CompareEvidenceHandler(BaseHandler):
    """Handler for comparing evidence from two phases (precheck vs postcheck)."""

    handler_id = "evidence.compare"
    supported_kinds = [StepKind.CHECK]
    display_name = "Compare Evidence"
    description = "Diff evidence artifacts between two steps (precheck vs postcheck)."
    category = "Checks"
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = CompareEvidenceConfig

    async def _fetch_artifacts_for_step(self, ctx: HandlerContext, step_id: str) -> list[dict]:
        """Fetch artifacts from API for a specific step."""
        run_id = ctx.run_id
        async with ctx.require_services().open_api_client(timeout=30) as client:
            try:
                # Use internal endpoint for worker-to-API calls
                response = await client.get(f"/internal/runs/{run_id}")
                if response.status_code != 200:
                    logger.error(f"Failed to fetch run {run_id}: {response.status_code}")
                    return []

                run_data = response.json()
                artifacts = run_data.get("artifacts", [])

                # Filter artifacts for the specified step
                step_artifacts = [a for a in artifacts if a.get("step_id") == step_id]
                return step_artifacts
            except Exception as e:
                logger.error(f"Failed to fetch artifacts for step {step_id}: {e}")
                return []

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Compare evidence between steps by fetching artifacts from API."""
        precheck_step_id = ctx.config.get("precheck_step_id")
        postcheck_step_id = ctx.config.get("postcheck_step_id")
        artifact_name = ctx.config.get("artifact_name")
        artifact_name_pattern = ctx.config.get("artifact_name_pattern")
        comparison_type = ctx.config.get("comparison_type", "exact")
        ignore_fields = ctx.config.get("ignore_fields", [])
        # Compile the ignore patterns ONCE here, bounded, rather than per
        # artifact inside the compare loop (ReDoS/perf guardrail).
        compiled_ignore = self._compile_ignore_patterns(ctx.config.get("ignore_patterns", []))

        if not precheck_step_id:
            return HandlerResult(
                success=False,
                error="No precheck_step_id configured",
                summary="Comparison configuration error",
            )

        # Fetch artifacts from API for both steps
        precheck_artifacts = await self._fetch_artifacts_for_step(ctx, precheck_step_id)
        postcheck_artifacts = await self._fetch_artifacts_for_step(
            ctx,
            postcheck_step_id or ctx.step_id,  # Use current step if postcheck not specified
        )

        # Restrict to artifacts whose name matches the glob, so volatile outputs
        # (routing/neighbor tables with counters) can be excluded and only the
        # meaningful evidence — e.g. the running-config — is compared. An exact
        # ``artifact_name`` still wins over the pattern.
        if not artifact_name and artifact_name_pattern:
            precheck_artifacts = [
                a
                for a in precheck_artifacts
                if a.get("name") and fnmatch(a["name"], artifact_name_pattern)
            ]
            postcheck_artifacts = [
                a
                for a in postcheck_artifacts
                if a.get("name") and fnmatch(a["name"], artifact_name_pattern)
            ]
            if not precheck_artifacts:
                return HandlerResult(
                    success=False,
                    error=(
                        f"No artifacts in precheck step '{precheck_step_id}' match "
                        f"pattern '{artifact_name_pattern}'"
                    ),
                    summary="No artifacts matched pattern",
                )
            if not postcheck_artifacts:
                return HandlerResult(
                    success=False,
                    error=(
                        f"No artifacts in postcheck step "
                        f"'{postcheck_step_id or ctx.step_id}' match "
                        f"pattern '{artifact_name_pattern}'"
                    ),
                    summary="No artifacts matched pattern",
                )

        if not precheck_artifacts:
            return HandlerResult(
                success=False,
                error=f"No artifacts found for precheck step '{precheck_step_id}'",
                summary="Missing precheck evidence",
            )

        # If artifact_name is specified, filter to just that artifact
        # Otherwise, compare all artifacts with matching names
        if artifact_name:
            precheck_filtered = [a for a in precheck_artifacts if a.get("name") == artifact_name]
            postcheck_filtered = [a for a in postcheck_artifacts if a.get("name") == artifact_name]

            if not precheck_filtered:
                return HandlerResult(
                    success=False,
                    error=f"No artifact '{artifact_name}' found in precheck step '{precheck_step_id}'",
                    summary="Missing precheck artifact",
                )

            if not postcheck_filtered:
                return HandlerResult(
                    success=False,
                    error=f"No artifact '{artifact_name}' found in postcheck step",
                    summary="Missing postcheck artifact",
                )

            # Compare the specific artifact — the NEWEST one on each side, in
            # case the pre/post steps ran more than once (loops, retries) and
            # left several artifacts under the same name.
            precheck_latest = latest_artifact(precheck_filtered)
            postcheck_latest = latest_artifact(postcheck_filtered)
            if precheck_latest is None or postcheck_latest is None:
                # Unreachable with the non-empty lists checked above, but a
                # clean failure beats a stripped assert under -O.
                return HandlerResult(
                    success=False,
                    error="Failed to select artifacts for comparison",
                    summary="Missing comparison artifacts",
                )
            # Prefer content_text for CLI output (actual command output) over content_json (metadata)
            precheck_text = precheck_latest.get("content_text")
            precheck_content = (
                precheck_text if precheck_text is not None else precheck_latest.get("content_json")
            )
            postcheck_text = postcheck_latest.get("content_text")
            postcheck_content = (
                postcheck_text
                if postcheck_text is not None
                else postcheck_latest.get("content_json")
            )

            passed, diff_details = self._compare(
                precheck_content, postcheck_content, comparison_type, ignore_fields, compiled_ignore
            )
            artifacts_compared = [artifact_name]
        else:
            # Compare all matching artifacts by name, keeping only the newest
            # per name (steps that ran more than once leave older duplicates).
            precheck_by_name = {
                name: artifact
                for name in {a["name"] for a in precheck_artifacts if a.get("name")}
                if (artifact := latest_artifact(precheck_artifacts, name=name)) is not None
            }
            postcheck_by_name = {
                name: artifact
                for name in {a["name"] for a in postcheck_artifacts if a.get("name")}
                if (artifact := latest_artifact(postcheck_artifacts, name=name)) is not None
            }

            common_names = set(precheck_by_name.keys()) & set(postcheck_by_name.keys())
            if not common_names:
                return HandlerResult(
                    success=False,
                    error="No matching artifacts found between precheck and postcheck steps",
                    summary="No artifacts to compare",
                )

            all_passed = True
            all_diffs = {}
            for name in sorted(common_names):
                # Prefer content_text for CLI output (actual command output) over content_json (metadata)
                pre_text = precheck_by_name[name].get("content_text")
                pre_content = (
                    pre_text if pre_text is not None else precheck_by_name[name].get("content_json")
                )
                post_text = postcheck_by_name[name].get("content_text")
                post_content = (
                    post_text
                    if post_text is not None
                    else postcheck_by_name[name].get("content_json")
                )
                passed, diff = self._compare(
                    pre_content, post_content, comparison_type, ignore_fields, compiled_ignore
                )
                all_diffs[name] = {"passed": passed, "diff": diff}
                if not passed:
                    all_passed = False

            passed = all_passed
            diff_details = all_diffs
            artifacts_compared = list(common_names)

        evidence = [
            {
                "kind": "comparison_result",
                "name": f"compare_evidence_{precheck_step_id}_vs_{postcheck_step_id or 'current'}",
                "content_json": {
                    "artifacts_compared": artifacts_compared,
                    "comparison_type": comparison_type,
                    "match": passed,  # UI uses 'match' for display
                    "passed": passed,
                    "diff": diff_details,
                    "before_step": precheck_step_id,
                    "after_step": postcheck_step_id or "current",
                    "precheck_step_id": precheck_step_id,
                    "postcheck_step_id": postcheck_step_id,
                },
            }
        ]

        # Phrase the outcome for the comparison mode: in "changed" mode a
        # difference is the SUCCESS signal, so "matched"/"differences found"
        # would read backwards.
        changed_mode = comparison_type == "changed"
        n = len(artifacts_compared)
        if passed:
            outcome = "changed as expected" if changed_mode else "matched"
            return HandlerResult(
                success=True,
                summary=f"Evidence comparison passed: {n} artifact(s) {outcome}",
                evidence=evidence,
            )
        else:
            # For a single artifact_name comparison, diff_details is one
            # comparison dict (not the {name: {...}} map), so exactly one
            # artifact failed. Only the multi-artifact path counts per-name.
            failed_count = (
                1
                if artifact_name
                else sum(
                    1
                    for d in (diff_details.values() if isinstance(diff_details, dict) else [])
                    if isinstance(d, dict) and not d.get("passed", True)
                )
            )
            if changed_mode:
                error = "Evidence comparison failed: no change detected"
                summary = f"No change in {failed_count} of {n} artifact(s)"
            else:
                error = "Evidence comparison failed: differences found"
                summary = f"Pre/post check mismatch in {failed_count} of {n} artifact(s)"
            return HandlerResult(
                success=False,
                error=error,
                summary=summary,
                evidence=evidence,
            )

    def _compare(
        self,
        precheck: Any,
        postcheck: Any,
        comparison_type: str,
        ignore_fields: list[str],
        ignore_patterns: list[re.Pattern[str]] | None = None,
    ) -> tuple[bool, dict]:
        """Compare two evidence values.

        ``ignore_patterns`` are pre-compiled regexes (see
        ``_compile_ignore_patterns``) applied to text evidence before comparing.
        """
        logger.info(
            f"Comparing evidence: type={comparison_type}, precheck_type={type(precheck).__name__}, postcheck_type={type(postcheck).__name__}"
        )

        # Remove ignored fields if dictionaries
        if isinstance(precheck, dict) and isinstance(postcheck, dict):
            precheck = self._remove_fields(precheck, ignore_fields)
            postcheck = self._remove_fields(postcheck, ignore_fields)

        # Mask volatile substrings (counters, timers, uptimes) from text on both
        # sides before comparing, so they never register as a difference.
        if isinstance(precheck, str) and isinstance(postcheck, str) and ignore_patterns:
            precheck = self._mask_ignored(precheck, ignore_patterns)
            postcheck = self._mask_ignored(postcheck, ignore_patterns)

        diff_details: dict[str, Any] = {
            "comparison_type": comparison_type,
            "precheck_type": type(precheck).__name__,
            "postcheck_type": type(postcheck).__name__,
        }

        # For text comparison, normalize whitespace and optionally show preview
        if isinstance(precheck, str) and isinstance(postcheck, str):
            # Log first 200 chars for debugging
            logger.debug(f"Precheck text (first 200): {precheck[:200]}")
            logger.debug(f"Postcheck text (first 200): {postcheck[:200]}")
            diff_details["precheck_length"] = len(precheck)
            diff_details["postcheck_length"] = len(postcheck)

        if comparison_type == "exact":
            passed = precheck == postcheck
            if not passed:
                diff_details["differences"] = self._find_differences(precheck, postcheck)
        elif comparison_type == "changed":
            passed = precheck != postcheck
            diff_details["changed"] = passed
            # Always show the diff for "changed" comparison type
            diff_details["differences"] = self._find_differences(precheck, postcheck)
        elif comparison_type == "subset":
            # Postcheck must contain all precheck items
            if isinstance(precheck, dict) and isinstance(postcheck, dict):
                passed = all(postcheck.get(k) == v for k, v in precheck.items())
            elif isinstance(precheck, list | set) and isinstance(postcheck, list | set):
                passed = set(precheck).issubset(set(postcheck))
            else:
                passed = precheck == postcheck
        elif comparison_type == "superset":
            # Postcheck must have all precheck items and more
            if isinstance(precheck, dict) and isinstance(postcheck, dict):
                passed = all(postcheck.get(k) == v for k, v in precheck.items()) and len(
                    postcheck
                ) > len(precheck)
            elif isinstance(precheck, list | set) and isinstance(postcheck, list | set):
                passed = set(precheck).issubset(set(postcheck)) and len(set(postcheck)) > len(
                    set(precheck)
                )
            else:
                passed = False
        elif comparison_type == "json_diff":
            passed, diff_details["json_diff"] = self._json_diff(precheck, postcheck)
        else:
            passed = precheck == postcheck

        return passed, diff_details

    def _remove_fields(self, data: dict, fields: list[str]) -> dict:
        """Remove specified fields from dictionary."""
        return {k: v for k, v in data.items() if k not in fields}

    def _mask_ignored(self, text: str, patterns: list[re.Pattern[str]]) -> str:
        """Remove every substring matching any pre-compiled pattern from text.

        Volatile output — interface/route counters, timers, uptimes — is masked
        in place so it does not register as a difference, while the surrounding
        content (and any genuinely new lines) is preserved: a route table whose
        only real change is an added prefix still compares as changed once the
        drifting timer columns are masked.

        Oversized text is left unmasked (with a warning): running a
        user-supplied regex over a very large blob risks pathological
        backtracking that would block the worker, and the raw comparison is a
        safe fallback.
        """
        if len(text) > _MAX_MASK_INPUT_CHARS:
            logger.warning(
                "evidence.compare: skipping ignore_patterns on %d-char artifact "
                "(exceeds %d-char cap) to avoid pathological regex backtracking",
                len(text),
                _MAX_MASK_INPUT_CHARS,
            )
            return text
        masked = text
        for pattern in patterns:
            masked = pattern.sub("", masked)
        return masked

    def _compile_ignore_patterns(self, patterns: list[str]) -> list[re.Pattern[str]]:
        """Compile ``ignore_patterns`` once, bounded and fail-soft.

        Compiling once (rather than per artifact) and capping the pattern count
        bounds the cost of user-supplied regexes run via ``re.sub`` over CLI
        output. Non-string/empty and invalid patterns are skipped with a warning
        instead of failing the step. ``re.MULTILINE`` makes ``^``/``$`` anchor to
        line boundaries.
        """
        compiled: list[re.Pattern[str]] = []
        if len(patterns) > _MAX_IGNORE_PATTERNS:
            logger.warning(
                "evidence.compare: %d ignore_patterns exceeds the cap of %d; "
                "extra patterns are ignored",
                len(patterns),
                _MAX_IGNORE_PATTERNS,
            )
        for pattern in patterns[:_MAX_IGNORE_PATTERNS]:
            if not isinstance(pattern, str) or not pattern:
                continue
            try:
                compiled.append(re.compile(pattern, re.MULTILINE))
            except re.error as exc:
                logger.warning(
                    "evidence.compare: invalid ignore pattern %r skipped: %s", pattern, exc
                )
        return compiled

    def _find_differences(self, a: Any, b: Any) -> list[dict]:
        """Find differences between two values."""
        differences = []

        if isinstance(a, dict) and isinstance(b, dict):
            all_keys = set(a.keys()) | set(b.keys())
            for key in all_keys:
                if key not in a:
                    differences.append({"field": key, "change": "added", "value": b[key]})
                elif key not in b:
                    differences.append({"field": key, "change": "removed", "value": a[key]})
                elif a[key] != b[key]:
                    differences.append(
                        {
                            "field": key,
                            "change": "modified",
                            "before": a[key],
                            "after": b[key],
                        }
                    )
        elif isinstance(a, str) and isinstance(b, str):
            # For strings, do a line-by-line comparison
            a_lines = a.strip().splitlines()
            b_lines = b.strip().splitlines()

            # Find lines that differ using unified diff
            differ = difflib.unified_diff(
                a_lines, b_lines, fromfile="before", tofile="after", lineterm="", n=3
            )
            diff_lines = list(differ)

            if diff_lines:
                differences.append(
                    {
                        "type": "text_diff",
                        "total_precheck_lines": len(a_lines),
                        "total_postcheck_lines": len(b_lines),
                        "text_diff": diff_lines,  # Full diff for UI display
                        "before_text": a.strip(),  # Original text for side-by-side view
                        "after_text": b.strip(),  # Original text for side-by-side view
                    }
                )
        else:
            if a != b:
                differences.append({"before": str(a)[:500], "after": str(b)[:500]})

        return differences

    def _json_diff(self, a: Any, b: Any) -> tuple[bool, dict]:
        """Deep diff for JSON structures."""
        # Simple implementation - returns True if equal
        differences = self._find_differences(a, b)
        return len(differences) == 0, {"differences": differences}
