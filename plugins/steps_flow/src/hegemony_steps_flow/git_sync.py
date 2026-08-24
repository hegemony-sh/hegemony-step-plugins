# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Git integration handlers for scheduled repo-wide pull sync.

Exports are owned by Configuration Exchange; Flow Git handlers only trigger sync operations.
"""

import asyncio
import logging
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)

logger = logging.getLogger(__name__)


class GitSyncRepoConfig(BaseModel):
    """Config for the internal ``flow.git_sync`` handler."""

    model_config = ConfigDict(extra="allow")

    git_repo_id: str = Field(
        min_length=1,
        title="Git Repository",
        description="UUID of the git repository whose flow definitions are pulled by this sync.",
    )
    conflict_policy: Literal["reject_dirty", "overwrite", "skip"] = Field(
        default="reject_dirty",
        title="Conflict Policy",
        description=(
            "How the sync treats flows with local modifications: reject_dirty "
            "rejects them, overwrite replaces them with the repository "
            "version, and skip leaves them out of the sync. Defaults to "
            "reject_dirty."
        ),
    )
    force: bool = Field(
        default=False,
        title="Force",
        description="Force the pull sync regardless of the conflict policy. Defaults to false.",
    )
    flow_ids: list[str] | None = Field(
        default=None,
        title="Limit to Flows",
        description=(
            "Optional list of flow UUIDs limiting the sync scope. Leave "
            "unset to sync every flow tracked by the repository."
        ),
    )


class GitSyncRepoHandler(BaseHandler):
    """Handler that triggers a repo-wide pull sync via the API.

    Config:
        git_repo_id (str, required): UUID of the git repository to sync.
        conflict_policy (str): "reject_dirty", "overwrite", or "skip". Default: "reject_dirty".
        force (bool): Shortcut for conflict_policy=force. Default: false.
        flow_ids (list[str]|None): Optional list of flow UUIDs to limit sync scope.
    """

    handler_id = "flow.git_sync"
    supported_kinds = [StepKind.ACTION]
    display_name = "Git Repo Sync"
    description = "Trigger a repo-wide pull sync of flow definitions (scheduled flows)."
    hidden = True
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = GitSyncRepoConfig

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        git_repo_id = ctx.config.get("git_repo_id")
        if not git_repo_id:
            return HandlerResult(
                success=False,
                error="Missing required config: git_repo_id",
                summary="No git_repo_id specified",
            )

        log_extra = {
            "git_repo_id": git_repo_id,
            "run_id": ctx.run_id,
            "step_id": ctx.step_id,
        }

        conflict_policy = ctx.config.get("conflict_policy", "reject_dirty")
        force = ctx.config.get("force", False)

        services = ctx.require_services()

        payload: dict = {
            "conflict_policy": conflict_policy,
            "force": force,
            "trigger_source": "scheduled",
        }

        max_attempts = 4
        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                async with services.open_api_client(timeout=120) as client:
                    resp = await client.post(
                        f"/api/v1/git-repositories/{git_repo_id}/sync",
                        json=payload,
                    )
                    resp.raise_for_status()
                    data = resp.json()
                break
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (429, 500, 502, 503, 504) and attempt < max_attempts:
                    delay = min(2 ** (attempt - 1), 8)
                    logger.warning(
                        "git_sync_repo_retrying",
                        extra={
                            **log_extra,
                            "status": e.response.status_code,
                            "attempt": attempt,
                            "delay": delay,
                        },
                    )
                    await asyncio.sleep(delay)
                    last_exc = e
                    continue
                detail = ""
                try:
                    detail = e.response.json().get("detail", "")
                except Exception:
                    detail = e.response.text[:500]
                logger.error(
                    "git_sync_repo_failed",
                    extra={**log_extra, "status": e.response.status_code},
                )
                return HandlerResult(
                    success=False,
                    error=f"Sync API returned {e.response.status_code}: {detail}",
                    summary=f"Repo sync failed ({e.response.status_code})",
                )
            except httpx.HTTPError as e:
                if attempt < max_attempts:
                    delay = min(2 ** (attempt - 1), 8)
                    logger.warning(
                        "git_sync_repo_retrying",
                        extra={**log_extra, "error": str(e), "attempt": attempt, "delay": delay},
                    )
                    await asyncio.sleep(delay)
                    last_exc = e
                    continue
                logger.error(
                    "git_sync_repo_http_error",
                    extra={**log_extra, "error": str(e)},
                )
                return HandlerResult(
                    success=False,
                    error=str(e),
                    summary="Repo sync HTTP error",
                )
        else:
            # All attempts exhausted
            logger.error(
                "git_sync_repo_all_retries_exhausted",
                extra={**log_extra, "attempts": max_attempts},
            )
            return HandlerResult(
                success=False,
                error=f"All {max_attempts} attempts failed: {last_exc}",
                summary="Repo sync failed after retries",
            )

        summary_data = data.get("summary", {})
        succeeded = summary_data.get("succeeded", 0)
        failed = summary_data.get("failed", 0)
        total = summary_data.get("total", 0)
        conflicts = summary_data.get("conflicts", 0)
        skipped = summary_data.get("skipped", 0)
        success = failed == 0 and conflicts == 0

        if success:
            outcome_parts = [f"{failed} failed"]
            if skipped:
                outcome_parts.append(f"{skipped} skipped")
            summary = f"Synced {succeeded}/{total} flows ({', '.join(outcome_parts)})"
            error = None
        else:
            outcome_parts: list[str] = []
            if failed:
                outcome_parts.append(f"{failed} failed")
            if conflicts:
                outcome_parts.append(f"{conflicts} conflict(s)")
            if skipped:
                outcome_parts.append(f"{skipped} skipped")
            outcome_text = ", ".join(outcome_parts) or "sync incomplete"
            summary = f"Repo sync incomplete: synced {succeeded}/{total} flows ({outcome_text})"
            error = f"Repo sync incomplete: {outcome_text}"

        return HandlerResult(
            success=success,
            summary=summary,
            metrics={
                "total": total,
                "succeeded": succeeded,
                "failed": failed,
                "conflicts": conflicts,
                "skipped": skipped,
            },
            error=error,
        )
