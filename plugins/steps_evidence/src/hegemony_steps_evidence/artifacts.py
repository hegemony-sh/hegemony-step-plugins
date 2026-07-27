# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared helpers for picking artifacts out of the internal run response."""

from typing import Any


def latest_artifact(
    artifacts: list[dict[str, Any]],
    *,
    step_id: str | None = None,
    name: str | None = None,
) -> dict[str, Any] | None:
    """Return the newest artifact matching ``step_id``/``name`` (None = any).

    A step that runs more than once in a run — loop iterations, retries —
    appends a new artifact with the same step_id and name each time, so
    "first match" reads stale first-iteration evidence forever. Prefer the
    highest ``created_at``; artifacts without one (older APIs) sort below
    dated ones but among themselves keep list order, where the API returns
    oldest first — so the last match still wins.
    """
    best: dict[str, Any] | None = None
    best_key = ""
    for artifact in artifacts:
        if step_id is not None and artifact.get("step_id") != step_id:
            continue
        if name is not None and artifact.get("name") != name:
            continue
        key = artifact.get("created_at") or ""
        if best is None or key >= best_key:
            best = artifact
            best_key = key
    return best
