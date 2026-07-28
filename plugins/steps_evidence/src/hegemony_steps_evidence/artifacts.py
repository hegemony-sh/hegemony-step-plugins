# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared helpers for picking artifacts out of the internal run response."""

from datetime import UTC, datetime
from typing import Any


def _parse_created_at(value: Any) -> datetime | None:
    """Parse an ISO-8601 ``created_at`` defensively; None when unusable.

    Comparing raw strings would mis-order mixed forms ('Z' vs '+00:00');
    naive values are pinned to UTC so aware/naive pairs stay comparable.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


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
    highest parsed ``created_at``; artifacts without a usable one (older
    APIs) sort below dated ones but among themselves keep list order, where
    the API returns oldest first — so the last match still wins.
    """
    best: dict[str, Any] | None = None
    best_key: datetime | None = None
    for artifact in artifacts:
        if step_id is not None and artifact.get("step_id") != step_id:
            continue
        if name is not None and artifact.get("name") != name:
            continue
        key = _parse_created_at(artifact.get("created_at"))
        if (
            best is None
            or (key is None and best_key is None)
            or (key is not None and (best_key is None or key >= best_key))
        ):
            best = artifact
            best_key = key
    return best
