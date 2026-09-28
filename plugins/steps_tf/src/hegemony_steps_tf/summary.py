# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Summarize a saved plan from ``show -json`` without keeping any of its values.

The JSON plan carries resource attributes in clear, sensitive ones included, so
nothing from it is stored: only resource addresses, the actions planned for
them, and counts. The human-readable plan (``show -no-color``), in which the
tool masks values marked sensitive, is what the step keeps as evidence.
"""

from __future__ import annotations

from typing import Any

#: Resource changes listed in the step output; the counts always cover all.
MAX_LISTED_CHANGES = 200


def _classify(actions: list[str]) -> str | None:
    if actions == ["create"]:
        return "create"
    if actions == ["update"]:
        return "update"
    if actions == ["delete"]:
        return "delete"
    if sorted(actions) == ["create", "delete"]:
        return "replace"
    if actions == ["read"]:
        return "read"
    if "forget" in actions:
        return "forget" if actions == ["forget"] else "forget+create"
    return None


def summarize_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Counts and addresses of a plan, matching the tool's own "Plan:" line.

    ``add`` counts creations plus replacements and ``destroy`` deletions plus
    replacements, as the CLI does; ``replace`` is also reported on its own.
    Imports and moves ride on another action (often no-op) and are counted
    separately. ``resource_changes`` and ``output_changes`` are absent from a
    plan without changes, which is not an error.
    """
    counts = {
        "add": 0,
        "change": 0,
        "destroy": 0,
        "replace": 0,
        "import": 0,
        "move": 0,
        "read": 0,
        "forget": 0,
    }
    changes: list[dict[str, Any]] = []
    for item in plan.get("resource_changes") or []:
        if not isinstance(item, dict):
            continue
        change = item.get("change") if isinstance(item.get("change"), dict) else {}
        actions = [str(action) for action in change.get("actions") or []]
        kind = _classify(actions)
        importing = bool(change.get("importing"))
        moved_from = item.get("previous_address")
        if kind == "create":
            counts["add"] += 1
        elif kind == "update":
            counts["change"] += 1
        elif kind == "delete":
            counts["destroy"] += 1
        elif kind == "replace":
            counts["replace"] += 1
            counts["add"] += 1
            counts["destroy"] += 1
        elif kind == "read":
            counts["read"] += 1
        elif kind in {"forget", "forget+create"}:
            counts["forget"] += 1
            if kind == "forget+create":
                counts["add"] += 1
        if importing:
            counts["import"] += 1
        if moved_from:
            counts["move"] += 1
        if kind in {None, "read"} and not importing and not moved_from:
            continue
        entry: dict[str, Any] = {"address": item.get("address"), "actions": actions}
        if importing:
            entry["importing"] = True
        if moved_from:
            entry["previous_address"] = moved_from
        if item.get("action_reason"):
            entry["reason"] = item["action_reason"]
        changes.append(entry)

    output_changes = sorted(
        name
        for name, change in (plan.get("output_changes") or {}).items()
        if isinstance(change, dict) and change.get("actions") not in (["no-op"], None)
    )
    summary: dict[str, Any] = {
        **counts,
        "resource_changes": changes[:MAX_LISTED_CHANGES],
        "output_changes": output_changes,
        "drift": len(plan.get("resource_drift") or []),
    }
    if len(changes) > MAX_LISTED_CHANGES:
        summary["resource_changes_truncated"] = True
    return summary


def plan_line(summary: dict[str, Any]) -> str:
    """``+3 ~1 -0`` plus replacements, imports and moves when there are any."""
    text = f"+{summary.get('add', 0)} ~{summary.get('change', 0)} -{summary.get('destroy', 0)}"
    extras = [
        f"{summary[key]} {label}"
        for key, label in (("replace", "replaced"), ("import", "imported"), ("move", "moved"))
        if summary.get(key)
    ]
    return text + (f" ({', '.join(extras)})" if extras else "")
