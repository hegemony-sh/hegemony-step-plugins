# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared helpers for picking artifacts out of the internal run response."""

from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from hegemony_step_sdk import command_label


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


#: Identity of one evidence capture: ``("command", device_id, device_name,
#: command)`` for output a netcli step recorded with its metadata, else
#: ``("name", artifact name)``.
CaptureKey = tuple[str, ...]


def _command_metadata(artifact: dict[str, Any]) -> dict[str, Any] | None:
    """The device and full command a netcli step records in ``content_json``."""
    meta = artifact.get("content_json")
    if isinstance(meta, dict) and isinstance(meta.get("command"), str):
        return meta
    return None


def _same_device(meta: dict[str, Any], device: dict[str, Any]) -> bool:
    """Match on the device id when both sides have one, else on the name."""
    if device.get("id") is not None and meta.get("device_id") is not None:
        return meta["device_id"] == device["id"]
    return meta.get("device_name") == device.get("name")


def find_command_artifact(
    artifacts: list[dict[str, Any]],
    *,
    step_id: str,
    device: dict[str, Any],
    command: str,
) -> dict[str, Any] | None:
    """Return the newest artifact of ``step_id`` with ``device``'s ``command`` output.

    An artifact's name holds the command cut to its first line and 80
    characters, so two long or multi-line commands can share a name. Match
    the full command (surrounding whitespace ignored) and the device that
    netcli steps record in ``content_json`` instead. Artifacts without that
    record match by name, ``<device>:<command>`` or the shortened form.
    """
    wanted = command.strip()
    device_name = device.get("name")
    names = {f"{device_name}:{command}", f"{device_name}:{command_label(command)}"}
    matches = []
    for artifact in artifacts:
        if artifact.get("step_id") != step_id:
            continue
        meta = _command_metadata(artifact)
        if meta is None:
            if artifact.get("name") in names:
                matches.append(artifact)
        elif meta["command"].strip() == wanted and _same_device(meta, device):
            matches.append(artifact)
    return latest_artifact(matches)


def capture_key(artifact: dict[str, Any]) -> CaptureKey:
    """Key one artifact by its device and full command, else by its name."""
    meta = _command_metadata(artifact)
    if meta is None:
        return ("name", str(artifact.get("name") or ""))
    return (
        "command",
        str(meta.get("device_id")),
        str(meta.get("device_name")),
        meta["command"].strip(),
    )


def latest_by_capture(artifacts: list[dict[str, Any]]) -> dict[CaptureKey, dict[str, Any]]:
    """The newest artifact per capture key; artifacts with no name or command are left out."""
    groups: dict[CaptureKey, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        key = capture_key(artifact)
        if key != ("name", ""):
            groups.setdefault(key, []).append(artifact)
    return {
        key: artifact
        for key, group in groups.items()
        if (artifact := latest_artifact(group)) is not None
    }


def capture_labels(keys: Iterable[CaptureKey]) -> dict[CaptureKey, str]:
    """A readable label per capture key, unique across ``keys``.

    A label reads like the artifact name, ``<device>:<command>`` with the
    command shortened. Keys whose labels clash get the full command, then
    also the device id.
    """

    def short(key: CaptureKey) -> str:
        return f"{key[2]}:{command_label(key[3])}" if key[0] == "command" else key[1]

    def full(key: CaptureKey) -> str:
        return f"{key[2]}:{key[3]}" if key[0] == "command" else key[1]

    def with_id(key: CaptureKey) -> str:
        return f"{key[2]} [{key[1]}]:{key[3]}" if key[0] == "command" else key[1]

    ordered = sorted(set(keys))
    labels = {key: short(key) for key in ordered}
    for render in (full, with_id):
        counts = Counter(labels.values())
        for key in ordered:
            if counts[labels[key]] > 1:
                labels[key] = render(key)
    return labels


def capture_error(artifact: dict[str, Any]) -> str | None:
    """The error a failed capture recorded instead of its output; None when it worked.

    A collect step stores a device it could not reach as an ``error``
    artifact, and a failed command as output whose record says
    ``success: false``.
    """
    if artifact.get("kind") == "error":
        meta = artifact.get("content_json")
        if isinstance(meta, dict) and meta.get("error"):
            return str(meta["error"])
        return str(artifact.get("content_text") or "collection failed")
    meta = _command_metadata(artifact)
    if meta is not None and meta.get("success") is False:
        return str(meta.get("error") or f"exit code {meta.get('exit_code')}")
    return None
