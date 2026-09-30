# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Structured playbook results: the callback plugin and its parser.

``ansible-playbook`` keeps its normal human-readable output, which streams into
the step's live log. Alongside it, a small aggregate callback plugin records
every task result per host and the play recap, and writes them to
``/hegemony/out/ansible-results.json`` when the play ends. The handler parses
that file into per-device evidence and the step's output.

The plugin source is kept as a string (in ``callback_plugin``, which is MIT
rather than AGPL because the plugin runs inside Ansible) and staged into the
container, so it needs nothing installed on the worker and is tested without
Ansible.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .callback_plugin import CALLBACK_TEMPLATE

#: File name of the callback plugin. It needs no ``callbacks_enabled`` entry:
#: a callback with ``CALLBACK_NEEDS_ENABLED = False`` on a callback plugin path
#: always loads, so the repository's own ``callbacks_enabled`` list stands.
CALLBACK_NAME = "hegemony_results"
#: Where the callback writes its results inside the container.
RESULTS_FILE = "/hegemony/out/ansible-results.json"

#: Bounds that keep one step's structured results reasonable.
MAX_TASK_RECORDS = 2000
MAX_MESSAGE_CHARS = 2000
MAX_DIFF_CHARS = 20_000
#: Size bound of the whole results file. The runner collects at most 8 MiB per
#: step and skips a file that does not fit, so the callback keeps well below it:
#: an uncollected file would leave the step without results.
MAX_RESULTS_BYTES = 4 * 1024 * 1024
#: Message length kept when the file must shrink.
TRIMMED_MESSAGE_CHARS = 200

CALLBACK_SOURCE = CALLBACK_TEMPLATE.substitute(
    results_file=RESULTS_FILE,
    max_tasks=MAX_TASK_RECORDS,
    max_message=MAX_MESSAGE_CHARS,
    max_diff=MAX_DIFF_CHARS,
    max_bytes=MAX_RESULTS_BYTES,
    trimmed_message=TRIMMED_MESSAGE_CHARS,
)

#: ansible-playbook exit codes worth naming in a summary.
EXIT_CODE_MEANINGS = {
    0: "success",
    1: "error",
    2: "one or more hosts failed",
    4: "hosts unreachable or a playbook parse error",
    5: "invalid command-line options",
    99: "interrupted",
    250: "unexpected Ansible error",
}

_STATUS_MARKS = {
    "ok": "ok",
    "changed": "changed",
    "failed": "FAILED",
    "ignored": "failed (ignored)",
    "unreachable": "UNREACHABLE",
    "skipped": "skipped",
}


@dataclass
class PlaybookResults:
    """The parsed callback output (empty when the play never finished)."""

    completed: bool = False
    hosts: dict[str, dict[str, int]] = field(default_factory=dict)
    custom: dict[str, Any] = field(default_factory=dict)
    tasks: list[dict[str, Any]] = field(default_factory=list)
    dropped_task_records: int = 0
    #: What the callback left out to stay within its size budget.
    trimmed: list[str] = field(default_factory=list)
    problem: str | None = None

    def hosts_where(self, key: str) -> list[str]:
        return sorted(host for host, counts in self.hosts.items() if counts.get(key, 0) > 0)

    def tasks_for(self, host: str) -> list[dict[str, Any]]:
        return [task for task in self.tasks if task.get("host") == host]


def parse_results(raw: bytes | None) -> PlaybookResults:
    """Parse the callback's JSON; a missing or broken file yields an empty result."""
    if raw is None:
        return PlaybookResults(
            problem=(
                "no results file was collected (the results callback did not run, the "
                "play stopped before its recap, or the file could not be read back)"
            )
        )
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return PlaybookResults(problem=f"the results file is not valid JSON: {exc}")
    if not isinstance(data, dict):
        return PlaybookResults(problem="the results file is not a JSON object")
    hosts = data.get("hosts")
    custom = data.get("custom")
    tasks = data.get("tasks")
    trimmed = data.get("trimmed")
    return PlaybookResults(
        completed=data.get("completed") is True,
        hosts={
            str(name): {str(k): int(v) for k, v in counts.items() if isinstance(v, int)}
            for name, counts in (hosts.items() if isinstance(hosts, dict) else [])
            if isinstance(counts, dict)
        },
        custom=custom if isinstance(custom, dict) else {},
        tasks=[task for task in tasks if isinstance(task, dict)] if isinstance(tasks, list) else [],
        dropped_task_records=int(data.get("dropped_task_records") or 0),
        trimmed=[str(item) for item in trimmed] if isinstance(trimmed, list) else [],
    )


def render_host_report(host: str, counts: dict[str, int], tasks: list[dict[str, Any]]) -> str:
    """A readable per-host task list for the host's evidence artifact."""
    lines = [
        f"{host}: ok={counts.get('ok', 0)} changed={counts.get('changed', 0)} "
        f"failed={counts.get('failures', 0)} unreachable={counts.get('unreachable', 0)} "
        f"skipped={counts.get('skipped', 0)}",
        "",
    ]
    play = None
    for task in tasks:
        if task.get("play") != play:
            play = task.get("play")
            lines.append(f"PLAY [{play or ''}]")
        mark = _STATUS_MARKS.get(str(task.get("status")), str(task.get("status")))
        line = f"  {mark:<17} {task.get('task', '')}"
        if task.get("msg") and task.get("status") in {"failed", "unreachable", "ignored"}:
            line += f" — {task['msg']}"
        lines.append(line)
        if task.get("diff"):
            diff_lines = str(task["diff"]).splitlines() or [""]
            lines.append(f"    diff: {diff_lines[0]}")
            # A multi-line diff stays indented under its task.
            lines.extend(f"          {line}" for line in diff_lines[1:])
    return "\n".join(lines) + "\n"
