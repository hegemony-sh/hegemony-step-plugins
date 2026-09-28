# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Structured playbook results: the callback plugin and its parser.

``ansible-playbook`` keeps its normal human-readable output, which streams into
the step's live log. Alongside it, a small aggregate callback plugin records
every task result per host and the play recap, and writes them to
``/hegemony/out/ansible-results.json`` when the play ends. The handler parses
that file into per-device evidence and the step's output.

The plugin source is kept here as a string and staged into the container, so it
needs nothing installed on the worker and is tested without Ansible.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from string import Template
from typing import Any

#: File name the callback is enabled by (Ansible matches the file's base name).
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

CALLBACK_SOURCE = Template('''\
# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hegemony results recorder: per-host task results and the play recap as JSON."""

import json
import os

from ansible.plugins.callback import CallbackBase

RESULTS_FILE = "$results_file"
MAX_TASK_RECORDS = $max_tasks
MAX_MESSAGE_CHARS = $max_message
MAX_DIFF_CHARS = $max_diff
MAX_RESULTS_BYTES = $max_bytes
TRIMMED_MESSAGE_CHARS = $trimmed_message


def _clip(value, limit):
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text if len(text) <= limit else text[: limit - 1] + "\\u2026"


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "aggregate"
    CALLBACK_NAME = "hegemony_results"
    CALLBACK_NEEDS_ENABLED = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._tasks = []
        self._dropped = 0
        self._play = ""

    def v2_playbook_on_play_start(self, play):
        self._play = play.get_name().strip() if play is not None else ""

    def _record(self, result, status):
        host = getattr(result, "host", None) or result._host
        task = getattr(result, "task", None) or result._task
        res = getattr(result, "result", None)
        if not isinstance(res, dict):
            res = result._result
        if len(self._tasks) >= MAX_TASK_RECORDS:
            self._dropped += 1
            return
        entry = {
            "host": host.get_name(),
            "play": self._play,
            "task": task.get_name().strip(),
            "action": getattr(task, "action", None),
            "status": "changed" if status == "ok" and res.get("changed") else status,
        }
        msg = res.get("msg")
        if msg:
            entry["msg"] = _clip(msg, MAX_MESSAGE_CHARS)
        if res.get("diff"):
            entry["diff"] = _clip(res["diff"], MAX_DIFF_CHARS)
        self._tasks.append(entry)

    def v2_runner_on_ok(self, result):
        self._record(result, "ok")

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record(result, "ignored" if ignore_errors else "failed")

    def v2_runner_on_unreachable(self, result):
        self._record(result, "unreachable")

    def v2_runner_on_skipped(self, result):
        self._record(result, "skipped")

    def v2_playbook_on_stats(self, stats):
        hosts = {}
        for host in sorted(stats.processed.keys()):
            hosts[host] = stats.summarize(host)
        payload = {
            "completed": True,
            "hosts": hosts,
            "custom": getattr(stats, "custom", {}) or {},
            "tasks": self._tasks,
            "dropped_task_records": self._dropped,
            "trimmed": [],
        }
        text = self._fit(payload)
        os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
        with open(RESULTS_FILE, "w", encoding="utf-8") as fh:
            fh.write(text)

    @staticmethod
    def _fit(payload):
        """Serialize, shrinking the least useful parts until it fits the budget.

        The recap always stays: it is what the step's changed/failed hosts come
        from. Then diffs go, then long messages, then task records, then the
        set_stats data.
        """
        text = json.dumps(payload, default=str)
        tasks = payload["tasks"]
        if len(text) > MAX_RESULTS_BYTES:
            for entry in tasks:
                entry.pop("diff", None)
            payload["trimmed"].append("diffs")
            text = json.dumps(payload, default=str)
        if len(text) > MAX_RESULTS_BYTES:
            for entry in tasks:
                if "msg" in entry:
                    entry["msg"] = _clip(entry["msg"], TRIMMED_MESSAGE_CHARS)
            payload["trimmed"].append("messages")
            text = json.dumps(payload, default=str)
        while len(text) > MAX_RESULTS_BYTES and tasks:
            keep = len(tasks) // 2
            payload["dropped_task_records"] += len(tasks) - keep
            del tasks[keep:]
            if "task records" not in payload["trimmed"]:
                payload["trimmed"].append("task records")
            text = json.dumps(payload, default=str)
        if len(text) > MAX_RESULTS_BYTES:
            payload["custom"] = {}
            payload["trimmed"].append("set_stats data")
            text = json.dumps(payload, default=str)
        return text
''').substitute(
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
            lines.append(f"    diff: {task['diff']}")
    return "\n".join(lines) + "\n"
