# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: MIT

"""Source of the Ansible callback plugin that the ansible.playbook step stages.

This module is MIT, unlike the rest of the package (AGPL-3.0-or-later). The
plugin runs inside ``ansible-playbook`` (GPL-3.0-or-later) and subclasses its
``CallbackBase``, so at run time it forms one program with Ansible. It is copied
there on its own, so a permissive licence lets the copy carry its whole licence
in its header and keeps that combination simple for everyone. See LICENSING.md.

``results`` fills in the placeholders (the results path and size bounds) and
stages the rendered file into the step's container. The rendered file travels
alone, so its header carries the MIT permission notice in full, as the licence
asks of every copy.
"""

from string import Template

CALLBACK_TEMPLATE = Template('''\
# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: MIT
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
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
    CALLBACK_NEEDS_ENABLED = False

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
''')
