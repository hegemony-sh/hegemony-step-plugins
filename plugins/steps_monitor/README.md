<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-monitor

Background connectivity-monitor step handlers for
[Hegemony](https://github.com/hegemony-sh/hegemony).

Registers under the `hegemony.step_handlers` entry-point group with the claimed
prefix `monitor`:

| Handler id | Purpose |
|------------|---------|
| `monitor.connectivity` | Start a background monitor that probes targets on a schedule |
| `monitor.start` | Internal lifecycle: start a monitor from an explicit config (hidden) |
| `monitor.stop` | Internal lifecycle: stop a running monitor (hidden) |

These handlers are thin shells. They assemble the monitor config and resolve
targets, then hand off to `services.start_monitor` / `services.stop_monitor`.
The host owns the monitor machinery — `MonitorManager`, sample emission, and the
graph engine's monitor-node semantics (until-join, run cleanup, keyed off the
`monitor.` id prefix) stay host-side. `check_type` options are registry-driven
(`hegemony.probes`).
