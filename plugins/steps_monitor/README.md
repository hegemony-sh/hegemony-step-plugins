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

The handler is a thin shell. It assembles the monitor config and resolves
targets, then hands off to `services.start_monitor`.
The host owns the monitor machinery — `MonitorManager`, sample emission, and the
graph engine's monitor-node semantics (until-join, run cleanup, keyed off the
`monitor.` id prefix) stay host-side. `check_type` options are registry-driven
(`hegemony.probes`).
