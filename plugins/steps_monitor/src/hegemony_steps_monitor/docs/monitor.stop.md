<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Stop Connectivity Monitor

`monitor.stop` is an internal handler: it is not offered in the flow
editor's step picker. It exists as a lifecycle shell that stops a running
background monitor by its `monitor_id`; the flow engine handles stopping
monitors itself (for example at a branch's join point), so flows do not
place this step directly. Monitors are started with the Connectivity
Monitor step (`monitor.connectivity`).

The step takes the `monitor_id` to stop and an optional `reason` recorded
with the stop (default `step_requested`). It fails when `monitor_id` is
missing or when no running monitor with that id is found (already stopped
counts as not found). On success it records one `transport_meta` evidence
entry, `monitor_stopped_<monitor id>`, capturing the id and reason. It
reports no metrics and adds no chainable output keys.
