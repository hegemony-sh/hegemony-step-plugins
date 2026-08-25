<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Start Connectivity Monitor

`monitor.start` is an internal handler: it is not offered in the flow
editor's step picker. It exists as a lifecycle shell that starts a background
monitor from an explicit, pre-assembled monitor configuration passed under
the step's `monitor` config key. To monitor connectivity from a flow, use the
Connectivity Monitor step (`monitor.connectivity`) instead — it builds this
configuration from its form fields.

The provided configuration must include a `monitor_id` and a registered
`check_id`; its `targets` selectors (role- or IP-based) are resolved to
concrete addresses according to the configured address kind; the address
family is a preference - `ipv4`/`ipv6` pick the first candidate address of
that family for role-resolved devices, falling back to the kind's normal
choice when no literal matches, while explicit IP targets are used as
written.
The step fails when the configuration or either id is missing, the check is
not registered, the address kind or family is invalid, no targets resolve,
or starting the monitor raises an error. On success it reports the monitor's
database id and target count as metrics and records one `transport_meta`
evidence entry, `monitor_started_<monitor id>`, listing the resolved
targets. It adds no chainable output keys.
