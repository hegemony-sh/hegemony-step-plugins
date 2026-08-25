<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-probe

Outside-observation reachability probes (tcp/icmp): one-shot connectivity
checks and stable-reachability waits. No device credentials involved.

Handlers: `probe.connectivity`, `probe.dns`, `probe.http`,
`probe.wait_reachable`.

Namespace prefix (= entry-point name): `probe.` — see the repo-level
`CONVENTIONS.md` for the naming rules.
