<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-probe

Outside-observation probes: one-shot connectivity, DNS, HTTP and TLS
certificate checks, and stable-reachability waits. No device credentials
involved.

Handlers: `probe.connectivity`, `probe.dns`, `probe.http`, `probe.tls`,
`probe.wait_reachable`. Each has its page under
`src/hegemony_steps_probe/docs/`.

Namespace prefix (= entry-point name): `probe.` — see the repo-level
`CONVENTIONS.md` for the naming rules.
