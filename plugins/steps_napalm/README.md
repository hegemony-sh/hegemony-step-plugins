<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-napalm

NAPALM for Hegemony flows — the `napalm.` namespace. Vendor-neutral reads
and configuration changes on Cisco IOS and IOS XE, Arista EOS and Cisco
NX-OS.

Handlers:

- `napalm.get` — read structured data with NAPALM getters (facts,
  interfaces, BGP neighbors, ...), the same shape on every platform.
- `napalm.config` — merge or replace configuration as a candidate, record
  the difference, then discard it (dry run, or nothing to change), commit
  it, or make a confirmed commit that is confirmed once a new session shows
  the device can still be managed.
- `napalm.rollback` — return to the configuration before the last NAPALM
  commit.

The platform opens the NAPALM session (`services.open_napalm`) through
`hegemony-transport-napalm`, with the device's SSH credentials, the flow's
egress policy, the organization's trusted host keys and the device's jump
host. This wheel depends on the SDK only and never sees a credential.

Namespace prefix (= entry-point name): `napalm.` — see the repo-level
`CONVENTIONS.md` for the naming rules. Each handler has its page under
`src/hegemony_steps_napalm/docs/`.
