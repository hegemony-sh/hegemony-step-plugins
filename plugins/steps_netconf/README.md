<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-netconf

NETCONF for Hegemony flows — the `netconf.` namespace. Vendor-neutral:
RFC 6241 over SSH (RFC 6242), with what each device supports read from its
hello.

Handlers:

- `netconf.get` — read the running, candidate or startup configuration
  (get-config), or configuration and state (get), with a subtree or XPath
  filter.
- `netconf.edit_config` — change the configuration as one transaction: on the
  candidate datastore it locks, diffs running against the changed candidate,
  validates, and commits directly, as a confirmed commit it confirms once a
  second session shows the device is still manageable, or as a confirmed
  commit left pending for a later step. A dry run shows the diff and
  discards it.
- `netconf.commit` — confirm the commit a change step left pending.
- `netconf.cancel_commit` — roll that commit back now.
- `netconf.rpc` — send any other operation (a vendor RPC, an action) and keep
  the reply.

The platform opens the SSH session (`services.open_netconf`) with the
device's SSH credentials, the flow's egress policy, the organization's
trusted host keys and the device's jump host; this wheel speaks NETCONF on it
(`hegemony_steps_netconf.client`). Vendor wheels can build on that client and
on the change transaction (`hegemony_steps_netconf.transaction`).

Namespace prefix (= entry-point name): `netconf.` — see the repo-level
`CONVENTIONS.md` for the naming rules. Each handler has its page under
`src/hegemony_steps_netconf/docs/`.
