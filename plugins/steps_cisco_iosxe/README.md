<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-cisco-iosxe

Cisco IOS XE workflows for Hegemony flows — the `cisco.iosxe.` namespace,
for steps whose settings are IOS XE's own (see the repo-level
`CONVENTIONS.md`, rule 1).

Handlers:

- `cisco.iosxe.config_replace` — Atomic Configuration Replace (ACR): send the
  device's whole configuration as CLI text (full replace, selective replace
  or merge) through the `Cisco-IOS-XE-cli-rpc` model into the candidate
  datastore, show the diff against running, validate, and commit it as one
  transaction: directly, as a confirmed commit confirmed once the device is
  still manageable, or left pending for `netconf.commit`. A dry run shows the
  diff and discards it.
- `cisco.iosxe.get_config` — read the modelled running or candidate
  configuration as CLI text, for a diff or an assertion. It is not a full
  backup: modelled CLI only, without wireless, app-hosting or telemetry
  configuration.

What a full replace does to configuration the model leaves out (wireless,
app-hosting, telemetry, banners) has not been verified on a device yet.

ACR needs IOS XE 17.15 or later (for the operation leaf), `netconf-yang`, `netconf-yang feature candidate-datastore`,
`yang-interfaces feature atomic-config` and `yang-interfaces feature
deprecated disable` on the device. Cisco introduced it in 2025 for Catalyst
9300 and 9500 as an early-field-trial feature (Cisco Live DEVNET-2385).

Built on `hegemony-steps-netconf` (its client, sessions and change
transaction), which this wheel depends on at the same version. Each handler
has its page under `src/hegemony_steps_cisco_iosxe/docs/`.
