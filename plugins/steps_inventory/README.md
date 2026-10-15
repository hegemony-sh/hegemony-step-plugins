<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-inventory

Inventory steps for Hegemony flows — the `inventory.` namespace.

Handlers: `inventory.sync` — sync one of the run organization's inventory
providers now, so later steps see what the source of truth holds (a device a
previous step created in NetBox, say). The step names the provider by id or
name and never talks to the source itself: it calls the platform's
`sync_inventory` service, which syncs only a provider an administrator has
opened to flows, skips the sync when the last one is recent enough, and
audits every sync. See `src/hegemony_steps_inventory/docs/inventory.sync.md`.

**In the platform's images**, as a wheel of its own (CONVENTIONS.md, "Wheel
granularity"), because starting syncs from a flow puts load on a source of
truth: a deployment that must not allow it builds its api and worker images
without the wheel (`uv pip uninstall hegemony-steps-inventory` in a derived
image). Installed, it syncs nothing until an administrator ticks "Flows may sync this provider" on a
provider, on a platform whose worker provides the `sync_inventory` service.

Namespace prefix (= entry-point name): `inventory.` — see the repo-level
`CONVENTIONS.md` for the naming rules.
