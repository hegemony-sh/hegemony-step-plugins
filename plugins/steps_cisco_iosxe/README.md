<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-cisco-iosxe

Cisco IOS-XE upgrade workflow (preflight/stage/install/verify/cleanup) in
install and bundle modes. Platform-specific by nature: the workflow and its
config schemas encode IOS-XE concepts, so it lives under the cisco.iosxe.*
namespace; other platforms get their own wheels.

Handlers: `cisco.iosxe.upgrade.preflight`, `cisco.iosxe.upgrade.stage`, `cisco.iosxe.upgrade.install`, `cisco.iosxe.upgrade.verify`, `cisco.iosxe.upgrade.cleanup`.

Namespace prefix (= entry-point name): `cisco.iosxe.` — see the repo-level
`CONVENTIONS.md` for the naming rules.
