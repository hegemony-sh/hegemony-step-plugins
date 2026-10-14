<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-netbox

Steps that work with NetBox from a flow: read and change NetBox objects, take
IP addresses, prefixes, VLANs and ASNs from NetBox pools and give them back,
and have NetBox render the intended configuration of devices.

Handlers: `netbox.request`, `netbox.ipam.allocate`, `netbox.ipam.release`,
`netbox.render_config`.

Every call to NetBox goes through `http.request`'s client
(`hegemony-steps-http`, a dependency): each request passes the flow's egress
policy, loopback, link-local (cloud instance metadata included), unspecified
and multicast destinations are refused, the API token is never sent over
plain HTTP unless the step allows it, and the token is scrubbed from
everything the step reports. A deployment without `hegemony-steps-http` has
no NetBox steps either. Each handler's page under
`src/hegemony_steps_netbox/docs/` documents its fields, output and security
rules.

Namespace prefix (= entry-point name): `netbox.` — see the repo-level
`CONVENTIONS.md` for the naming rules.
