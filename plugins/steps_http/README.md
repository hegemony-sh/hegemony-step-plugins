<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-http

Outbound HTTP(S) requests from the worker: one request with any method,
headers, JSON or text body and authentication (bearer, basic, or a custom
header, with the secret taken from a secret reference), optionally following
redirects and next-page links, returned as structured output that later
steps read.

Handlers: `http.request`.

Every request, redirect hops and next pages included, passes the flow's
egress policy, and loopback, link-local (cloud instance metadata included),
unspecified and multicast destinations are refused. The wheel is its own so
that a deployment can leave out arbitrary outbound requests from workers
entirely: without it, flows have no `http.request` step. The handler's page
(`src/hegemony_steps_http/docs/http.request.md`) documents its fields,
output and security rules. Other wheels that speak HTTP send through the same
client (`HttpRequestHandler.send`), so these rules apply to them too:
`hegemony-steps-netbox` does.

Namespace prefix (= entry-point name): `http.` — see the repo-level
`CONVENTIONS.md` for the naming rules.
