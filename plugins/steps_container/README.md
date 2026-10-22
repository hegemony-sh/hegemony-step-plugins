<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-container

Container execution on the platform's Docker-in-Docker sandbox, never on the
worker's own Docker daemon. Deliberately its own wheel: the security-sensitive
handlers (docker socket, privileged mode, image builds) — hardened deployments
simply don't install it.

Handlers: `container.run` (run a container) and `container.build` (build an
image from the flow's attachments and push it to the organization's namespace
of the platform registry or to another registry, or keep it in the sandbox
when the platform runs no registry).

Namespace prefix (= entry-point name): `container.` — see the repo-level
`CONVENTIONS.md` for the naming rules.
