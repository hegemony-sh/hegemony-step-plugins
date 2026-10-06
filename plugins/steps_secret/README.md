<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-secret

Secret-store steps for Hegemony flows — the `secret.` namespace.

Handlers: `secret.write` — store keys in a secret of the run's organization,
from files an earlier step left in the run's shared workspace or from secret
references and literals; swap the keys of two secrets; or delete a secret.
The step names a path under the organization's own secret root (`certs/web`)
and never a backend: it calls the platform's `read_secret`, `write_secret`
and `delete_secret` services, which decide where the path lives, refuse what
the organization's administrators have not allowed, register the values for
redaction and audit every call. Its output names keys and the reference
later steps read them through, never the values. See
`src/hegemony_steps_secret/docs/secret.write.md`.

A wheel of its own (CONVENTIONS.md, "Wheel granularity"): writing secrets
from a flow is a security surface, so a deployment that must not allow it
leaves this wheel out. Installed, it writes nothing until an administrator
enables secret writes by steps for the organization, on a platform whose
worker provides the secret store services.

Namespace prefix (= entry-point name): `secret.` — see the repo-level
`CONVENTIONS.md` for the naming rules.
