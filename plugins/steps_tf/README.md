<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-tf

OpenTofu and Terraform for Hegemony flows — the `tf.` namespace.

Handlers:

- `tf.plan` — init, validate and plan a configuration from the flow's
  attachments. The saved plan stays in the run's shared workspace, the
  readable plan is kept as evidence, and the step output reports what would
  change (counts and resource addresses, never values), so a branch or an
  approval can act on it. A scheduled plan-only flow is drift detection.
- `tf.apply` — apply exactly the plan a `tf.plan` step saved earlier in the
  run, in the same working directory and image; the tool refuses a plan made
  stale by a state change.

OpenTofu is the default engine and Terraform is selectable; the engine never
appears in the handler id (CONVENTIONS.md, rule 3). State lives in the
configuration's own backend, or in ephemeral per-run state for tests.
Provider credentials, secret variables and OpenTofu's state encryption key are
resolved by the platform, passed as files, and redacted from output.

Both steps run on the platform's Docker-in-Docker sandbox through
`container.run`'s runner (this wheel depends on `hegemony-steps-container`),
under the flow's egress policy. `images/opentofu-runner/` in this repository
builds a runner image with the OpenTofu binary for teams that prefer their own
image over the official one.
