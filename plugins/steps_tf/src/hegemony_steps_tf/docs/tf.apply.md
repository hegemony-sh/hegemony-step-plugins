<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Apply OpenTofu or Terraform Changes

`tf.apply` applies exactly the plan a `tf.plan` step saved earlier in the
same run. The usual shape is plan, then an approval step, then apply.

## Using It

Pick the plan step in Plan step. Nothing about the configuration is
repeated: the apply runs in the plan step's working directory with the same
engine and image, so the lock file, providers, backend settings, and
variables are the ones that were planned. Give both steps shared (or
explicit) execution affinity so they share the run's workspace and worker; the
worker must have shared workspaces enabled.

Provider credentials are never stored in a plan, so give them again in
Secret environment, as on the plan step. With OpenTofu state encryption, set
the same State encryption key the plan step used. With managed state, the
apply gets its own short-lived access to the state the plan step named.

When the plan has no changes, the step succeeds without starting a
container.

## Output

The apply's output streams into the step's live log and is kept as the
container output artifact. Later steps read the configuration's
non-sensitive outputs under `steps.NODE_ID.output.outputs`, for example
`steps.NODE_ID.output.outputs.vpc_id`; sensitive outputs are listed by name
in `sensitive_outputs` but their values are never kept.

## When It Fails

The step fails when the plan step did not succeed in this run, when either
step lacks shared affinity or the worker has shared workspaces disabled, or
when the apply itself fails. The tool refuses
a saved plan made stale by a state change since planning: plan again. The
state lock is taken for the apply; Lock timeout sets how long to wait for
it. Managed state access lasts as long as the step's timeout (its own
Timeout, else the one from its policy or the flow), plus a margin.
