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

The step fails before starting a container when Plan step names a step
that is not a `tf.plan` step or did not succeed in this run, and when a
step lacks a shared workspace: the error says whether the plan step ran
without one (its saved plan is gone, so give it shared affinity and plan
again) or this step has none (shared affinity missing, or the worker has
shared workspaces disabled). It also fails when the apply itself fails.
The tool refuses
a saved plan made stale by a state change since planning: plan again. The
saved plan lives in the run's shared workspace; when that workspace is gone
(for example cleaned up after a worker restart while the run waited a long
time for approval), the step says so: plan again. The state lock is taken
for the apply; Lock timeout sets how long to wait for it. Managed state
access lasts as long as the step's timeout (its own Timeout, else the one
from its policy or the flow), plus a margin.

When the tool changes resources but cannot save the resulting state (the
backend is unreachable or refuses the write), it leaves the state in
`errored.tfstate`. The step saves it again (`state push`), retrying for
about 40 seconds. If that fails too, the step keeps the state as the run
artifact `errored.tfstate.gz` and says so: the working directory is deleted
when the run ends, so this is the only copy. It holds the state in clear,
secrets included, and anyone who can view the run can download it: save it
with `tofu state push` (or `terraform state push`), then delete the artifact,
before planning again. With OpenTofu state encryption the kept file is
encrypted too.

A failure to read the configuration's outputs after a successful apply does
not fail the step: the summary says the outputs could not be read.
