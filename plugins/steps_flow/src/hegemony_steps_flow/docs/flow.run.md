<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Run Flow

`flow.run` launches another committed flow as a child run of the current
flow. Pick the child flow, map its input fields and target roles, and the
step starts the run; by default it then waits until the child finishes and
succeeds or fails with it, making the child flow's outputs available to
later steps.

## Using It

Select the child flow either by id or by name — exactly one of the two must
be set. Selecting by name resolves to the newest flow with that name at
launch time, which keeps imported flow bundles portable. Version pins a
specific committed version of the child flow; omitted, the latest committed
version runs.

Field mappings feed the child flow's input fields: each field either keeps
the child's default, receives a literal value, or receives a template that
is resolved with this flow's context before the child starts. A template
that is a single expression keeps its value's type, so a run input that is
false, empty, a number or null reaches the child as such. Target
mappings bind the child's target roles — each role uses mode child_default,
parent_role (forwarding the devices this run bound to a chosen parent
role), or none. Both mappings are edited with the dedicated run-flow
widget.

The child run is named after the parent run plus a short random suffix
unless Child run name sets an explicit name. With Wait for completion on
(the default), the step polls the child run at the configured poll interval
(1-60 seconds, default 5) until it reaches SUCCESS, FAILED, or CANCELLED
and mirrors that result. With waiting off, the step succeeds as soon as the
child run is created and does not track it further. The default step
timeout is 2 hours; if the step is cancelled or times out while waiting,
the handler asks the platform to cancel the child run as well.

A template in Version, Wait for completion or Poll interval is read as that
setting's type once rendered: `3` pins version 3, and `false` turns waiting
off.

## Output

Later steps can read `steps.NODE_ID.child_run_id`,
`steps.NODE_ID.child_workflow_id`, `steps.NODE_ID.child_status`, and
`steps.NODE_ID.waited`. Without waiting, the reported status is
`PENDING`. When the step waited and the child succeeded, the child flow's
evaluated outputs land under `steps.NODE_ID.outputs`, one key per child
flow output. Metrics record `child_run_count` (always 1) and, when the step
waited, `wait_seconds`; a polling error that fails the step records no
metrics. Progress events carry the child run id while the
step starts and waits; no evidence artifacts are produced.

## When It Fails

The step fails before starting anything when the configuration is invalid:
both or neither of flow id and flow name set, a malformed flow id, a bad
version, a poll interval outside 1-60 seconds, or field/target mapping
entries missing a valid mode or a required value. It fails when the platform rejects creating the child run, and —
while waiting — when polling the child errors out (the reported status is
then `UNKNOWN`) or the child run ends FAILED or CANCELLED, in which case
the child's error message becomes the step error. A child that succeeds but
whose outputs cannot be evaluated also fails the step. With Wait for
completion off, nothing that happens to the child later affects this step.
