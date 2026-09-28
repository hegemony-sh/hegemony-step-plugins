<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Plan OpenTofu or Terraform Changes

`tf.plan` initializes, validates, and plans an OpenTofu or Terraform
configuration taken from the flow's attachments, then reports what would
change. A `tf.apply` step later in the run applies exactly the plan it saved,
usually after an approval step. OpenTofu is the default engine; set Engine to
`terraform` to use Terraform. The step runs in a container on the platform's
Docker-in-Docker sandbox, under the flow's egress policy.

## Using It

Add the `.tf` files (and their `.terraform.lock.hcl`) to the flow's
attachments and set Configuration folder to their folder, or leave it empty
for the attachments root. Variables are `NAME=value` lines that may use
templates such as `{{ inputs.service_name }}`; a value that is a JSON list or
object is passed as that type. Secret variables, provider credentials in
Secret environment, and the OpenTofu state encryption key are secret
references: a `{{ secret('...') }}` template or a bare reference such as
`vault://orgs/acme/secrets/aws/key`. They are resolved by the platform on
their own (without step variables) and only once, passed from files inside
the container (never environment variables or arguments), and redacted from
the step's output.

State decides where the state lives:

- `managed` (default): the platform stores the state under State name, in
  the run's organization. It is locked while a plan or apply runs, kept as
  versions, and encrypted with a key held outside the database. Any backend
  block in the configuration is replaced, so the configuration needs none.
  Every flow that uses the same name shares one state and its lock. The step
  gets short-lived access to that one state, which ends with the step.
- `backend`: the configuration's own backend block, such as S3, Azure
  Storage, GCS, Consul, or PostgreSQL. Backend settings fill a partial block
  (bucket, key, and so on) from a file. A configuration without a backend
  block is refused, because its state would be lost when the run ends.
- `ephemeral`: local state that lives only for this run, for tests and
  demos.

With a State encryption key (OpenTofu only), OpenTofu encrypts the state and
the saved plan before writing them anywhere.

## Applying The Plan

For a later `tf.apply`, give both steps shared (or explicit) execution
affinity on a worker with shared workspaces enabled: the plan's working
directory, with its providers and lock file, lives in the run's shared
workspace under `/shared/tf/<step id>`, and the apply runs there on the same
worker. Otherwise the plan reports `apply_ready: false` and keeps a
`plan_only_<step id>` note saying why a `tf.apply` would refuse it. A
plan-only flow needs no shared affinity. The saved plan contains every variable value, secret ones
included; it stays inside the run's workspace, which is deleted when the run
ends.

The working directory and the apply's lookup of the plan are per step, not
per execution, so `tf.plan` and `tf.apply` cannot be in the body of a loop
with parallel iterations (the flow is refused when saved). A sequential loop
works: each iteration plans and applies before the next one plans.

## Output

The readable plan is kept as a `plan_<step id>.txt` artifact; values the
configuration marks sensitive are masked by the tool. Results read back from
the container share an 8 MiB budget, with the readable plan ahead of the
JSON plan used for the counts; when a plan with changes is too large to
keep, the summary ends with "(the readable plan could not be collected)". The step output
reports `has_changes`, the counts `add`, `change`, `destroy`, `replace`,
`import`, and `move`, the changed resource addresses with their actions under
`resource_changes`, changed `output_changes` names, `drift`, and a
`summary` line such as `Plan: +3 ~1 -0`. Resource values are never kept: the
tool's JSON plan carries them in clear. `outputs` holds the configuration's
non-sensitive output values as the state held them when the plan was made
(before its changes), and `sensitive_outputs` the names of the others; a
`tf.apply` of a plan without changes returns these. Failing to read them does
not fail the plan: they are then empty. Branch on
`steps.NODE_ID.output.has_changes`, or show the summary in an approval
message.

## When It Fails

The step succeeds when the plan is made, with or without changes. It fails
when init, validate, or plan fails (see the container output), when backend
state has no backend block, when the plan's result code cannot be read back
from the container (so whether it has changes is unknown), when another
plan or apply holds the state lock for longer than Lock timeout (the error
names the holder from the lock's Who and Info lines), or before running
anything when the config is
invalid, a secret resolves to nothing, or the platform cannot serve managed
state (for example, no state encryption key is configured). Provider downloads and remote state
need network access to those endpoints under the flow's egress policy. The
timeout covers the whole run, image pull included. Without a Timeout on the
step, the step's timeout from its policy or the flow applies; managed state
access lasts as long as that timeout, plus a 10-minute margin. The platform
grants state access for at most 24 hours, so with managed state the step's
own Timeout is refused above 85800 seconds; a longer timeout from the policy
or the flow is not refused, but the state access still ends after 24 hours,
and the step's log says so.
