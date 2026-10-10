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
object, or `true` or `false`, is passed as that type, and anything else,
numbers included, as a string (the tool converts it to a number variable). Secret variables are always passed as
strings, so a JSON secret such as a cloud service-account key fits a
`string` variable; decode it with `jsondecode()` where the configuration
needs its fields. Secret variables, provider credentials in
Secret environment, and the OpenTofu state encryption key are secret
references: a `{{ secret('...') }}` template or a bare reference such as
`vault://orgs/acme/secrets/aws/key`. They are resolved by the platform on
their own (without step variables) and only once, and passed from files
inside the container (never environment variables or arguments). Values
resolved from references are redacted from the step's output; text that is
not a reference is used as written and is not redacted.

State decides where the state lives:

- `managed` (default): the platform stores the state under State name, in
  the run's organization. It is locked while a plan or apply runs, kept as
  versions, and encrypted with a key held outside the database. Any backend
  block in the configuration is replaced, so the configuration needs none.
  Every flow that uses the same name shares one state and its lock. The step
  gets short-lived access to that one state, which ends with the step.
  With Hold the state until apply, the plan's lock also holds the state for
  the run until the run applies or ends: meanwhile other runs and people
  cannot lock or change it (they wait, or fail after their Lock timeout,
  naming the run), so the plan stays valid however long an approval takes.
  Every other flow using the state waits that long. A plan with no changes
  ends the hold at once, since there is nothing to apply; when the platform
  cannot end it, the hold may last until the run ends, and the summary says
  so. A plan that fails after its tool started ends the hold as well, if
  its lock took one. Either way the step ends only a hold its own lock
  took, never one another plan of the run took for its apply; a platform
  that cannot tell which step took a hold keeps it until the run ends. An
  admin can end the hold with Force unlock on the state's page.
- `backend`: the configuration's own backend block, such as S3, Azure
  Storage, GCS, Consul, or PostgreSQL. Backend settings fill a partial block
  (bucket, key, and so on) from a file. A configuration without a backend
  block is refused, because its state would be lost when the run ends.
- `ephemeral`: local state that lives only for this run, for tests and
  demos.

With a State encryption key (OpenTofu only), OpenTofu encrypts the state and
the saved plan before writing them anywhere.

## The Image

OpenTofu runs in `ghcr.io/hegemony-sh/opentofu-runner:0.28` by default:
OpenTofu at an exact version on Alpine Linux, with git and an SSH client for
module sources, built from `images/opentofu-runner` in the plugin repository.
`tofu` is compiled there from the OpenTofu release's source, with Go libraries
that have known vulnerabilities raised to fixed versions until an OpenTofu
release carries them; the image lists the change. That tag names a minor version of the plugins and follows its
newest patch release.
Terraform runs in HashiCorp's `hashicorp/terraform` image at an exact
version. Image replaces either; it needs a POSIX `sh` with `timeout` and
`sha256sum` (as BusyBox and coreutils have) and must run as root, since the step writes the
run's shared workspace. An image in a registry that needs a login pulls with
the organization's registry credential for that host, stored once by an
admin; the step itself needs no login settings.

When the platform runs its own container registry, Cache image (on by
default) keeps a copy of the image there after the first pull; later plans
use it, asking the image's registry only whether the tag moved, and a plan
with that registry unreachable uses the copy. The apply follows the plan's
choice.

The plan records the image's registry digest (`image_digest`, in its output
and its metrics, as `tf.apply` does in its own), and `tf.apply` runs that
digest: a saved plan is refused by any other tool version, and the tag may
move between the plan and an approved apply. When the plan ran a copy from
the platform registry, the digest names that copy, which the apply pulls
from the platform registry too. An image built on the sandbox and never
pushed has no digest, so the apply runs its tag.

## Applying The Plan

For a later `tf.apply`, give both steps shared (or explicit) execution
affinity on a worker with shared workspaces enabled: the plan's working
directory, with its providers and lock file, lives in the run's shared
workspace under `/shared/tf/<step id>`, and the apply runs there on the same
worker. Otherwise the plan reports `apply_ready: false` and keeps a
`plan_only_<step id>` note saying why a `tf.apply` would refuse it (a
plan with no changes is the exception: the apply has nothing to apply and
succeeds). A plan-only flow needs no shared affinity. The saved plan contains every variable value, secret ones
included; it stays inside the run's workspace, which is deleted when the run
ends.

Every container step in the run can write the shared workspace, so the tool
saves the plan in the step container's own folder first. The SHA-256 digest,
the readable plan and the JSON plan all come from that one file, which is then
copied to the shared workspace; `tf.apply` applies the shared copy only while
it still has that digest.

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
`import`, `move`, `read` (data sources read during apply), and `forget`,
the changed resource addresses with their actions under `resource_changes`
(the first 200; `resource_changes_truncated` is then true, and the counts
still cover all), changed `output_changes` names, `drift` (resources changed
outside the configuration), and a `summary` line such as
`Plan: +3 ~1 -0`. A refresh-only plan changes no resource, so its summary
names the drift instead, such as `Plan: +0 ~0 -0 (3 drifted)`. Resource values are never kept: the
tool's JSON plan carries them in clear. `outputs` holds the configuration's
non-sensitive output values as the state held them when the plan was made
(before its changes), and `sensitive_outputs` the names of the others; a
`tf.apply` of a plan without changes returns these. Failing to read them does
not fail the plan: they are then empty. `handler` (`tf.plan`) marks the
output for `tf.apply`, which refuses a step output without it. Branch on
`steps.NODE_ID.output.has_changes`, or show the summary in an approval
message. `plan_sha256` is the saved plan's digest, which also ends the
readable plan artifact. `state_held` is true when the run still holds the managed state
for the apply. `image` is the image the plan ran, and `image_digest`
the same image by digest (empty when it has none).

## When It Fails

The step succeeds when the plan is made, with or without changes. It fails
when init, validate, or plan fails (see the container output), when backend
state has no backend block, when the plan's result code cannot be read back
from the container (so whether it has changes is unknown), when the saved
plan's digest cannot be read back (so `tf.apply` could not check the plan), when another
plan or apply holds the state lock for longer than Lock timeout (the error
names the holder from the lock's Who and Info lines), or before running
anything when the config is
invalid (Plan a destroy, Refresh only and Replace each exclude the other
two), a secret resolves to nothing, or the platform cannot serve managed
state (for example, no state encryption key is configured). Provider downloads and remote state
need network access to those endpoints under the flow's egress policy. The
timeout covers the whole run, image pull included. The tool receives
SIGTERM Stop grace period (120 seconds by default, at most half the
timeout) before the timeout, and when the step is cancelled, so it can
release the state lock and exit cleanly; it is killed only if it still runs
after that. The SIGTERM at the timeout comes from inside the container (the
image's `timeout` command, with SIGKILL once the grace period has passed,
and not before five minutes), so the tool stops even when the worker that
should stop the container is gone. A Timeout longer than the step's
timeout raises the step's timeout to fit it plus a minute. Without a
Timeout on the step, the step's timeout from its policy or the flow applies; managed state
access lasts as long as that timeout, plus a 10-minute margin. The platform
grants state access for at most 24 hours, so with managed state the step's
own Timeout is refused above 85800 seconds; a longer timeout from the policy
or the flow is not refused, but the state access still ends after 24 hours,
and the step's log says so.
