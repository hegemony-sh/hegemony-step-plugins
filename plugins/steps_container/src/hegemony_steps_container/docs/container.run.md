<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Run Container

`container.run` runs a script inside a Docker container on the platform's
Docker-in-Docker sandbox, never on the worker's own Docker daemon.
Pick an image, write the command lines, and the step pulls the image, starts a
fresh container, streams its output live, and cleans the container up when
it is done. Any container-based tool — Python, Terraform, Ansible,
containerlab — can run as a flow step this way.

## Using It

Docker Image is the only required field: an image reference such as
`alpine:3.20` (a reference without a tag pulls `latest`). The
image is pulled before every run (a cached image is detected and reported, not
re-downloaded). Command holds shell lines that run sequentially under
`set -e`, so the first failing line aborts the script. With no entrypoint
override, the handler runs the script with `sh -c`; set Entrypoint override to
`/bin/sh` for tool images whose default entrypoint is the tool itself. Config
fields accept templates such as `{{ steps.NODE_ID.output.stdout }}`, resolved
before the container starts.

An image in a registry that needs a login (a private ghcr.io package, a
Docker Hub account, a company registry) pulls without any change to the step:
an organization admin stores the login once as a registry credential (host,
username, password as a secret reference), and the platform hands it to the
pull whenever an image's host matches. Without a matching credential the pull
is anonymous, as before. The step's evidence records the image reference it
ran. For a tagged image that is the tag, which can move between runs; give a
digest-qualified reference (`image@sha256:…`) when the exact content that ran
must be on record, and the evidence carries that digest.

When the platform runs its own container registry, Cache image (on by
default) keeps a copy of the pulled image there, under the organization's
namespace, named after the image's own registry and repository. Later runs
ask the image's registry only which digest the tag points at today (one
manifest request, plus whatever login round trip that registry asks for;
Docker Hub does not count these requests against its pull limits) and pull
the copy when it matches, or the newest copy under the tag when that registry
is unreachable; the step's events say which. A new digest is pulled from the
image's registry by that digest, so the copy holds exactly what was checked
even if the tag moves meanwhile, and saved as a copy in turn, without ever
failing the step when the save cannot happen. A registry that refuses the
check's login gets the plain pull instead, with no copy served or saved: a
refusal may mean access was withdrawn. An image from a registry whose name
has no dot and is not `localhost` (`myregistry:5000`) is pulled from it and
never cached: the platform registry tells a copy's host segment from an
organization's own image names by that shape. A copy made by another organization is never
used; copies the platform admins place in the global namespace are. Turn the
option off for an image that must come straight from its registry every
time. Without a platform registry the option changes nothing. The evidence
records the reference the container ran by (`image_served`), where it came
from (`image_source`: `upstream`, `cache` or `platform`) and whether this run
saved a copy (`image_cached`).

The container is provisioned with your flow's files. Flow attachments are
copied under the attachments mount path (default `/attachments`); use the
Attachments selector to narrow which ones. Snapshots of every completed
upstream step land under `/step_outputs`, one folder per step id holding
`output.json`, `metrics.json`, `status.txt`, `summary.txt`, `details.json`,
and `step_id.txt` — use
the Step Outputs selector to narrow them. Artifacts from the upstream steps
chosen in the Artifacts selector are copied under `/artifacts`, one folder per
step id. All these mount paths can be changed with the advanced path fields.

To publish results, write files into the new-artifacts folder (default
`/artifacts/new`): after the container exits, UTF-8 text files found there
become step artifacts and other files are uploaded as downloadable files
(up to the worker's per-file cap, 50 MiB by default). A file the harvest
drops - over the cap, unreadable, or a symlink resolving outside the
new-artifacts folder, which is never followed - is named with the reason,
and its size where that is known, in a `skipped_artifacts_<step id>`
artifact, counted in the step's `skipped_artifacts` metric, and noted in the
step summary; raise `HEGEMONY_RUN_ARTIFACT_MAX_FILE_SIZE_BYTES` on the worker
and the API to take a larger file. Skipping never fails the step.
When the step uses shared or explicit execution affinity, the run's shared
workspace is also mounted (default `/shared`) so files persist across the
steps of one run. The workspace is deleted when the run ends, so it is no
place for anything that must outlive the run, such as Terraform state.

The `/hegemony` folder is reserved for the platform's step I/O files (since
0.6.0): the step stages them there before the container starts and copies
`/hegemony/out` back out after it exits, so an image should keep nothing of
its own there. Every container also gets `/hegemony/context.json`: the run
and step ids, flow and run names, the attempt number, and the step's tags.
It holds no flow inputs: pass the ones the script needs as environment
variables such as `REGION={{ inputs.region }}`, which also applies the
input's default when the run left it unset (a sensitive value belongs in
Secret files instead). To hand structured data to later steps, write a JSON
object to `/hegemony/out/output.json`; it becomes the step's `output.data`
(at most 64 KiB), so a later step reads
`{{ steps.NODE_ID.output.data.KEY }}`. A file that is not a JSON object, or
is too large, is reported in an `output_data_rejected_<step id>` artifact
instead and never fails the step. When the results cannot be copied out of
the container (a failed copy, or a file over the 8 MiB collection budget),
an `output_not_collected_<step id>` artifact names what is missing and why.

Put credentials in Secret files rather than environment variables: each
`NAME=reference` entry is resolved and written to `/run/secrets/NAME` inside
the container. The value may be a `{{ secret('...') }}` template or a bare
reference such as `vault://orgs/acme/secrets/db/password`; it is resolved on
its own, without step variables, and only once, so a secret whose value looks
like a URL (`postgres://…`) is written as is. Anything written as
`scheme://…` is read as a reference, so a literal URL cannot be entered
directly: store it in a secret backend and reference it. Other text is used
as written. Values resolved from references are redacted from the step's
output; a literal is not, so keep real secrets in a backend. Unlike
environment variables, secret files never appear in the sandbox's container
metadata.

Defaults: working directory `/workspace`, 512m memory, 1.0 CPUs, 300 s
timeout, normal Docker networking. Turn on "Disable network access" for full
isolation, or set an egress policy mode with allow/deny rules for a
per-step outbound firewall; an egress policy cannot be combined with the
admin-only host-access options (network mode, sandbox Docker socket, privileged,
PID namespace, extra bind mounts) or with disabled networking. Environment
variables are passed through except keys starting with `HEGEMONY_`, which are
reserved and ignored.

## Output

Later steps can read `steps.NODE_ID.output.stdout` and
`steps.NODE_ID.output.stderr`, each capped at 4096 characters, and
`steps.NODE_ID.output.data` when the container wrote
`/hegemony/out/output.json`. The full output is stored as a `container_output` evidence
artifact - stdout and stderr each capped at 2.5 MB (half of a 5 MB budget),
with a truncation marker beyond that - that also records the exit code, image, duration, and the separated
stdout/stderr streams. Text files harvested from the new-artifacts folder are
added as further evidence artifacts; binary files become downloadable run
artifacts. Metrics record `exit_code`, `duration_seconds`, and `image`.
While the container runs, its output streams into the step's live log, up to
5 MB. Past that the live log says so and shows no more; the container goes on,
and the evidence keeps stdout and stderr as above.

## When It Fails

The step succeeds only when the container exits with code 0; any non-zero
exit code fails it with that code in the error. It also fails when config
validation rejects the step, the image cannot be pulled, attachments or
selected artifacts cannot be provisioned, a secret file resolves to nothing,
the Docker binary is missing on the worker, or the worker has no
Docker-in-Docker sandbox configured: the step never runs on the worker's own
Docker daemon instead. The timeout covers the whole step — image pull
included — and on expiry the container is killed and the step fails as timed
out, with the output it produced. An empty Timeout uses the step's timeout;
a longer Timeout raises the step's timeout to fit it plus a minute. On a
platform too old to do that, the container stops at the step's timeout
instead, and the step's log says so. Step-output snapshots and post-run artifact harvesting are best-effort:
problems there are logged but do not fail the step. The container is
force-removed after every attempt, success or failure. Step containers carry
the Docker labels `hegemony.run_id`, `hegemony.step_run_id`, and
`hegemony.handler_id`; the last one names the step type that started the
container, so tool steps built on this runner (`ansible.playbook`,
`tf.plan`, `tf.apply`) carry their own id there, not `container.run`.
