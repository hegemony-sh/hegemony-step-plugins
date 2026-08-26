<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Run Container

`container.run` runs a script inside a Docker container on the worker host.
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
fields accept templates such as `{{ steps.NODE_ID.stdout }}`, resolved before
the container starts.

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
drops - over the cap, or unreadable - is named with its size and the cap it
hit in a `skipped_artifacts_<step id>` artifact, counted in the step's
`skipped_artifacts` metric, and noted in the step summary; raise
`HEGEMONY_RUN_ARTIFACT_MAX_FILE_SIZE_BYTES` on the worker and the API to
take a larger file. Skipping never fails the step.
When the step uses shared or explicit execution affinity, the run's shared
workspace is also mounted (default `/shared`) so files such as Terraform
state persist across steps.

Defaults: working directory `/workspace`, 512m memory, 1.0 CPUs, 300 s
timeout, normal Docker networking. Turn on "Disable network access" for full
isolation, or set an egress policy mode with allow/deny rules for a
per-step outbound firewall; an egress policy cannot be combined with the
admin-only host-access options (network mode, host Docker socket, privileged,
PID namespace, extra bind mounts) or with disabled networking. Environment
variables are passed through except keys starting with `HEGEMONY_`, which are
reserved and ignored.

## Output

Later steps can read `steps.NODE_ID.stdout` and `steps.NODE_ID.stderr`,
each capped at 4096 characters. The full output is stored as a `container_output` evidence
artifact - stdout and stderr each capped at 2.5 MB (half of a 5 MB budget),
with a truncation marker beyond that - that also records the exit code, image, duration, and the separated
stdout/stderr streams. Text files harvested from the new-artifacts folder are
added as further evidence artifacts; binary files become downloadable run
artifacts. Metrics record `exit_code`, `duration_seconds`, and `image`.
While the container runs, its output streams into the step's live log.

## When It Fails

The step succeeds only when the container exits with code 0; any non-zero
exit code fails it with that code in the error. It also fails when config
validation rejects the step, the image cannot be pulled, attachments or
selected artifacts cannot be provisioned, or the Docker binary is missing on
the worker. The timeout covers the whole step — image pull included — and on
expiry the container is killed and the step fails as timed out. Step-output
snapshots and post-run artifact harvesting are best-effort: problems there
are logged but do not fail the step. The container is force-removed after
every attempt, success or failure.
