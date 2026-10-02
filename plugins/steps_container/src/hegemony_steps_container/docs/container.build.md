<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build Image

`container.build` builds a container image from a Dockerfile among the flow's
attachments, on the platform's Docker-in-Docker sandbox, and pushes it to the
organization's namespace of the platform registry. Any later step on any
worker can then run it, by tag or by the digest the step reports.

The step needs the platform registry: without it, or when the platform cannot
grant the step access to it, the step fails and says so.

## Using It

Image name is the only required field: the image's name under the
organization, such as `tools/netbox-sync`. The step pushes
`registry.hegemony.internal/orgs/ORG/tools/netbox-sync` (the registry's host
is the platform's). The name is lowercase, without a registry host or a tag,
and its first segment may not look like a registry host (a dot, or
`localhost`): those names are reserved for the platform's cached copies of
upstream images.

Every build is tagged `run-` and the run's short id (the first eight
characters of the run id, as the run pages show it), so each run's image stays
addressable. Extra tags adds more, one per line, such as `latest` or
`{{ inputs.version }}`. Tags are up to 128 letters, digits, `_`, `.` or `-`;
the digest shapes `sha256_…` and `sha256-…` are reserved. A tag that already
exists is moved to the new image.

The build context is a folder among the flow's attachments: Build context
folder (empty for the attachments root), and Dockerfile, the Dockerfile's path
inside that folder (default `Dockerfile`). Only the files under the folder are
sent to the build, and a `.dockerignore` there is honoured. Attachments are
text files, so the context holds text only, and files arrive without an
executable bit: use `COPY --chmod=0755` for scripts. A flow synced from git
brings its attachments, and so its build context, from the repository.

Build arguments are `NAME=value` lines for the Dockerfile's `ARG`
instructions; values may use templates such as `{{ inputs.version }}`. Build
arguments end up in the image's history, so never put a credential there.
Build secrets are `ID=reference` lines instead (a `{{ secret('...') }}`
template or a bare reference such as `vault://orgs/acme/secrets/pypi/token`).
A `RUN` instruction reads one with `--mount=type=secret,id=ID`, at
`/run/secrets/ID`:

```dockerfile
RUN --mount=type=secret,id=pypi_token \
    PIP_INDEX_URL="https://__token__:$(cat /run/secrets/pypi_token)@pypi.example.com/simple" \
    pip install -r requirements.txt
```

A secret is handed to BuildKit from a private file on the worker: it never
lands in a layer, the image's history or the build's command line, and its
value is redacted from the log.

Target stage builds a multi-stage Dockerfile up to one stage (`--target`).
Platform builds for another platform, such as `linux/arm64`; one platform per
step, and an architecture other than the sandbox's needs emulation (QEMU)
registered on the sandbox host. Labels adds image labels such as
`org.opencontainers.image.source`. The step always sets
`org.opencontainers.image.created` (the build's start, in UTC),
`sh.hegemony.run` (the run id) and `sh.hegemony.step` (the step id); label
keys starting with `sh.hegemony.` are reserved.

## Network and Sources

The build's `RUN` instructions reach the network only when the step's egress
policy is open: the flow's network policy, narrowed by the step's own egress
fields, in open mode with no Deny rules. Under any other policy
(`allow-listed`, `deny-all`, or Deny rules) the build runs with no network at
all (`--network=none`), since a build cannot be held to allow rules. A
`RUN --network` flag in the Dockerfile does not change that.

Base images (`FROM`, `COPY --from`) are pulled by the sandbox daemon, as every
container step's image is, with the organization's registry logins and the
step's platform registry token: an image in another organization's namespace
is refused. They are pulled on every build, never taken from the sandbox's
local images, and no build reads the sandbox's build cache: the sandbox is
shared by every organization. Every instruction therefore runs on every build.
`ADD` with a URL is fetched by the sandbox daemon too, outside the egress
policy, like the base images.

Only the official Dockerfile frontend builds: a `# syntax=` directive is taken
when it names `docker/dockerfile` (any tag or digest), and refused otherwise.
`BUILDKIT_*` build arguments are refused for the same reason: they steer
BuildKit itself.

## Output

While the build runs, its log streams into the step's live log. Later steps
can read `steps.NODE_ID.output.reference`, the pushed image by digest
(`registry.hegemony.internal/orgs/ORG/NAME@sha256:…`), which a `container.run`
step can run exactly; `steps.NODE_ID.output.digest`, `.image` (the repository),
`.tags` and `.references` (one per tag).

The evidence holds a `container_output` artifact `build_output_<step id>` with
the build log (capped at 5 MB, with a truncation marker beyond), the exit code,
the pushed reference and the duration; and, after a push, a `step_result`
artifact `image_build_<step id>` naming the repository, digest, every pushed
reference, the build context, the network, the labels, and the names (never
the values) of the build arguments and secrets. Metrics record `exit_code`,
`duration_seconds`, `image`, `image_digest` and `tag_count`.

## When It Fails

The step fails when config validation rejects it (an invalid image name or
tag, a path outside the attachments, a reserved label or build argument), when
the Dockerfile is not among the attachments, when its syntax directive names
another frontend, when a secret resolves to nothing, when the platform has no
registry or did not grant the step access to it, when the worker's Docker CLI
has no buildx plugin, or when the build or the push fails: the error names the
build's own explanation and the full log is in the evidence. A push the
registry refuses (an image name outside what the step may write) fails the
same way. The step's timeout (30 minutes unless the step or the flow sets
another) covers the whole build and push; at its end the build is cancelled.
