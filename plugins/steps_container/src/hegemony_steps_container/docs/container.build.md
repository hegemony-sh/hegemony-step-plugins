<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Build Image

`container.build` builds a container image from a Dockerfile among the flow's
attachments, on the platform's Docker-in-Docker sandbox. Where the image goes
depends on its name:

- **A name such as `tools/netbox-sync`** goes under the organization's
  namespace: `registry.hegemony.internal/orgs/ORG/tools/netbox-sync` (the
  registry's host is the platform's). When the platform runs its own
  registry, the step pushes the image there, and any later step on any worker
  can run it, by tag or by the digest the step reports. When it runs none, the
  image is built into the sandbox only, under that same name, and nothing is
  pushed.
- **A name with its registry in front, such as `ghcr.io/acme/netbox-sync`**,
  is pushed to that registry, with the organization's saved login for it
  (Settings, Registry Credentials). Without a saved login the push goes
  without one, which most registries refuse. Docker Hub is `docker.io`, as in
  `docker.io/acme/netbox-sync`: a name without a registry is always the
  organization's.

## Using It

Image name is the only required field. It is lowercase and has no tag (the
tags come from their own field). A name without a registry may not start
with a segment that looks like a registry host (a dot, or `localhost`): those
names are reserved for the platform's cached copies of upstream images. A
name with a registry in front may not name `localhost` (the sandbox itself)
or the platform registry, with or without its default port (80 or 443): give
the platform registry's images their short
name, and the step puts them under the organization's namespace. The registry
host is used in lowercase, the spelling its saved login goes by.

Every build is tagged `run-` and the run's short id (the first eight
characters of the run id, as the run pages show it), so each run's image stays
addressable. Extra tags add more, one per line, such as `latest` or
`{{ inputs.version }}`. Tags are up to 128 letters, digits, `_`, `.` or `-`;
the digest shapes `sha256_…` and `sha256-…` are reserved. A tag that already
exists is moved to the new image, in the sandbox and in the registry the
image is pushed to.

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
lands in a layer, the image's history or the build's command line. A value
resolved from a reference is redacted from the log; text that is not a
reference is used as written and is not redacted, so keep real secrets in a
backend.

Target stage builds a multi-stage Dockerfile up to one stage (`--target`).
Platform builds for another platform, such as `linux/arm64`; one platform per
step, and an architecture other than the sandbox's needs emulation (QEMU)
registered on the sandbox host. Labels add image labels such as
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
container step's image is, with the organization's registry logins and, with
a platform registry, the step's platform registry token: an image in another
organization's namespace is refused. They are pulled on every build, never
taken from the sandbox's local images, and no build reads the sandbox's build
cache: the sandbox is shared by every organization. An image another build
kept in the sandbox can therefore not be a base image: that needs a registry. Every instruction therefore runs on every build,
and cache mounts (`RUN --mount=type=cache`) start empty: each build's cache
mounts get a name of their own, never shared with another build.
`ADD` with a URL is fetched by the sandbox daemon too, outside the egress
policy, like the base images.

Pushing to a registry other than the platform's is allowed only under the
same condition as the network: an open egress policy. The sandbox daemon
pushes, outside the policy the step's containers are held to, so a stricter
policy refuses the step before it builds (summary "Push not allowed"). Once
the push is done, or has failed, the image's names are taken off the sandbox,
which every organization shares: a later step pulls it from that registry.

Only the official Dockerfile frontend builds: a `# syntax=` directive is taken
when it names `docker/dockerfile` (any tag or digest), and refused otherwise.
`BUILDKIT_*` build arguments are refused for the same reason: they steer
BuildKit itself.

## Output

While the build runs, its log streams into the step's live log. Later steps
can read `steps.NODE_ID.output.reference`: for a pushed image, the image by
digest (`registry.hegemony.internal/orgs/ORG/NAME@sha256:…`, or
`ghcr.io/acme/NAME@sha256:…`), which a `container.run` step can run exactly.
Also `steps.NODE_ID.output.digest`, `.image` (the repository), `.tags`,
`.references` (one per tag), `.destination` (`platform`, `remote` or `local`)
and `.pushed`.

An image kept in the sandbox has no digest a registry knows (`.digest` is
empty), so its reference is the run tag
(`registry.hegemony.internal/orgs/ORG/NAME:run-1a2b3c4d`), which no other
run's build takes (a second build of the same name in the same run moves it). Steps that use the sandbox's images directly can run it,
such as `docker run` or containerlab inside a step. A `container.run` step
cannot: it always pulls its image, and no registry holds this one. Anything
in the sandbox can be run by any step that uses the sandbox directly, so keep
credentials out of images; build secrets never reach a layer.

The evidence holds a `container_output` artifact `build_output_<step id>` with
the build log (capped at 5 MB, with a truncation marker beyond), the exit code,
the reference and the duration; and, after a successful build, a
`step_result` artifact `image_build_<step id>` naming the repository, digest,
every reference, where the image went and whether a saved login was found for
another registry, the build context, the network, the labels, and the names
(never the values) of the build arguments and secrets. Metrics record `exit_code`,
`duration_seconds`, `image`, `image_digest` and `tag_count`.

## When It Fails

The step fails when config validation rejects it (an invalid image name or
tag, a path outside the attachments, a reserved label or build argument), when
the Dockerfile is not among the attachments, when its syntax directive names
another frontend, when a secret resolves to nothing, when the platform runs a
registry but did not grant the step access to it, when the image goes to
another registry under an egress policy that is not open, when the worker's
Docker CLI has no buildx plugin, or when the build or the push fails: the error names the
build's own explanation and the full log is in the evidence. It also fails
when the pushed image's digest cannot be read, rather than report a tag that
can later move to another image. A push the
registry refuses (an image name outside what the step may write, or a login
that may not push there) fails the same way. The step's timeout (30 minutes unless the step or the flow sets
another) covers the whole build and push; at its end the build is cancelled.
