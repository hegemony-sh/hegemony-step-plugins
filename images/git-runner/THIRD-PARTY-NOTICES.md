<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Third-party notices: git-runner image

`ghcr.io/hegemony-sh/git-runner` is the default image of Hegemony's
`git.commit` step. It is built from [`images/git-runner/Dockerfile`](Dockerfile)
in the [hegemony-step-plugins](https://github.com/hegemony-sh/hegemony-step-plugins)
repository and published by its Images workflow.

**The image contains no Hegemony code.** Every program and library in it is
third-party software under its own licence, unmodified. Hegemony's licence
(`AGPL-3.0-or-later`; see [LICENSING.md](../../LICENSING.md)) covers none of
it, and cannot grant rights over it. This file travels inside the image at
`/usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md`, next to files written when
the image is built:

- `/usr/share/doc/hegemony/alpine-packages.txt`: every installed Alpine
  package, its version and its licence (`apk list --installed`);
- `/usr/share/doc/hegemony/git-version.txt`: the git version
  (`git --version`).

## How the step uses these components

The step's script starts `git` as a separate program inside this container.
Collecting separate programs in one image is mere aggregation (GPL-2.0
section 2, GPL-3.0 section 5): no copyleft reaches Hegemony's own code.

The step stages its own files into the container at run time (a shell
script, the files it commits, the commit message, the login); they are data
for these programs, not part of the image.

## Components

### Base image

`alpine` (`alpine:3.22`): the Alpine Linux userland. musl (MIT), BusyBox
(GPL-2.0-only), apk-tools (GPL-2.0-only), and libraries under MIT, BSD, zlib
and OpenSSL/Apache-2.0 licences.

### Alpine packages this image adds

| Package | Licence | Used for |
| --- | --- | --- |
| `git` | GPL-2.0-only | Cloning, committing and pushing |
| `ca-certificates` | MPL-2.0 AND MIT | The Mozilla CA bundle git trusts for HTTPS, and its update script |

Their dependencies (among them curl, pcre2 and zlib) are resolved at build time
and listed, with versions and licences, in
`/usr/share/doc/hegemony/alpine-packages.txt`.

## Corresponding Source

Some of these components are licensed under the GNU GPL. Their source is
offered in two ways.

### Where to get the source (network distribution)

The image is offered from `ghcr.io`, so GPL-3.0 section 6(d) applies: access to
the Corresponding Source is offered with directions next to the object code.
Every component is an **upstream release**, unmodified:

| Component | Corresponding Source |
| --- | --- |
| Alpine packages (`git`, `ca-certificates`, and the rest of the `alpine:3.22` userland) | The package's build recipe under <https://gitlab.alpinelinux.org/alpine/aports>, branch `3.22-stable`, and the upstream source archives it names, mirrored at <https://distfiles.alpinelinux.org/distfiles/v3.22/> |

The exact versions are read from the image: the inventory files above. The
build instructions are [`images/git-runner/Dockerfile`](Dockerfile).

### Written offer

Additionally, and to cover GPL-2.0 section 3(b), which the GPL-2.0 components
above are conveyed under and which also applies if you receive the image
embedded in a product or an appliance: the complete corresponding source code
is available on request, for three years from the date you received the image,
by writing to **<contact@hegemony.sh>** with the image name and digest. It will
be supplied on a durable physical medium or by download, at no charge beyond
the cost of performing the distribution. This offer is valid to any third
party.

## Reporting an omission

If a component is missing here, or a notice is wrong, open an issue in
hegemony-step-plugins or write to <contact@hegemony.sh>. Attribution errors are
treated as bugs.
