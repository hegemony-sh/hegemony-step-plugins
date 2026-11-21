# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Default image of the git.commit step: git and the CA bundle on Alpine Linux.
# The step runs it with /bin/sh and needs `timeout` (BusyBox's). It runs as an
# unprivileged user: the step stages its files readable by any user, clones
# into a temporary folder and writes its report to the collect folder, which
# the runner stages writable.
#
# The Images workflow (.github/workflows/images.yml) publishes it for every
# release tag vX.Y.Z as ghcr.io/hegemony-sh/git-runner:X.Y.Z and :X.Y. The
# step's default names X.Y (DEFAULT_IMAGE in
# plugins/steps_git/src/hegemony_steps_git/commit.py), currently
# ghcr.io/hegemony-sh/git-runner:0.50.

# Pinned by digest, so a build uses exactly the reviewed image; Renovate
# proposes the new digest when the tag moves (.github/renovate.json).
FROM alpine:3.22@sha256:bfe7ceb9f09ec0566c48fb93356e45a47a00be5a1dd14fa5b909e7709c66b034

# The pinned base carries Alpine's fixes only up to its digest; upgrade so a
# rebuild of the same tag still picks up the fixed packages.
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates git

# Everything above is third-party. The notices (with the written source offer)
# travel inside the image, next to an inventory of exactly what this build
# installed.
COPY THIRD-PARTY-NOTICES.md /usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md
RUN apk list --installed > /usr/share/doc/hegemony/alpine-packages.txt \
    && git --version > /usr/share/doc/hegemony/git-version.txt \
    && adduser -D -u 1000 git

USER git
ENTRYPOINT ["/bin/sh"]
