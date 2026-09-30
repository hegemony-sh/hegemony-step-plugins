# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Default image of the tf.plan and tf.apply steps for engine opentofu.
#
# Since OpenTofu 1.10 the project asks users to copy the tofu binary out of its
# minimal image into their own image, rather than run its image directly. This
# is that image: the unmodified tofu binary at the exact version below, on
# Alpine Linux, with git and an SSH client for module sources and the CA bundle
# for provider downloads. The steps run it with /bin/sh and need `timeout`
# (BusyBox's). It runs as root: the steps write the run's shared workspace,
# which the worker creates.
#
# The Images workflow (.github/workflows/images.yml) publishes it for every
# release tag vX.Y.Z as ghcr.io/hegemony-sh/opentofu-runner:X.Y.Z and :X.Y. The
# steps' default names X.Y (DEFAULT_IMAGES in
# plugins/steps_tf/src/hegemony_steps_tf/common.py), currently
# ghcr.io/hegemony-sh/opentofu-runner:0.6. For another OpenTofu version, build
# and push it under your own tag and set the plan step's Image:
#
#   docker build --build-arg OPENTOFU_VERSION=1.12.6 \
#       -t registry.example.com/opentofu-runner:custom images/opentofu-runner
#   docker push registry.example.com/opentofu-runner:custom

ARG OPENTOFU_VERSION=1.12.6

FROM ghcr.io/opentofu/opentofu:${OPENTOFU_VERSION}-minimal AS tofu

FROM alpine:3.22

RUN apk add --no-cache ca-certificates git openssh-client

COPY --from=tofu /usr/local/bin/tofu /usr/local/bin/tofu

# Everything above is third-party. The notices (with the written source offer)
# travel inside the image, next to inventories of exactly what this build
# installed: the Alpine packages with their licences, and the OpenTofu version.
COPY THIRD-PARTY-NOTICES.md /usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md
RUN apk list --installed > /usr/share/doc/hegemony/alpine-packages.txt \
    && tofu version > /usr/share/doc/hegemony/opentofu-version.txt

ENTRYPOINT ["/bin/sh"]
