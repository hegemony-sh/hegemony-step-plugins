# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Optional runner image for the tf.plan and tf.apply steps.
#
# Since OpenTofu 1.10 the project recommends copying the tofu binary out of its
# minimal image into your own, rather than running the official image
# directly. The steps default to the official image pinned to an exact version
# (which still runs); set a step's Image to one built from this file to follow
# the recommendation. The steps need /bin/sh and the tofu binary; git and
# openssh let module sources use git URLs.
#
#   docker build -t registry.example.com/opentofu-runner:1.12.6 images/opentofu-runner

ARG OPENTOFU_VERSION=1.12.6

FROM ghcr.io/opentofu/opentofu:${OPENTOFU_VERSION}-minimal AS tofu

FROM alpine:3.22
RUN apk add --no-cache ca-certificates git openssh-client
COPY --from=tofu /usr/local/bin/tofu /usr/local/bin/tofu
ENTRYPOINT ["/bin/sh"]
