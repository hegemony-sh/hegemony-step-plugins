# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Default image of the tf.plan and tf.apply steps for engine opentofu.
#
# OpenTofu asks users to put its binary into their own image rather than run
# its image directly. This is that image: OpenTofu at the exact version below
# on Alpine Linux, with git and an SSH client for module sources and the CA
# bundle for provider downloads. The steps run it with /bin/sh and need
# `timeout` (BusyBox's). It runs as root: the steps write the run's shared
# workspace, which the worker creates.
#
# tofu is built here from the upstream release commit with the release's own
# build flags, and with one change: the Go modules in GO_MODULE_RAISES are
# raised to the first versions that fix the HIGH vulnerabilities the Images
# workflow's scan finds in the released binary, since no OpenTofu release
# carries them yet. Raising the OpenTelemetry SDK also moves the semconv import
# in internal/tracing/traceattrs/semconv.go to the SDK's own version, as that
# file's comment asks for every SDK upgrade. OpenTofu's tests for the code those
# modules serve (tracing, the provider plugin protocol, provider and module
# installation, registries) run on the result before it is used. The image
# carries the change as a diff (/usr/share/doc/hegemony/opentofu/source.diff),
# every module compiled in (modules.txt next to it), and the licence files of
# the Go standard library and of each of those modules (licenses/), which their
# BSD, MIT and Apache licences ask a binary distribution to include. When an OpenTofu
# release carries fixed versions, move OPENTOFU_VERSION and OPENTOFU_COMMIT to
# it and drop the raises it makes unnecessary.
#
# The Images workflow (.github/workflows/images.yml) publishes it for every
# release tag vX.Y.Z as ghcr.io/hegemony-sh/opentofu-runner:X.Y.Z and :X.Y. The
# steps' default names X.Y (DEFAULT_IMAGES in
# plugins/steps_tf/src/hegemony_steps_tf/common.py), currently
# ghcr.io/hegemony-sh/opentofu-runner:0.18. For another OpenTofu version, build
# and push it under your own tag and set the plan step's Image:
#
#   docker build --build-arg OPENTOFU_VERSION=<version> \
#       --build-arg OPENTOFU_COMMIT=<commit the v<version> tag names> \
#       --build-arg GO_MODULE_RAISES= \
#       -t registry.example.com/opentofu-runner:custom images/opentofu-runner
#   docker push registry.example.com/opentofu-runner:custom

ARG GO_VERSION=1.26.8

# The Debian-based Go image, which has git; only the compiled tofu leaves it.
FROM golang:${GO_VERSION}-bookworm AS tofu

ARG OPENTOFU_VERSION=1.12.6
# The commit the v1.12.6 tag names; the build refuses any other.
ARG OPENTOFU_COMMIT=b4305e5a5dd2fb79a27897ae30784a181d3a26cb
# First fixed versions of the modules the scan flags (THIRD-PARTY-NOTICES.md);
# the modules they need move with them.
ARG GO_MODULE_RAISES="go.opentelemetry.io/otel/sdk@v1.44.0 golang.org/x/crypto@v0.55.0 golang.org/x/mod@v0.40.0 golang.org/x/net@v0.58.0 golang.org/x/text@v0.41.0 google.golang.org/grpc@v1.83.2 oras.land/oras-go/v2@v2.6.2"

RUN git clone --quiet --depth 1 --branch "v${OPENTOFU_VERSION}" \
        https://github.com/opentofu/opentofu.git /src \
    && test "$(git -C /src rev-parse HEAD)" = "${OPENTOFU_COMMIT}"

WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=
RUN if [ -n "${GO_MODULE_RAISES}" ]; then \
        go get ${GO_MODULE_RAISES} \
        && sdk="$(go list -m -f '{{.Dir}}' go.opentelemetry.io/otel/sdk)" \
        && semconv="$(grep -ho 'go.opentelemetry.io/otel/semconv/v[0-9.]*[0-9]' \
            "${sdk}/resource/builtin.go" | head -n 1)" \
        && test -n "${semconv}" \
        && sed -i "s#go.opentelemetry.io/otel/semconv/v[0-9.]*[0-9]\"#${semconv}\"#" \
            internal/tracing/traceattrs/semconv.go \
        && go mod tidy; \
    fi \
    && go test ./internal/tracing/... ./internal/plugin/... ./internal/plugin6/... \
        ./internal/grpcwrap/... ./internal/getproviders/... ./internal/getmodules/... \
        ./internal/providercache/... ./internal/registry/... ./internal/httpclient/... \
    && go test ./internal/command/e2etest -run 'TestTelemetry' \
    && go build -mod=readonly -trimpath \
        -ldflags "-s -w -X 'github.com/opentofu/opentofu/version.dev=no'" \
        -o /out/tofu ./cmd/tofu \
    && mkdir -p /out/doc/licenses/go \
    && git diff > /out/doc/source.diff \
    && go version -m /out/tofu > /out/doc/modules.txt \
    && cp /usr/local/go/LICENSE /out/doc/licenses/go/LICENSE \
    && go list -deps -f '{{with .Module}}{{.Path}} {{.Dir}}{{end}}' ./cmd/tofu | sort -u \
        | while read -r module dir; do \
            [ -n "${module}" ] || continue; \
            files="$(find "${dir}" -maxdepth 1 -type f \( -iname 'LICEN[CS]E*' \
                -o -iname 'COPYING*' -o -iname 'NOTICE*' \))"; \
            if [ -n "${files}" ]; then \
                mkdir -p "/out/doc/licenses/${module}" \
                && printf '%s\n' "${files}" | xargs -I{} cp {} "/out/doc/licenses/${module}/"; \
            else \
                echo "${module}" >> /out/doc/licenses/MISSING.txt; \
            fi; \
        done \
    && test -s /out/doc/licenses/github.com/opentofu/opentofu/LICENSE

FROM alpine:3.22

RUN apk add --no-cache ca-certificates git openssh-client

COPY --from=tofu /out/tofu /usr/local/bin/tofu

# Everything above is third-party. The notices (with the written source offer)
# travel inside the image, next to inventories of exactly what this build
# installed: the Alpine packages with their licences, the OpenTofu version, the
# Go modules compiled into tofu, and the change made to OpenTofu's source.
COPY THIRD-PARTY-NOTICES.md /usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md
COPY --from=tofu /out/doc/ /usr/share/doc/hegemony/opentofu/
RUN apk list --installed > /usr/share/doc/hegemony/alpine-packages.txt \
    && tofu version > /usr/share/doc/hegemony/opentofu-version.txt

ENTRYPOINT ["/bin/sh"]
