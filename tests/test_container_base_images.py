# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The base images ``container.build`` reads off a Dockerfile to serve from the cache."""

from __future__ import annotations

import pytest

from hegemony_steps_container.base_images import base_image_references, familiar_name

DIGEST = "sha256:" + "ab" * 32


@pytest.mark.parametrize(
    ("reference", "familiar"),
    [
        ("alpine", "alpine"),
        ("alpine:latest", "alpine"),
        ("docker.io/library/alpine", "alpine"),
        ("index.docker.io/library/alpine:latest", "alpine"),
        ("library/alpine:3.20", "alpine:3.20"),
        ("docker.io/acme/tool:1", "acme/tool:1"),
        (f"alpine:latest@{DIGEST}", f"alpine:latest@{DIGEST}"),
        (f"docker.io/library/alpine@{DIGEST}", f"alpine@{DIGEST}"),
        ("ghcr.io/acme/tool:latest", "ghcr.io/acme/tool"),
        ("registry.example.com:5000/library/base", "registry.example.com:5000/library/base"),
        ("localhost/tool:1", "localhost/tool:1"),
    ],
)
def test_familiar_names_are_the_ones_buildkit_matches(reference: str, familiar: str) -> None:
    assert familiar_name(reference) == familiar


def test_the_images_the_last_stage_uses_in_order_without_repeats() -> None:
    dockerfile = (
        "FROM alpine:3.20 AS one\n"
        "FROM python:3.12-slim AS two\n"
        "FROM alpine:3.20\n"
        "COPY --from=one /a /a\n"
        "COPY --from=two /b /b\n"
        "COPY --from=docker.io/library/alpine:3.20 /c /c\n"
    )
    assert base_image_references(dockerfile, {}) == ["alpine:3.20", "python:3.12-slim"]


def test_registries_digests_and_keywords_in_any_case() -> None:
    dockerfile = (
        f"from ghcr.io/acme/tool:1.2@{DIGEST} as tool\n"
        "From registry.example.com:5000/team/base AS base\n"
        f"FROM alpine@{DIGEST}\n"
        "copy --from=tool /t /t\n"
        "COPY --from=base /b /b\n"
    )
    assert base_image_references(dockerfile, {}) == [
        f"ghcr.io/acme/tool:1.2@{DIGEST}",
        "registry.example.com:5000/team/base",
        f"alpine@{DIGEST}",
    ]


def test_stages_scratch_and_stage_references_are_not_images() -> None:
    dockerfile = (
        "FROM golang:1.22 AS Build\n"
        "RUN go build ./...\n"
        "FROM build AS test\n"
        "FROM alpine:3.20 AS later\n"
        "FROM scratch\n"
        "COPY --from=test /out /app\n"
        "COPY --from=2 /etc/os-release /\n"
    )
    assert base_image_references(dockerfile, {}) == ["golang:1.22", "alpine:3.20"]


def test_copy_from_an_image_is_a_base_image() -> None:
    dockerfile = (
        "FROM alpine:3.20\n"
        "COPY --chown=1000 --from=docker.io/library/busybox:1.36 /bin/busybox /bin/\n"
        "COPY --from=$IMAGE /x /x\n"
        "COPY app /app\n"
    )
    assert base_image_references(dockerfile, {}) == [
        "alpine:3.20",
        "docker.io/library/busybox:1.36",
    ]


def test_global_args_and_build_arguments_fill_in_from_lines() -> None:
    dockerfile = (
        "ARG REGISTRY=ghcr.io/acme\n"
        "ARG VERSION=3.20\n"
        "ARG FLAVOUR\n"
        "FROM alpine:${VERSION} AS a\n"
        "FROM $REGISTRY/base:${FLAVOUR:-slim} AS b\n"
        "ARG VERSION=9\n"
        "FROM python:3.12${FLAVOUR:+-$FLAVOUR}\n"
        "COPY --from=a / /a\n"
        "COPY --from=b / /b\n"
    )
    assert base_image_references(dockerfile, {}) == [
        "alpine:3.20",
        "ghcr.io/acme/base:slim",
        "python:3.12",
    ]
    assert base_image_references(dockerfile, {"VERSION": "3.19", "FLAVOUR": "bookworm"}) == [
        "alpine:3.19",
        "ghcr.io/acme/base:bookworm",
        "python:3.12-bookworm",
    ]


def test_a_build_argument_the_file_does_not_declare_is_not_used() -> None:
    assert base_image_references("FROM alpine:${VERSION}\n", {"VERSION": "3.20"}) == []


@pytest.mark.parametrize(
    "line",
    [
        # Variables BuildKit sets that the file does not declare.
        "FROM alpine-$TARGETARCH",
        # Expansion forms this reader does not evaluate.
        "FROM alpine:${VERSION#v}",
        "FROM alpine:${VERSION%%-*}",
        # Another platform than the build's own: a copy holds one platform.
        "FROM --platform=linux/arm64 alpine:3.20",
        "FROM --platform=$TARGETPLATFORM alpine:3.20",
        # Not an image reference at all.
        "FROM Alpine",
        "FROM",
    ],
)
def test_what_cannot_be_read_off_the_file_is_left_to_buildkit(line: str) -> None:
    assert base_image_references(f"ARG VERSION=v3.20\n{line}\n", {}) == []


def test_the_build_platform_is_the_platform_a_copy_holds() -> None:
    dockerfile = (
        "FROM --platform=$BUILDPLATFORM golang:1.22 AS build\n"
        "FROM alpine:3.20\n"
        "COPY --from=build /out /out\n"
    )
    assert base_image_references(dockerfile, {}) == ["golang:1.22", "alpine:3.20"]


def test_an_image_whose_familiar_name_is_a_stage_name_is_left_out() -> None:
    """A context named ``alpine`` would replace the whole stage named ``alpine``."""
    dockerfile = (
        "FROM alpine:latest AS base\n"
        "RUN echo base > /base\n"
        "FROM busybox AS alpine\n"
        "RUN echo final > /final\n"
        "COPY --from=base /base /base\n"
    )
    assert base_image_references(dockerfile, {}) == ["busybox"]
    spelled = dockerfile.replace("alpine:latest", "docker.io/library/alpine")
    assert base_image_references(spelled, {}) == ["busybox"]
    # A tag keeps the name apart from the stage's.
    tagged = dockerfile.replace("alpine:latest", "alpine:3.20")
    assert base_image_references(tagged, {}) == ["alpine:3.20", "busybox"]


def test_an_image_another_stage_uses_for_another_platform_is_left_out() -> None:
    """One context serves every platform: the native copy must not reach the ARM stage."""
    dockerfile = (
        "FROM alpine:3.20 AS native\n"
        "FROM --platform=linux/arm64 alpine:3.20 AS arm\n"
        "COPY --from=busybox:1.36 /bin/busybox /bb\n"
        "RUN --mount=type=bind,from=python:3.12,target=/py true\n"
        "FROM debian:12\n"
        "COPY --from=native / /native\n"
        "COPY --from=arm / /arm\n"
        "COPY --from=busybox /bin/busybox /bb\n"
        "COPY --from=python:3.12 / /py\n"
    )
    # alpine, busybox:1.36 and python:3.12 are used for arm64 in the arm stage.
    # "busybox" is busybox:latest, another context.
    assert base_image_references(dockerfile, {}) == ["debian:12", "busybox"]


def test_only_the_stages_the_target_depends_on_count() -> None:
    dockerfile = (
        "FROM ubuntu:24.04 AS unused\n"
        "RUN apt-get update\n"
        "FROM golang:1.22 AS build\n"
        "FROM node:22 AS assets\n"
        "FROM alpine:3.20 AS runtime\n"
        "COPY --from=build /out /app\n"
        "RUN --mount=type=bind,from=assets,target=/assets cp -r /assets /app\n"
        "FROM runtime AS debug\n"
        "COPY --from=busybox:1.36 /bin/busybox /bin/\n"
    )
    assert base_image_references(dockerfile, {}, "runtime") == [
        "golang:1.22",
        "node:22",
        "alpine:3.20",
    ]
    # Without a target the last stage is built, and what it depends on.
    assert base_image_references(dockerfile, {}) == [
        "golang:1.22",
        "node:22",
        "alpine:3.20",
        "busybox:1.36",
    ]
    assert base_image_references(dockerfile, {}, "Unused") == ["ubuntu:24.04"]
    # A target the file does not have leaves everything to BuildKit, which fails it.
    assert base_image_references(dockerfile, {}, "missing") == []


def test_continued_lines_and_comments() -> None:
    dockerfile = (
        "# syntax=docker/dockerfile:1\n"
        "FROM \\\n"
        "  # a comment inside the instruction\n"
        "  alpine:3.20 \\\n"
        "  AS base\n"
        "RUN echo hi\n"
    )
    assert base_image_references(dockerfile, {}) == ["alpine:3.20"]


def test_the_escape_directive_changes_the_continuation_character() -> None:
    dockerfile = "# escape=`\nFROM `\n  mcr.microsoft.com/windows/servercore:ltsc2022\n"
    assert base_image_references(dockerfile, {}) == [
        "mcr.microsoft.com/windows/servercore:ltsc2022"
    ]


@pytest.mark.parametrize("separator", [" ", "\t", " \t "])
def test_any_whitespace_separates_an_instruction_from_its_arguments(separator: str) -> None:
    """BuildKit takes tabs as separators: a stage name or a platform must not slip by."""
    colliding = (
        f"FROM{separator}alpine:latest AS base\n"
        f"FROM{separator}busybox{separator}AS{separator}alpine\n"
        f"COPY{separator}--from=base /base /base\n"
    )
    assert base_image_references(colliding, {}) == ["busybox"]
    mixed = (
        f"FROM{separator}alpine:3.20 AS native\n"
        f"FROM{separator}--platform=linux/arm64{separator}alpine:3.20 AS arm\n"
        "FROM scratch\n"
        f"COPY{separator}--from=native / /native\n"
        f"COPY{separator}--from=arm / /arm\n"
    )
    assert base_image_references(mixed, {}) == []
    args = f"ARG{separator}V=3.20\nFROM{separator}alpine:${{V}}\n"
    assert base_image_references(args, {}) == ["alpine:3.20"]
