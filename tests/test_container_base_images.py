# SPDX-FileCopyrightText: 2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The base images ``container.build`` reads off a Dockerfile to serve from the cache."""

from __future__ import annotations

import pytest

from hegemony_steps_container.base_images import base_image_references

DIGEST = "sha256:" + "ab" * 32


def test_from_lines_in_order_without_repeats() -> None:
    dockerfile = "FROM alpine:3.20\nRUN echo hi\nFROM python:3.12-slim\nFROM alpine:3.20\n"
    assert base_image_references(dockerfile, {}) == ["alpine:3.20", "python:3.12-slim"]


def test_registries_digests_and_keywords_in_any_case() -> None:
    dockerfile = (
        f"from ghcr.io/acme/tool:1.2@{DIGEST}\n"
        "From registry.example.com:5000/team/base\n"
        f"FROM alpine@{DIGEST}\n"
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
        "FROM scratch\n"
        "COPY --from=build /out /app\n"
        "COPY --from=0 /out /app\n"
        "COPY --from=later /x /x\n"
        "FROM alpine:3.20 AS later\n"
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
        "FROM alpine:${VERSION}\n"
        "FROM $REGISTRY/base:${FLAVOUR:-slim}\n"
        "FROM python:3.12${FLAVOUR:+-$FLAVOUR}\n"
        "ARG VERSION=9\n"
        "FROM alpine:${VERSION}\n"
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
    dockerfile = "FROM --platform=$BUILDPLATFORM golang:1.22 AS build\nFROM alpine:3.20\n"
    assert base_image_references(dockerfile, {}) == ["golang:1.22", "alpine:3.20"]


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
