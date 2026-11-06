#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Accept raw UTF-8 Dockerfiles and also generate valid dependency graphs."""

import sys

import atheris

with atheris.instrument_imports(include=["hegemony_steps_container"]):
    from hegemony_steps_container.base_images import base_image_references, familiar_name


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    dockerfile = data[:16384].decode("utf-8", errors="replace")
    # Always traverse the default target; a random missing target must not
    # prevent malformed COPY/RUN dependencies from reaching the parser.
    references = base_image_references(dockerfile, {})
    assert all(isinstance(reference, str) and reference for reference in references)
    names = [familiar_name(reference) for reference in references]
    assert len(names) == len(set(names)), references

    fdp = atheris.FuzzedDataProvider(data)
    tag = str(fdp.ConsumeIntInRange(0, 99999))
    image = "alpine:" + tag
    target = "stage" + str(fdp.ConsumeIntInRange(0, 99))
    args = {"VERSION": tag}
    generated = "ARG VERSION=latest\nFROM alpine:${VERSION} AS base\n"
    assert base_image_references(generated, args) == [image]
    generated += f"FROM busybox:1 AS {target}\n"
    dependency = "base" if fdp.ConsumeBool() else "0"
    if fdp.ConsumeBool():
        generated += f"COPY --from={dependency} /x /y\n"
    else:
        generated += f"RUN --mount=from={dependency},target=/x true\n"
    expected = [image, "busybox:1"]
    assert base_image_references(generated, args, target) == expected
    assert base_image_references(generated, args) == expected
    # An unrelated stage must not affect an explicitly selected target.
    assert base_image_references(generated + "FROM debian:12 AS unused\n", args, target) == expected
    assert base_image_references(generated, args, "missing") == []
    # Docker's familiar-name aliases must collapse to one reference.
    aliases = f"FROM {image}\nCOPY --from=docker.io/library/{image} /x /y\n"
    assert base_image_references(aliases, {}) == [image]
    build_args = {"VERSION": fdp.ConsumeUnicodeNoSurrogates(64)}
    base_image_references(dockerfile, build_args, "")
    base_image_references(dockerfile, build_args, fdp.ConsumeUnicodeNoSurrogates(32))


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
