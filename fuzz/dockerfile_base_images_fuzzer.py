#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fuzz container.build's Dockerfile reader, which finds the base images to resolve.

The Dockerfile is the flow author's, and the reader is documented to never
fail: whatever it cannot follow, it leaves to BuildKit.
"""

import sys

import atheris

with atheris.instrument_imports():
    from hegemony_steps_container.base_images import base_image_references


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 16))
    build_args = {
        fdp.ConsumeUnicodeNoSurrogates(8): fdp.ConsumeUnicodeNoSurrogates(32)
        for _ in range(fdp.ConsumeIntInRange(0, 3))
    }
    dockerfile = fdp.ConsumeUnicodeNoSurrogates(8192)
    references = base_image_references(dockerfile, build_args, target)
    assert all(isinstance(reference, str) and reference for reference in references)
    assert len(references) == len(set(references)), references


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
