#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fuzz the http.request path language: a path reads a value or fails with PathError.

The path comes from a flow author and the document from an HTTP response, so
neither may make the step fail with anything but its documented error.
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from hegemony_steps_http.jsonpath import PathError, get_path, parse_path, replace_at


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    path = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 512))
    try:
        parts = parse_path(path)
    except PathError:
        return
    assert all(isinstance(part, (str, int)) for part in parts)
    try:
        document = json.loads(fdp.ConsumeUnicodeNoSurrogates(4096))
    except (ValueError, RecursionError):
        # Not a document, or nested deeper than json.loads itself handles: the
        # standard library's limit, not the path language's.
        return
    found = get_path(document, parts)
    try:
        replaced = replace_at(document, parts, "fuzz")
    except PathError:
        return
    # A path that replace_at found, get_path must find too, at the new value.
    if parts:
        assert get_path(replaced, parts) == "fuzz", (path, found)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
