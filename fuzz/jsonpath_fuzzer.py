#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Raw seeds are a UTF-8 path, a newline, then a JSON document.

Every input also builds a matching document/path pair to exercise successful
lookup and replacement, independently of whether the raw text parses.
"""

import copy
import json
import sys

import atheris

with atheris.instrument_imports(include=["hegemony_steps_http"]):
    from hegemony_steps_http.jsonpath import PathError, get_path, parse_path, replace_at


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    leaf = fdp.ConsumeUnicodeNoSurrogates(32)
    replacement = {"replacement": [42, None]}
    document = leaf
    expected = replacement
    path = ""
    for _ in range(fdp.ConsumeIntInRange(0, 8)):
        if fdp.ConsumeBool():
            key = f"key.{fdp.ConsumeIntInRange(0, 100)}"
            document = {key: document, "untouched": [1, None]}
            expected = {key: expected, "untouched": [1, None]}
            path = f'["{key}"]' + path
        else:
            document = ["untouched", document]
            expected = ["untouched", expected]
            path = ("[1]" if fdp.ConsumeBool() else "[-1]") + path
    parts = parse_path("$" + path)
    assert get_path(document, parts) == leaf
    assert replace_at(document, parts, replacement) == expected
    # A missing path must fail without modifying the document.
    before = copy.deepcopy(document)
    try:
        replace_at(document, ("missing",), replacement)
    except PathError:
        pass
    else:
        raise AssertionError("replacement accepted a missing path")
    assert document == before

    path_text, _, json_text = data[:16384].decode("utf-8", errors="replace").partition("\n")
    try:
        parts = parse_path(path_text)
    except PathError:
        return
    assert all(isinstance(part, (str, int)) for part in parts)
    try:
        document = json.loads(json_text)
    except (ValueError, RecursionError):
        return
    get_path(document, parts)
    try:
        replaced = replace_at(document, parts, replacement)
    except PathError:
        return
    assert get_path(replaced, parts) == replacement


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
