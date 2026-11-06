#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fuzz http.request's expected-status spec (``200-299,304``).

A spec either parses into valid HTTP status ranges or fails with ValueError,
which the step reports as a configuration error.
"""

import sys

import atheris

with atheris.instrument_imports():
    from hegemony_steps_http.request import parse_status_spec, status_matches


def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    spec = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))
    try:
        ranges = parse_status_spec(spec)
    except ValueError:
        return
    assert ranges
    for low, high in ranges:
        assert 100 <= low <= high <= 599, (spec, ranges)
        assert status_matches(low, ranges)
        assert status_matches(high, ranges)
    assert not status_matches(99, ranges)
    assert not status_matches(600, ranges)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
