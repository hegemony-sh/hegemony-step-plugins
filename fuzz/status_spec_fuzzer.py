#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Fuzz raw status specs and compare generated valid specs with a set oracle."""

import sys

import atheris

with atheris.instrument_imports(include=["hegemony_steps_http"]):
    from hegemony_steps_http.request import parse_status_spec, status_matches


@atheris.instrument_func
def test_one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    entries = []
    expected = set()
    for _ in range(fdp.ConsumeIntInRange(1, 6)):
        low = fdp.ConsumeIntInRange(100, 599)
        high = fdp.ConsumeIntInRange(low, 599)
        entries.append(str(low) if low == high else f"{low}-{high}")
        expected.update(range(low, high + 1))
    ranges = parse_status_spec(" , ".join(entries))
    actual = {status for low, high in ranges for status in range(low, high + 1)}
    assert actual == expected
    for status in (99, 100, 599, 600, fdp.ConsumeIntInRange(98, 601)):
        assert status_matches(status, ranges) == (status in expected)

    spec = data[:16384].decode("utf-8", errors="replace")
    try:
        ranges = parse_status_spec(spec)
    except ValueError:
        return
    assert ranges
    expected = set()
    for low, high in ranges:
        assert 100 <= low <= high <= 599, (spec, ranges)
        expected.update(range(low, high + 1))
        assert status_matches(low, ranges)
        assert status_matches(high, ranges)
    status = fdp.ConsumeIntInRange(98, 601)
    assert status_matches(status, ranges) == (status in expected)
    assert not status_matches(99, ranges)
    assert not status_matches(600, ranges)


if __name__ == "__main__":
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
