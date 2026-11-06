# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Generate readable seeds, including large boundary cases, into a corpus root."""

import hashlib
import sys
from pathlib import Path

SEEDS = {
    "jsonpath_fuzzer": [
        '$\n{"a": null}',
        'a[1].b\n{"a": [null, {"b": 42}]}',
        '["a.b"][-1]\n{"a.b": [1, 2]}',
        "missing\n{}",
        "a[\n{}",
        "[" + "9" * 5000 + "]\n[]",
        '["' + "9" * 5000 + '"]\n[]',
        "$\n" + "[" * 1100 + "0" + "]" * 1100,
    ],
    "dockerfile_base_images_fuzzer": [
        "FROM alpine\n",
        "ARG VERSION=3.20\nFROM alpine:${VERSION} AS base\nFROM busybox\nCOPY --from=base /x /y\n",
        "FROM alpine\nCOPY --from=² /x /y\n",
        "FROM alpine\nRUN --mount=from=² true\n",
        "FROM alpine\nCOPY --from=" + "9" * 5000 + " /x /y\n",
        "FROM alpine\nRUN --mount=from=" + "9" * 5000 + " true\n",
        "FROM alpine\nFROM busybox\nCOPY --from=" + "0" * 5000 + " /x /y\n",
        "FROM --platform=linux/arm64 alpine AS arm\nFROM alpine\nCOPY --from=arm /x /y\n",
    ],
    "status_spec_fuzzer": [
        "200-299,304",
        "100,599",
        "99",
        "600",
        "299-200",
        "200-205,203-210",
        " , 200 , ",
        "²",
        "9" * 5000,
    ],
}


def seed_corpus(root: Path) -> None:
    for name, seeds in SEEDS.items():
        directory = root / name
        directory.mkdir(parents=True, exist_ok=True)
        for seed in seeds:
            data = seed.encode("utf-8")
            (directory / hashlib.sha256(data).hexdigest()).write_bytes(data)


if __name__ == "__main__":
    seed_corpus(Path(sys.argv[1]))
