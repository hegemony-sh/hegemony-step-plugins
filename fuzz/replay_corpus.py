# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Replay all corpus files once, including seeds, for regressions and coverage."""

import itertools
import runpy
import sys
import traceback
from pathlib import Path

if __name__ == "__main__":
    target, corpus = sys.argv[1:]
    callback = runpy.run_path(target)["test_one_input"]
    failed = False
    inputs = itertools.chain(
        [("<empty input>", b"")],
        (
            (str(path), path.read_bytes())
            for path in sorted(Path(corpus).iterdir())
            if path.is_file()
        ),
    )
    for name, data in inputs:
        try:
            callback(data)
        except Exception:
            print(f"Corpus input failed: {name}", file=sys.stderr, flush=True)
            traceback.print_exc()
            failed = True
    raise SystemExit(int(failed))
