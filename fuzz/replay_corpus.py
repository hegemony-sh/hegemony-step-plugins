# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Replay all corpus files once, including seeds, for regressions and coverage."""

import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    target, corpus = sys.argv[1:]
    callback = runpy.run_path(target)["test_one_input"]
    callback(b"")
    for path in sorted(Path(corpus).iterdir()):
        if path.is_file():
            callback(path.read_bytes())
