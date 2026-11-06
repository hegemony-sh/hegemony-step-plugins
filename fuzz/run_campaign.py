# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Run bounded fuzzing, minimize the corpus, and report Python branch coverage.

Only a successful campaign should save the resulting corpus to a shared cache.
Failures remain nonzero and their reproducer files are kept separately.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from seed_corpus import seed_corpus


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=600)
    args = parser.parse_args()
    if args.seconds < 0:
        parser.error("--seconds must be nonnegative")
    corpus_root = Path("build/fuzz-corpus")
    reports = Path("build/fuzz-coverage")
    reports.mkdir(parents=True, exist_ok=True)
    seed_corpus(corpus_root)
    run_env = dict(
        os.environ, PATH=str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")
    )
    failed = False
    for target in sorted(Path("fuzz").glob("*_fuzzer.py")):
        corpus = corpus_root / target.stem
        crashes = Path("build/fuzz-crashes") / target.stem
        crashes.mkdir(parents=True, exist_ok=True)
        command = [sys.executable, str(target)]
        options = ["-max_len=16384", "-timeout=10", f"-artifact_prefix={crashes}/"]
        if args.seconds:
            result = subprocess.run(
                [*command, str(corpus), *options, f"-max_total_time={args.seconds}"],
                check=False,
                env=run_env,
            )
            failed |= result.returncode != 0
            # Merge keeps only inputs that add coverage; replace only on success.
            minimized = corpus_root / (target.stem + ".minimized")
            minimized.mkdir(exist_ok=True)
            result = subprocess.run(
                [*command, "-merge=1", str(minimized), str(corpus), *options],
                check=False,
                env=run_env,
            )
            if result.returncode == 0 and any(minimized.iterdir()):
                shutil.rmtree(corpus)
                minimized.rename(corpus)
            else:
                failed = True
                shutil.rmtree(minimized)
        # Always replay seeds too: minimization preserves coverage, not every
        # semantic regression. Keep these explicit cases on every run.
        seed_corpus(corpus_root)
        env = dict(os.environ, COVERAGE_FILE=str(reports / (".coverage." + target.stem)))
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--branch",
                "--source=hegemony_steps_http.jsonpath,hegemony_steps_http.request,hegemony_steps_container.base_images",
                "fuzz/replay_corpus.py",
                str(target),
                str(corpus),
            ],
            env=env,
            check=False,
        )
        failed |= result.returncode != 0
    env = dict(os.environ, COVERAGE_FILE=str(reports / ".coverage"))
    for arguments in (
        ["combine", str(reports)],
        ["report", "--show-missing"],
        ["html", "-d", str(reports / "html")],
        ["json", "-o", str(reports / "coverage.json")],
    ):
        subprocess.run([sys.executable, "-m", "coverage", *arguments], env=env, check=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
