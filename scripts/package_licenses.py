# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Put the licence texts each wheel is under into that wheel.

Every package declares its licence as an SPDX expression (``license``) and
ships the matching texts through ``license-files`` (PEP 639), so an installed
wheel carries them under ``*.dist-info/licenses/``. A package may only name
files inside its own directory, so each holds a copy of the repository's
``LICENSES/<id>.txt`` as ``LICENSE-<id>.txt``, one per identifier in its
expression. REUSE skips files named ``LICENSE-*``.

Usage:
    python scripts/package_licenses.py           # write the copies
    python scripts/package_licenses.py --check   # fail when one is missing or stale
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

from package_paths import PACKAGE_DIRS, ROOT

LICENSE_FILES = ["LICENSE-*.txt"]


def license_ids(expression: str) -> list[str]:
    """The SPDX identifiers an expression names, operators and brackets dropped."""
    tokens = re.split(r"[\s()]+", expression)
    return sorted({t for t in tokens if t and t.upper() not in {"AND", "OR", "WITH"}})


def expected_files(package_dir: Path) -> tuple[dict[Path, Path], list[str]]:
    """``({copy: source text}, problems)`` for one package."""
    with (package_dir / "pyproject.toml").open("rb") as fh:
        project = tomllib.load(fh)["project"]
    name = package_dir.relative_to(ROOT)
    expression = project.get("license")
    if not isinstance(expression, str) or not expression.strip():
        return {}, [f"{name}/pyproject.toml: license must be an SPDX expression string"]
    problems: list[str] = []
    if project.get("license-files") != LICENSE_FILES:
        problems.append(f"{name}/pyproject.toml: license-files must be {LICENSE_FILES}")
    files: dict[Path, Path] = {}
    for license_id in license_ids(expression):
        source = ROOT / "LICENSES" / f"{license_id}.txt"
        if not source.is_file():
            problems.append(f"{name}: {license_id} has no text in LICENSES/")
            continue
        files[package_dir / f"LICENSE-{license_id}.txt"] = source
    return files, problems


def check() -> list[str]:
    """Every problem with the packages' licence files; empty when all are in place."""
    problems: list[str] = []
    for package_dir in PACKAGE_DIRS:
        files, package_problems = expected_files(package_dir)
        problems += package_problems
        for copy, source in files.items():
            if not copy.is_file() or copy.read_bytes() != source.read_bytes():
                problems.append(
                    f"{copy.relative_to(ROOT)} is missing or differs from "
                    f"{source.relative_to(ROOT)}"
                )
        for extra in sorted(package_dir.glob("LICENSE-*.txt")):
            if extra not in files:
                problems.append(
                    f"{extra.relative_to(ROOT)} names a licence the package does not declare"
                )
    return problems


def write() -> None:
    """Write every package's copies, and remove copies of licences it no longer declares."""
    for package_dir in PACKAGE_DIRS:
        files, _ = expected_files(package_dir)
        for extra in package_dir.glob("LICENSE-*.txt"):
            if extra not in files:
                extra.unlink()
        for copy, source in files.items():
            copy.write_bytes(source.read_bytes())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report, do not write")
    args = parser.parse_args(argv)
    if not args.check:
        write()
    problems = check()
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    if problems:
        print(
            "Package licence files are not in place; run "
            "`python scripts/package_licenses.py` and commit the result.",
            file=sys.stderr,
        )
        return 1
    print(f"Package licence files in place for {len(PACKAGE_DIRS)} packages")
    return 0


if __name__ == "__main__":
    sys.exit(main())
