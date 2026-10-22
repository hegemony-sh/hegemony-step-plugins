# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Every wheel carries the texts of the licences its expression names.

``scripts/package_licenses.py`` keeps a copy of ``LICENSES/<id>.txt`` in each
package, which ``license-files`` puts into the wheel. The repository must pass
its check; the rest pins what the check refuses, on packages built here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


def _script():
    sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(
        "package_licenses", SCRIPTS / "package_licenses.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


licenses = _script()


def test_every_package_carries_its_licence_texts():
    assert licenses.check() == []


@pytest.mark.parametrize(
    ("expression", "ids"),
    [
        ("AGPL-3.0-or-later", ["AGPL-3.0-or-later"]),
        ("AGPL-3.0-or-later AND MIT", ["AGPL-3.0-or-later", "MIT"]),
        ("(MIT OR Apache-2.0) AND BSD-3-Clause", ["Apache-2.0", "BSD-3-Clause", "MIT"]),
    ],
)
def test_license_ids(expression, ids):
    assert licenses.license_ids(expression) == ids


def _package(root: Path, name: str, pyproject_license: str) -> Path:
    package = root / name
    package.mkdir()
    (package / "pyproject.toml").write_text(f'[project]\nname = "{name}"\n{pyproject_license}\n')
    return package


def test_the_check_refuses_missing_stale_and_undeclared_copies(tmp_path, monkeypatch):
    (tmp_path / "LICENSES").mkdir()
    (tmp_path / "LICENSES" / "AGPL-3.0-or-later.txt").write_text("agpl")
    (tmp_path / "LICENSES" / "MIT.txt").write_text("mit")
    fine = _package(
        tmp_path, "fine", 'license = "AGPL-3.0-or-later"\nlicense-files = ["LICENSE-*.txt"]'
    )
    stale = _package(
        tmp_path, "stale", 'license = "AGPL-3.0-or-later"\nlicense-files = ["LICENSE-*.txt"]'
    )
    old_form = _package(tmp_path, "old_form", 'license = { text = "AGPL-3.0-or-later" }')
    no_files = _package(tmp_path, "no_files", 'license = "MIT"')
    unknown = _package(
        tmp_path, "unknown", 'license = "BSD-3-Clause"\nlicense-files = ["LICENSE-*.txt"]'
    )
    monkeypatch.setattr(licenses, "ROOT", tmp_path)
    monkeypatch.setattr(licenses, "PACKAGE_DIRS", (fine, stale, old_form, no_files, unknown))

    licenses.write()
    assert (fine / "LICENSE-AGPL-3.0-or-later.txt").read_text() == "agpl"
    (stale / "LICENSE-AGPL-3.0-or-later.txt").write_text("edited")
    (stale / "LICENSE-MIT.txt").write_text("mit")

    problems = licenses.check()
    assert problems == [
        "stale/LICENSE-AGPL-3.0-or-later.txt is missing or differs from "
        + "LICENSES/AGPL-3.0-or-later.txt",
        "stale/LICENSE-MIT.txt names a licence the package does not declare",
        "old_form/pyproject.toml: license must be an SPDX expression string",
        "no_files/pyproject.toml: license-files must be ['LICENSE-*.txt']",
        "unknown: BSD-3-Clause has no text in LICENSES/",
    ]

    # Writing again restores the copy and drops the undeclared one.
    licenses.write()
    assert (stale / "LICENSE-AGPL-3.0-or-later.txt").read_text() == "agpl"
    assert not (stale / "LICENSE-MIT.txt").exists()
