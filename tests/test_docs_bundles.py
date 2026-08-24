# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The plugin-owned documentation contract, enforced under plain pytest.

Two halves: unit tests for :mod:`hegemony_step_sdk.docs` (the loader whose
strictness *is* the contract), and one test that runs the repo-wide gate in
``scripts/check_docs.py`` so a missing page, an undocumented config field,
or a stale README fails the ordinary test run - not just ``task docs:check``.
"""

from __future__ import annotations

import importlib
import shutil
import sys
from pathlib import Path

import pytest

from hegemony_step_sdk.docs import (
    MAX_PAGE_BYTES,
    DocsBundleError,
    load_docs_bundle,
)

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


@pytest.fixture
def synthetic_package(tmp_path, monkeypatch):
    """An importable throwaway package whose docs/ the test controls."""
    pkg = tmp_path / "fake_steps_plugin"
    (pkg / "docs").mkdir(parents=True)
    (pkg / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    yield pkg
    sys.modules.pop("fake_steps_plugin", None)


def test_valid_bundle_loads_sorted(synthetic_package):
    (synthetic_package / "docs" / "fake.two.md").write_text("# Two\n", encoding="utf-8")
    (synthetic_package / "docs" / "fake.one.md").write_text("# One\n", encoding="utf-8")
    bundle = load_docs_bundle("fake_steps_plugin")
    assert list(bundle) == ["fake.one", "fake.two"]
    assert bundle["fake.one"] == "# One\n"


def test_missing_docs_dir_is_an_empty_bundle(synthetic_package):
    """Absence is not an error - wheels predating the contract keep working."""
    shutil.rmtree(synthetic_package / "docs")
    assert load_docs_bundle("fake_steps_plugin") == {}


@pytest.mark.parametrize(
    ("setup", "fragment"),
    [
        (lambda d: (d / "sub").mkdir(), "bundles are flat"),
        (lambda d: (d / "notes.txt").write_text("x", encoding="utf-8"), "not a Markdown page"),
        (lambda d: (d / "Bad_Id.md").write_text("x", encoding="utf-8"), "invalid doc id"),
        (
            lambda d: (d / "fake.big.md").write_bytes(b"x" * (MAX_PAGE_BYTES + 1)),
            "page cap",
        ),
        (lambda d: (d / "fake.bin.md").write_bytes(b"\xff\xfe"), "not valid UTF-8"),
        (lambda d: (d / "fake.nul.md").write_bytes(b"# x\x00"), "NUL byte"),
    ],
    ids=["subdir", "non-md", "bad-id", "oversized", "bad-utf8", "nul"],
)
def test_contract_violations_raise(synthetic_package, setup, fragment):
    setup(synthetic_package / "docs")
    with pytest.raises(DocsBundleError, match=fragment):
        load_docs_bundle("fake_steps_plugin")


def test_every_real_plugin_satisfies_the_contract(monkeypatch, capsys):
    """The repo-wide gate: pages 1:1 with handlers, field docs, READMEs."""
    monkeypatch.syspath_prepend(str(SCRIPTS))
    check_docs = importlib.import_module("check_docs")
    exit_code = check_docs.main()
    if exit_code != 0:
        pytest.fail("scripts/check_docs.py found violations:\n" + capsys.readouterr().err)
