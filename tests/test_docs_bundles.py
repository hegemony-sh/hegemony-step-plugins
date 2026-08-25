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
    MAX_BUNDLE_BYTES,
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
        (
            # Every page individually at the cap, but their sum over the
            # bundle cap.
            lambda d: [
                (d / f"fake.part{i}.md").write_bytes(b"x" * MAX_PAGE_BYTES)
                for i in range(MAX_BUNDLE_BYTES // MAX_PAGE_BYTES + 1)
            ],
            "bundle exceeds",
        ),
        (
            lambda d: (shutil.rmtree(d), d.write_text("x", encoding="utf-8")),
            "not a directory",
        ),
    ],
    ids=["subdir", "non-md", "bad-id", "oversized", "bad-utf8", "nul", "bundle-cap", "docs-file"],
)
def test_contract_violations_raise(synthetic_package, setup, fragment):
    setup(synthetic_package / "docs")
    with pytest.raises(DocsBundleError, match=fragment):
        load_docs_bundle("fake_steps_plugin")


_PAGE_HEADER = (
    "<!--\nSPDX-FileCopyrightText: 2026 Test\n\nSPDX-License-Identifier: AGPL-3.0-or-later\n-->\n"
)


@pytest.fixture
def check_docs(monkeypatch):
    """The gate module, importable from its scripts/ home."""
    monkeypatch.syspath_prepend(str(SCRIPTS))
    return importlib.import_module("check_docs")


def test_check_page_flags_raw_html_with_attributes(check_docs):
    """An attributed tag is still raw HTML the renderer drops."""
    page = _PAGE_HEADER + '\n# Thing\n\nThe `x` handler; see <a href="https://e.example"> it.\n'
    problems = check_docs.check_page("pkg", "x", page)
    assert any("raw HTML" in p for p in problems), problems


def test_check_page_flags_non_https_reference_link_definitions(check_docs):
    """`[name]: destination` renders a link too - same https-only contract."""
    page = (
        _PAGE_HEADER
        + "\n# Thing\n\nThe `x` handler; see [docs][ref].\n\n[ref]: http://example.com\n"
    )
    problems = check_docs.check_page("pkg", "x", page)
    assert any("link definition" in p for p in problems), problems


def test_check_page_ignores_h1_lookalikes_in_fences(check_docs):
    """A shell comment inside a fence is not a second H1."""
    page = _PAGE_HEADER + "\n# Thing\n\nThe `x` handler.\n\n```sh\n# just a comment\nls\n```\n"
    assert check_docs.check_page("pkg", "x", page) == []


def test_check_page_accepts_tilde_fences_and_bracketed_definitions(check_docs):
    """Tilde fences are code too, and CommonMark brackets are a valid destination."""
    page = (
        _PAGE_HEADER
        + "\n# Thing\n\nThe `x` handler; see [docs][ref].\n\n~~~sh\n# just a comment\n~~~\n\n"
        + "[ref]: <https://example.com>\n"
    )
    assert check_docs.check_page("pkg", "x", page) == []


def test_check_page_flags_non_https_autolinks(check_docs):
    """An autolink renders as a link, so it obeys the same https-only contract."""
    page = _PAGE_HEADER + "\n# Thing\n\nThe `x` handler; see <http://example.com>.\n"
    problems = check_docs.check_page("pkg", "x", page)
    assert any("autolink" in p for p in problems), problems


def test_every_real_plugin_satisfies_the_contract(monkeypatch, capsys):
    """The repo-wide gate: pages 1:1 with handlers, field docs, READMEs."""
    monkeypatch.syspath_prepend(str(SCRIPTS))
    check_docs = importlib.import_module("check_docs")
    exit_code = check_docs.main()
    if exit_code != 0:
        pytest.fail("scripts/check_docs.py found violations:\n" + capsys.readouterr().err)
