# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Dependency direction between the workspace packages.

steps → hegemony-step-sdk ← hegemony-transport-support ← transports

The SDK is the contract only, so it imports no transport and not the
transports' shared code. Step plugins build on the SDK alone, so they import
no transport and not ``hegemony_transport_support``. No transport imports
another transport. Imports anywhere in a module count, including ones inside
functions and ``TYPE_CHECKING`` blocks.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "packages" / "step_sdk"
SUPPORT = ROOT / "packages" / "transport_support"
PLUGINS = sorted(path for path in (ROOT / "plugins").iterdir() if (path / "src").is_dir())
TRANSPORTS = sorted(path for path in (ROOT / "transports").iterdir() if (path / "src").is_dir())

SUPPORT_MODULE = "hegemony_transport_support"
SUPPORT_DIST = "hegemony-transport-support"


def imported_modules(package_dir: Path) -> dict[str, set[str]]:
    """Top-level module name -> the source files of ``package_dir`` that import it."""
    found: dict[str, set[str]] = {}
    for path in sorted((package_dir / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            else:
                continue
            for name in names:
                found.setdefault(name.split(".")[0], set()).add(str(path.relative_to(ROOT)))
    return found


def transport_imports(package_dir: Path, *, allowed: frozenset[str] = frozenset()) -> list[str]:
    """``module in file`` for each ``hegemony_transport_*`` import not in ``allowed``."""
    return sorted(
        f"{module} in {file}"
        for module, files in imported_modules(package_dir).items()
        if module.startswith("hegemony_transport_") and module not in allowed
        for file in files
    )


def dependency_names(package_dir: Path) -> set[str]:
    """Normalized distribution names ``package_dir``'s pyproject depends on."""
    with (package_dir / "pyproject.toml").open("rb") as fh:
        project = tomllib.load(fh)["project"]
    requirements = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        requirements += extra
    names = set()
    for requirement in requirements:
        name = requirement.split(";")[0].split("[")[0]
        for separator in "=<>!~ ":
            name = name.split(separator)[0]
        names.add(name.strip().lower().replace("_", "-").replace(".", "-"))
    return names


def module_name(package_dir: Path) -> str:
    """The import name a workspace package's wheel ships."""
    with (package_dir / "pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["tool"]["uv"]["build-backend"]["module-name"]


def test_scanner_sees_the_transports_imports():
    """The checks below would pass vacuously if the scanner missed imports."""
    for transport in TRANSPORTS:
        assert SUPPORT_MODULE in imported_modules(transport), transport.name
    assert "hegemony_step_sdk" in imported_modules(SUPPORT)
    assert PLUGINS and len(TRANSPORTS) >= 3


def test_sdk_imports_no_transport_code():
    assert transport_imports(SDK) == []
    assert not {name for name in dependency_names(SDK) if name.startswith("hegemony-")}


@pytest.mark.parametrize("plugin", PLUGINS, ids=lambda path: path.name)
def test_step_plugins_import_no_transport_code(plugin):
    assert transport_imports(plugin) == []
    assert not {name for name in dependency_names(plugin) if name.startswith("hegemony-transport-")}


def test_transport_support_imports_no_transport():
    assert transport_imports(SUPPORT, allowed=frozenset({SUPPORT_MODULE})) == []
    assert dependency_names(SUPPORT) == {"hegemony-step-sdk"}


@pytest.mark.parametrize("transport", TRANSPORTS, ids=lambda path: path.name)
def test_transports_import_no_other_transport(transport):
    own = module_name(transport)
    assert transport_imports(transport, allowed=frozenset({own, SUPPORT_MODULE})) == []
    # A transport that uses the shared code declares it, so its wheel installs it.
    if SUPPORT_MODULE in imported_modules(transport):
        assert SUPPORT_DIST in dependency_names(transport)
