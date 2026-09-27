# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Set the unified release version across all workspace packages."""

from __future__ import annotations

import argparse
import re

from package_paths import PACKAGE_DIRS, PLUGIN_DIRS, SDK_VERSION_FILE

SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[a-zA-Z0-9.+-]+)?$")


def _replace(pattern: str, replacement: str, text: str, *, path: str) -> str:
    next_text, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"Could not update {path}: pattern not found")
    return next_text


def _set_project_version(pyproject, version: str) -> None:
    text = pyproject.read_text(encoding="utf-8")
    text = _replace(
        r'^version = "[^"]+"$',
        f'version = "{version}"',
        text,
        path=str(pyproject),
    )
    pyproject.write_text(text, encoding="utf-8")


def _set_plugin_sdk_pin(pyproject, version: str) -> None:
    text = pyproject.read_text(encoding="utf-8")
    text = _replace(
        r"hegemony-step-sdk(?:==|>=)[^\",<\]]*(?:,<\d+\.\d+(?:\.\d+)?)?",
        f"hegemony-step-sdk=={version}",
        text,
        path=str(pyproject),
    )
    pyproject.write_text(text, encoding="utf-8")


#: A pin on another wheel of this monorepo (a tool handler built on
#: hegemony-steps-container, say). They release in lockstep, so every such pin
#: moves with the version; a pyproject without one is left alone.
SIBLING_PIN = re.compile(r"(hegemony-(?:steps|probe|transport)-[a-z0-9-]+)==[^\",\]]+")


def _set_sibling_pins(pyproject, version: str) -> None:
    text = pyproject.read_text(encoding="utf-8")
    pyproject.write_text(SIBLING_PIN.sub(rf"\g<1>=={version}", text), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="Release version without a leading v, e.g. 0.2.0")
    args = parser.parse_args()

    version = args.version.removeprefix("v")
    if not SEMVER.fullmatch(version):
        raise SystemExit(f"Invalid semver release version: {args.version}")

    for package_dir in PACKAGE_DIRS:
        _set_project_version(package_dir / "pyproject.toml", version)
    for plugin_dir in PLUGIN_DIRS:
        _set_plugin_sdk_pin(plugin_dir / "pyproject.toml", version)
        _set_sibling_pins(plugin_dir / "pyproject.toml", version)

    text = SDK_VERSION_FILE.read_text(encoding="utf-8")
    text = _replace(
        r'^__version__ = "[^"]+"$',
        f'__version__ = "{version}"',
        text,
        path=str(SDK_VERSION_FILE),
    )
    SDK_VERSION_FILE.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
