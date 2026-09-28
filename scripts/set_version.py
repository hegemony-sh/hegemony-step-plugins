# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Set the unified release version across all workspace packages."""

from __future__ import annotations

import argparse
import re

from package_paths import (
    PACKAGE_DIRS,
    PLUGIN_DIRS,
    RUNNER_IMAGE,
    RUNNER_IMAGE_FILES,
    SDK_VERSION_FILE,
)

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


#: A dependency on another wheel of this monorepo (a tool handler built on
#: hegemony-steps-container, say), in a quoted dependency string. They release
#: in lockstep, so every such constraint (``==``, ``>=``, a range) becomes an
#: exact pin on the version; an environment marker after it is kept, and a
#: pyproject without one is left alone. The constraint is required, so a bare
#: name (``name = "hegemony-steps-tf"``) and a ``[tool.uv.sources]`` key never
#: match.
SIBLING_PIN = re.compile(
    r'"(hegemony[-_.](?:steps|probe|transport)[-_.][a-z0-9._-]+\s*(?:\[[^\]"]*\])?)\s*'
    r'(?:===|==|>=|<=|~=|!=|>|<)[^";]*',
    re.IGNORECASE,
)


def set_sibling_pins(text: str, version: str) -> str:
    """``text`` (a pyproject) with every sibling-wheel constraint pinned to ``version``."""
    return SIBLING_PIN.sub(lambda match: f'"{match.group(1).rstrip()}=={version}', text)


def _set_sibling_pins(pyproject, version: str) -> None:
    text = pyproject.read_text(encoding="utf-8")
    pyproject.write_text(set_sibling_pins(text, version), encoding="utf-8")


#: The default execution image with its tag, which names a minor version.
#: A sentence may end right after it, but a patch version (``:0.6.0``) is not it.
RUNNER_IMAGE_TAG = re.compile(re.escape(RUNNER_IMAGE) + r":\d+\.\d+(?!\.?\d)")


def set_runner_image_tag(text: str, version: str) -> str:
    """``text`` with every ``RUNNER_IMAGE:X.Y`` naming the minor version of ``version``."""
    minor = ".".join(version.split(".")[:2])
    return RUNNER_IMAGE_TAG.sub(f"{RUNNER_IMAGE}:{minor}", text)


def _set_runner_image_tags(version: str) -> None:
    for index, path in enumerate(RUNNER_IMAGE_FILES):
        text = path.read_text(encoding="utf-8")
        # The first file defines DEFAULT_IMAGE: losing that line must not pass silently.
        if index == 0 and not RUNNER_IMAGE_TAG.search(text):
            raise SystemExit(f"Could not update {path}: {RUNNER_IMAGE}:X.Y not found")
        path.write_text(set_runner_image_tag(text, version), encoding="utf-8")


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

    _set_runner_image_tags(version)


if __name__ == "__main__":
    main()
