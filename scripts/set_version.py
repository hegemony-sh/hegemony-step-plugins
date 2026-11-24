# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Set the release version on every package except the SDK, and every SDK pin.

The SDK keeps its own version, which a pull request sets by hand
(scripts/sdk_version.py); each wheel's SDK requirement follows that version,
in the form its kind takes (CONVENTIONS.md, "Plugin kinds").
"""

from __future__ import annotations

import argparse
import re

from package_paths import PLUGIN_DIRS, RELEASE_DIRS, RUNNER_IMAGES
from sdk_version import read_sdk_version, write_pins

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


#: A dependency on another wheel of this monorepo other than the SDK (a tool
#: handler built on hegemony-steps-container, say), in a quoted dependency
#: string. They release in lockstep, so every such constraint (``==``, ``>=``, a range) becomes an
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


def _runner_image_tag(repository: str) -> re.Pattern[str]:
    """``repository:X.Y``, the tag that names a minor version.

    A sentence may end right after it, but a patch version (``:0.6.0``) is not it.
    """
    return re.compile(re.escape(repository) + r":\d+\.\d+(?!\.?\d)")


def set_runner_image_tag(text: str, version: str, repository: str) -> str:
    """``text`` with every ``repository:X.Y`` naming the minor version of ``version``."""
    minor = ".".join(version.split(".")[:2])
    return _runner_image_tag(repository).sub(f"{repository}:{minor}", text)


def _set_runner_image_tags(version: str) -> None:
    for image in RUNNER_IMAGES:
        for index, path in enumerate(image.files):
            text = path.read_text(encoding="utf-8")
            # The first file holds the step's default: losing it must not pass silently.
            if index == 0 and not _runner_image_tag(image.repository).search(text):
                raise SystemExit(f"Could not update {path}: {image.repository}:X.Y not found")
            path.write_text(set_runner_image_tag(text, version, image.repository), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="Release version without a leading v, e.g. 0.2.0")
    args = parser.parse_args()

    version = args.version.removeprefix("v")
    if not SEMVER.fullmatch(version):
        raise SystemExit(f"Invalid semver release version: {args.version}")

    for package_dir in RELEASE_DIRS:
        _set_project_version(package_dir / "pyproject.toml", version)
    for plugin_dir in PLUGIN_DIRS:
        _set_sibling_pins(plugin_dir / "pyproject.toml", version)
    write_pins(read_sdk_version())

    _set_runner_image_tags(version)


if __name__ == "__main__":
    main()
