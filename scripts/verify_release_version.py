# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify a release tag matches every package version, SDK pin, sibling-wheel pin, and image tag."""

from __future__ import annotations

import argparse
import os
import re
import tomllib

from package_paths import (
    PACKAGE_DIRS,
    PLUGIN_DIRS,
    RUNNER_IMAGE,
    RUNNER_IMAGE_FILES,
    SDK_VERSION_FILE,
)

#: A requirement's name, extras and version constraint (markers split off first).
REQUIREMENT = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)")
#: Another wheel of this monorepo, by normalized name: they release in
#: lockstep, so each must be pinned exactly, whatever its constraint says.
SIBLING_NAME = re.compile(r"hegemony-(?:steps|probe|transport)-[a-z0-9-]+")


def sibling_pin_failure(package: str, dependency: str, version: str) -> str | None:
    """Why ``dependency`` of ``package`` is not an exact pin on ``version``, if it is a sibling."""
    match = REQUIREMENT.fullmatch(dependency.split(";", 1)[0].strip())
    if match is None:
        return None
    name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
    if not SIBLING_NAME.fullmatch(name) or "".join(match.group(3).split()) == f"=={version}":
        return None
    return f"{package} must pin {name}=={version}, not {dependency}"


def runner_image_failures(path, text: str, version: str) -> list[str]:
    """Why ``text`` (one of RUNNER_IMAGE_FILES) names a runner image tag other than ``version``'s X.Y."""
    minor = ".".join(version.split(".")[:2])
    tags = re.findall(re.escape(RUNNER_IMAGE) + r":([0-9][0-9.]*[0-9])", text)
    return [
        f"{path} names {RUNNER_IMAGE}:{tag}, expected {RUNNER_IMAGE}:{minor}"
        for tag in sorted(set(tags))
        if tag != minor
    ]


def _project_metadata(pyproject) -> dict:
    return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "tag",
        nargs="?",
        default=os.environ.get("GITHUB_REF_NAME", ""),
        help="Release tag, usually vX.Y.Z",
    )
    args = parser.parse_args()
    version = args.tag.removeprefix("v")
    if not version:
        raise SystemExit("Release tag is required")

    failures: list[str] = []

    for package_dir in PACKAGE_DIRS:
        metadata = _project_metadata(package_dir / "pyproject.toml")
        if metadata["version"] != version:
            failures.append(
                f"{metadata['name']} version is {metadata['version']}, expected {version}"
            )

    expected_sdk_dependency = f"hegemony-step-sdk=={version}"
    for plugin_dir in PLUGIN_DIRS:
        metadata = _project_metadata(plugin_dir / "pyproject.toml")
        if expected_sdk_dependency not in metadata["dependencies"]:
            failures.append(f"{metadata['name']} must depend on {expected_sdk_dependency}")
        # Pins on sibling wheels of this monorepo release in lockstep too.
        for dependency in metadata["dependencies"]:
            failure = sibling_pin_failure(metadata["name"], dependency, version)
            if failure:
                failures.append(failure)

    sdk_version_text = SDK_VERSION_FILE.read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', sdk_version_text, re.MULTILINE)
    if match is None or match.group(1) != version:
        failures.append(f"{SDK_VERSION_FILE} __version__ must be {version}")

    for path in RUNNER_IMAGE_FILES:
        text = path.read_text(encoding="utf-8")
        failures.extend(runner_image_failures(path, text, version))
    default_image = re.search(
        r'^DEFAULT_IMAGE = "([^"]+)"$',
        RUNNER_IMAGE_FILES[0].read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if default_image is None or not default_image.group(1).startswith(f"{RUNNER_IMAGE}:"):
        failures.append(f"{RUNNER_IMAGE_FILES[0]} must set DEFAULT_IMAGE to {RUNNER_IMAGE}:X.Y")

    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
