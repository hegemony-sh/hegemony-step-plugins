# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Verify a release tag matches every package version, sibling-wheel pin, and image tag.

The SDK has its own version (scripts/sdk_version.py): it must agree with its
ABI version, every wheel must pin it in the form its kind takes, and it must
be the version the SDK's change since the previous release needs.

Also that a patch release keeps the series (X.Y) of every tool the steps run
by default: a new one is a change of behaviour for every flow on the default
image, so it needs a minor release. Likewise it keeps every series a step can
choose: a flow that names one would have no image after the upgrade.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tomllib
from collections.abc import Callable

import sdk_version
from package_paths import (
    BUNDLED_TOOLS,
    PLUGIN_DIRS,
    RELEASE_DIRS,
    ROOT,
    RUNNER_IMAGES,
)

#: A requirement's name, extras and version constraint (markers split off first).
REQUIREMENT = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)")
#: Another wheel of this monorepo, by normalized name, apart from the SDK: they
#: release in lockstep, so each must be pinned exactly, whatever its
#: constraint says.
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


def runner_image_failures(path, text: str, version: str, repository: str) -> list[str]:
    """Why ``text`` names a ``repository`` tag other than ``version``'s X.Y."""
    minor = ".".join(version.split(".")[:2])
    tags = re.findall(re.escape(repository) + r":([0-9][0-9.]*[0-9])", text)
    return [
        f"{path} names {repository}:{tag}, expected {repository}:{minor}"
        for tag in sorted(set(tags))
        if tag != minor
    ]


def default_image_failure(image) -> str | None:
    """Why the step that ``image`` is the default of does not name it."""
    default = re.search(
        image.default_pattern, image.files[0].read_text(encoding="utf-8"), re.MULTILINE
    )
    if default is None or not default.group(1).startswith(f"{image.repository}:"):
        return f"{image.files[0]} must default to {image.repository}:X.Y"
    return None


def tool_series(tool, text: str) -> str | None:
    """The series (X.Y) of ``tool`` that ``text``, its source file, sets."""
    match = re.search(tool.pattern, text, re.MULTILINE)
    return match.group(1) if match else None


def tool_docs_failures(tool, series: str) -> list[str]:
    """The files that should state ``<name> <series>`` and do not.

    The whole series: a file stating 1.12 does not state 1.1.
    """
    stated = re.compile(re.escape(f"{tool.name} {series}") + r"(?!\d)")
    return [
        f"{path.relative_to(ROOT)} must state {tool.name} {series} (set in {tool.source})"
        for path in tool.files
        if not stated.search(path.read_text(encoding="utf-8"))
    ]


def previous_patch_tag(version: str, tags: list[str]) -> str | None:
    """The newest release tag of ``version``'s minor before it; None for X.Y.0.

    Also None for a version that is not X.Y.Z, which the other checks refuse.
    """
    match = re.fullmatch(r"(\d+\.\d+)\.(\d+)", version)
    if match is None:
        return None
    minor, patch = match.group(1), int(match.group(2))
    release = re.compile(r"v" + re.escape(minor) + r"\.(\d+)")
    earlier = [
        int(found.group(1))
        for tag in tags
        if (found := release.fullmatch(tag.strip())) and int(found.group(1)) < patch
    ]
    return f"v{minor}.{max(earlier)}" if earlier else None


def tool_series_failures(
    version: str, previous_tag: str | None, read_at: Callable[[str, str], str | None]
) -> list[str]:
    """Why ``version`` may not be released with the tools the tree sets.

    ``previous_tag`` is the release it follows within its minor (None: there
    is none to compare with), and ``read_at(tag, path)`` a file's text at a
    tag, or None when the tag has no such file.
    """
    failures: list[str] = []
    for tool in BUNDLED_TOOLS:
        series = tool_series(tool, (ROOT / tool.source).read_text(encoding="utf-8"))
        if series is None:
            failures.append(f"{tool.source} no longer sets the {tool.name} version")
            continue
        if previous_tag is None:
            continue
        before_text = read_at(previous_tag, tool.source)
        # A tool the previous release did not have is new, not moved.
        before = tool_series(tool, before_text) if before_text is not None else None
        if before is not None and before != series:
            failures.append(
                f"{tool.source} moves {tool.name} from {before} ({previous_tag}) to {series}, "
                f"but {version} is a patch release: a new default tool version needs a "
                "minor release, so commit that change as feat (CONTRIBUTING.md, Releasing)"
            )
    return failures


def variant_series(tool, text: str) -> tuple[str, list[str]] | None:
    """The default series and every series ``text``, the tool's variants.json, publishes."""
    try:
        data = json.loads(text)
        return str(data["default"]), sorted(str(series) for series in data["variants"])
    except (ValueError, KeyError, TypeError):
        return None


def variant_failures(tool) -> list[str]:
    """Why the tool's variants disagree with its Dockerfile, its step or its docs."""
    if tool.variants is None:
        return []
    read = variant_series(tool, (ROOT / tool.variants).read_text(encoding="utf-8"))
    if read is None:
        return [f"{tool.variants} must name a default and its variants"]
    default, series = read
    failures: list[str] = []
    if default not in series:
        failures.append(f"{tool.variants} names the default {default}, which it does not publish")
    built = tool_series(tool, (ROOT / tool.source).read_text(encoding="utf-8"))
    if built != default:
        failures.append(
            f"{tool.source} builds {tool.name} {built} by default, "
            f"but {tool.variants} names {default}"
        )
    choice = re.search(
        rf"^{re.escape(tool.choice)} = Literal\[([^\]]*)\]$",
        tool.variant_files[0].read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    offered = re.findall(r'"([^"]*)"', choice.group(1)) if choice else []
    if offered != ["default", *series]:
        failures.append(
            f"{tool.variant_files[0].relative_to(ROOT)} must offer exactly the series of "
            f"{tool.variants}: {tool.choice} = Literal[{', '.join(['default', *series])}]"
        )
    for one in series:
        stated = re.compile(r"(?<![\d.])" + re.escape(one) + r"(?![\d.]\d)")
        failures.extend(
            f"{path.relative_to(ROOT)} must name the {tool.name} series {one} "
            f"({tool.variants} publishes it)"
            for path in tool.variant_files
            if not stated.search(path.read_text(encoding="utf-8"))
        )
    return failures


def dropped_variant_failures(
    version: str, previous_tag: str | None, read_at: Callable[[str, str], str | None]
) -> list[str]:
    """The series a step could choose in ``previous_tag`` that this patch release drops."""
    failures: list[str] = []
    for tool in BUNDLED_TOOLS:
        if tool.variants is None or previous_tag is None:
            continue
        before_text = read_at(previous_tag, tool.variants)
        before = variant_series(tool, before_text) if before_text is not None else None
        now = variant_series(tool, (ROOT / tool.variants).read_text(encoding="utf-8"))
        if before is None or now is None:
            # No choice in the previous release; variant_failures reports a broken file.
            continue
        failures.extend(
            f"{tool.variants} no longer publishes {tool.name} {series} ({previous_tag} did), "
            f"but {version} is a patch release: flows that name the series would have no "
            "image, so dropping one needs a minor release (CONTRIBUTING.md, Releasing)"
            for series in before[1]
            if series not in now[1]
        )
    return failures


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed arguments, no shell
        ["git", "-C", str(ROOT), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )


def _read_at(tag: str, path: str) -> str | None:
    """``path`` at ``tag``; None only when the tag's tree has no such file.

    A tag or an object that cannot be read (a partial clone, say) is not a
    missing file: it ends the check, or a tool could move unseen.
    """
    listed = _git("ls-tree", "--name-only", tag, "--", path)
    if listed.returncode != 0:
        raise SystemExit(f"Could not read {tag} to look for {path}: {listed.stderr.strip()}")
    if not listed.stdout.strip():
        return None
    shown = _git("show", f"{tag}:{path}")
    if shown.returncode != 0:
        raise SystemExit(f"Could not read {path} at {tag}: {shown.stderr.strip()}")
    return shown.stdout


def _release_tags() -> list[str]:
    listed = _git("tag", "--list", "v*")
    if listed.returncode != 0:
        raise SystemExit(f"Could not list the release tags: {listed.stderr.strip()}")
    return listed.stdout.split()


def _project_metadata(pyproject) -> dict:
    return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]


def _name_and_dependencies(package_dir) -> tuple[str, list[str]]:
    metadata = _project_metadata(package_dir / "pyproject.toml")
    return metadata["name"], list(metadata.get("dependencies", []))


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

    for package_dir in RELEASE_DIRS:
        metadata = _project_metadata(package_dir / "pyproject.toml")
        if metadata["version"] != version:
            failures.append(
                f"{metadata['name']} version is {metadata['version']}, expected {version}"
            )

    for plugin_dir in PLUGIN_DIRS:
        metadata = _project_metadata(plugin_dir / "pyproject.toml")
        # Pins on sibling wheels of this monorepo release in lockstep.
        for dependency in metadata["dependencies"]:
            failure = sibling_pin_failure(metadata["name"], dependency, version)
            if failure:
                failures.append(failure)

    # The SDK's own version: consistent, pinned right, and the bump its change needs.
    failures.extend(sdk_version.pin_failures(_name_and_dependencies))
    failures.extend(sdk_version.check(release=version))

    for image in RUNNER_IMAGES:
        for path in image.files:
            text = path.read_text(encoding="utf-8")
            failures.extend(runner_image_failures(path, text, version, image.repository))
        failure = default_image_failure(image)
        if failure:
            failures.append(failure)

    patch = re.fullmatch(r"\d+\.\d+\.(\d+)", version)
    previous_tag = previous_patch_tag(version, _release_tags())
    if patch is not None and int(patch.group(1)) > 0 and previous_tag is None:
        # Without the earlier release there is nothing to compare with: refuse
        # rather than let a tool move unseen (a checkout without its tags).
        failures.append(
            f"found no earlier release tag of {version}'s minor to compare the tool "
            "versions with; fetch the tags"
        )
    failures.extend(tool_series_failures(version, previous_tag, _read_at))
    failures.extend(dropped_variant_failures(version, previous_tag, _read_at))
    for tool in BUNDLED_TOOLS:
        failures.extend(variant_failures(tool))
        series = tool_series(tool, (ROOT / tool.source).read_text(encoding="utf-8"))
        if series is not None:
            failures.extend(tool_docs_failures(tool, series))

    if failures:
        raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
