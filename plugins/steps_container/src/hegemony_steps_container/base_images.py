# SPDX-FileCopyrightText: 2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The images a Dockerfile builds on, as BuildKit will resolve them.

``container.build`` serves them from the platform registry's cache: BuildKit
replaces an image reference used in ``FROM``, ``COPY --from`` or
``RUN --mount=from=`` with a named build context of the same name
(``--build-context alpine:3.20=docker-image://<copy>@sha256:...``). Names
are compared in Docker's familiar form (:func:`familiar_name`), so
``alpine``, ``alpine:latest`` and ``docker.io/library/alpine`` are one name,
and a context whose name is a stage's name replaces that whole stage.

What is returned is only what the build of the step's target stage uses and
the cache can serve as one context for every platform:

- the stages the target depends on (``FROM <stage>``, ``COPY --from`` with a
  stage name or index, ``RUN --mount=from=``), the last stage without a
  target: BuildKit builds no other;
- their ``FROM`` and ``COPY --from`` images, but none whose familiar name is
  a stage's name, and none that one of those stages uses with a
  ``--platform`` other than ``$BUILDPLATFORM`` (a copy holds the one platform
  the sandbox pulled, the build platform; the context would serve it to the
  other platform too);
- references read from the Dockerfile and the step's build arguments alone. A
  reference that needs a variable the file does not declare before its first
  ``FROM`` (``$TARGETARCH``, say), or an expansion form other than ``$NAME``,
  ``${NAME}``, ``${NAME:-word}`` and ``${NAME:+word}``, is left out.

Images a ``RUN --mount=from=`` uses are not served from the cache themselves.
Everything left out is pulled by BuildKit from its registry, as before.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
#: An image reference: optional registry host (with a dot, a port or
#: ``localhost``), a lowercase repository path, an optional tag and an
#: optional digest.
_REFERENCE_RE = re.compile(
    rf"^(?:{_HOST_LABEL}(?:\.{_HOST_LABEL})*(?::[0-9]{{1,5}})?/)?"
    rf"{_NAME_COMPONENT}(?:/{_NAME_COMPONENT})*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?"
    r"(?:@sha256:[0-9a-f]{64})?$"
)
#: A parser directive at the top of a Dockerfile (``# escape=`` ``).
_DIRECTIVE_RE = re.compile(r"^#\s*([A-Za-z_]+)\s*=\s*(.*?)\s*$")
_VARIABLE_RE = re.compile(r"\$(?:\{([^}]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
#: The one ``FROM --platform`` a copy serves: the platform the build runs on.
_BUILD_PLATFORM_FLAGS = frozenset({"--platform=$buildplatform", "--platform=${buildplatform}"})
#: Docker Hub's names for itself, which the familiar form drops.
_DOCKER_HUB_HOSTS = frozenset({"docker.io", "index.docker.io"})


def _escape_character(lines: list[str]) -> str:
    """The Dockerfile's line-continuation character (``\\`` unless a directive says otherwise)."""
    for line in lines:
        match = _DIRECTIVE_RE.match(line.strip())
        if match is None:
            break
        if match.group(1).lower() == "escape" and match.group(2) in ("\\", "`"):
            return match.group(2)
    return "\\"


def _instructions(dockerfile: str) -> list[str]:
    """The Dockerfile's instructions, continuation lines joined, comments dropped."""
    lines = dockerfile.splitlines()
    escape = _escape_character(lines)
    instructions: list[str] = []
    current: list[str] = []
    for raw in lines:
        stripped = raw.strip()
        # A comment line is dropped, inside a continued instruction too.
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith(escape):
            current.append(stripped[: -len(escape)])
            continue
        current.append(stripped)
        instructions.append(" ".join(part.strip() for part in current))
        current = []
    if current:
        instructions.append(" ".join(part.strip() for part in current))
    return instructions


def _expand(value: str, variables: Mapping[str, str | None]) -> str | None:
    """``value`` with its variables expanded, or None when one cannot be."""
    unresolved = False

    def substitute(match: re.Match[str]) -> str:
        nonlocal unresolved
        braced, bare = match.group(1), match.group(2)
        if bare is not None:
            name, operator, word = bare, "", ""
        else:
            name, operator, word = braced, "", ""
            for candidate in (":-", ":+"):
                if candidate in braced:
                    name, _, word = braced.partition(candidate)
                    operator = candidate
                    break
        if not _NAME_RE.match(name) or name not in variables:
            unresolved = True
            return ""
        current = variables[name] or ""
        if operator:
            # The word may use variables itself (``${FLAVOUR:+-$FLAVOUR}``).
            expanded_word = _expand(word, variables)
            if expanded_word is None:
                unresolved = True
                return ""
            if operator == ":-":
                return current or expanded_word
            return expanded_word if current else ""
        return current

    expanded = _VARIABLE_RE.sub(substitute, value)
    if unresolved or "$" in expanded:
        return None
    return expanded


def _global_args(arguments: str, build_args: Mapping[str, str]) -> dict[str, str | None]:
    """The variables one ``ARG`` before the first ``FROM`` declares, with their values."""
    declared: dict[str, str | None] = {}
    for token in arguments.split():
        name, separator, default = token.partition("=")
        if not _NAME_RE.match(name):
            continue
        if name in build_args:
            declared[name] = build_args[name]
        else:
            declared[name] = default.strip("\"'") if separator else None
    return declared


def familiar_name(reference: str) -> str:
    """``reference`` as Buildx and BuildKit name a build context or match one.

    Docker's familiar form: Docker Hub's host and its ``library/`` dropped
    (``docker.io/library/alpine`` is ``alpine``), and a ``:latest`` tag
    dropped unless a digest follows. Two references with the same familiar
    name select the same named context, and a stage whose name equals it is
    replaced by that context entirely.
    """
    name, _, digest = reference.partition("@")
    tag = ""
    slash, colon = name.rfind("/"), name.rfind(":")
    if colon > slash:
        name, tag = name[:colon], name[colon + 1 :]
    first, separator, rest = name.partition("/")
    other_registry = separator and (
        ("." in first or ":" in first or first == "localhost") and first not in _DOCKER_HUB_HOSTS
    )
    if not other_registry:
        if separator and first in _DOCKER_HUB_HOSTS:
            name = rest
        if name.startswith("library/") and name.count("/") == 1:
            name = name[len("library/") :]
    if digest:
        return f"{name}{':' + tag if tag else ''}@{digest}"
    return f"{name}:{tag}" if tag and tag != "latest" else name


@dataclass
class _Stage:
    """One ``FROM`` and what its instructions take from other stages or images."""

    index: int
    # The stage's name (``AS name``), lowercased as BuildKit does; "" for none.
    name: str
    # The FROM reference with its variables expanded; None when it cannot be.
    base: str | None
    # Built for another platform than the build's own (``FROM --platform=...``).
    foreign: bool
    # ``COPY --from`` values: a stage name, a stage index or an image.
    copies: list[str] = field(default_factory=list)
    # ``RUN --mount=...,from=`` values: the same, never served from the cache.
    mounts: list[str] = field(default_factory=list)


def _stages(dockerfile: str, build_args: Mapping[str, str]) -> list[_Stage]:
    variables: dict[str, str | None] = {}
    stages: list[_Stage] = []
    for instruction in _instructions(dockerfile):
        keyword, _, rest = instruction.partition(" ")
        keyword = keyword.upper()
        words = rest.split()
        flags = []
        for word in words:
            if not word.startswith("--"):
                break
            flags.append(word)
        if keyword == "ARG" and not stages:
            variables.update(_global_args(rest, build_args))
        elif keyword == "FROM":
            names = [word for word in words if not word.startswith("--")]
            alias = names[2].lower() if len(names) >= 3 and names[1].lower() == "as" else ""
            foreign = any(
                flag.lower().startswith("--platform") and flag.lower() not in _BUILD_PLATFORM_FLAGS
                for flag in flags
            )
            base = _expand(names[0], variables) if names else None
            stages.append(_Stage(len(stages), alias, base, foreign))
        elif stages and keyword == "COPY":
            for flag in flags:
                if flag.lower().startswith("--from="):
                    stages[-1].copies.append(flag.split("=", 1)[1])
        elif stages and keyword == "RUN":
            for flag in flags:
                if flag.lower().startswith("--mount="):
                    for option in flag.split("=", 1)[1].split(","):
                        key, _, value = option.partition("=")
                        if key.lower() == "from" and value:
                            stages[-1].mounts.append(value)
    return stages


def base_image_references(
    dockerfile: str, build_args: Mapping[str, str], target: str = ""
) -> list[str]:
    """The image references the build of ``target`` uses, in order and without repeats.

    ``build_args`` are the step's build arguments: they set the ``ARG``
    variables declared before the first ``FROM``, which is all a ``FROM``
    line may use. ``target`` is the step's target stage; without one the
    last stage is built. Only the stages it depends on count, as BuildKit
    builds only those. An image that any of those stages uses for another
    platform is left out entirely (one named context serves every platform),
    and so is one whose familiar name is a stage's name (the context would
    replace that stage).
    """
    stages = _stages(dockerfile, build_args)
    if not stages:
        return []
    by_name = {stage.name: stage for stage in stages if stage.name}
    if target:
        start = by_name.get(target.strip().lower())
        if start is None:
            return []
    else:
        start = stages[-1]

    def stage_named(value: str) -> _Stage | None:
        if value.isdigit():
            index = int(value)
            return stages[index] if index < len(stages) else None
        return by_name.get(value.lower())

    reachable: set[int] = set()
    pending = [start]
    while pending:
        stage = pending.pop()
        if stage.index in reachable:
            continue
        reachable.add(stage.index)
        dependencies: list[_Stage | None] = [stage_named(value) for value in stage.copies]
        dependencies += [stage_named(value) for value in stage.mounts]
        if stage.base is not None and stage.base.lower() in by_name:
            # FROM names only an earlier stage.
            earlier = by_name[stage.base.lower()]
            dependencies.append(earlier if earlier.index < stage.index else None)
        pending.extend(dependency for dependency in dependencies if dependency is not None)

    def image(value: str | None) -> str | None:
        if not value or "$" in value or value.isdigit() or value.lower() in by_name:
            return None
        if value == "scratch" or not _REFERENCE_RE.match(value):
            return None
        return value

    wanted: list[str] = []
    other_platform: set[str] = set()
    for stage in stages:
        if stage.index not in reachable:
            continue
        used = [image(stage.base), *(image(value) for value in stage.copies)]
        mounted = [image(value) for value in stage.mounts]
        for reference in used:
            if reference is None:
                continue
            if stage.foreign:
                other_platform.add(familiar_name(reference))
            else:
                wanted.append(reference)
        if stage.foreign:
            other_platform.update(familiar_name(ref) for ref in mounted if ref is not None)

    found: list[str] = []
    seen: set[str] = set()
    for reference in wanted:
        name = familiar_name(reference)
        if name in other_platform or name in by_name or name in seen:
            continue
        seen.add(name)
        found.append(reference)
    return found


__all__ = ["base_image_references", "familiar_name"]
