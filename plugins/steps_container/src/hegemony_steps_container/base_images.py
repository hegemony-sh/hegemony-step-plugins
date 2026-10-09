# SPDX-FileCopyrightText: 2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The images a Dockerfile builds on, as BuildKit will resolve them.

``container.build`` serves them from the platform registry's cache: BuildKit
replaces an image reference used in ``FROM`` or ``COPY --from`` with a named
build context of the same name (``--build-context alpine:3.20=docker-image://
<copy>@sha256:...``), matching names the way Docker normalizes them, so
``alpine``, ``alpine:latest`` and ``docker.io/library/alpine`` are one name.

Only what can be read from the Dockerfile and the step's build arguments
alone is returned. A reference that needs a variable the file does not
declare before its first ``FROM`` (``$TARGETARCH``, say), or an expansion
form other than ``$NAME``, ``${NAME}``, ``${NAME:-word}`` and
``${NAME:+word}``, is left out: BuildKit pulls it from its registry as before.
So are stage names, ``scratch``, stage indexes in ``COPY --from``, a ``FROM``
with a ``--platform`` other than ``$BUILDPLATFORM`` (a copy holds the one
platform the sandbox pulled, the build platform), and images a
``RUN --mount=from=...`` uses.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

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


def _usable(reference: str | None, stages: set[str]) -> str | None:
    if not reference or reference.lower() in stages or reference == "scratch":
        return None
    if not _REFERENCE_RE.match(reference):
        return None
    return reference


def base_image_references(dockerfile: str, build_args: Mapping[str, str]) -> list[str]:
    """The image references ``dockerfile`` builds on, in order and without repeats.

    ``build_args`` are the step's build arguments: they set the ``ARG``
    variables declared before the first ``FROM``, which is all a ``FROM``
    line may use.
    """
    instructions = _instructions(dockerfile)
    # Every stage name first: ``COPY --from`` may name a stage defined later.
    stages: set[str] = set()
    for instruction in instructions:
        keyword, _, rest = instruction.partition(" ")
        if keyword.upper() == "FROM":
            words = [word for word in rest.split() if not word.startswith("--")]
            if len(words) >= 3 and words[1].lower() == "as":
                stages.add(words[2].lower())

    variables: dict[str, str | None] = {}
    seen_from = False
    found: list[str] = []
    for instruction in instructions:
        keyword, _, rest = instruction.partition(" ")
        keyword = keyword.upper()
        if keyword == "ARG" and not seen_from:
            variables.update(_global_args(rest, build_args))
        elif keyword == "FROM":
            seen_from = True
            words = rest.split()
            flags = [word for word in words if word.startswith("--")]
            names = [word for word in words if not word.startswith("--")]
            if not names or any(
                flag.lower().startswith("--platform") and flag.lower() not in _BUILD_PLATFORM_FLAGS
                for flag in flags
            ):
                continue
            reference = _usable(_expand(names[0], variables), stages)
            if reference:
                found.append(reference)
        elif keyword == "COPY":
            for word in rest.split():
                if not word.startswith("--"):
                    break
                if word.lower().startswith("--from="):
                    value = word.split("=", 1)[1]
                    if "$" in value or value.isdigit():
                        continue
                    reference = _usable(value, stages)
                    if reference:
                        found.append(reference)
    return list(dict.fromkeys(found))


__all__ = ["base_image_references"]
