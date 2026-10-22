#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify every image and component the step plugins ship or pull is licence-reviewed.

The platform's Python gate sees the plugin wheels' dependencies, because the
platform installs every plugin. Nothing sees the container images: the ones
``images/`` builds (``ansible-runner`` is published to ghcr.io, so Hegemony
conveys everything inside it) and the ones a step pulls when its author sets no
image. This script covers both:

* every image a Dockerfile under ``images/`` builds on (``FROM``,
  ``COPY --from=<registry ref>``) and every image a step defaults to (a
  module-level ``DEFAULT_IMAGE`` or ``DEFAULT_IMAGES`` literal under
  ``plugins/``) must be in ``images/.images-allowed.txt``;
* every package those Dockerfiles install must be in the allowlist for its
  kind: ``apt-get install``/``apk add`` in ``images/.os-packages-allowed.txt``,
  ``pip install`` in ``images/.python-packages-allowed.txt``,
  ``ansible-galaxy collection install`` in ``images/.collections-allowed.txt``;
* every image ``.github/workflows/images.yml`` publishes must carry a
  THIRD-PARTY-NOTICES.md (copied into the image under /usr/share/doc/hegemony/)
  that names each component its Dockerfile installs.

The allowlists use the platform's format (``deploy/.images-allowed.txt`` in the
hegemony repository): ``name | SPDX licence | tier | statement``. The platform's
licence process runs this script against the plugin release it pins.

Stdlib only, so it runs without the workspace installed.

Usage:
    python3 scripts/check_image_licenses.py            # gate: unlisted entries fail
    python3 scripts/check_image_licenses.py --strict   # also fail on review-tier licences
    python3 scripts/check_image_licenses.py --list     # print what is referenced
    python3 scripts/check_image_licenses.py --root DIR # check another checkout
"""

from __future__ import annotations

import argparse
import ast
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Where each image tier's rows live, and which tiers they may use.
IMAGE_TIERS = {"first-party", "base-image", "step-default"}
#: ``exec``: a separate program (or data it reads) that Hegemony code starts,
#: or that such a program loads. ``linked``: loaded into a Hegemony process.
COMPONENT_TIERS = {"exec", "linked"}

#: Licences that need a written acceptance: their terms reach past notices and a
#: source offer, either by attaching source obligations to offering the software
#: over a network (AGPL, SSPL) or by restricting who may use or offer it (BUSL,
#: Elastic, RSAL, Commons Clause). Mirrors the platform's
#: scripts/check-image-licenses.py.
REVIEW_LICENSES = {
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "BUSL-1.1",
    "Elastic-2.0",
    "RSAL-1.0",
    "SSPL-1.0",
    "Commons-Clause",
}
#: Licences known to be compatible with AGPL-3.0-or-later. Any licence is fine
#: for a program Hegemony executes (mere aggregation); a library linked into a
#: Hegemony process forms one work with Hegemony's own code, so a linked row
#: passes only when every identifier in its licence is in this set. The check
#: fails closed: a licence the set does not name -- APSL, CPAL, MS-PL, a
#: LicenseRef -- fails until a reviewer adds it here with the reason it is
#: compatible, or moves the component to 'exec'. GPL-2.0-only, AGPL-1.0-only,
#: EPL, CDDL, MPL-1.x and the source-available licences are absent because they
#: are not compatible. Mirrors the platform's scripts/check-image-licenses.py.
COMPATIBLE_WHEN_LINKED = {
    # Copyleft licences that AGPL-3.0 code may be combined with: AGPL-3.0
    # section 13 permits combining with GPL-3.0 work, LGPL-2.x lets a recipient
    # take the code under GPL-2.0 or any later version, and MPL-2.0 names the
    # GPL as a secondary licence.
    "AGPL-1.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "GPL-1.0-or-later",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
    # Permissive licences the FSF lists as compatible with GPL-3.0.
    "0BSD",
    "Apache-2.0",
    "Artistic-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "curl",
    "ISC",
    "MIT",
    "MIT-0",
    "NCSA",
    "PostgreSQL",
    "PSF-2.0",
    "Python-2.0",
    "Unicode-3.0",
    "Unicode-DFS-2016",
    "Unlicense",
    "UPL-1.0",
    "X11",
    "Zlib",
}

#: Options whose next token is a value, not a package name.
_VALUE_OPTIONS = {
    "pip": {
        "-r",
        "--requirement",
        "-c",
        "--constraint",
        "-i",
        "--index-url",
        "--extra-index-url",
        "-t",
        "--target",
        "--prefix",
        "--root",
    },
    "galaxy": {
        "-p",
        "--collections-path",
        "-r",
        "--requirements-file",
        "-s",
        "--server",
    },
    "os": {"-o", "--repository", "-X", "--virtual", "-t"},
}
#: Options that install whatever a file lists, which this gate cannot see: the
#: file lives in the image, not in the Dockerfile. An install that uses one
#: fails the gate; name the packages on the install command instead.
_FILE_OPTIONS = {
    "pip": {"-r", "--requirement"},
    "galaxy": {"-r", "--requirements-file"},
    "os": set(),
}
_SHELL_OPERATORS = {"&&", "||", ";", "|", "&"}
_STAGE_ALIAS = re.compile(r"\s+AS\s+(\S+)\s*$", re.IGNORECASE)
_ARG = re.compile(r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(\S*))?", re.IGNORECASE)
_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
#: How the Images workflow names an image it publishes: a literal build
#: context, or a matrix entry (``- image: <name>``) for ``images/${{ matrix.image }}``.
_PUBLISHED = re.compile(
    r"context:\s*images/([A-Za-z0-9._-]+)|^\s*(?:-\s+)?image:\s*([A-Za-z0-9._-]+)\s*$",
    re.MULTILINE,
)
_NOTICES_PATH = "/usr/share/doc/hegemony/"


@dataclass(frozen=True)
class Entry:
    """One allowlist row."""

    name: str
    license_id: str
    tier: str
    statement: str


@dataclass(frozen=True)
class Found:
    """A component the tree references, and where."""

    kind: str  # image, os, python, collection; unreviewable: an install from a file
    name: str
    source: str


def parse_allowlist(path: Path) -> dict[str, Entry]:
    """Rows of a ``name | licence | tier | statement`` file, keyed by name."""
    entries: dict[str, Entry] = {}
    if not path.exists():
        return entries
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = [field.strip() for field in line.split("|", 3)]
        if len(fields) != 4 or not all(fields):
            raise SystemExit(f"{path}:{number}: expected 'name | licence | tier | statement'")
        entries[fields[0]] = Entry(*fields)
    return entries


def license_identifiers(expression: str) -> set[str]:
    """The SPDX licence identifiers an expression names.

    Operators, brackets and exceptions are dropped. An exception ("WITH
    Classpath-exception-2.0") only widens what its licence permits, so judging
    the licence alone can make it look less compatible than it is, never more.
    """
    identifiers: set[str] = set()
    after_with = False
    for token in re.split(r"[\s()]+", expression):
        if not token or token.upper() in {"AND", "OR"}:
            continue
        if token.upper() == "WITH":
            after_with = True
        elif after_with:
            after_with = False
        else:
            identifiers.add(token)
    return identifiers


def repository_of(reference: str) -> str:
    """An image reference without its digest and tag."""
    reference = reference.split("@", 1)[0]
    last = reference.rsplit("/", 1)[-1]
    if ":" in last:
        reference = reference[: len(reference) - len(last)] + last.split(":", 1)[0]
    return reference


def _expand(value: str, args: dict[str, str]) -> str:
    return _VAR.sub(lambda m: args.get(m.group(1) or m.group(2), m.group(0)), value)


def _instructions(text: str) -> list[str]:
    """Dockerfile instructions with continuation lines joined and comments dropped."""
    joined: list[str] = []
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not current and (not line or line.startswith("#")):
            continue
        if line.startswith("#"):
            continue
        if line.endswith("\\"):
            current += line[:-1] + " "
            continue
        joined.append(current + line)
        current = ""
    if current:
        joined.append(current)
    return joined


def _file_option(token: str, kind: str) -> str | None:
    """The file-list option ``token`` is (``-r``, ``-rfile``, ``--requirement=f``), if any."""
    for option in _FILE_OPTIONS[kind]:
        if token == option or token.startswith(f"{option}="):
            return option
        if not option.startswith("--") and token.startswith(option):
            return option
    return None


def _packages_after(tokens: list[str], start: int, kind: str) -> tuple[list[str], list[str]]:
    """``(packages, file options)`` from ``start`` up to the next shell operator.

    The second list holds each option that installs from a file, with its value.
    """
    names: list[str] = []
    files: list[str] = []
    skip_next = False
    for index, token in enumerate(tokens[start:], start):
        if token in _SHELL_OPERATORS:
            break
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            option = _file_option(token, kind)
            if option is not None:
                attached = token != option
                value = token if attached else " ".join(tokens[index : index + 2])
                files.append(value)
            if "=" not in token and token in _VALUE_OPTIONS[kind]:
                skip_next = True
            continue
        names.append(token)
    return names, files


def _normalise(kind: str, token: str) -> str:
    if kind == "python":
        # "ansible-core==2.19.13", "pkg[extra]>=1" -> the distribution name.
        name = re.split(r"[\[<>=!~;@ ]", token, maxsplit=1)[0]
        return re.sub(r"[-_.]+", "-", name).lower()
    if kind == "collection":
        return token.split(":", 1)[0].split(",", 1)[0]
    # apt: "pkg=1.2" pins, apk: "pkg=1.2" / "pkg~1.2" pins.
    return re.split(r"[=~]", token, maxsplit=1)[0]


def scan_dockerfile(path: Path, root: Path) -> list[Found]:
    """Images and packages one Dockerfile builds on and installs."""
    source = str(path.relative_to(root))
    args: dict[str, str] = {}
    stages: set[str] = set()
    found: list[Found] = []
    for instruction in _instructions(path.read_text(encoding="utf-8")):
        keyword, _, rest = instruction.partition(" ")
        keyword = keyword.upper()
        if keyword == "ARG":
            match = _ARG.match(instruction)
            if match and match.group(2) is not None:
                args[match.group(1)] = match.group(2).strip("\"'")
        elif keyword == "FROM":
            alias = _STAGE_ALIAS.search(rest)
            if alias:
                stages.add(alias.group(1))
                rest = rest[: alias.start()]
            words = [w for w in rest.split() if not w.startswith("--")]
            if words:
                ref = _expand(words[0], args)
                if ref not in stages and ref != "scratch":
                    found.append(Found("image", repository_of(ref), source))
        elif keyword == "COPY":
            for word in rest.split():
                if word.startswith("--from="):
                    ref = _expand(word.removeprefix("--from="), args)
                    if ref not in stages and not ref.isdigit():
                        found.append(Found("image", repository_of(ref), source))
        elif keyword == "RUN":
            tokens = [_expand(t, args) for t in shlex.split(rest, comments=False, posix=True)]
            for i, token in enumerate(tokens):
                pair = tokens[i : i + 2]
                if pair == ["apt-get", "install"] or pair == ["apk", "add"]:
                    kind, start, option_kind = "os", i + 2, "os"
                elif token in {"pip", "pip3"} and tokens[i + 1 : i + 2] == ["install"]:
                    kind, start, option_kind = "python", i + 2, "pip"
                elif tokens[i : i + 3] == ["ansible-galaxy", "collection", "install"]:
                    kind, start, option_kind = "collection", i + 3, "galaxy"
                else:
                    continue
                names, files = _packages_after(tokens, start, option_kind)
                for name in names:
                    found.append(Found(kind, _normalise(kind, name), source))
                for option in files:
                    found.append(Found("unreviewable", f"{kind}: {option}", source))
    return found


def scan_step_defaults(root: Path) -> list[Found]:
    """Images the steps pull when their author sets none.

    A step's default must be a module-level ``DEFAULT_IMAGE`` (a string) or
    ``DEFAULT_IMAGES`` (a dict of strings) literal, which is what CONVENTIONS.md
    asks for; read with ``ast`` so nothing is imported.
    """
    found: list[Found] = []
    for path in sorted((root / "plugins").glob("*/src/**/*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                target, value = node.target, node.value
            else:
                continue
            if not isinstance(target, ast.Name) or target.id not in {
                "DEFAULT_IMAGE",
                "DEFAULT_IMAGES",
            }:
                continue
            literal = ast.literal_eval(value)
            refs = literal.values() if isinstance(literal, dict) else [literal]
            for ref in refs:
                found.append(Found("image", repository_of(str(ref)), str(path.relative_to(root))))
    return found


def published_images(root: Path) -> list[str]:
    """Image directories the Images workflow builds and pushes."""
    workflow = root / ".github" / "workflows" / "images.yml"
    if not workflow.exists():
        return []
    text = workflow.read_text(encoding="utf-8")
    return sorted({context or entry for context, entry in _PUBLISHED.findall(text)})


def check_notices(root: Path, name: str, components: list[Found]) -> list[str]:
    """Failures for a published image whose notices are missing or incomplete."""
    directory = root / "images" / name
    notices = directory / "THIRD-PARTY-NOTICES.md"
    if not notices.exists():
        return [
            f"images/{name} is published but has no THIRD-PARTY-NOTICES.md.\n"
            f"      Everything inside a published image is conveyed by Hegemony; the"
            f"\n      notices and the source offer must travel with it."
        ]
    failures: list[str] = []
    dockerfile = (directory / "Dockerfile").read_text(encoding="utf-8")
    if not re.search(
        rf"^COPY\s+THIRD-PARTY-NOTICES\.md\s+{re.escape(_NOTICES_PATH)}", dockerfile, re.M
    ):
        failures.append(
            f"images/{name}/Dockerfile does not copy THIRD-PARTY-NOTICES.md to "
            f"{_NOTICES_PATH}.\n      The written source offer must accompany the image."
        )
    text = notices.read_text(encoding="utf-8")
    for component in sorted({(c.kind, c.name) for c in components}):
        if f"`{component[1]}`" not in text:
            failures.append(
                f"images/{name}/THIRD-PARTY-NOTICES.md does not name `{component[1]}` "
                f"({component[0]}),\n      which images/{name}/Dockerfile installs or builds on."
            )
    return failures


def main(argv: list[str] | None = None) -> int:
    """Check the images tree and the step defaults; return a process exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="also fail on review-tier licences")
    parser.add_argument("--list", action="store_true", help="print every reference and exit")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    args = parser.parse_args(argv)
    root = args.root.resolve()

    per_dockerfile = {
        path: scan_dockerfile(path, root) for path in sorted((root / "images").glob("*/Dockerfile"))
    }
    found = [f for items in per_dockerfile.values() for f in items] + scan_step_defaults(root)
    if args.list:
        for item in sorted(set(found), key=lambda f: (f.kind, f.name, f.source)):
            print(f"{item.kind:11} {item.name:45} {item.source}")
        return 0

    allowlists = {
        "image": root / "images" / ".images-allowed.txt",
        "os": root / "images" / ".os-packages-allowed.txt",
        "python": root / "images" / ".python-packages-allowed.txt",
        "collection": root / "images" / ".collections-allowed.txt",
    }
    allowed = {kind: parse_allowlist(path) for kind, path in allowlists.items()}
    failures: list[str] = []
    warnings: list[str] = []

    for item in sorted({f for f in found if f.kind == "unreviewable"}, key=str):
        failures.append(
            f"{item.source} installs from a file ({item.name}), which this gate cannot\n"
            f"      read: name every package on the install command so each one is reviewed."
        )
    found = [f for f in found if f.kind != "unreviewable"]

    unlisted: dict[tuple[str, str], set[str]] = {}
    for item in found:
        if item.name not in allowed[item.kind]:
            unlisted.setdefault((item.kind, item.name), set()).add(item.source)
    for (kind, name), sources in sorted(unlisted.items()):
        failures.append(
            f"{kind} '{name}' is not in {allowlists[kind].relative_to(root)}\n"
            f"      referenced by: {', '.join(sorted(sources))}\n"
            f"      Record its verified licence, or drop it."
        )

    referenced = {(f.kind, f.name) for f in found}
    for kind, entries in allowed.items():
        tiers = IMAGE_TIERS if kind == "image" else COMPONENT_TIERS
        for entry in entries.values():
            if (kind, entry.name) not in referenced:
                print(
                    f"note: {kind} '{entry.name}' is allow-listed but not referenced",
                    file=sys.stderr,
                )
                continue
            if entry.tier not in tiers:
                failures.append(
                    f"{kind} '{entry.name}' has tier {entry.tier!r}; expected one of "
                    f"{', '.join(sorted(tiers))}."
                )
                continue
            # Every identifier is judged, so a linked row reading "GPL-2.0-only
            # OR MIT" fails although its MIT arm is compatible. That is
            # deliberate, as in the platform's gate: rows are written by hand,
            # so the arm Hegemony elects for a linked component belongs in the
            # row itself, and failing is how the reviewer is asked to write it.
            ids = license_identifiers(entry.license_id)
            unknown = ids - COMPATIBLE_WHEN_LINKED
            if entry.tier == "linked" and unknown:
                failures.append(
                    f"{kind} '{entry.name}' is {entry.license_id} and marked 'linked'.\n"
                    f"      Loading it into a Hegemony process would combine it with"
                    f" Hegemony's own code,\n      and {', '.join(sorted(unknown))} is not in"
                    f" COMPATIBLE_WHEN_LINKED, the licences known to be\n      compatible"
                    f" with AGPL-3.0-or-later. Mark it 'exec', drop it, or add the licence"
                    f" to that\n      set with the reason it is compatible."
                )
            elif entry.tier != "first-party" and ids & REVIEW_LICENSES:
                message = f"{kind} '{entry.name}' is {entry.license_id}: {entry.statement}"
                (failures if args.strict else warnings).append(message)

    for name in published_images(root):
        dockerfile = root / "images" / name / "Dockerfile"
        if not dockerfile.exists():
            failures.append(
                f".github/workflows/images.yml publishes images/{name}, which has no Dockerfile."
            )
            continue
        failures.extend(check_notices(root, name, per_dockerfile.get(dockerfile, [])))

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if failures:
        print(f"\nImage licence check FAILED ({len(failures)} problem(s)):\n", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    counts = {kind: len({f.name for f in found if f.kind == kind}) for kind in allowlists}
    print(
        f"Image licence check passed: {counts['image']} image(s), {counts['os']} OS package(s), "
        f"{counts['python']} Python package(s) and {counts['collection']} collection(s) reviewed"
        + (f", {len(warnings)} under provisional acceptance" if warnings else "")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
