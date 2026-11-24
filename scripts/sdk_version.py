# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The SDK's own version: its public surface, the bump a change needs, and the SDK pins.

The SDK (``hegemony-step-sdk``) does not take the release version. Its
version is set by hand, in the pull request that changes the SDK, and this
script checks that it was set right, against the last release tag:

- nothing in ``packages/step_sdk`` changed: the version must not change;
- something changed, but not the public surface: at least a patch bump;
- the surface only gained names, parameters with defaults or optional
  fields: at least a minor bump;
- the surface lost or changed something: a major bump, and
  ``SDK_ABI_VERSION`` moves with it (the SDK's major always equals it).

The surface is recorded in ``packages/step_sdk/api-surface.json``, so the
pull request's diff shows a contract change as such. It holds the names,
call shapes (parameter names, kinds, whether each has a default), fields and
enum values of every public module; it does not hold types or constants'
values, so a change there needs a reviewer's judgement (the check accepts a
larger bump than it requires).

Commands (``uv run python scripts/sdk_version.py ...``):

``check [--base REF]``
    The default. Fails when the surface file is stale or the version does not
    match the change since ``REF`` (the newest release tag in HEAD's history).
``write``
    Rewrite the surface file from the code.
``bump {major,minor,patch}``
    Set the next SDK version (and the ABI version on a major), every SDK pin
    and the surface file. Run ``uv lock`` afterwards.
``set X.Y.Z``
    The same with an explicit version.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import enum
import importlib
import inspect
import json
import pkgutil
import re
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from package_paths import (
    PLUGIN_DIRS,
    ROOT,
    SDK_DIR,
    SDK_EXACT_PIN_DIRS,
    SDK_PYPROJECT,
    SDK_SURFACE_FILE,
    SDK_VERSION_FILE,
)

SDK_PACKAGE = "hegemony_step_sdk"
SDK_DISTRIBUTION = "hegemony-step-sdk"
SURFACE_FORMAT = 1

VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
_PROJECT_VERSION = re.compile(r'^version = "([^"]+)"$', re.MULTILINE)
_DUNDER_VERSION = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)
_ABI_VERSION = re.compile(r"^SDK_ABI_VERSION = (\d+)$", re.MULTILINE)
#: The SDK requirement in a quoted dependency string; a marker after ``;`` is kept.
_SDK_REQUIREMENT = re.compile(r'"hegemony[-_.]step[-_.]sdk\b[^";]*', re.IGNORECASE)

BUMPS = ("patch", "minor", "major")

# --------------------------------------------------------------------------
# Versions and pins


def parse_version(version: str) -> tuple[int, int, int]:
    match = VERSION.fullmatch(version)
    if match is None:
        raise ValueError(f"{version!r} is not an X.Y.Z version")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def next_version(version: str, bump: str) -> str:
    major, minor, patch = parse_version(version)
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"unknown bump {bump!r}")


def version_step(old: str, new: str) -> str | None:
    """The bump from ``old`` to ``new``: None when equal, else major, minor or patch.

    Raises ValueError for a version that is lower, or that skips one (1.0.0 to
    1.2.0): every SDK version a release publishes is the next one.
    """
    if old == new:
        return None
    for bump in reversed(BUMPS):
        if next_version(old, bump) == new:
            return bump
    if parse_version(new) < parse_version(old):
        raise ValueError(f"the SDK version may not go down, from {old} to {new}")
    raise ValueError(
        f"{new} does not follow {old}: the next SDK versions are "
        + ", ".join(next_version(old, bump) for bump in BUMPS)
    )


def range_pin(sdk_version: str) -> str:
    """What a step-handler or probe wheel requires: the SDK's minor and up, within its major."""
    major, minor, _ = parse_version(sdk_version)
    return f"{SDK_DISTRIBUTION}>={major}.{minor},<{major + 1}"


def exact_pin(sdk_version: str) -> str:
    """What a transport wheel and hegemony-transport-support require: this SDK exactly."""
    return f"{SDK_DISTRIBUTION}=={sdk_version}"


def expected_sdk_pin(package_dir: Path, sdk_version: str) -> str:
    return exact_pin(sdk_version) if package_dir in SDK_EXACT_PIN_DIRS else range_pin(sdk_version)


def set_sdk_requirement(text: str, pin: str, *, path: str = "pyproject.toml") -> str:
    """``text`` (a pyproject) with its one SDK requirement replaced by ``pin``."""
    replaced, count = _SDK_REQUIREMENT.subn(lambda _: f'"{pin}', text)
    if count != 1:
        raise SystemExit(f"Could not update {path}: expected one {SDK_DISTRIBUTION} requirement")
    return replaced


def sdk_requirement(dependencies: list[str]) -> str | None:
    """The SDK requirement among ``dependencies``, whitespace removed, marker kept."""
    for dependency in dependencies:
        if re.match(r"hegemony[-_.]step[-_.]sdk\b", dependency.strip(), re.IGNORECASE):
            return "".join(dependency.split())
    return None


def read_sdk_version() -> str:
    match = _PROJECT_VERSION.search(SDK_PYPROJECT.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit(f"{SDK_PYPROJECT} has no version")
    return match.group(1)


def read_abi_version() -> int:
    match = _ABI_VERSION.search(SDK_VERSION_FILE.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit(f"{SDK_VERSION_FILE} has no SDK_ABI_VERSION")
    return int(match.group(1))


def consistency_failures() -> list[str]:
    """The SDK's version agrees with itself: pyproject, ``__version__``, the ABI version."""
    version = read_sdk_version()
    failures: list[str] = []
    dunder = _DUNDER_VERSION.search(SDK_VERSION_FILE.read_text(encoding="utf-8"))
    if dunder is None or dunder.group(1) != version:
        failures.append(
            f"{rel(SDK_VERSION_FILE)} __version__ must be {version}, as in its pyproject"
        )
    try:
        major = parse_version(version)[0]
    except ValueError as exc:
        return [*failures, f"{rel(SDK_PYPROJECT)}: {exc}"]
    abi = read_abi_version()
    if abi != major:
        failures.append(
            f"SDK_ABI_VERSION is {abi} but the SDK version is {version}: "
            "the SDK's major version is its ABI version, so they move together"
        )
    return failures


def pin_failures(read_dependencies: Callable[[Path], tuple[str, list[str]]]) -> list[str]:
    """Every wheel's SDK requirement is the one its kind takes, for the current SDK version."""
    version = read_sdk_version()
    failures = []
    for package_dir in PLUGIN_DIRS:
        name, dependencies = read_dependencies(package_dir)
        expected = expected_sdk_pin(package_dir, version)
        found = sdk_requirement(dependencies)
        if found != expected:
            failures.append(f"{name} must depend on {expected}, not {found}")
    return failures


def write_version(version: str) -> None:
    """Set the SDK's version, its ABI version, and every wheel's SDK pin."""
    major = parse_version(version)[0]
    text = SDK_PYPROJECT.read_text(encoding="utf-8")
    SDK_PYPROJECT.write_text(
        _PROJECT_VERSION.sub(f'version = "{version}"', text, count=1), encoding="utf-8"
    )
    text = SDK_VERSION_FILE.read_text(encoding="utf-8")
    text = _DUNDER_VERSION.sub(f'__version__ = "{version}"', text, count=1)
    text = _ABI_VERSION.sub(f"SDK_ABI_VERSION = {major}", text, count=1)
    SDK_VERSION_FILE.write_text(text, encoding="utf-8")
    write_pins(version)


def write_pins(sdk_version: str) -> None:
    for package_dir in PLUGIN_DIRS:
        pyproject = package_dir / "pyproject.toml"
        text = pyproject.read_text(encoding="utf-8")
        pin = expected_sdk_pin(package_dir, sdk_version)
        pyproject.write_text(set_sdk_requirement(text, pin, path=str(pyproject)), encoding="utf-8")


# --------------------------------------------------------------------------
# The public surface


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def public_modules() -> list[str]:
    """The SDK package and every submodule whose name has no leading underscore."""
    package = importlib.import_module(SDK_PACKAGE)
    names = [SDK_PACKAGE]
    names += sorted(
        f"{SDK_PACKAGE}.{info.name}"
        for info in pkgutil.iter_modules(package.__path__)
        if not info.name.startswith("_")
    )
    return names


def module_public_names(module) -> list[str]:
    """``__all__``, or else every top-level name the module itself defines without ``_``."""
    exported = getattr(module, "__all__", None)
    if exported is not None:
        return sorted(exported)
    source = inspect.getsource(module)
    names: set[str] = set()
    for node in ast.parse(source).body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return sorted(name for name in names if not name.startswith("_"))


def _params(func) -> list[list[Any]]:
    signature = inspect.signature(func)
    return [
        [param.name, param.kind.name, param.default is not inspect.Parameter.empty]
        for param in signature.parameters.values()
    ]


def _is_sdk(obj) -> bool:
    return str(getattr(obj, "__module__", "")).startswith(SDK_PACKAGE)


def _class_members(cls) -> dict[str, dict[str, Any]]:
    """Every public member an SDK class defines or inherits from another SDK class."""
    members: dict[str, dict[str, Any]] = {}
    model_fields = getattr(cls, "__pydantic_fields__", None)
    dataclass_fields = (
        {f.name: f for f in dataclasses.fields(cls)} if dataclasses.is_dataclass(cls) else {}
    )
    for klass in cls.__mro__:
        if not _is_sdk(klass):
            continue
        names = set(klass.__dict__) | set(inspect.get_annotations(klass))
        for name in sorted(names):
            if name in members or (name.startswith("_") and name not in ("__init__", "__call__")):
                continue
            if isinstance(model_fields, Mapping) and name in model_fields:
                members[name] = {"kind": "field", "required": model_fields[name].is_required()}
                continue
            if name in dataclass_fields:
                one = dataclass_fields[name]
                required = (
                    one.default is dataclasses.MISSING
                    and one.default_factory is dataclasses.MISSING
                )
                members[name] = {"kind": "field", "required": required}
                continue
            if name not in klass.__dict__:
                members[name] = {"kind": "attribute", "required": True}
                continue
            raw = klass.__dict__[name]
            if isinstance(cls, enum.EnumMeta) and name in cls.__members__:
                members[name] = {"kind": "enum member", "value": repr(cls[name].value)}
            elif isinstance(raw, staticmethod | classmethod):
                kind = "staticmethod" if isinstance(raw, staticmethod) else "classmethod"
                members[name] = {"kind": kind, "params": _params(raw.__func__)}
            elif isinstance(raw, property):
                members[name] = {"kind": "property", "settable": raw.fset is not None}
            elif inspect.isfunction(raw):
                if name.startswith("_") and not _is_sdk(raw):
                    continue  # typing.Protocol's own __init__
                members[name] = {"kind": "method", "params": _params(raw)}
            elif inspect.isclass(raw):
                members[name] = {"kind": "class"}
            else:
                members[name] = {"kind": "attribute", "required": False}
    return members


def describe(obj) -> dict[str, Any]:
    if inspect.ismodule(obj):
        return {"kind": "module"}
    if inspect.isclass(obj):
        return {"kind": "class"}
    if inspect.isfunction(obj) or inspect.isbuiltin(obj):
        return {"kind": "function", "params": _params(obj)}
    return {"kind": "constant", "type": type(obj).__name__}


def surface() -> dict[str, dict[str, Any]]:
    """The public surface: ``module:name`` and ``module:Class.member`` -> its description."""
    entries: dict[str, dict[str, Any]] = {}
    for module_name in public_modules():
        module = importlib.import_module(module_name)
        for name in module_public_names(module):
            obj = getattr(module, name)
            key = f"{module_name}:{name}"
            entries[key] = describe(obj)
            if inspect.isclass(obj) and _is_sdk(obj):
                for member, description in _class_members(obj).items():
                    entries[f"{key}.{member}"] = description
    return dict(sorted(entries.items()))


def render_surface(entries: Mapping[str, Mapping[str, Any]]) -> str:
    """One entry per line, so a contract change is a one-line diff."""
    lines = [
        f"    {json.dumps(key)}: {json.dumps(value, sort_keys=True)}"
        for key, value in sorted(entries.items())
    ]
    return (
        "{\n"
        f'  "format": {SURFACE_FORMAT},\n'
        '  "note": "Written by scripts/sdk_version.py; do not edit by hand.",\n'
        '  "entries": {\n' + ",\n".join(lines) + "\n  }\n}\n"
    )


def parse_surface(text: str) -> dict[str, dict[str, Any]]:
    data = json.loads(text)
    if data.get("format") != SURFACE_FORMAT:
        raise SystemExit(f"Unknown SDK surface format {data.get('format')!r}")
    return data["entries"]


# --------------------------------------------------------------------------
# Comparing two surfaces


@dataclass
class SurfaceDiff:
    added: list[str] = field(default_factory=list)
    extended: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)

    @property
    def breaking(self) -> list[str]:
        return sorted(self.removed + self.changed)


_POSITIONAL = ("POSITIONAL_ONLY", "POSITIONAL_OR_KEYWORD")


def params_compatible(old: list[list[Any]], new: list[list[Any]]) -> bool:
    """Every call that worked against ``old`` still works against ``new``.

    Positional parameters keep their order, name and kind; a new one comes last
    and has a default. A keyword-only parameter keeps its name; a new one has a
    default. A parameter may gain a default but never lose one, and ``*args``
    and ``**kwargs`` stay.
    """
    old_pos = [p for p in old if p[1] in _POSITIONAL]
    new_pos = [p for p in new if p[1] in _POSITIONAL]
    if len(new_pos) < len(old_pos):
        return False
    for before, after in zip(old_pos, new_pos, strict=False):
        if before[0] != after[0] or before[1] != after[1] or (before[2] and not after[2]):
            return False
    if not all(p[2] for p in new_pos[len(old_pos) :]):
        return False
    old_kw = {p[0]: p for p in old if p[1] == "KEYWORD_ONLY"}
    new_kw = {p[0]: p for p in new if p[1] == "KEYWORD_ONLY"}
    new_by_name = {p[0]: p for p in new}
    for name, before in old_kw.items():
        after = new_by_name.get(name)
        if after is None or after[1] not in ("KEYWORD_ONLY", "POSITIONAL_OR_KEYWORD"):
            return False
        if before[2] and not after[2]:
            return False
    if not all(p[2] for name, p in new_kw.items() if name not in old_kw):
        return False
    for kind in ("VAR_POSITIONAL", "VAR_KEYWORD"):
        if any(p[1] == kind for p in old) and not any(p[1] == kind for p in new):
            return False
    return True


def entry_compatible(old: Mapping[str, Any], new: Mapping[str, Any]) -> bool:
    """``new`` only adds to what ``old`` promised."""
    if old.get("kind") != new.get("kind"):
        return False
    if "params" in old:
        return params_compatible(old["params"], new.get("params", []))
    if "required" in old:
        # Required to optional relaxes; optional to required breaks.
        return not new["required"] or old["required"]
    return dict(old) == dict(new)


def _owner(key: str) -> str | None:
    module, _, name = key.partition(":")
    return f"{module}:{name.rsplit('.', 1)[0]}" if "." in name else None


def diff_surface(old: Mapping[str, Mapping], new: Mapping[str, Mapping]) -> SurfaceDiff:
    diff = SurfaceDiff()
    for key in sorted(set(old) | set(new)):
        if key not in new:
            diff.removed.append(key)
        elif key not in old:
            owner = _owner(key)
            # A new required field of a class that existed breaks its callers.
            if owner in old and new[key].get("kind") == "field" and new[key].get("required"):
                diff.changed.append(key)
            else:
                diff.added.append(key)
        elif dict(old[key]) != dict(new[key]):
            (diff.extended if entry_compatible(old[key], new[key]) else diff.changed).append(key)
    return diff


def required_bump(diff: SurfaceDiff, content_changed: bool) -> str | None:
    if diff.breaking:
        return "major"
    if diff.added or diff.extended:
        return "minor"
    if content_changed:
        return "patch"
    return None


def bump_failures(
    *,
    base: str,
    base_version: str,
    base_surface: Mapping[str, Mapping] | None,
    version: str,
    current_surface: Mapping[str, Mapping],
    content_changed: bool,
) -> list[str]:
    """Why ``version`` is not the SDK version the change since ``base`` needs."""
    if base_surface is None:
        # The first independent SDK version: the base release had no record yet.
        try:
            lower = parse_version(version) < parse_version(base_version)
        except ValueError as exc:
            return [str(exc)]
        if lower:
            return [f"the SDK version may not go down, from {base_version} ({base}) to {version}"]
        if version == base_version and content_changed:
            return [_unbumped(base, base_version, "patch", [])]
        return []
    try:
        step = version_step(base_version, version)
    except ValueError as exc:
        return [f"{exc} ({base_version} is the SDK version at {base})"]
    diff = diff_surface(base_surface, current_surface)
    needed = required_bump(diff, content_changed)
    if needed is None:
        if step is not None:
            return [
                f"the SDK version moved from {base_version} ({base}) to {version}, but nothing "
                f"in {rel(SDK_DIR)} changed: keep {base_version}, so one SDK version is one wheel"
            ]
        return []
    if step is None:
        return [_unbumped(base, base_version, needed, diff.breaking or diff.added + diff.extended)]
    if BUMPS.index(step) < BUMPS.index(needed):
        listed = diff.breaking if needed == "major" else diff.added + diff.extended
        return [
            f"the SDK change since {base} needs a {needed} version ({next_version(base_version, needed)}), "
            f"not {version}: {_reason(needed)}" + "".join(f"\n  {key}" for key in listed[:40])
        ]
    return []


def _reason(bump: str) -> str:
    return {
        "major": "the public surface lost or changed these (a major is an ABI change; "
        "prefer keeping the old name working and adding a new one)",
        "minor": "the public surface gained these",
        "patch": f"files in {rel(SDK_DIR)} changed",
    }[bump]


def _unbumped(base: str, base_version: str, needed: str, keys: list[str]) -> str:
    return (
        f"the SDK changed since {base} but its version is still {base_version}: "
        f"{_reason(needed)}. Run `uv run python scripts/sdk_version.py bump {needed}` "
        "and `uv lock`" + "".join(f"\n  {key}" for key in keys[:40])
    )


# --------------------------------------------------------------------------
# git


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed arguments, no shell
        ["git", "-C", str(ROOT), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )


def latest_release_tag() -> str:
    """The newest ``vX.Y.Z`` tag in HEAD's history: what was last published."""
    listed = _git("tag", "--merged", "HEAD", "--list", "v*")
    if listed.returncode != 0:
        raise SystemExit(f"Could not list the release tags: {listed.stderr.strip()}")
    tags = [tag for tag in listed.stdout.split() if VERSION.fullmatch(tag[1:])]
    if not tags:
        raise SystemExit(
            "Found no release tag in HEAD's history to compare the SDK with; fetch the "
            "tags (actions/checkout with fetch-depth: 0) or pass --base"
        )
    return max(tags, key=lambda tag: parse_version(tag[1:]))


def _show(ref: str, path: str) -> str | None:
    listed = _git("ls-tree", "--name-only", ref, "--", path)
    if listed.returncode != 0:
        raise SystemExit(f"Could not read {ref}: {listed.stderr.strip()}")
    if not listed.stdout.strip():
        return None
    shown = _git("show", f"{ref}:{path}")
    if shown.returncode != 0:
        raise SystemExit(f"Could not read {path} at {ref}: {shown.stderr.strip()}")
    return shown.stdout


def normalized_sdk_file(path: str, text: str) -> str:
    """``text`` without the version lines, which a bump itself changes."""
    if path == rel(SDK_PYPROJECT):
        return _PROJECT_VERSION.sub("", text, count=1)
    if path == rel(SDK_VERSION_FILE):
        text = _DUNDER_VERSION.sub("", text, count=1)
        return _ABI_VERSION.sub("", text, count=1)
    return text


def sdk_files_at(ref: str) -> dict[str, str]:
    listed = _git("ls-tree", "-r", "--name-only", ref, "--", rel(SDK_DIR))
    if listed.returncode != 0:
        raise SystemExit(f"Could not list {rel(SDK_DIR)} at {ref}: {listed.stderr.strip()}")
    return {path: _show(ref, path) or "" for path in listed.stdout.split()}


def sdk_files_now() -> dict[str, str]:
    listed = _git("ls-files", "--cached", "--others", "--exclude-standard", "--", rel(SDK_DIR))
    if listed.returncode != 0:
        raise SystemExit(f"Could not list {rel(SDK_DIR)}: {listed.stderr.strip()}")
    return {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in listed.stdout.split()
        if (ROOT / path).is_file()
    }


def sdk_content_changed(before: Mapping[str, str], after: Mapping[str, str]) -> bool:
    """Whether the SDK's files differ, apart from the version lines."""
    surface_path = rel(SDK_SURFACE_FILE)
    keys = (set(before) | set(after)) - {surface_path}
    return any(
        normalized_sdk_file(path, before.get(path, "\0missing"))
        != normalized_sdk_file(path, after.get(path, "\0missing"))
        for path in keys
    )


# --------------------------------------------------------------------------
# Commands


def surface_file_failures() -> list[str]:
    if not SDK_SURFACE_FILE.is_file():
        return [
            f"{rel(SDK_SURFACE_FILE)} is missing; run `uv run python scripts/sdk_version.py write`"
        ]
    recorded = parse_surface(SDK_SURFACE_FILE.read_text(encoding="utf-8"))
    current = surface()
    if recorded == current:
        return []
    diff = diff_surface(recorded, current)
    changes = [f"+ {k}" for k in diff.added + diff.extended] + [f"- {k}" for k in diff.breaking]
    return [
        f"{rel(SDK_SURFACE_FILE)} does not match the code; run "
        "`uv run python scripts/sdk_version.py write` and bump the SDK version as the "
        "check then says" + "".join(f"\n  {line}" for line in changes[:40])
    ]


def check(base: str | None = None) -> list[str]:
    """Every failure of the SDK's version against the code and the last release."""
    failures = consistency_failures() + surface_file_failures()
    if failures:
        return failures
    ref = base or latest_release_tag()
    base_pyproject = _show(ref, rel(SDK_PYPROJECT))
    match = _PROJECT_VERSION.search(base_pyproject or "")
    if match is None:
        return [f"{rel(SDK_PYPROJECT)} at {ref} has no version"]
    base_surface_text = _show(ref, rel(SDK_SURFACE_FILE))
    return bump_failures(
        base=ref,
        base_version=match.group(1),
        base_surface=parse_surface(base_surface_text) if base_surface_text else None,
        version=read_sdk_version(),
        current_surface=parse_surface(SDK_SURFACE_FILE.read_text(encoding="utf-8")),
        content_changed=sdk_content_changed(sdk_files_at(ref), sdk_files_now()),
    )


def write_surface() -> None:
    SDK_SURFACE_FILE.write_text(render_surface(surface()), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n", 1)[0])
    commands = parser.add_subparsers(dest="command")
    check_parser = commands.add_parser("check", help="Check the SDK version (the default)")
    check_parser.add_argument("--base", help="Compare with this ref, not the newest release tag")
    commands.add_parser("write", help="Rewrite the surface file from the code")
    bump_parser = commands.add_parser("bump", help="Set the next SDK version")
    bump_parser.add_argument("bump", choices=BUMPS)
    set_parser = commands.add_parser("set", help="Set the SDK version to X.Y.Z")
    set_parser.add_argument("version")
    args = parser.parse_args()

    if args.command == "write":
        write_surface()
        return
    if args.command in ("bump", "set"):
        current = read_sdk_version()
        version = next_version(current, args.bump) if args.command == "bump" else args.version
        parse_version(version)
        write_version(version)
        write_surface()
        print(f"hegemony-step-sdk {current} -> {version}; now run `uv lock`")
        return
    failures = check(getattr(args, "base", None))
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"hegemony-step-sdk {read_sdk_version()}: version matches the change")


if __name__ == "__main__":
    main()
