# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The SDK's own version: the surface record, the bump rules and the pins per wheel kind."""

from __future__ import annotations

import importlib.util
import sys
import tomllib
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _script(name: str):
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # Registered first: the script's dataclasses look their module up.
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPTS))


sdk_version = _script("sdk_version")
paths = _script("package_paths")


# --------------------------------------------------------------------------
# The tree as it is


def test_the_surface_file_matches_the_code():
    """A change of the public surface shows in api-surface.json; run `sdk_version.py write`."""
    assert sdk_version.surface_file_failures() == []


def test_the_sdk_version_agrees_with_itself_and_with_the_abi_version():
    import hegemony_step_sdk as sdk

    assert sdk_version.consistency_failures() == []
    assert sdk.__version__ == sdk_version.read_sdk_version()
    assert int(sdk.__version__.split(".")[0]) == sdk.SDK_ABI_VERSION


def test_every_wheel_pins_the_sdk_in_the_form_its_kind_takes():
    def read(package_dir):
        project = tomllib.loads((package_dir / "pyproject.toml").read_text(encoding="utf-8"))
        return project["project"]["name"], project["project"]["dependencies"]

    assert sdk_version.pin_failures(read) == []


def test_the_wheel_kinds_are_sorted_into_exact_and_range_pins():
    exact = {path.name for path in paths.SDK_EXACT_PIN_DIRS}
    assert exact == {
        "transport_support",
        "transport_netmiko",
        "transport_scrapli",
        "transport_asyncssh",
        "transport_napalm",
    }
    ranged = {path.parent.name for path in paths.SDK_RANGE_PIN_DIRS}
    assert ranged == {"plugins", "probes"}
    assert set(paths.SDK_EXACT_PIN_DIRS) | set(paths.SDK_RANGE_PIN_DIRS) == set(paths.PLUGIN_DIRS)
    assert paths.SDK_DIR not in paths.RELEASE_DIRS


def test_the_surface_covers_the_contract_plugins_use():
    entries = sdk_version.surface()
    for key in (
        "hegemony_step_sdk:BaseHandler.execute",
        "hegemony_step_sdk:HandlerServices.connect",
        "hegemony_step_sdk:StepKind.ACTION",
        "hegemony_step_sdk:SDK_ABI_VERSION",
        "hegemony_step_sdk.ssh:SshSecurityConfig",
        "hegemony_step_sdk.trust:CONTAINER_CA_BUNDLE",
        "hegemony_step_sdk.docs:load_docs_bundle",
    ):
        assert key in entries, key
    # Private names and what pydantic or typing define stay out.
    private = [key for key in entries if ":_" in key or "._" in key.replace(".__init__", "")]
    assert private == ["hegemony_step_sdk:__version__"]  # exported in __all__
    assert "hegemony_step_sdk.ssh:SshSecurityConfig.model_validate" not in entries


# --------------------------------------------------------------------------
# Versions and pins


@pytest.mark.parametrize(
    ("old", "new", "step"),
    [
        ("1.0.0", "1.0.0", None),
        ("1.0.0", "1.0.1", "patch"),
        ("1.0.3", "1.1.0", "minor"),
        ("1.4.3", "2.0.0", "major"),
        ("0.55.0", "1.0.0", "major"),
    ],
)
def test_a_version_step(old, new, step):
    assert sdk_version.version_step(old, new) == step


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("1.0.0", "1.2.0", "does not follow"),
        ("1.0.0", "1.0.2", "does not follow"),
        ("1.1.0", "1.0.9", "may not go down"),
        ("1.0.0", "1.1", "not an X.Y.Z version"),
    ],
)
def test_a_version_that_skips_or_goes_down_is_refused(old, new, message):
    with pytest.raises(ValueError, match=message):
        sdk_version.version_step(old, new)


def test_the_pin_forms():
    assert sdk_version.range_pin("1.4.2") == "hegemony-step-sdk>=1.4,<2"
    assert sdk_version.exact_pin("1.4.2") == "hegemony-step-sdk==1.4.2"


def test_setting_the_sdk_requirement_keeps_a_marker_and_wants_exactly_one():
    text = "dependencies = [\n    \"hegemony-step-sdk==0.55.0 ; python_version >= '3.11'\",\n]\n"
    replaced = sdk_version.set_sdk_requirement(text, "hegemony-step-sdk>=1.0,<2")
    assert "\"hegemony-step-sdk>=1.0,<2; python_version >= '3.11'\"" in replaced
    with pytest.raises(SystemExit, match="expected one"):
        sdk_version.set_sdk_requirement('dependencies = ["pydantic>=2"]', "x")
    with pytest.raises(SystemExit, match="expected one"):
        sdk_version.set_sdk_requirement('["hegemony-step-sdk>=1", "hegemony_step_sdk<3"]', "x")


def test_the_sdk_requirement_is_found_whitespace_removed():
    found = sdk_version.sdk_requirement(["pydantic>=2", "hegemony-step-sdk >= 1.0, < 2"])
    assert found == "hegemony-step-sdk>=1.0,<2"
    assert sdk_version.sdk_requirement(["hegemony-steps-http==1"]) is None


def test_write_pins_gives_each_kind_its_form(tmp_path, monkeypatch):
    step = tmp_path / "plugins" / "steps_x"
    transport = tmp_path / "transports" / "transport_x"
    for package in (step, transport):
        package.mkdir(parents=True)
        (package / "pyproject.toml").write_text(
            '[project]\ndependencies = ["hegemony-step-sdk==0.55.0", "hegemony-steps-http==0.55.0"]\n',
            encoding="utf-8",
        )
    monkeypatch.setattr(sdk_version, "PLUGIN_DIRS", (step, transport))
    monkeypatch.setattr(sdk_version, "SDK_EXACT_PIN_DIRS", (transport,))

    sdk_version.write_pins("1.2.3")

    assert '"hegemony-step-sdk>=1.2,<2"' in (step / "pyproject.toml").read_text(encoding="utf-8")
    transport_text = (transport / "pyproject.toml").read_text(encoding="utf-8")
    assert '"hegemony-step-sdk==1.2.3"' in transport_text
    # Sibling pins are the release's business (set_version.py), not this one's.
    assert '"hegemony-steps-http==0.55.0"' in transport_text


# --------------------------------------------------------------------------
# Comparing surfaces


def _fn(*params):
    return {"kind": "function", "params": [list(p) for p in params]}


POS = "POSITIONAL_OR_KEYWORD"
KW = "KEYWORD_ONLY"


@pytest.mark.parametrize(
    ("old", "new", "ok"),
    [
        # A new parameter with a default, last or keyword-only, is an addition.
        ([("a", POS, False)], [("a", POS, False), ("b", POS, True)], True),
        ([("a", POS, False)], [("a", POS, False), ("b", KW, True)], True),
        # Gaining a default relaxes; losing one breaks.
        ([("a", POS, False)], [("a", POS, True)], True),
        ([("a", POS, True)], [("a", POS, False)], False),
        # A new required parameter, a rename, a reorder or a removal breaks.
        ([("a", POS, False)], [("a", POS, False), ("b", POS, False)], False),
        ([("a", POS, False)], [("a", POS, False), ("b", KW, False)], False),
        ([("a", POS, False)], [("x", POS, False)], False),
        ([("a", POS, False), ("b", POS, False)], [("b", POS, False), ("a", POS, False)], False),
        ([("a", POS, False), ("b", POS, True)], [("a", POS, False)], False),
        # A keyword-only parameter may become positional-or-keyword, not go.
        ([("a", KW, True)], [("a", POS, True)], True),
        ([("a", KW, True)], [], False),
        # **kwargs stays.
        ([("kw", "VAR_KEYWORD", False)], [], False),
        # A new positional slot ahead of an existing *args captures an argument
        # *args used to take: f(*args, x=1) -> f(x=1, *args) breaks f(5, x=9).
        (
            [("args", "VAR_POSITIONAL", False), ("x", KW, True)],
            [("x", POS, True), ("args", "VAR_POSITIONAL", False)],
            False,
        ),
        (
            [("a", POS, False), ("args", "VAR_POSITIONAL", False)],
            [("a", POS, False), ("b", POS, True), ("args", "VAR_POSITIONAL", False)],
            False,
        ),
        # Without *args, a trailing optional positional stays an addition.
        (
            [("a", POS, False), ("x", KW, True)],
            [("a", POS, False), ("b", POS, True), ("x", KW, True)],
            True,
        ),
    ],
)
def test_which_signature_changes_are_compatible(old, new, ok):
    assert sdk_version.entry_compatible(_fn(*old), _fn(*new)) is ok


def test_a_surface_diff_sorts_additions_from_breaks():
    old = {
        "m:A": {"kind": "class"},
        "m:A.f": {"kind": "field", "required": False},
        "m:A.g": {"kind": "field", "required": False},
        "m:A.run": _fn(("self", POS, False)),
        "m:K": {"kind": "constant", "type": "int"},
        "m:Gone": {"kind": "class"},
    }
    new = {
        "m:A": {"kind": "class"},
        "m:A.f": {"kind": "field", "required": False},
        "m:A.g": {"kind": "field", "required": True},  # optional to required
        "m:A.h": {"kind": "field", "required": True},  # a new required field
        "m:A.i": {"kind": "field", "required": False},
        "m:A.run": _fn(("self", POS, False), ("x", KW, True)),
        "m:K": {"kind": "constant", "type": "str"},
        "m:B": {"kind": "class"},
        "m:B.h": {"kind": "field", "required": True},  # a new class may need it
    }

    diff = sdk_version.diff_surface(old, new)

    assert diff.added == ["m:A.i", "m:B", "m:B.h"]
    assert diff.extended == ["m:A.run"]
    assert diff.removed == ["m:Gone"]
    assert sorted(diff.changed) == ["m:A.g", "m:A.h", "m:K"]


def test_the_internal_transport_interface_changes_with_a_minor():
    """The device-transport interface has no stability promise: only the built-in
    transports use it, and they pin the SDK exactly."""
    old = {
        "hegemony_step_sdk.transports:DeviceConnectionSpec": {"kind": "class"},
        "hegemony_step_sdk.transports:DeviceConnectionSpec.host": {
            "kind": "field",
            "required": True,
        },
        "hegemony_step_sdk:TransportRegistry": {"kind": "class"},
        "hegemony_step_sdk.transports:JumpHostSpec.host": {"kind": "field", "required": True},
    }
    new = {
        "hegemony_step_sdk.transports:DeviceConnectionSpec": {"kind": "class"},
        "hegemony_step_sdk.transports:DeviceConnectionSpec.address": {
            "kind": "field",
            "required": True,
        },
    }

    diff = sdk_version.diff_surface(old, new)

    # A new required field of an internal class is an internal change too.
    assert diff.internal == [
        "hegemony_step_sdk.transports:DeviceConnectionSpec.address",
        "hegemony_step_sdk.transports:DeviceConnectionSpec.host",
        "hegemony_step_sdk:TransportRegistry",
    ]
    assert diff.changed == []
    # JumpHostSpec is part of the handler contract: removing a field breaks.
    assert diff.removed == ["hegemony_step_sdk.transports:JumpHostSpec.host"]
    assert sdk_version.required_bump(diff, True) == "major"
    del old["hegemony_step_sdk.transports:JumpHostSpec.host"]
    assert sdk_version.required_bump(sdk_version.diff_surface(old, new), True) == "minor"


def test_the_internal_names_are_the_ones_the_transports_module_declares():
    import hegemony_step_sdk.transports as transports

    doc = transports.__doc__ or ""
    for name in sdk_version.INTERNAL_NAMES - {"TRANSPORT_ENTRY_POINT_GROUP"}:
        assert f":class:`{name}`" in doc, name
    assert "hegemony.device_transports" in doc
    assert not {"DeviceCredentials", "JumpHostSpec"} & sdk_version.INTERNAL_NAMES


def test_a_new_obligation_on_an_existing_class_breaks():
    """What existing implementations lack: a required protocol attribute, a new
    abstract method, a concrete method made abstract."""
    run = _fn(("self", POS, False))
    abstract_run = {**run, "abstract": True}
    old = {
        "m:Result": {"kind": "class"},
        "m:Base": {"kind": "class"},
        "m:Base.run": run,
    }
    new = {
        "m:Result": {"kind": "class"},
        "m:Result.latency_ms": {"kind": "attribute", "required": True},
        "m:Result.note": {"kind": "attribute", "required": False},
        "m:Base": {"kind": "class"},
        "m:Base.run": abstract_run,
        "m:Base.check": {**_fn(("self", POS, False)), "abstract": True},
        "m:Base.helper": _fn(("self", POS, False)),
    }

    diff = sdk_version.diff_surface(old, new)

    assert diff.changed == ["m:Base.check", "m:Base.run", "m:Result.latency_ms"]
    assert diff.added == ["m:Base.helper", "m:Result.note"]
    assert sdk_version.required_bump(diff, True) == "major"
    # An abstract method that becomes concrete only relaxes.
    relaxed = sdk_version.diff_surface({"m:Base.run": abstract_run}, {"m:Base.run": run})
    assert relaxed.extended == ["m:Base.run"] and relaxed.breaking == []


def test_the_surface_records_the_abstract_methods_subclasses_implement():
    entries = sdk_version.surface()
    assert entries["hegemony_step_sdk:BaseHandler.execute"].get("abstract") is True
    assert entries["hegemony_step_sdk:BaseProbe.execute"].get("abstract") is True
    assert "abstract" not in entries["hegemony_step_sdk:BaseHandler.parse_config"]


def test_nested_public_modules_are_recorded(monkeypatch):
    from types import SimpleNamespace

    found = [
        SimpleNamespace(name="hegemony_step_sdk.ssh"),
        SimpleNamespace(name="hegemony_step_sdk.helpers"),
        SimpleNamespace(name="hegemony_step_sdk.helpers.codec"),
        SimpleNamespace(name="hegemony_step_sdk._private.codec"),
        SimpleNamespace(name="hegemony_step_sdk.helpers._impl"),
    ]
    monkeypatch.setattr(sdk_version.pkgutil, "walk_packages", lambda path, prefix: iter(found))

    assert sdk_version.public_modules() == [
        "hegemony_step_sdk",
        "hegemony_step_sdk.helpers",
        "hegemony_step_sdk.helpers.codec",
        "hegemony_step_sdk.ssh",
    ]


def test_verifying_a_tagged_release_compares_with_the_release_before(monkeypatch):
    import subprocess

    def fake_git(*args):
        return subprocess.CompletedProcess(args, 0, stdout="v0.55.0\nv0.56.0\nv0.57.0\n", stderr="")

    monkeypatch.setattr(sdk_version, "_git", fake_git)
    assert sdk_version.latest_release_tag() == "v0.57.0"
    assert sdk_version.latest_release_tag(before="0.57.0") == "v0.56.0"
    with pytest.raises(SystemExit, match="Found no release tag"):
        sdk_version.latest_release_tag(before="0.55.0")


# --------------------------------------------------------------------------
# The bump a change needs

BASE = {"m:A": {"kind": "class"}, "m:A.run": _fn(("self", POS, False))}
ADDED = {**BASE, "m:B": {"kind": "class"}}
REMOVED = {"m:A": {"kind": "class"}}


def _failures(version, current, *, content_changed=True, base_surface=BASE, base_version="1.2.3"):
    return sdk_version.bump_failures(
        base="v0.60.0",
        base_version=base_version,
        base_surface=base_surface,
        version=version,
        current_surface=current,
        content_changed=content_changed,
    )


def test_no_change_keeps_the_version():
    assert _failures("1.2.3", BASE, content_changed=False) == []
    (failure,) = _failures("1.2.4", BASE, content_changed=False)
    assert "nothing in packages/step_sdk changed: keep 1.2.3" in failure


def test_a_change_inside_the_sdk_needs_at_least_a_patch():
    (failure,) = _failures("1.2.3", BASE)
    assert "its version is still 1.2.3" in failure
    assert "bump patch" in failure
    assert _failures("1.2.4", BASE) == []
    # A larger bump than needed is the author's choice (a behaviour change the
    # surface cannot show).
    assert _failures("1.3.0", BASE) == []


def test_an_addition_needs_a_minor():
    (failure,) = _failures("1.2.3", ADDED)
    assert "bump minor" in failure and "m:B" in failure
    (failure,) = _failures("1.2.4", ADDED)
    assert "needs a minor version (1.3.0), not 1.2.4" in failure
    assert _failures("1.3.0", ADDED) == []


def test_a_removal_needs_a_major():
    (failure,) = _failures("1.3.0", REMOVED)
    assert "needs a major version (2.0.0)" in failure and "m:A.run" in failure
    assert _failures("2.0.0", REMOVED) == []


def test_a_skipped_or_lower_version_is_refused():
    (failure,) = _failures("1.4.0", ADDED)
    assert "does not follow 1.2.3" in failure and "v0.60.0" in failure
    (failure,) = _failures("1.2.2", BASE)
    assert "may not go down" in failure


def test_the_first_independent_version_needs_only_to_be_higher():
    assert _failures("1.0.0", BASE, base_surface=None, base_version="0.55.0") == []
    (failure,) = _failures("0.54.0", BASE, base_surface=None, base_version="0.55.0")
    assert "may not go down" in failure
    (failure,) = _failures("0.55.0", BASE, base_surface=None, base_version="0.55.0")
    assert "still 0.55.0" in failure
    assert (
        _failures("0.55.0", BASE, base_surface=None, base_version="0.55.0", content_changed=False)
        == []
    )


def test_the_version_lines_alone_are_no_content_change():
    pyproject = paths.SDK_PYPROJECT.relative_to(paths.ROOT).as_posix()
    version_file = paths.SDK_VERSION_FILE.relative_to(paths.ROOT).as_posix()
    before = {
        pyproject: '[project]\nversion = "0.55.0"\ndependencies = ["pydantic>=2.7"]\n',
        version_file: '__version__ = "0.55.0"\nSDK_ABI_VERSION = 1\n',
        "packages/step_sdk/src/x.py": "A = 1\n",
    }
    bumped = {
        pyproject: '[project]\nversion = "1.0.0"\ndependencies = ["pydantic>=2.7"]\n',
        version_file: '__version__ = "1.0.0"\nSDK_ABI_VERSION = 2\n',
        "packages/step_sdk/src/x.py": "A = 1\n",
    }
    assert not sdk_version.sdk_content_changed(before, bumped)
    assert sdk_version.sdk_content_changed(before, {**bumped, "packages/step_sdk/src/x.py": "A=2"})
    assert sdk_version.sdk_content_changed(before, {**bumped, "packages/step_sdk/src/y.py": ""})
    deps = {**bumped, pyproject: bumped[pyproject].replace("2.7", "2.8")}
    assert sdk_version.sdk_content_changed(before, deps)


def test_check_compares_with_the_newest_release_tag(monkeypatch):
    recorded = sdk_version.parse_surface(paths.SDK_SURFACE_FILE.read_text(encoding="utf-8"))
    version = sdk_version.read_sdk_version()
    pyproject = paths.SDK_PYPROJECT.relative_to(paths.ROOT).as_posix()
    surface_file = paths.SDK_SURFACE_FILE.relative_to(paths.ROOT).as_posix()
    shown = {
        pyproject: f'[project]\nversion = "{version}"\n',
        surface_file: sdk_version.render_surface(recorded),
    }
    monkeypatch.setattr(sdk_version, "latest_release_tag", lambda before=None: "v9.9.9")
    monkeypatch.setattr(sdk_version, "_show", lambda ref, path: shown.get(path))
    monkeypatch.setattr(sdk_version, "sdk_files_at", lambda ref: {"a": "1"})
    monkeypatch.setattr(sdk_version, "sdk_files_now", lambda: {"a": "1"})
    assert sdk_version.check() == []

    # One entry fewer at the release: this tree added it without a bump.
    shown[surface_file] = sdk_version.render_surface(dict(list(recorded.items())[1:]))
    monkeypatch.setattr(sdk_version, "sdk_files_now", lambda: {"a": "2"})
    (failure,) = sdk_version.check()
    assert "changed since v9.9.9" in failure and "bump minor" in failure
