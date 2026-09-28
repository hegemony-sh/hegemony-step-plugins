# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Sibling wheels release in lockstep: set_version pins them, the verifier insists."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _script(name: str):
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPTS))


PYPROJECT = """\
[project]
name = "hegemony-steps-tf"
version = "0.5.0"
dependencies = [
    "hegemony-step-sdk==0.5.0",
    "hegemony-steps-container==0.5.0",
    "hegemony-steps-probes>=0.4.0,<0.6",
    "hegemony-transport-netmiko >= 0.2 ; python_version >= '3.11'",
    "hegemony-steps-extra[docker]>=0.4",
    "Hegemony_Steps_Legacy>=0.1",
    "pydantic>=2",
]

[tool.uv.sources]
hegemony-steps-container = { workspace = true }
"""


def test_set_version_pins_every_sibling_constraint_exactly():
    pinned = _script("set_version").set_sibling_pins(PYPROJECT, "0.6.0")

    assert '"hegemony-steps-container==0.6.0"' in pinned
    assert '"hegemony-steps-probes==0.6.0"' in pinned
    # A marker after the constraint is kept.
    assert "\"hegemony-transport-netmiko==0.6.0; python_version >= '3.11'\"" in pinned
    assert '"hegemony-steps-extra[docker]==0.6.0"' in pinned
    assert '"Hegemony_Steps_Legacy==0.6.0"' in pinned
    # The package's own name, the SDK pin (set elsewhere), other packages and
    # the uv source key are left alone.
    assert 'name = "hegemony-steps-tf"' in pinned
    assert '"hegemony-step-sdk==0.5.0"' in pinned
    assert '"pydantic>=2"' in pinned
    assert "hegemony-steps-container = { workspace = true }" in pinned


@pytest.mark.parametrize(
    ("dependency", "ok"),
    [
        ("hegemony-steps-container==0.6.0", True),
        ("hegemony-steps-container == 0.6.0", True),
        ("hegemony-steps-container==0.6.0 ; python_version >= '3.11'", True),
        ("hegemony-steps-container==0.5.0", False),
        ("hegemony-steps-container>=0.2.0", False),
        ("hegemony-steps-container>=0.6.0,<0.7", False),
        ("hegemony-steps-container", False),
        ("hegemony-steps-container[docker]==0.6.0", True),
        ("hegemony-steps-container[docker]>=0.1", False),
        ("Hegemony_Steps_Container>=0.1", False),
        ("hegemony.steps.container==0.6.0", True),
        ("hegemony-step-sdk>=0.1", True),  # the SDK pin is checked on its own
        ("pydantic>=2", True),
    ],
)
def test_the_verifier_insists_on_an_exact_sibling_pin(dependency, ok):
    failure = _script("verify_release_version").sibling_pin_failure(
        "hegemony-steps-tf", dependency, "0.6.0"
    )
    assert (failure is None) is ok, failure


def test_set_version_moves_the_runner_image_to_the_release_minor():
    text = (
        'DEFAULT_IMAGE = "ghcr.io/hegemony-sh/ansible-runner:0.6"\n'
        "docker pull ghcr.io/hegemony-sh/ansible-runner:0.6 # and again\n"
        "registry.example.com/ansible-runner:0.6 stays\n"
        "The default is ghcr.io/hegemony-sh/ansible-runner:0.6.\n"
        "Exact ghcr.io/hegemony-sh/ansible-runner:0.6.2 is not the default's form.\n"
    )
    moved = _script("set_version").set_runner_image_tag(text, "0.7.1")

    assert 'DEFAULT_IMAGE = "ghcr.io/hegemony-sh/ansible-runner:0.7"' in moved
    assert "docker pull ghcr.io/hegemony-sh/ansible-runner:0.7 # and again" in moved
    # Only the first-party image moves.
    assert "registry.example.com/ansible-runner:0.6 stays" in moved
    # A tag ending a sentence moves; a full version does not.
    assert "The default is ghcr.io/hegemony-sh/ansible-runner:0.7.\n" in moved
    assert "ghcr.io/hegemony-sh/ansible-runner:0.6.2 is not" in moved


@pytest.mark.parametrize(
    ("text", "ok"),
    [
        ("ghcr.io/hegemony-sh/ansible-runner:0.7 and ghcr.io/hegemony-sh/ansible-runner:0.7", True),
        ("no image named at all", True),
        ("ghcr.io/hegemony-sh/ansible-runner:0.6", False),
        ("ghcr.io/hegemony-sh/ansible-runner:0.7.1", False),
    ],
)
def test_the_verifier_insists_on_the_release_minor_image_tag(text, ok):
    failures = _script("verify_release_version").runner_image_failures("f", text, "0.7.1")

    assert (failures == []) is ok


def test_the_default_runner_image_names_the_current_minor_version():
    """Between releases too: the release commit moves both together."""
    import tomllib

    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads(
        (root / "plugins" / "steps_ansible" / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    verifier = _script("verify_release_version")
    paths = _script("package_paths")

    failures = [
        failure
        for path in paths.RUNNER_IMAGE_FILES
        for failure in verifier.runner_image_failures(
            path, path.read_text(encoding="utf-8"), project["version"]
        )
    ]
    assert failures == []
