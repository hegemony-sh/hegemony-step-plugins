# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""container.run config validation of optional-with-default fields.

The path and mode fields default to "" and the handler resolves that to a
documented default at run time, so validation must treat "" the same as
absent. Otherwise a step that only fills in image + command (leaving the
optional paths/modes at their empty defaults) fails against its own defaults.
"""

from __future__ import annotations

import pytest

from hegemony_steps_container.run import RunContainerHandler


def _errors(config: dict) -> list[str]:
    return RunContainerHandler().validate_config(config)


def test_bare_image_and_command_is_valid() -> None:
    assert _errors({"image": "alpine:3.20", "command": ["echo hi"]}) == []


def test_empty_optional_paths_and_modes_use_defaults() -> None:
    # Exactly the shape the editor sends for a step that only set image +
    # command: every optional path/mode present but empty.
    config = {
        "image": "alpine:3.20",
        "command": ["ping", "-c1", "::1"],
        "attachments_path": "",
        "artifacts_path": "",
        "new_artifacts_path": "",
        "step_outputs_path": "",
        "shared_path": "",
        "working_dir": "",
        "network_mode": "",
        "pid_mode": "",
    }
    assert _errors(config) == []


def test_whitespace_is_treated_as_unset() -> None:
    assert _errors({"image": "alpine:3.20", "attachments_path": "   "}) == []


def test_nonempty_optional_fields_are_still_validated() -> None:
    # A provided value is still checked — a relative path and a bogus mode fail.
    errors = _errors(
        {"image": "alpine:3.20", "attachments_path": "relative/path", "pid_mode": "bogus"}
    )
    assert any("absolute path" in e for e in errors)
    assert any("pid_mode" in e for e in errors)


# ── templates in a step with host-access options ─────────────────────────────

_HOST_ACCESS = [
    {"privileged": True},
    {"attach_docker_socket": True},
    {"network_mode": "host"},
    {"pid_mode": "host"},
    {"extra_mounts": ["/srv/data:/data:ro"]},
    {"privileged": "{{ inputs.privileged }}"},
]


def test_host_access_options_are_the_admin_only_fields() -> None:
    from hegemony_steps_container.run import _HOST_ACCESS_FIELDS

    assert set(_HOST_ACCESS_FIELDS) == {
        "privileged",
        "attach_docker_socket",
        "network_mode",
        "pid_mode",
        "extra_mounts",
    }


@pytest.mark.parametrize("options", _HOST_ACCESS)
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command", ["echo {{ inputs.name }}"]),
        ("command", ["{% if inputs.x %}rm -rf /data{% endif %}"]),
        ("entrypoint", "{{ inputs.shell }}"),
        ("entrypoint", ["/bin/sh", "-c", "{{ inputs.script }}"]),
    ],
)
def test_templates_in_the_command_of_a_host_access_step_are_refused(options, field, value) -> None:
    errors = RunContainerHandler().template_errors({"image": "alpine", field: value, **options})
    assert len(errors) == 1
    assert errors[0].startswith(f"{field} cannot hold")
    assert next(iter(options)) in errors[0]


def test_values_reach_a_host_access_step_through_environment_variables() -> None:
    config = {
        "image": "alpine",
        "command": ['echo "$NAME"'],
        "env": {"NAME": "{{ inputs.name }}"},
        "privileged": True,
    }
    assert RunContainerHandler().template_errors(config) == []


@pytest.mark.parametrize(
    "options",
    [{}, {"privileged": False}, {"network_mode": "  "}, {"extra_mounts": []}, {"pid_mode": ""}],
)
def test_templates_stay_allowed_without_host_access(options) -> None:
    config = {"image": "alpine", "command": ["echo {{ inputs.name }}"], **options}
    assert RunContainerHandler().template_errors(config) == []


def test_cache_image_takes_a_rendered_boolean() -> None:
    # A templated switch is rendered as text before the step runs.
    for value in (True, False, "true", "false", "False", "0"):
        assert _errors({"image": "alpine:3.20", "cache_image": value}) == [], value
    assert _errors({"image": "alpine:3.20", "cache_image": "maybe"}) == [
        "'cache_image' must be true or false"
    ]
