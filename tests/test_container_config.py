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
