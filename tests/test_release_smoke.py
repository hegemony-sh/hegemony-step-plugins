# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The release smoke test knows every package's modules and entry points."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def _smoke_module():
    sys.path.insert(0, str(SCRIPTS))
    try:
        spec = importlib.util.spec_from_file_location(
            "smoke_install_wheels", SCRIPTS / "smoke_install_wheels.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPTS))


def test_the_smoke_test_expects_every_packages_modules_and_entry_points():
    smoke = _smoke_module()
    assert smoke.source_gaps() == []
    assert {"hegemony_steps_ansible", "hegemony_steps_tf", "hegemony_steps_secret"} <= set(
        smoke.EXPECTED_MODULES
    )
    assert {"ansible", "tf", "secret"} <= smoke.EXPECTED_ENTRY_POINTS


def test_a_forgotten_entry_point_is_reported(monkeypatch):
    smoke = _smoke_module()
    monkeypatch.setattr(smoke, "EXPECTED_MODULES", ("hegemony_step_sdk",))
    monkeypatch.setitem(smoke._EXPECTED_BY_GROUP, "hegemony.step_handlers", {"general"})
    gaps = smoke.source_gaps()
    assert "EXPECTED_MODULES lacks hegemony_steps_tf" in gaps
    assert "expected entry points of hegemony.step_handlers lack 'tf'" in gaps
    assert "EXPECTED_MODULES lacks hegemony_steps_secret" in gaps
    assert "expected entry points of hegemony.step_handlers lack 'secret'" in gaps
