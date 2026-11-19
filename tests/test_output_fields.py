# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Every registered step handler declares its output keys (``output_fields``).

The flow editor's variable picker lists them for later steps. Each handler's
own tests check that the declaration matches what the step really outputs;
this module checks the declarations themselves, for every handler at once.
"""

from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path
from typing import Any

import pytest

from hegemony_step_sdk import OutputField
from hegemony_step_sdk.docs import load_docs_bundle

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"

#: The platform reads a name as dotted segments of letters, digits and
#: underscores; it skips any other (packages/core/step_handlers/registry.py).
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_TYPES = {"string", "int", "float", "bool", "object", "list"}
#: Handlers whose output is empty by design.
_NO_OUTPUT = {"general.noop", "general.sleep"}


def _handlers() -> list[tuple[str, Any]]:
    sys.path.insert(0, str(SCRIPTS))
    try:
        check_docs = importlib.import_module("check_docs")
    finally:
        sys.path.remove(str(SCRIPTS))
    return sorted(
        (
            (package, cls)
            for package, classes in check_docs.registered_handlers().items()
            for cls in classes
        ),
        key=lambda item: item[1].handler_id,
    )


HANDLERS = _handlers()


def test_every_plugin_handler_is_checked():
    # The download steps were first; this guards against an empty discovery.
    ids = {cls.handler_id for _, cls in HANDLERS}
    assert {"shell.file_download", "netcli.file_download", "shell.execute"} <= ids


@pytest.mark.parametrize(
    ("package", "handler"), HANDLERS, ids=[cls.handler_id for _, cls in HANDLERS]
)
def test_the_handler_declares_its_output_fields(package, handler):
    fields = handler.output_fields
    assert isinstance(fields, tuple)
    if handler.handler_id in _NO_OUTPUT and not fields:
        return
    assert fields, f"{handler.handler_id} declares no output fields"
    names = [field.name for field in fields]
    assert len(names) == len(set(names)), "a name is declared twice"
    page = load_docs_bundle(package)[handler.handler_id]
    for field in fields:
        assert isinstance(field, OutputField)
        assert _NAME.fullmatch(field.name), field.name
        assert field.description.strip(), f"{field.name} has no description"
        assert field.type in _TYPES, f"{field.name}: unknown type {field.type!r}"
        assert f"output.{field.name}`" in page, (
            f"docs/{handler.handler_id}.md does not name output.{field.name}"
        )
