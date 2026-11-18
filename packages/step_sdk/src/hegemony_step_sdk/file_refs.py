# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""File references: a file-repository file named by repository and path.

A run-form "Repository file" field, a step's ``file`` setting and a download
step's ``output.file`` all carry one as ``{"repository": ..., "path": ...}``.
``repository`` is the file repository's name; ``path`` is the folder and the
file name, with no leading slash (a file in the repository root is just its
name). Other keys (the form adds ``folder`` and ``filename``) are ignored.

:func:`parse_file_ref` takes every form a step may receive: the dict, a list
holding exactly one, or either as text. Text comes from platforms that render
the value instead of passing it on: as JSON, or with Python's ``str()`` on one
that does not honour ``BaseHandler.native_config_keys``.
"""

from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from typing import Any

__all__ = ["FileRef", "parse_file_ref"]


@dataclass(frozen=True, slots=True)
class FileRef:
    """A file-repository file named by its repository's name and its path."""

    repository: str
    path: str

    def as_dict(self) -> dict[str, str]:
        """The reference as the JSON object steps and run forms pass around."""
        return {"repository": self.repository, "path": self.path}


def _from_text(text: str) -> Any:
    """The value ``text`` holds, read as JSON or else as a Python literal."""
    try:
        return json.loads(text)
    except RecursionError:
        # Nested deeper than the decoder goes: no reference looks like that.
        raise ValueError(
            "File is not a file reference: expected an object with repository and path"
        ) from None
    except ValueError:
        pass
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
        raise ValueError(
            "File is not a file reference: expected an object with repository and path"
        ) from None


def parse_file_ref(value: Any) -> FileRef:
    """Read a file reference from a step setting, raising ``ValueError`` if it is not one.

    Accepts a dict with non-empty ``repository`` and ``path`` text, a list
    with exactly one such dict, or either as JSON or Python-literal text.
    A leading slash on ``path`` is dropped; spaces in it are kept, since a
    stored file name may start or end with one.
    """
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("File is empty: pick a file or reference a run input")
        value = _from_text(text)
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            raise ValueError(
                f"File must name exactly one file, but {len(value)} were given"
                if value
                else "File is an empty list: pick a file"
            )
        value = value[0]
    if not isinstance(value, dict):
        raise ValueError(
            "File is not a file reference: expected an object with repository and path"
        )
    missing = [
        key
        for key in ("repository", "path")
        if not isinstance(value.get(key), str) or not value[key].strip()
    ]
    if missing:
        raise ValueError(f"File reference is missing {' and '.join(missing)}")
    repository = value["repository"].strip()
    # Only slashes are trimmed: a stored file name may end in a space, and the
    # path must still name that file.
    path = value["path"].lstrip("/")
    if not path.strip():
        raise ValueError("File reference is missing path")
    return FileRef(repository=repository, path=path)
