# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Path rules for ``secret.write``: secret paths and shared-workspace file paths.

A secret path is relative to the run organization's own secret root
(``certs/web``); the host turns it into a backend path and decides whether the
step may touch it. The rules here are the handler's own, stricter than any
backend's, so a malformed path is refused before the host is asked.

A source file is named as the step that wrote it sees it: ``/shared/<rel>``
(the shared workspace's default mount path in a step container) or ``<rel>``
relative to the workspace.
"""

from __future__ import annotations

import re

#: Longest secret path accepted (the path below the organization's root).
MAX_SECRET_PATH_LENGTH = 256

#: Where a step container sees the run's shared workspace by default.
SHARED_MOUNT_PATH = "/shared"

#: One secret path segment: letters, digits, ``_``, ``.``, ``-``; never a
#: leading ``.``, so ``.``, ``..`` and hidden names are out.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*$")

#: Template syntax, which the host renders before the step runs.
_TEMPLATE_RE = re.compile(r"\{\{|\{%")


def templated(value: object) -> bool:
    """Whether ``value`` still holds template syntax (rendered by the host before a run)."""
    return isinstance(value, str) and bool(_TEMPLATE_RE.search(value))


def secret_path_error(field: str, value: object, *, allow_template: bool) -> str | None:
    """Why ``value`` is not a secret path relative to the organization's root, or None."""
    if not isinstance(value, str) or not value.strip():
        return (
            f"'{field}' is required: a secret path relative to the organization's secret "
            "root, e.g. certs/web"
        )
    if allow_template and templated(value):
        return None
    path = value.strip()
    if len(path) > MAX_SECRET_PATH_LENGTH:
        return f"'{field}' must be at most {MAX_SECRET_PATH_LENGTH} characters"
    if "://" in path:
        return (
            f"'{field}' must be a path relative to the organization's secret root, such as "
            "certs/web, not a secret reference: the platform decides the backend"
        )
    if path.startswith("/"):
        return (
            f"'{field}' must be relative to the organization's secret root, without a leading '/'"
        )
    for segment in path.split("/"):
        if not segment:
            return f"'{field}' must not contain empty segments ('//' or a trailing '/')"
        if segment in (".", ".."):
            return f"'{field}' must not contain '.' or '..' segments"
        if segment.startswith("."):
            return f"'{field}' segment {segment!r} must not start with '.'"
        if not _SEGMENT_RE.match(segment):
            return f"'{field}' segment {segment!r} may use only letters, digits, '_', '.' and '-'"
    return None


def workspace_relative(value: str) -> str:
    """The path of ``value`` inside the run's shared workspace.

    ``/shared/out/cert.pem`` and ``out/cert.pem`` both give ``out/cert.pem``.
    Raises ``ValueError`` for any other absolute path, an empty path, an empty,
    ``.`` or ``..`` segment, a backslash or a NUL byte.
    """
    path = value.strip()
    if path == SHARED_MOUNT_PATH or path.startswith(SHARED_MOUNT_PATH + "/"):
        path = path[len(SHARED_MOUNT_PATH) + 1 :]
    elif path.startswith("/"):
        raise ValueError(
            f"must be a file under {SHARED_MOUNT_PATH}/ (the run's shared workspace as a step "
            "container sees it) or a path relative to that workspace"
        )
    if not path:
        raise ValueError("names the shared workspace itself, not a file in it")
    if "\\" in path or "\0" in path:
        raise ValueError("must not contain a backslash or a NUL byte")
    for segment in path.split("/"):
        if not segment:
            raise ValueError("must not contain empty segments ('//' or a trailing '/')")
        if segment in (".", ".."):
            raise ValueError("must not contain '.' or '..' segments")
    return path


def workspace_file_error(field: str, value: object, *, allow_template: bool) -> str | None:
    """Why ``value`` does not name a file in the run's shared workspace, or None."""
    if not isinstance(value, str) or not value.strip():
        return (
            f"'{field}' must name a file in the run's shared workspace, e.g. /shared/out/cert.pem"
        )
    if allow_template and templated(value):
        return None
    try:
        workspace_relative(value)
    except ValueError as exc:
        return f"'{field}' {exc}"
    return None
