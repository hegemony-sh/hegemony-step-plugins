# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Key names and the ``values`` map of ``secret.write``.

``values`` is listed in the handler's ``raw_config_keys``, so each value
arrives as the step author wrote it. The convention is the one of
``container.run``'s secret fields (``hegemony_steps_container.runner``),
repeated here so this wheel does not depend on container execution:

- a bare reference (``vault://orgs/acme/secrets/db/password``) is resolved
  through the host as ``{{ secret('<reference>') }}``;
- a template (``{{ secret('vault://…') }}``) is rendered through the host;
- anything else is a literal, used as written.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from hegemony_step_sdk import HandlerServices

#: A key of a stored secret: a letter or underscore, then letters, digits,
#: ``_``, ``.``, ``-``; at most 128 characters.
KEY_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")

#: A secret reference written bare rather than as a ``{{ secret('...') }}``
#: template (the same shape ``container.run`` accepts).
_BARE_SECRET_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s'\"{}\\]+$")

#: Template syntax, rendered through the host.
_TEMPLATE_RE = re.compile(r"\{\{|\{%")

KEY_NAME_RULE = (
    "must start with a letter or underscore and use only letters, digits, '_', '.', '-' (max 128)"
)


def key_name_error(field: str, key: object) -> str | None:
    """Why ``key`` cannot name a key of the stored secret, or None."""
    if not isinstance(key, str) or not KEY_NAME_RE.match(key):
        return f"'{field}' key {key!r} {KEY_NAME_RULE}"
    return None


def value_map_errors(field: str, value: Any) -> list[str]:
    """Validation errors for the ``key -> reference/template/literal`` map (empty when valid)."""
    if value is None:
        return []
    if not isinstance(value, dict):
        return [f"'{field}' must be an object mapping key names to values or secret references"]
    errors: list[str] = []
    for key, raw in value.items():
        error = key_name_error(field, key)
        if error:
            errors.append(error)
        elif not isinstance(raw, str) or not raw.strip():
            errors.append(f"'{field}.{key}' must be a non-empty string")
    return errors


def is_bare_secret_ref(value: str) -> bool:
    """Whether ``value`` is a bare secret reference like ``vault://path/key``."""
    return bool(_BARE_SECRET_REF_RE.match(value.strip()))


async def resolve_values(
    services: HandlerServices, values: Mapping[str, str], *, source: str
) -> dict[str, str]:
    """Resolve the ``values`` map into the strings to store.

    The written text decides how a value is read, never the resolved value:
    a secret whose value looks like a reference is not resolved a second
    time. Any ``scheme://…`` text is read as a reference, since only the
    host knows its backends' schemes, so a literal URL cannot be written
    directly. The host registers every value it resolves for redaction; a
    literal is stored as written, and nothing registers it where it is
    written (the step's own configuration).

    Raises ``ValueError`` for an invalid key, a non-string value, or a
    reference or template that resolves to nothing. Messages name keys and
    reference schemes, never values.
    """
    resolved: dict[str, str] = {}
    for key, raw in values.items():
        error = key_name_error("values", key)
        if error:
            raise ValueError(error)
        if not isinstance(raw, str):
            raise ValueError(f"'values.{key}' must be a string")
        bare = is_bare_secret_ref(raw)
        if bare:
            template = "{{ secret('" + raw.strip() + "') }}"
        elif _TEMPLATE_RE.search(raw):
            template = raw
        else:
            resolved[key] = raw
            continue
        value = await services.resolve_secret_ref(template, source=source) or ""
        if not value and bare:
            scheme = raw.strip().split("://", 1)[0]
            raise ValueError(
                f"'values.{key}' resolved to an empty value: it is written as a secret "
                f"reference (scheme {scheme!r}), and no secret backend returned a value for "
                "it. Check the reference; a literal value shaped like a URL cannot be "
                "written directly, so store it in a secret backend and reference it"
            )
        if not value:
            raise ValueError(f"'values.{key}' resolved to an empty value")
        resolved[key] = value
    return resolved
