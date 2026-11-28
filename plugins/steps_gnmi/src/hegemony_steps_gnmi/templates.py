# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Where a gNMI step accepts ``{{ }}`` templates, checked as written.

The platform renders a step's templates before the step runs, so a rendered
value lands in a path or a JSON value as text. These rules keep it data
(CONVENTIONS.md, "Rendered values are data"):

- **Paths.** A template may only be a whole key value, and must end with the
  ``tojson`` filter: ``[name={{ inputs.interface | tojson }}]``. It renders
  to a JSON string in quotes, which the path parser reads as one key value,
  so no rendered text can end the key or add elements.
- **Values.** Every template must end with ``| tojson`` and stand where a
  JSON value goes, not inside a JSON string: ``{"mtu": {{ inputs.mtu | tojson
  }}}``. It renders to one complete JSON value.
- ``{% %}`` blocks and ``{# #}`` comments are refused in both.
"""

from __future__ import annotations

import re

_EXPR_RE = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)
_TOJSON_END_RE = re.compile(r"\|\s*tojson\s*(?:\(\s*\))?\s*$")
_BLOCK_RE = re.compile(r"\{%|\{#")

PATH_RULE = "end it with | tojson, as [name={{ inputs.x | tojson }}]"
VALUE_RULE = (
    "write it where a JSON value goes (not inside quotes) with | tojson, as "
    '{"mtu": {{ inputs.mtu | tojson }}}'
)


def has_template(text: str) -> bool:
    return "{{" in text or bool(_BLOCK_RE.search(text))


def _spans(text: str) -> list[tuple[int, int, str]]:
    return [(match.start(), match.end(), match.group(1)) for match in _EXPR_RE.finditer(text)]


def path_template_errors(text: str, where: str) -> list[str]:
    """Problems with the templates in one path as written; empty when it has none."""
    if _BLOCK_RE.search(text):
        return [f"{where}: {{% %}} blocks and {{# #}} comments are not allowed in a path"]
    errors: list[str] = []
    for start, end, inner in _spans(text):
        before = text[:start]
        opened = before.rfind("[")
        closed = before.rfind("]")
        in_key = opened > closed and "=" in before[opened:]
        whole_value = in_key and before.endswith("=") and text[end : end + 1] == "]"
        if not whole_value or not _TOJSON_END_RE.search(inner):
            errors.append(f"{where}: a template in a path must be a whole key value; {PATH_RULE}")
    if not errors and "{{" in _EXPR_RE.sub("", text):
        errors.append(f"{where}: a '{{{{' without its '}}}}'")
    return errors


def value_template_errors(text: str, where: str) -> list[str]:
    """Problems with the templates in one JSON value as written."""
    if _BLOCK_RE.search(text):
        return [f"{where}: {{% %}} blocks and {{# #}} comments are not allowed in a value"]
    spans = _spans(text)
    if not spans:
        return [f"{where}: a '{{{{' without its '}}}}'"] if "{{" in text else []
    errors: list[str] = []
    in_string = False
    position = 0
    index = 0
    while position < len(text):
        if index < len(spans) and position == spans[index][0]:
            start, end, inner = spans[index]
            if in_string or not _TOJSON_END_RE.search(inner):
                errors.append(f"{where}: a template in a value must be a JSON value; {VALUE_RULE}")
            position = end
            index += 1
            continue
        ch = text[position]
        if in_string and ch == "\\":
            position += 2
            continue
        if ch == '"':
            in_string = not in_string
        position += 1
    return errors
