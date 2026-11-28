# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""gNMI values (``gnmi.TypedValue``) to and from JSON-ready Python values."""

from __future__ import annotations

import base64
import json
import math
from decimal import Decimal
from typing import Any

from . import messages

#: How a step sends a value, by its ``encoding`` setting.
VALUE_ENCODINGS = ("json_ietf", "json")


class GnmiValueError(ValueError):
    """A value that cannot be sent or read."""


def encode_value(value: Any, encoding: str) -> Any:
    """A ``gnmi.TypedValue`` holding ``value`` as JSON text (``json_ietf`` or ``json``)."""
    if encoding not in VALUE_ENCODINGS:
        raise GnmiValueError(f"values are sent as json_ietf or json, not {encoding!r}")
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    typed = messages.TypedValue()
    if encoding == "json_ietf":
        typed.json_ietf_val = data
    else:
        typed.json_val = data
    return typed


def decode_value(typed: Any) -> Any:
    """A received ``gnmi.TypedValue`` as a JSON-ready value.

    JSON is parsed; bytes become base64 text; a decimal becomes a number;
    a float that JSON cannot hold (NaN, infinity) becomes its text.
    """
    kind = typed.WhichOneof("value")
    if kind is None:
        return None
    if kind in ("json_val", "json_ietf_val"):
        raw = getattr(typed, kind)
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GnmiValueError(f"the device sent {kind} that is not JSON: {exc}") from None
    if kind in ("string_val", "ascii_val"):
        return getattr(typed, kind)
    if kind in ("int_val", "uint_val", "bool_val"):
        return getattr(typed, kind)
    if kind in ("float_val", "double_val"):
        number = float(getattr(typed, kind))
        return number if math.isfinite(number) else str(number)
    if kind == "decimal_val":
        decimal = Decimal(typed.decimal_val.digits).scaleb(-typed.decimal_val.precision)
        return float(decimal)
    if kind in ("bytes_val", "proto_bytes"):
        return base64.b64encode(getattr(typed, kind)).decode("ascii")
    if kind == "leaflist_val":
        return [decode_value(item) for item in typed.leaflist_val.element]
    if kind == "any_val":
        return {
            "@type": typed.any_val.type_url,
            "value": base64.b64encode(typed.any_val.value).decode("ascii"),
        }
    return str(getattr(typed, kind))
