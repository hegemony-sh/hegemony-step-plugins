# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The gNMI message classes, built from the descriptors in a private pool.

The descriptors are the compiled upstream ``proto/*.proto`` files
(``_descriptors``). They are loaded into a pool of this module's own, not
protobuf's default pool, so another gNMI library in the same worker (with its
own copy of ``gnmi.Notification``) cannot clash with this one, and no
generated ``_pb2`` module pins the protobuf runtime to one version.
"""

from __future__ import annotations

from typing import Any

from google.protobuf import any_pb2, descriptor_pb2, descriptor_pool, duration_pb2, message_factory

from ._descriptors import FILE_DESCRIPTORS

#: The gNMI service's full name, as the RPC paths use it (``/gnmi.gNMI/Get``).
SERVICE = "gnmi.gNMI"

_POOL: Any = descriptor_pool.DescriptorPool()  # ty: ignore[possibly-missing-implicit-call]
for _well_known in (descriptor_pb2, any_pb2, duration_pb2):
    _POOL.AddSerializedFile(_well_known.DESCRIPTOR.serialized_pb)
for _data in FILE_DESCRIPTORS.values():
    _POOL.AddSerializedFile(_data)


def message_class(full_name: str) -> Any:
    """The message class of ``full_name`` (``gnmi.GetRequest``)."""
    return message_factory.GetMessageClass(_POOL.FindMessageTypeByName(full_name))


def enum_value(enum_name: str, value_name: str) -> int:
    """The number of ``value_name`` in the enum ``enum_name`` (``gnmi.Encoding``, ``JSON``)."""
    return _POOL.FindEnumTypeByName(enum_name).values_by_name[value_name].number


def enum_name(enum_name_: str, number: int) -> str:
    """The name of ``number`` in the enum ``enum_name_``, or the number as text."""
    value = _POOL.FindEnumTypeByName(enum_name_).values_by_number.get(number)
    return value.name if value is not None else str(number)


CapabilityRequest = message_class("gnmi.CapabilityRequest")
CapabilityResponse = message_class("gnmi.CapabilityResponse")
GetRequest = message_class("gnmi.GetRequest")
GetResponse = message_class("gnmi.GetResponse")
SetRequest = message_class("gnmi.SetRequest")
SetResponse = message_class("gnmi.SetResponse")
Notification = message_class("gnmi.Notification")
Update = message_class("gnmi.Update")
UpdateResult = message_class("gnmi.UpdateResult")
TypedValue = message_class("gnmi.TypedValue")
Path = message_class("gnmi.Path")
PathElem = message_class("gnmi.PathElem")
ScalarArray = message_class("gnmi.ScalarArray")
Decimal64 = message_class("gnmi.Decimal64")
ModelData = message_class("gnmi.ModelData")
