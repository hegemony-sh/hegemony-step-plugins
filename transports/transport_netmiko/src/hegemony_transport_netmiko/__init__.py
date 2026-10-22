# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Netmiko device transport for Hegemony.

Registers the ``netmiko`` transport under the ``hegemony.device_transports``
entry-point group. The host selects it by id, constructs it from a resolved
``DeviceConnectionSpec``, and injects its cancellation registry.
"""

from __future__ import annotations

from hegemony_step_sdk import TransportRegistry

from .transport import SSHResult, SSHTransport

ALL_TRANSPORTS: tuple[type, ...] = (SSHTransport,)


def register(registry: TransportRegistry) -> None:
    """Entry point: register this wheel's transports with the host registry."""
    for transport_class in ALL_TRANSPORTS:
        registry.register_transport(transport_class)


__all__ = ["ALL_TRANSPORTS", "SSHResult", "SSHTransport", "register"]
