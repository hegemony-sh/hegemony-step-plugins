# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""NAPALM device transport for Hegemony.

Registers the ``napalm`` transport under the ``hegemony.device_transports``
entry-point group: the netmiko network-CLI transport plus NAPALM driver
sessions (``open_napalm``) over the same hardened SSH login.
"""

from __future__ import annotations

from hegemony_step_sdk import TransportRegistry

from .transport import (
    PLATFORM_TO_DRIVER,
    NapalmDriverSession,
    NapalmSessionClosedError,
    NapalmTransport,
    driver_for,
)

ALL_TRANSPORTS: tuple[type, ...] = (NapalmTransport,)


def register(registry: TransportRegistry) -> None:
    """Entry point: register this wheel's transports with the host registry."""
    for transport_class in ALL_TRANSPORTS:
        registry.register_transport(transport_class)


__all__ = [
    "ALL_TRANSPORTS",
    "PLATFORM_TO_DRIVER",
    "NapalmDriverSession",
    "NapalmSessionClosedError",
    "NapalmTransport",
    "driver_for",
    "register",
]
