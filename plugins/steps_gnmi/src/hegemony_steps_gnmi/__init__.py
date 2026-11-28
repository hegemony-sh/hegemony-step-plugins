# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""gNMI step handlers for Hegemony: the ``gnmi.`` namespace.

Vendor-neutral gNMI (gRPC Network Management Interface, openconfig gNMI
0.10): read configuration and state (``gnmi.get``), and change configuration
as one transaction with a dry run and the values before and after
(``gnmi.set``). The wheel dials the device itself over gRPC with TLS
(``client``), under the flow's egress policy (``services.enforce_egress``)
and the organization's trusted CAs; the protocol's messages come from the
upstream ``proto/`` files (``messages``).

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``gnmi``).
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .get import GnmiGetHandler
from .set_config import GnmiSetHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (
    GnmiGetHandler,
    GnmiSetHandler,
)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
