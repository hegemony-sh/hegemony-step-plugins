# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unauthenticated probe step handlers (reachability, DNS, HTTP, TLS) for Hegemony.

Outside-observation probes: one-shot connectivity, DNS, HTTP and TLS
certificate checks, and stable-reachability waits. No device credentials
involved.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``probe``).
Handlers reach every platform facility through ``ctx.services``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .connectivity import ConnectivityCheckHandler
from .dns_check import DnsProbeHandler
from .http_check import HttpProbeHandler
from .tls_check import TlsProbeHandler
from .wait_reachable import WaitReachableHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (
    ConnectivityCheckHandler,
    DnsProbeHandler,
    HttpProbeHandler,
    TlsProbeHandler,
    WaitReachableHandler,
)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
