# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Background connectivity-monitor step handlers for Hegemony.

Registers under the ``hegemony.step_handlers`` entry-point group with the
claimed prefix ``monitor``. The handler is a thin shell: it assembles config
and resolves targets, then drives the host monitor machinery through
``services.start_monitor``. MonitorManager and the engine's monitor-node
semantics stay host-side.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .handlers import ConnectivityMonitorHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (ConnectivityMonitorHandler,)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
