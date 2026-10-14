# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Inventory step handlers for Hegemony (sync an inventory provider from a flow).

Syncs the run organization's inventory providers through the host's
``sync_inventory`` service, so a flow sees what its source of truth holds
right now. An opt-in wheel of its own, not in the platform's images:
starting syncs from a flow puts load on a source of truth, so a deployment
that wants it installs it.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``inventory``).
Handlers reach every platform facility through ``ctx.services``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .sync import InventorySyncHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (InventorySyncHandler,)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
