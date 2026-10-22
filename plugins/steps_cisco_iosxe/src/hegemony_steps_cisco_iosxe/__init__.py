# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Cisco IOS-XE upgrade workflow step handlers for Hegemony.

Cisco IOS-XE upgrade workflow (preflight/stage/install/verify/cleanup) in
install and bundle modes. Platform-specific by nature: the workflow and its
config schemas encode IOS-XE concepts, so it lives under the cisco.iosxe.*
namespace; other platforms get their own wheels.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``cisco.iosxe``).
Handlers reach every platform facility through ``ctx.services``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .upgrade.handlers import (
    UpgradeCleanupHandler,
    UpgradeInstallHandler,
    UpgradePreflightHandler,
    UpgradeStageHandler,
    UpgradeVerifyHandler,
)

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (
    UpgradeCleanupHandler,
    UpgradeInstallHandler,
    UpgradePreflightHandler,
    UpgradeStageHandler,
    UpgradeVerifyHandler,
)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
