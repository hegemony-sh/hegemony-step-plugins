# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Docker container execution step handler for Hegemony.

Container execution on the platform's Docker-in-Docker sandbox, never on the
worker's own Docker daemon. Deliberately its own wheel: the security-sensitive
handler (docker socket, privileged mode) — hardened deployments simply don't
install it.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``container``).
Handlers reach every platform facility through ``ctx.services``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .run import RunContainerHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (RunContainerHandler,)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
