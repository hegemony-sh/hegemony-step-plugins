# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Remote shell execution step handlers for Hegemony.

The remote-shell paradigm: run commands on Linux/Unix hosts over an
exec-channel transport (SSH today; WinRM slots in behind the same
``ShellTransport`` surface). In the platform's images, so ``shell.*``
is in every editor; a deployment that must not run commands on hosts
builds its api and worker images without the wheel.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``shell``).
Handlers reach every platform facility through ``ctx.services``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .execute import ShellExecuteHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (ShellExecuteHandler,)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
