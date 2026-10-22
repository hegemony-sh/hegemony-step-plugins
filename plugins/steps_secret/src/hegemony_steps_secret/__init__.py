# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Secret-store step handlers for Hegemony (write, swap and delete a secret).

Stores values in the run organization's own secret store through the host's
``read_secret`` / ``write_secret`` / ``delete_secret`` services. A wheel of its
own because writing secrets from a flow is a security surface a deployment
can leave out entirely, by not installing it.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``secret``).
Handlers reach every platform facility through ``ctx.services``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .write import WriteSecretHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (WriteSecretHandler,)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
