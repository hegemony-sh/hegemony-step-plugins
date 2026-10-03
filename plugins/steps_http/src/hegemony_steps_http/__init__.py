# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""HTTP(S) request step handler for Hegemony (http.request).

Sends one HTTP(S) request from the worker, with any method, headers, body
and authentication, and returns the response as structured step output.
A wheel of its own so that a deployment can leave out arbitrary outbound
requests entirely.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``http``).
Handlers reach every platform facility through ``ctx.services``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .request import HttpRequestHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (HttpRequestHandler,)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
