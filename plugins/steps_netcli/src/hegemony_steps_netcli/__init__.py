# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Network-device CLI step handlers for Hegemony.

Network-device CLI paradigm: execute command lines and collect outputs as
evidence. Vendor-neutral by design — platform
dialects and transports (netmiko/scrapli, ssh) are resolved beneath the
handler layer from device access config.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``netcli``).
Handlers reach every platform facility through ``ctx.services``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .collect_evidence import CollectEvidenceHandler
from .execute import ExecuteCLIActionHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (
    CollectEvidenceHandler,
    ExecuteCLIActionHandler,
)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
