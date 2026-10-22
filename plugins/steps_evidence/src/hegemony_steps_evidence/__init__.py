# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Evidence assertion and comparison step handlers for Hegemony.

Assertions and diffs over evidence artifacts produced by collection steps.
Paradigm-neutral: works on artifact content regardless of how it was collected.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``evidence``).
Handlers reach every platform facility through ``ctx.services``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .assert_check import AssertHandler
from .compare import CompareEvidenceHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (
    AssertHandler,
    CompareEvidenceHandler,
)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
