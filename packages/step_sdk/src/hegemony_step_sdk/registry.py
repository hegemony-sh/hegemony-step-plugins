# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Plugin registration protocol.

A plugin wheel exposes a ``register(registry)`` callable under the
``hegemony.step_handlers`` entry-point group. The host passes a registry facade
satisfying :class:`StepHandlerRegistry`; the plugin registers each handler
class. Registration is atomic per plugin: if ``register()`` raises partway, none
of that plugin's handlers are committed to the shared registry.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class StepHandlerRegistry(Protocol):
    """Registry facade the host passes to a plugin's ``register(registry)``."""

    #: Plugin registration ABI understood by this host (mirrors ``SDK_ABI_VERSION``).
    api_version: int

    def register_handler_type(self, handler_class: type) -> None:
        """Register a step-handler type from its handler class.

        The class carries the whole contract: ``handler_id``,
        ``supported_kinds``, editor metadata, and ``config_model``.
        Raises ``ValueError`` on duplicate handler ids.
        """
        ...
