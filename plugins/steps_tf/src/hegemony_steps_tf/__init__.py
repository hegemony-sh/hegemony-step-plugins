# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""OpenTofu/Terraform step handlers for Hegemony.

``tf.plan`` plans a configuration from the flow's attachments and reports what
would change; ``tf.apply`` applies exactly that saved plan, typically after an
approval step. OpenTofu (the default) and Terraform share one namespace: the
engine is a config field. Built on ``container.run``'s runner, so both run on
the Docker-in-Docker sandbox under the flow's egress policy.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``tf``).
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .apply import TfApplyHandler
from .plan import TfPlanHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (TfPlanHandler, TfApplyHandler)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
