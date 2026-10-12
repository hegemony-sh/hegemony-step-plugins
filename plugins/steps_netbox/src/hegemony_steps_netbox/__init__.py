# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""NetBox step handlers for Hegemony.

- ``netbox.request``: get, list, create, update or delete NetBox objects, or
  post to a NetBox endpoint.
- ``netbox.ipam.allocate`` / ``netbox.ipam.release``: take the next free IP
  address, prefix, VLAN or ASN from a pool, and give it back.
- ``netbox.render_config``: have NetBox render the intended configuration of
  devices from their config templates.

Every call goes through ``http.request``'s client, so the flow's egress
policy and that step's safeguards apply to NetBox too. Registers under the
``hegemony.step_handlers`` entry-point group; the entry point name is the
claimed handler-id namespace prefix (``netbox``).
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .ipam import AllocateHandler, ReleaseHandler
from .render_config import RenderConfigHandler
from .request import NetBoxRequestHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (
    NetBoxRequestHandler,
    AllocateHandler,
    ReleaseHandler,
    RenderConfigHandler,
)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
