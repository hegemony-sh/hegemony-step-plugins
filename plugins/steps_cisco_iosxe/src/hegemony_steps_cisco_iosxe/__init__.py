# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Cisco IOS XE step handlers for Hegemony: the ``cisco.iosxe.`` namespace.

Workflows whose settings are IOS XE's own (CONVENTIONS.md, rule 1):

- ``cisco.iosxe.config_replace``: Atomic Configuration Replace (ACR), the
  whole configuration as CLI text through the ``Cisco-IOS-XE-cli-rpc`` model,
  committed with the netconf wheel's transaction (diff, validate, dry run,
  confirmed commit);
- ``cisco.iosxe.get_config``: the modelled configuration as CLI text.

Built on ``hegemony-steps-netconf`` (its client, sessions and transaction).
Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``cisco.iosxe``).
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .handlers import ConfigReplaceHandler, GetConfigHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (ConfigReplaceHandler, GetConfigHandler)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
