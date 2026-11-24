# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""NETCONF step handlers for Hegemony: the ``netconf.`` namespace.

Vendor-neutral NETCONF (RFC 6241 over SSH, RFC 6242): read configuration and
state, change configuration as one transaction on the candidate datastore
(diff, validate, dry run, confirmed commit), settle a pending confirmed commit
in a later step, and send any other operation. The host opens the SSH session
(``services.open_netconf``); the protocol is this wheel's (``client``), and
vendor wheels (``cisco.iosxe``) build on it.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``netconf``).
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .commit import NetconfCancelCommitHandler, NetconfCommitHandler
from .edit_config import NetconfEditConfigHandler
from .get import NetconfGetHandler
from .rpc import NetconfRpcHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (
    NetconfGetHandler,
    NetconfEditConfigHandler,
    NetconfCommitHandler,
    NetconfCancelCommitHandler,
    NetconfRpcHandler,
)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
