# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""NAPALM step handlers for Hegemony: the ``napalm.`` namespace.

Vendor-neutral reads (NAPALM getters) and configuration changes (load a
candidate, diff, dry run, commit, confirmed commit, rollback) on Cisco IOS
and IOS XE, Arista EOS and Cisco NX-OS. The host opens the NAPALM session
(``services.open_napalm``) over its hardened SSH login; this wheel never sees
a credential.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``napalm``).
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .config import NapalmConfigHandler
from .get import NapalmGetHandler
from .rollback import NapalmRollbackHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (
    NapalmGetHandler,
    NapalmConfigHandler,
    NapalmRollbackHandler,
)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
