# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Ansible step handler for Hegemony.

``ansible.playbook`` runs a playbook from the flow's attachments against the
step's target devices, with the inventory generated from Hegemony's inventory
(local and external providers alike) and credentials, secrets, and Ansible
Vault passwords resolved by the platform. Built on ``container.run``'s runner,
so it runs on the Docker-in-Docker sandbox under the flow's egress policy.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``ansible``).
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .playbook import AnsiblePlaybookHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (AnsiblePlaybookHandler,)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "register", *sorted(cls.__name__ for cls in ALL_HANDLERS)]
