# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Git step handlers for Hegemony: the ``git.`` namespace.

``git.commit`` commits an earlier step's evidence to a Git repository, only
when it changed. It runs git in a container through ``container.run``'s
runner, so this wheel depends on ``hegemony-steps-container``.

Registers under the ``hegemony.step_handlers`` entry-point group; the entry
point name is the claimed handler-id namespace prefix (``git``).
"""

from __future__ import annotations

from hegemony_step_sdk import BaseHandler, StepHandlerRegistry

from .commit import GitCommitHandler

ALL_HANDLERS: tuple[type[BaseHandler], ...] = (GitCommitHandler,)


def register(registry: StepHandlerRegistry) -> None:
    """Entry point: register this wheel's handlers with the host registry."""
    for handler_class in ALL_HANDLERS:
        registry.register_handler_type(handler_class)


__all__ = ["ALL_HANDLERS", "GitCommitHandler", "register"]
