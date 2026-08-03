# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Device-transport plugin contract — pluggable device I/O beneath handlers.

A *transport* is the concrete device-connection library (netmiko, scrapli,
asyncssh, …) that satisfies the :class:`Transport` I/O surface. Transports are
pluggable: out-of-tree wheels register under the ``hegemony.device_transports``
entry-point group, each exposing a ``register(registry)`` callable that calls
:meth:`TransportRegistry.register_transport` with a transport class.

The host stays the factory: it resolves credentials, picks a transport by id,
and constructs it from a :class:`DeviceConnectionSpec` — so a transport wheel
never imports the platform's credential resolver, settings, or cancellation
registry. Cancellation of in-flight blocking I/O is threaded through an injected
:class:`ConnectionCancellationRegistry` (the host owns the registry; other host
code cancels through it). The transport never appears in a handler id — which
transport runs is resolved from ``device.access_config``, per CONVENTIONS.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .contract import DEFAULT_DEVICE_PLATFORM

#: The entry-point group out-of-tree device-transport plugins register under.
TRANSPORT_ENTRY_POINT_GROUP = "hegemony.device_transports"

#: Default SSH/CLI management port when a device does not specify one.
DEFAULT_DEVICE_MGMT_PORT = 22


@dataclass(frozen=True, slots=True)
class JumpHostSpec:
    """Resolved bastion (ProxyJump) hop a transport must tunnel through.

    Built by the host from ``device.access_config.jump_host`` with secret
    references already resolved. The transport opens its first SSH session to
    this endpoint with these credentials, then runs the device session inside
    a forwarded channel — the bastion never sees device credentials.
    """

    host: str
    port: int = DEFAULT_DEVICE_MGMT_PORT
    username: str = ""
    # Secrets are kept out of repr so a logged/traceback'd spec never leaks them.
    password: str = field(default="", repr=False)
    # Optional PEM private key for the bastion login (empty = password/agent).
    private_key: str = field(default="", repr=False)


@dataclass(frozen=True, slots=True)
class DeviceConnectionSpec:
    """Fully-resolved parameters the host hands a transport at construction.

    Credentials are already resolved (no secret references) — the host resolves
    them so the transport wheel stays free of the platform's secret pipeline.
    """

    host: str
    port: int = DEFAULT_DEVICE_MGMT_PORT
    username: str = ""
    # Secrets are kept out of repr so a logged/traceback'd spec never leaks them.
    password: str = field(default="", repr=False)
    enable_secret: str = field(default="", repr=False)
    platform: str = DEFAULT_DEVICE_PLATFORM
    connect_timeout: float = 10.0
    command_timeout: float = 30.0
    # Optional bastion hop (design-dind-sandbox.md §11): None = direct.
    jump_host: JumpHostSpec | None = None


class ConnectionCancellationRegistry(Protocol):
    """Host-owned registry the transport uses to make blocking I/O cancellable.

    When a step is cancelled, blocking device I/O running in a thread pool keeps
    going; the transport registers each live connection under a key so the host
    can force-close it, and checks :meth:`is_cancelled` at safe points. The key
    is the host's step-run id. Structurally satisfied by the host's
    ``ConnectionRegistry``.
    """

    def register(self, key: str | None, connection: Any) -> None: ...

    def unregister(self, key: str | None, connection: Any) -> None: ...

    def is_cancelled(self, key: str | None) -> bool: ...


class TransportRegistry(Protocol):
    """Facade passed to a transport plugin's ``register(registry)`` callable."""

    def register_transport(self, transport_class: type) -> None:
        """Register a transport type from its class (must define ``transport_id``)."""
        ...
