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


@dataclass(frozen=True, slots=True)
class DeviceCredentials:
    """A device's resolved login material, for handlers that hand it to a tool.

    Returned by :meth:`HandlerServices.resolve_device_credentials` for handlers
    that do not dial the device themselves but pass credentials to an external
    tool (an Ansible inventory, a script's context file). The host resolves the
    ``device.access_config`` references in the run's org and registers every
    secret value for redaction from step output before returning — usernames
    excepted, as for :class:`DeviceConnectionSpec`.

    Empty strings mean "not configured"; ``jump_host`` is None for a direct
    connection.
    """

    username: str = ""
    # Secrets are kept out of repr so a logged/traceback'd value never leaks them.
    password: str = field(default="", repr=False)
    # PEM private key for SSH key login (empty = password login).
    private_key: str = field(default="", repr=False)
    enable_password: str = field(default="", repr=False)
    jump_host: JumpHostSpec | None = None


class TransportOutputSink(Protocol):
    """Host-owned sink for live session-output streaming (Phase B).

    The host builds one sink per ``connect()`` call and passes it to
    transport constructors that advertise ``supports_output_sink = True``
    (feature-detected, so wheels and hosts upgrade independently). The sink
    owns batching, sanitization (ANSI stripping, credential redaction), and
    emission as Logs-tab output events — transports only push raw chunks.

    All entry points are best-effort and never raise into the transport.
    ``push`` is for event-loop producers; ``push_from_thread`` marshals from
    executor threads (netmiko); ``flush``/``flush_from_thread`` drain any
    buffered tail at the end of a streamed command.
    """

    async def push(self, text: str, *, stream: str = "stdout") -> None: ...

    def push_from_thread(self, text: str, *, stream: str = "stdout") -> None: ...

    async def flush(self) -> None: ...

    def flush_from_thread(self, timeout: float = 5.0) -> None: ...


class HostKeyRejectedError(ConnectionError):
    """An SSH host failed its host-key check; no credential was sent to it.

    Transports raise the instance :meth:`HostKeyVerifier.rejected` returns, so
    the step fails with the host's message: which key is trusted, which one
    was presented, and what an admin does about it.
    """


class HostKeyVerifier(Protocol):
    """Host-owned SSH host-key trust for the hops of one connection.

    The host builds one per ``connect()`` call and passes it to transport
    constructors that advertise ``supports_host_key_verifier = True``
    (feature-detected, like the output sink). Before a transport dials a hop
    (the jump host first, then the device) it asks :meth:`trusted_keys` and
    connects accepting only those keys, so a host presenting any other key
    fails during the key exchange, before a password or private key is sent.

    Keys are OpenSSH public key lines: ``<type> <base64>``, no comment.
    ``host`` and ``port`` are the hop's endpoint as the spec names it.
    """

    async def trusted_keys(self, host: str, port: int) -> tuple[str, ...] | None:
        """The keys ``host:port`` may present.

        Returns:
            None to connect without a check (the organization switched checks
            off). An empty tuple when no key is trusted yet and the host learns
            one on first contact: the transport fetches the key the host
            presents without logging in, passes it to :meth:`learn`, then logs
            in accepting only that key. Otherwise the trusted keys.

        Raises:
            HostKeyRejectedError: the host may not be dialled (no key is trusted
                and the organization does not learn new keys).
        """
        ...

    async def learn(self, host: str, port: int, presented_key: str) -> None:
        """Record ``presented_key`` as the trusted key of ``host:port`` (first contact).

        Called before any credential is sent to the host.

        Raises:
            HostKeyRejectedError: another key was recorded for the host
                meanwhile, or the organization no longer learns keys.
        """
        ...

    async def rejected(
        self, host: str, port: int, presented_key: str | None
    ) -> HostKeyRejectedError:
        """Report that ``host:port`` failed its check; returns the error to raise.

        ``presented_key`` is None when the transport could not tell which key
        the host presented. Never raises.
        """
        ...


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
