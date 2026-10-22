# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe plugin contract — outside-observation reachability checks.

A *probe* implements one ``check_type`` (``tcp_connect``, ``icmp_ping``,
``http_health``, ``dns_resolve``, …): given a target address and options it
reports reachability plus metrics, without authenticating into the target.
Probes are pluggable the same way step handlers are — out-of-tree wheels
register under the ``hegemony.probes`` entry-point group, each exposing a
``register(registry)`` callable that calls
:meth:`ProbeRegistry.register_probe` with a probe class.

The host loads probes into its own registry and exposes them two ways: the
background ``MonitorManager`` runs them on its tick loop, and one-shot
``probe.*`` step handlers run them through
:meth:`HandlerServices.run_probe`. A single probe implementation therefore
serves both surfaces — there is no separate monitor-vs-step probe code.

Probe ids are a small **global** vocabulary shared across the whole platform
(they appear in monitor configs and run histories), so — unlike step-handler
ids — they are not namespaced per wheel.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Protocol

#: The entry-point group out-of-tree probe plugins register under.
PROBE_ENTRY_POINT_GROUP = "hegemony.probes"


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Outcome of one probe execution against a single target address."""

    ok: bool
    """Whether the probe succeeded."""

    metrics: dict[str, Any] = field(default_factory=dict)
    """Probe-specific metrics (e.g. ``connect_ms``, ``rtt_ms``, ``status_code``)."""

    error_kind: str | None = None
    """Machine-readable error category if the probe failed (``timeout``, …)."""

    error_detail: str | None = None
    """Human-readable failure detail."""

    raw_text: str | None = None
    """Optional raw output (ping text, response snippet, resolved records)."""


class BaseProbe(ABC):
    """Base class for probe implementations.

    Subclasses set :attr:`probe_id` (the ``check_type`` string) and implement
    :meth:`execute`. Probes are stateless — configuration arrives per call in
    ``options`` — so the host instantiates one per id and reuses it.
    """

    #: The check-type string this probe implements (e.g. ``"tcp_connect"``).
    probe_id: str = ""

    @abstractmethod
    async def execute(self, address: str, options: dict[str, Any]) -> ProbeResult:
        """Probe ``address`` with ``options`` and return a :class:`ProbeResult`.

        Implementations should not raise for expected failures (timeout,
        refused, unresolved) — return ``ProbeResult(ok=False, error_kind=…)``.
        """
        ...


class ProbeRegistry(Protocol):
    """Facade passed to a probe plugin's ``register(registry)`` callable."""

    def register_probe(self, probe_class: type) -> None:
        """Register a probe type from its class (must define ``probe_id``)."""
        ...
