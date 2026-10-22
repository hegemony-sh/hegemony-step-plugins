# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Network reachability probes for Hegemony (tcp/icmp/http/dns).

Registers under the ``hegemony.probes`` entry-point group. Each probe
implements one ``check_type`` consumed by both the background MonitorManager
and the one-shot ``probe.*`` step handlers via ``HandlerServices.run_probe``.
"""

from __future__ import annotations

from hegemony_step_sdk import BaseProbe, ProbeRegistry

from .dns_resolve import DnsResolveProbe
from .http_health import HttpHealthProbe
from .icmp_ping import IcmpPingProbe
from .tcp_connect import TcpConnectProbe

ALL_PROBES: tuple[type[BaseProbe], ...] = (
    TcpConnectProbe,
    IcmpPingProbe,
    HttpHealthProbe,
    DnsResolveProbe,
)


def register(registry: ProbeRegistry) -> None:
    """Entry point: register this wheel's probes with the host registry."""
    for probe_class in ALL_PROBES:
        registry.register_probe(probe_class)


__all__ = ["ALL_PROBES", "register", *sorted(cls.__name__ for cls in ALL_PROBES)]
