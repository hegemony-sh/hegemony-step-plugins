# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What the handlers that run checks through ``run_probe`` share.

``probe.connectivity`` and ``probe.wait_reachable`` both offer the worker's
registered checks and build their probe options the same way.
"""

#: Display names for the check types the probe wheel ships. Cosmetic: the
#: options themselves come from the worker's probe registry, and an id
#: without a label shows as itself.
CHECK_TYPE_LABELS = {
    "tcp_connect": "TCP Connect",
    "icmp_ping": "ICMP Ping",
    "http_health": "HTTP Health",
    "dns_resolve": "DNS Resolve",
}

#: Checks that connect to a port; the others (icmp_ping, dns_resolve) take none.
PORT_CHECKS = frozenset({"tcp_connect", "http_health", "tls_handshake", "ssh_banner"})


class CheckUnavailable(Exception):
    """``run_probe`` has no probe for the check type (it raised KeyError)."""


#: Ports a check uses when the step sets none, where SSH's 22 would be wrong.
_CHECK_DEFAULT_PORTS = {"http_health": 80}


def default_port(check_type: str, fallback: int = 22) -> int:
    """The port ``check_type`` uses when the step sets none.

    HTTP Health asks port 80; every other check keeps ``fallback``, which is
    the SSH port the steps have always defaulted to.
    """
    return _CHECK_DEFAULT_PORTS.get(check_type, fallback)
