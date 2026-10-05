# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Probe options shared by the handlers that run checks through ``run_probe``."""

#: Checks that connect to a port; the others (icmp_ping, dns_resolve) take none.
PORT_CHECKS = frozenset({"tcp_connect", "http_health", "tls_handshake", "ssh_banner"})

#: Ports a check uses when the step sets none, where SSH's 22 would be wrong.
_CHECK_DEFAULT_PORTS = {"http_health": 80}


def default_port(check_type: str, fallback: int = 22) -> int:
    """The port ``check_type`` uses when the step sets none.

    HTTP Health asks port 80; every other check keeps ``fallback``, which is
    the SSH port the steps have always defaulted to.
    """
    return _CHECK_DEFAULT_PORTS.get(check_type, fallback)
