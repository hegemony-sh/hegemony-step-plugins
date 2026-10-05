# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Target helpers for connectivity monitors.

Reads the addresses out of a ``type: ip`` target selector. A pure function
over plain dicts, so the wheel carries no host imports.
"""

from __future__ import annotations

from typing import Any


def extract_ip_addresses(selector: Any) -> list[str]:
    """Extract valid IPs from a ``type: ip`` selector.

    Supports ``ip`` (single string) and ``addresses`` (list); when both are
    present ``ip`` comes first. Duplicates and blanks are dropped.
    """
    if not isinstance(selector, dict) or selector.get("type") != "ip":
        return []
    ips: list[str] = []
    seen: set[str] = set()
    single_ip = selector.get("ip")
    if isinstance(single_ip, str):
        normalized = single_ip.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            ips.append(normalized)
    addresses = selector.get("addresses")
    if isinstance(addresses, list):
        for addr in addresses:
            if not isinstance(addr, str):
                continue
            normalized = addr.strip()
            if normalized and normalized not in seen:
                seen.add(normalized)
                ips.append(normalized)
    return ips
