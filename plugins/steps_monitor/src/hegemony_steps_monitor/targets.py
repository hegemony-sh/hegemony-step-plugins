# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Target resolution for connectivity monitors.

Resolves monitor ``targets`` selectors (role / ip) into concrete address dicts
the host ``start_monitor`` service converts to its internal ResolvedTarget.
Pure functions over plain dicts — selector/address kinds are the string values
of the host's Monitor* enums, so the wheel carries no host imports.
"""

from __future__ import annotations

import ipaddress
from typing import Any

#: Address kinds a role selector may resolve (string values of the host's
#: MonitorAddressKind enum); an unknown kind is a config error, not a silent
#: fallback to mgmt.
VALID_ADDRESS_KINDS = frozenset({"mgmt", "primary", "loopback", "custom"})
#: Address family preferences (host MonitorAddressFamily values).
VALID_ADDRESS_FAMILIES = frozenset({"auto", "ipv4", "ipv6"})


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


def _literal_family(address: Any) -> str | None:
    """``"ipv4"``/``"ipv6"`` for an IP literal, ``None`` for hostnames/junk."""
    if not isinstance(address, str) or not address:
        return None
    try:
        parsed = ipaddress.ip_address(address.strip("[]"))
    except ValueError:
        return None
    return "ipv6" if parsed.version == 6 else "ipv4"


def _address_candidates(device: dict[str, Any], address_kind: str) -> list[str]:
    """The addresses an address kind may resolve to, in preference order."""
    if address_kind == "primary":
        candidates = [*device.get("mgmt_ips", []), device.get("mgmt_host")]
    elif address_kind == "loopback":
        candidates = [device.get("loopback_ip"), device.get("mgmt_host")]
    elif address_kind == "custom":
        candidates = [device.get("hostname"), device.get("mgmt_host")]
    else:
        # "mgmt" and any unknown kind fall back to the management host.
        candidates = [device.get("mgmt_host")]
    return [c for c in candidates if isinstance(c, str) and c]


def get_device_address(
    device: dict[str, Any], address_kind: str, address_family: str = "auto"
) -> str | None:
    """Extract the address from a device dict for the given address kind.

    ``address_family`` is a preference (the host's MonitorAddressFamily
    semantics): with ``ipv4``/``ipv6`` the first candidate that is an IP
    literal of that family wins; when no candidate matches — hostnames
    included, since their family is unknowable without resolving them — the
    ordinary first candidate is used rather than dropping the device.
    """
    candidates = _address_candidates(device, address_kind)
    if address_family in ("ipv4", "ipv6"):
        for candidate in candidates:
            if _literal_family(candidate) == address_family:
                return candidate
    return candidates[0] if candidates else None


def resolve_targets(
    config: dict[str, Any],
    target_devices_by_role: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Resolve a monitor config's ``targets`` selectors to address dicts.

    Returns a list of ``{instance_id, selector_index, selector_type, role,
    device_id, address}`` dicts (``selector_type`` is ``"role"`` or ``"ip"``).

    ``address_family`` is honored as a preference for role-resolved devices:
    ``ipv4``/``ipv6`` pick the first candidate address of that family and fall
    back to the kind's normal choice when no literal matches. Explicit ``ip``
    selectors are used exactly as written.

    Raises:
        ValueError: for an unknown ``address_kind`` or ``address_family`` —
            a typo must fail the step, not silently monitor the wrong address.
    """
    targets: list[dict[str, Any]] = []
    address_kind = config.get("address_kind", "mgmt")
    if address_kind not in VALID_ADDRESS_KINDS:
        raise ValueError(f"Invalid address_kind: {address_kind!r}")
    address_family = config.get("address_family", "auto")
    if address_family not in VALID_ADDRESS_FAMILIES:
        raise ValueError(f"Invalid address_family: {address_family!r}")

    for idx, selector in enumerate(config.get("targets", [])):
        selector_type = selector.get("type")

        if selector_type == "role":
            role = selector.get("role", "")
            for device in target_devices_by_role.get(role, []):
                address = get_device_address(device, address_kind, address_family)
                if address:
                    targets.append(
                        {
                            "instance_id": f"{role}:{device.get('id', 'unknown')}",
                            "selector_index": idx,
                            "selector_type": "role",
                            "role": role,
                            "device_id": device.get("id"),
                            "address": address,
                        }
                    )
        elif selector_type == "ip":
            for addr in extract_ip_addresses(selector):
                targets.append(
                    {
                        "instance_id": f"ip:{addr}",
                        "selector_index": idx,
                        "selector_type": "ip",
                        "role": None,
                        "device_id": None,
                        "address": addr,
                    }
                )

    return targets
