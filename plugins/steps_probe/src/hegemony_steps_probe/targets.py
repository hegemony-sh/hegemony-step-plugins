# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Target resolution shared by the probe handlers.

A probe aims at addresses, not at inventory: a step targeted at direct IPs
(the API's ``ip`` selectors, surfaced as ``ctx.get_target_ips()``) is as
legitimate as one targeted at devices, and the monitor handler has always
accepted both. The check handlers read their targets through here so the two
sources stay a union everywhere rather than device-only in some handlers.
"""

from typing import Any


def all_probe_targets(ctx) -> list[dict[str, Any]]:
    """Role-resolved devices first, then direct-IP selector targets.

    IP targets come back device-shaped so the handlers' loops need no second
    code path, but deliberately carry no ``"id"`` key: they have no inventory
    identity, so evidence must record ``device_id`` as None (the artifact
    column is a UUID), and code that keys state by ``get("id", <fallback>)``
    falls through to the address.
    """
    targets = list(ctx.get_target_devices())
    targets.extend({"name": addr, "mgmt_host": addr} for addr in ctx.get_target_ips())
    return targets
