# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Target resolution shared by the probe handlers.

A probe aims at addresses, not at inventory: a step targeted at direct IPs
(the API's ``ip`` selectors, surfaced as ``ctx.get_target_ips()``) is as
legitimate as one targeted at devices, and the monitor handler has always
accepted both. The check handlers read their targets through here so the two
sources stay a union everywhere rather than device-only in some handlers.

The handlers check their targets concurrently (``for_each_target_device``)
and merge one :class:`TargetOutcome` per target afterwards, in target order.
"""

from dataclasses import dataclass
from typing import Any

#: Targets a probe handler checks at once when the step does not say. A probe
#: mostly waits on the network, so one slow target should not hold up the rest.
DEFAULT_MAX_PARALLEL_TARGETS = 10


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


@dataclass
class TargetOutcome:
    """One target's check result, merged in target order after the fan-out.

    Workers return these instead of appending to shared lists, so evidence,
    metrics and the failure list follow target order whatever order the
    checks finish in.
    """

    name: str
    ok: bool
    #: Why the check failed, shown as ``name (error)`` in the step error.
    error: str | None = None
    latency_ms: float | None = None
    #: None for a target that was never checked (no address, nothing to ask).
    evidence: dict[str, Any] | None = None


def merge_outcomes(
    outcomes: list[TargetOutcome],
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Evidence, ``<name>_ms`` metrics and failure lines, in target order."""
    evidence = [outcome.evidence for outcome in outcomes if outcome.evidence is not None]
    metrics: dict[str, Any] = {
        f"{outcome.name}_ms": outcome.latency_ms
        for outcome in outcomes
        if outcome.ok and outcome.latency_ms is not None
    }
    failures = [f"{outcome.name} ({outcome.error})" for outcome in outcomes if not outcome.ok]
    return evidence, metrics, failures
