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

from collections import Counter
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


#: Evidence fields a probe's chainable output leaves out: the target is the key,
#: and these are its identity, not what the check found.
_IDENTITY_FIELDS = frozenset({"device_id", "device_name", "success", "error"})


def chain_output(outcomes: list[TargetOutcome]) -> dict[str, Any]:
    """A probe step's chainable output: what each target's check found.

    ``targets`` maps each target name to ``ok``, ``error``, ``latency_ms`` and
    the facts its evidence records (resolved answers, an HTTP status, the
    check type), so a later step reads
    ``{{ steps.ID.output.targets['r1'].ok }}`` instead of opening artifacts.
    Inventory names are unique per site only, and an IP target is named by
    its address, so a name two targets share is keyed as ``name (device id)``
    (or ``name #2`` without an id) and every result is kept.
    """
    facts_by_target = []
    for outcome in outcomes:
        facts = dict((outcome.evidence or {}).get("content_json") or {})
        device_id = facts.get("device_id")
        for key in _IDENTITY_FIELDS:
            facts.pop(key, None)
        facts_by_target.append((outcome, facts, device_id))
    names = Counter(outcome.name for outcome in outcomes)
    taken: set[str] = set()
    targets: dict[str, Any] = {}
    for outcome, facts, device_id in facts_by_target:
        key = base = (
            outcome.name
            if names[outcome.name] == 1 or not device_id
            else f"{outcome.name} ({device_id})"
        )
        number = 2
        while key in taken:
            key, number = f"{base} #{number}", number + 1
        taken.add(key)
        # The outcome's own fields win over evidence keys of the same name.
        targets[key] = {
            **facts,
            "ok": outcome.ok,
            "error": outcome.error,
            "latency_ms": outcome.latency_ms,
        }
    return {"targets": targets}
