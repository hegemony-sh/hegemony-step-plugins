# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""IOS XE Atomic Configuration Replace (ACR) over NETCONF.

Cisco's ``Cisco-IOS-XE-cli-rpc`` model takes a whole configuration as CLI text
(``config-ios-cli-trans``: ``clis``, ``operation`` full-replace,
selective-replace or merge, ``do-commit``) and returns the modelled
configuration as CLI text (``get-modelled-config-clis``, from running or
candidate). With ``do-commit`` false the change lands in the candidate
datastore, so ACR fits the netconf wheel's transaction: lock, read running,
replace, read candidate, diff, validate, dry run or (confirmed) commit.

The device needs ``netconf-yang``, ``netconf-yang feature candidate-datastore``,
``yang-interfaces feature atomic-config`` and ``yang-interfaces feature
deprecated disable`` (Cisco Live DEVNET-2385, 2025).
"""

from __future__ import annotations

from xml.sax.saxutils import escape

from hegemony_steps_netconf.client import (
    CAP_CANDIDATE,
    NetconfError,
    NetconfSession,
    local_name,
)

CLI_RPC_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-cli-rpc"

PREREQUISITES = (
    "netconf-yang, netconf-yang feature candidate-datastore, yang-interfaces feature "
    "atomic-config and yang-interfaces feature deprecated disable"
)


def require_acr(session: NetconfSession) -> None:
    """Fail with the device's missing prerequisites when it cannot run ACR."""
    missing = []
    if not session.supports(CAP_CANDIDATE):
        missing.append("the candidate datastore")
    if not session.has_module(CLI_RPC_NS):
        missing.append("the Cisco-IOS-XE-cli-rpc model")
    if missing:
        raise NetconfError(
            f"the device does not offer {' or '.join(missing)}; atomic configuration replace "
            f"needs a software release with ACR and {PREREQUISITES} configured"
        )


async def read_cli_config(session: NetconfSession, datastore: str) -> str:
    """The modelled configuration of ``datastore`` as CLI text (get-modelled-config-clis)."""
    if not session.has_module(CLI_RPC_NS):
        raise NetconfError(
            "the device does not offer the Cisco-IOS-XE-cli-rpc model (get-modelled-config-clis)"
        )
    reply = await session.rpc(
        f'<get-modelled-config-clis xmlns="{CLI_RPC_NS}">'
        f"<datastore>{datastore}</datastore></get-modelled-config-clis>",
        operation=f"get-modelled-config-clis {datastore}",
    )
    result, error = _result(reply.element)
    if error:
        raise NetconfError(f"get-modelled-config-clis {datastore} failed: {error}")
    return result.strip("\n") + "\n" if result.strip() else ""


async def apply_cli_config(session: NetconfSession, clis: str, operation: str) -> str:
    """Send ``clis`` with ACR ``operation`` into the candidate; returns the device's result.

    Raises ``NetconfError`` with the device's error message (which names the
    line ACR rejected) when the configuration is refused.
    """
    reply = await session.rpc(
        f'<config-ios-cli-trans xmlns="{CLI_RPC_NS}">'
        f"<clis>{escape(clis)}</clis>"
        f"<operation>{operation}</operation>"
        "<do-commit>false</do-commit>"
        "</config-ios-cli-trans>",
        operation=f"config-ios-cli-trans {operation}",
    )
    result, error = _result(reply.element)
    if error or (result and "success" not in result.lower()):
        raise NetconfError(f"ACR refused the configuration: {error or result}")
    return result


def _result(reply) -> tuple[str, str]:
    """The ``result`` and ``error-message`` leaves of a cli-rpc reply."""
    result = error = ""
    for node in reply.iter():
        name = local_name(node.tag)
        if name == "result" and not result:
            result = node.text or ""
        elif name == "error-message" and not error:
            error = (node.text or "").strip()
    return result, error
