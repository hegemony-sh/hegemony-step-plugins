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

import weakref
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from hegemony_steps_netconf.client import (
    CAP_CANDIDATE,
    NetconfError,
    NetconfSession,
    RpcFailed,
    local_name,
)

CLI_RPC_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-cli-rpc"
YANG_LIBRARY_NS = "urn:ietf:params:xml:ns:yang:ietf-yang-library"

#: Longest ``clis`` the model accepts, in characters: 1..524288 from IOS XE
#: 17.15 (1..60000 on 17.12 to 17.14), per Cisco's published YANG.
MAX_CLIS_CHARS = 524_288

PREREQUISITES = (
    "netconf-yang, netconf-yang feature candidate-datastore, yang-interfaces feature "
    "atomic-config and yang-interfaces feature deprecated disable"
)

#: Sessions whose YANG library was found to list the cli-rpc model.
_IN_YANG_LIBRARY: weakref.WeakKeyDictionary[NetconfSession, bool] = weakref.WeakKeyDictionary()


async def has_cli_rpc(session: NetconfSession) -> bool:
    """Whether the device implements ``Cisco-IOS-XE-cli-rpc``.

    The model is YANG 1.1 since revision 2022-11-01, and a server lists YANG
    1.1 modules in its YANG library rather than in the hello (RFC 7950,
    section 5.6.4). So the hello is checked first, then the YANG library
    (RFC 8525 ``yang-library`` and RFC 7895 ``modules-state``).
    """
    if session.has_module(CLI_RPC_NS):
        return True
    if session in _IN_YANG_LIBRARY:
        return _IN_YANG_LIBRARY[session]
    found = False
    for top in ("yang-library", "modules-state"):
        try:
            reply = await session.get(
                f'<filter type="subtree"><{top} xmlns="{YANG_LIBRARY_NS}"/></filter>'
            )
        except RpcFailed:
            continue
        if any(
            local_name(node.tag) == "namespace" and (node.text or "").strip() == CLI_RPC_NS
            for node in reply.element.iter()
        ):
            found = True
            break
    _IN_YANG_LIBRARY[session] = found
    return found


async def require_acr(session: NetconfSession) -> None:
    """Fail with the device's missing prerequisites when it cannot run ACR."""
    missing = []
    if not session.supports(CAP_CANDIDATE):
        missing.append("the candidate datastore")
    if not await has_cli_rpc(session):
        missing.append("the Cisco-IOS-XE-cli-rpc model")
    if missing:
        raise NetconfError(
            f"the device does not offer {' or '.join(missing)}; atomic configuration replace "
            f"needs a software release with ACR and {PREREQUISITES} configured"
        )


async def read_cli_config(session: NetconfSession, datastore: str) -> str:
    """The modelled configuration of ``datastore`` as CLI text (get-modelled-config-clis).

    Modelled CLI only: Cisco's model description says the RPC leaves out
    wireless, app-hosting and telemetry configuration.
    """
    if not await has_cli_rpc(session):
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

    Any ``error-message`` in the reply (or an rpc-error) is a failure, whatever
    ``result`` says: success is never read from the result text, which reads
    "unsuccessful" as readily as "successful". Raises ``NetconfError`` with
    the device's error message, which names the line ACR rejected.
    """
    if len(clis) > MAX_CLIS_CHARS:
        raise NetconfError(
            f"the configuration has {len(clis)} characters; IOS XE accepts at most "
            f"{MAX_CLIS_CHARS} (17.15 and later)"
        )
    try:
        reply = await session.rpc(
            f'<config-ios-cli-trans xmlns="{CLI_RPC_NS}">'
            f"<clis>{escape(clis)}</clis>"
            f"<operation>{operation}</operation>"
            "<do-commit>false</do-commit>"
            "</config-ios-cli-trans>",
            operation=f"config-ios-cli-trans {operation}",
        )
    except RpcFailed as exc:
        if _names_operation_leaf(exc):
            raise NetconfError(
                "the device does not know config-ios-cli-trans's operation leaf "
                "(merge, selective-replace, full-replace): ACR needs IOS XE 17.15 or later"
            ) from exc
        raise
    result, error = _result(reply.element)
    if error:
        detail = f"{error} (result: {result.strip()})" if result.strip() else error
        raise NetconfError(f"ACR refused the configuration: {detail}")
    return result.strip()


def _names_operation_leaf(exc: RpcFailed) -> bool:
    """Whether the rpc-error is about an element the device does not know: ``operation``."""
    return any(
        error.tag in ("unknown-element", "bad-element", "malformed-message")
        and "operation" in f"{error.info} {error.message} {error.path}"
        for error in exc.errors
    )


def _result(reply: ET.Element) -> tuple[str, str]:
    """The ``result`` and ``error-message`` leaves of a cli-rpc reply.

    Matched by namespace as well as name: a warning's ``<rpc-error>`` (which
    ``rpc()`` lets through) has a base-namespace ``<error-message>`` that is
    not the model's leaf.
    """
    result_node = reply.find(f".//{{{CLI_RPC_NS}}}result")
    error_node = reply.find(f".//{{{CLI_RPC_NS}}}error-message")
    result = "" if result_node is None else result_node.text or ""
    error = "" if error_node is None else (error_node.text or "").strip()
    return result, error
