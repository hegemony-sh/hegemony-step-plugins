# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The in-process NETCONF device of ``netconf_fakes`` with IOS XE's CLI-RPC model.

It keeps a CLI configuration beside the XML datastores, for Cisco's
``config-ios-cli-trans`` and ``get-modelled-config-clis`` RPCs, and carries it
through discard, commit, confirmed commit and rollback with the XML.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

from tests.netconf_fakes import (
    ALL_CAPABILITIES as NETCONF_CAPABILITIES,
    FakeChannel,
    FakeNetconfDevice,
    FakeServices,
)

CLI_RPC_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-cli-rpc"

ALL_CAPABILITIES = (
    *NETCONF_CAPABILITIES,
    f"{CLI_RPC_NS}?module=Cisco-IOS-XE-cli-rpc&revision=2024-07-01",
)

__all__ = ["ALL_CAPABILITIES", "CLI_RPC_NS", "FakeIosXeDevice", "FakeServices"]


@dataclass
class FakeIosXeDevice(FakeNetconfDevice):
    """A NETCONF device with IOS XE's CLI configuration and CLI-RPC operations."""

    capabilities: tuple[str, ...] = ALL_CAPABILITIES
    running_cli: str = "hostname r1\n"
    candidate_cli: str = ""
    #: False: list Cisco-IOS-XE-cli-rpc in the YANG library only (a YANG 1.1
    #: module, RFC 7950 section 5.6.4), not in the hello.
    cli_rpc_in_hello: bool = True
    #: False: a release before 17.15, whose config-ios-cli-trans has no
    #: operation leaf.
    operation_leaf: bool = True
    #: The result text of a successful config-ios-cli-trans.
    trans_result: str = "Configuration applied successfully"

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.cli_rpc_in_hello:
            self.capabilities = tuple(c for c in self.capabilities if CLI_RPC_NS not in c)
            self.yang_library = (*self.yang_library, CLI_RPC_NS)

    def reset_candidate(self) -> None:
        super().reset_candidate()
        self.candidate_cli = self.running_cli

    def commit_candidate(self) -> None:
        super().commit_candidate()
        self.running_cli = self.candidate_cli

    def candidate_dirty(self) -> bool:
        return super().candidate_dirty() or self.candidate_cli != self.running_cli

    def snapshot(self) -> Any:
        return (super().snapshot(), self.running_cli)

    def restore(self, saved: Any) -> None:
        running, self.running_cli = saved
        super().restore(running)

    def handle_other(self, channel: FakeChannel, op: ET.Element) -> tuple[str, bool] | None:
        name = op.tag.rsplit("}", 1)[-1]
        if name == "config-ios-cli-trans":
            clis = op.findtext(f"{{{CLI_RPC_NS}}}clis") or ""
            operation = op.findtext(f"{{{CLI_RPC_NS}}}operation") or "merge"
            if not self.operation_leaf and op.find(f"{{{CLI_RPC_NS}}}operation") is not None:
                return (
                    "<rpc-error><error-type>protocol</error-type>"
                    "<error-tag>unknown-element</error-tag>"
                    "<error-severity>error</error-severity>"
                    "<error-info><bad-element>operation</bad-element></error-info>"
                    "</rpc-error>",
                    False,
                )
            if "bogus" in clis:
                line = next(i for i, text in enumerate(clis.splitlines(), 1) if "bogus" in text)
                return (
                    f'<result xmlns="{CLI_RPC_NS}">failure</result>'
                    f'<error-message xmlns="{CLI_RPC_NS}">% Invalid input at line {line}: bogus'
                    "</error-message>",
                    False,
                )
            text = clis.strip() + "\n"
            if operation == "merge":
                text = self.candidate_cli.rstrip("\n") + "\n" + text
            self.candidate_cli = text
            return (f'<result xmlns="{CLI_RPC_NS}">{escape(self.trans_result)}</result>', False)
        if name == "get-modelled-config-clis":
            store = op.findtext(f"{{{CLI_RPC_NS}}}datastore") or "running"
            text = self.candidate_cli if store == "candidate" else self.running_cli
            escaped = text.replace("&", "&amp;").replace("<", "&lt;")
            return (f'<result xmlns="{CLI_RPC_NS}">{escaped}</result>', False)
        return None
