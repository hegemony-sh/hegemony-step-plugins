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

from tests.netconf_fakes import (
    ALL_CAPABILITIES as NETCONF_CAPABILITIES,
    FakeChannel,
    FakeNetconfDevice,
    FakeServices,
)

CLI_RPC_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-cli-rpc"

ALL_CAPABILITIES = (
    *NETCONF_CAPABILITIES,
    f"{CLI_RPC_NS}?module=Cisco-IOS-XE-cli-rpc&revision=2023-11-01",
)

__all__ = ["ALL_CAPABILITIES", "CLI_RPC_NS", "FakeIosXeDevice", "FakeServices"]


@dataclass
class FakeIosXeDevice(FakeNetconfDevice):
    """A NETCONF device with IOS XE's CLI configuration and CLI-RPC operations."""

    capabilities: tuple[str, ...] = ALL_CAPABILITIES
    running_cli: str = "hostname r1\n"
    candidate_cli: str = ""

    def reset_candidate(self) -> None:
        super().reset_candidate()
        self.candidate_cli = self.running_cli

    def commit_candidate(self) -> None:
        super().commit_candidate()
        self.running_cli = self.candidate_cli

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
            return (
                f'<result xmlns="{CLI_RPC_NS}">Configuration applied successfully</result>',
                False,
            )
        if name == "get-modelled-config-clis":
            store = op.findtext(f"{{{CLI_RPC_NS}}}datastore") or "running"
            text = self.candidate_cli if store == "candidate" else self.running_cli
            escaped = text.replace("&", "&amp;").replace("<", "&lt;")
            return (f'<result xmlns="{CLI_RPC_NS}">{escaped}</result>', False)
        return None
