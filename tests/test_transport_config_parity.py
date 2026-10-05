# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The netmiko and scrapli transports run a configuration session alike.

The two transport wheels share only the SDK, so each keeps its own copy of
the rules that split a configuration session into config blocks and exec
commands, and of the result a command that is not run gets. These tests run
the same sessions through both copies and fail when they drift apart.
"""

from __future__ import annotations

import pytest

from hegemony_transport_netmiko import transport as netmiko
from hegemony_transport_scrapli import transport as scrapli

_SESSIONS = {
    "plain lines, block left open": [
        "configure terminal",
        "hostname r1",
        "ip domain-name lab.example",
    ],
    "end then save": ["configure terminal", "hostname r1", "end", "write memory"],
    "exit inside a block": [
        "conf t",
        "interface GigabitEthernet1",
        " description uplink",
        " exit",
        "interface GigabitEthernet2",
        " no shutdown",
        "end",
        "write memory",
    ],
    "nested interface and router blocks": [
        "configure terminal",
        "router bgp 65000",
        " neighbor 192.0.2.1 remote-as 65001",
        " address-family ipv4",
        "  neighbor 192.0.2.1 activate",
        " exit-address-family",
        " exit",
        "interface Loopback0",
        " ip address 10.0.0.1 255.255.255.255",
        " exit",
        "end",
    ],
    "save inside a block splits it": [
        "configure terminal",
        "hostname r1",
        "write memory",
        "ntp server 192.0.2.5",
        "end",
    ],
    "copy run save, block left open": ["config t", "hostname r1", "copy run start"],
    "copy running-config save": [
        "config t",
        "hostname r1",
        "end",
        "copy running-config startup-config",
    ],
    "two blocks with exec commands between": [
        "configure terminal",
        "hostname r1",
        "end",
        "show clock",
        "conf t",
        "ntp server 192.0.2.5",
        "end",
        "write memory",
    ],
    "configure terminal inside an open block": [
        "configure terminal",
        "hostname r1",
        "configure terminal",
        "ntp server 192.0.2.5",
        "end",
    ],
    "blank lines": [
        "configure terminal",
        "",
        "vlan 75",
        " name vlan_75",
        "   ",
        "end",
        "",
        "write memory",
        "",
    ],
    "wrapper case and whitespace": ["  Configure Terminal ", "hostname r1", " END", "Write Memory"],
    "end outside a block": ["configure terminal", "hostname r1", "end", "end", "show clock"],
    "exit after end": ["configure terminal", "hostname r1", "end", "exit"],
    "wrappers only": ["configure terminal", "end"],
}


def _netmiko_plan(commands: list[str]) -> list[tuple[bool, list[str]]]:
    """Netmiko's plan in scrapli's shape: each step's lines to send.

    Netmiko plans command indexes and gives every command a result, the
    'configure terminal' / 'end' wrappers and blank lines included. Scrapli
    plans only the lines it sends and never sends those. Dropping them, and
    the steps they leave empty, gives plans the two can share.
    """
    plan = []
    for is_config, indexes in netmiko._plan_config_set(commands):
        lines = [
            commands[idx]
            for idx in indexes
            if commands[idx].strip() and not netmiko._is_mode_wrapper(commands[idx])
        ]
        if lines:
            plan.append((is_config, lines))
    return plan


@pytest.mark.parametrize("commands", list(_SESSIONS.values()), ids=list(_SESSIONS))
def test_both_transports_plan_a_config_session_alike(commands: list[str]) -> None:
    assert _netmiko_plan(commands) == scrapli._plan_config_set(commands)


def test_both_transports_share_the_config_rules() -> None:
    assert netmiko._CONFIG_ENTER_COMMANDS == scrapli._CONFIG_ENTER_COMMANDS
    for command in (
        "write memory",
        "write",
        "wr mem",
        "copy run start",
        "copy running-config startup-config",
        "copy startup-config running-config",
        "show running-config",
    ):
        assert netmiko._is_save_command(command) == scrapli._is_save_command(command), command


def test_both_transports_report_a_command_not_run_alike() -> None:
    assert netmiko._SKIPPED_ERROR == scrapli._SKIPPED_ERROR
    assert netmiko._CANCELLED_ERROR == scrapli._CANCELLED_ERROR
    for reason in (netmiko._SKIPPED_ERROR, netmiko._CANCELLED_ERROR):
        netmiko_result = netmiko._skipped("write memory", reason)
        scrapli_result = scrapli._skipped("write memory", reason)
        assert (
            netmiko_result.command,
            netmiko_result.output,
            netmiko_result.exit_code,
            netmiko_result.error,
        ) == (
            scrapli_result.command,
            scrapli_result.output,
            scrapli_result.exit_code,
            scrapli_result.error,
        )
