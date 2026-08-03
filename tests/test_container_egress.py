# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Egress-policy config validation for container.run.

Admission-side checks only (enforcement is host-side): the mode vocabulary,
the shared rule grammar, coherence between mode and rule lists, and the
refusal to combine egress with host-access options that would make
enforcement impossible.
"""

from __future__ import annotations

from hegemony_steps_container.run import RunContainerHandler, egress_rule_error

_BASE = {"image": "alpine:3.20"}


def _errors(config: dict) -> list[str]:
    return RunContainerHandler().validate_config({**_BASE, **config})


class TestEgressRuleGrammar:
    def test_valid_rules(self) -> None:
        for rule in (
            "172.20.30.0/24",
            "10.0.0.1",
            "0.0.0.0/0:443/tcp",
            "192.168.0.0/16:1000-2000/udp",
            "10.1.2.3:22",
            "dind:3000",
            "some-service.internal:8443",
        ):
            assert egress_rule_error(rule) is None, rule

    def test_invalid_rules(self) -> None:
        for rule in (
            "",
            "999.1.1.1/24",
            "10.0.0.0/33",
            "10.0.0.0/24:0",
            "10.0.0.0/24:70000",
            "10.0.0.0/24:2000-1000",
            "http://dind:3000",
            "dind",
            "dind:0",
            "-bad:80",
        ):
            assert egress_rule_error(rule) is not None, rule


class TestEgressConfigValidation:
    def test_no_egress_fields_is_valid(self) -> None:
        assert _errors({}) == []

    def test_allow_listed_happy_path(self) -> None:
        assert _errors({"egress_mode": "allow-listed", "egress_allow": ["172.20.30.0/24"]}) == []

    def test_open_with_deny_happy_path(self) -> None:
        assert _errors({"egress_mode": "open", "egress_deny": ["169.254.169.254/32"]}) == []

    def test_deny_all_happy_path(self) -> None:
        assert _errors({"egress_mode": "deny-all"}) == []

    def test_unknown_mode_rejected(self) -> None:
        errors = _errors({"egress_mode": "blocklist"})
        assert any("Invalid 'egress_mode'" in e for e in errors)

    def test_rules_without_mode_rejected(self) -> None:
        errors = _errors({"egress_allow": ["10.0.0.0/8"]})
        assert any("require an explicit 'egress_mode'" in e for e in errors)

    def test_deny_all_with_rules_rejected(self) -> None:
        errors = _errors({"egress_mode": "deny-all", "egress_deny": ["10.0.0.0/8"]})
        assert any("does not take allow/deny rules" in e for e in errors)

    def test_allow_listed_without_allow_rejected(self) -> None:
        errors = _errors({"egress_mode": "allow-listed"})
        assert any("requires at least one 'egress_allow' rule" in e for e in errors)

    def test_open_with_allow_rejected(self) -> None:
        errors = _errors({"egress_mode": "open", "egress_allow": ["10.0.0.0/8"]})
        assert any("does not take 'egress_allow' rules" in e for e in errors)

    def test_bad_rule_string_reported_with_index(self) -> None:
        errors = _errors(
            {"egress_mode": "allow-listed", "egress_allow": ["10.0.0.0/8", "not a rule"]}
        )
        assert any("'egress_allow[1]'" in e for e in errors)

    def test_host_access_combinations_rejected(self) -> None:
        for field, value in (
            ("network_mode", "host"),
            ("attach_docker_socket", True),
            ("privileged", True),
            ("pid_mode", "host"),
            ("extra_mounts", ["/var/run/netns:/var/run/netns:shared"]),
        ):
            errors = _errors({"egress_mode": "deny-all", field: value})
            assert any(
                "cannot be combined with host-access options" in e and field in e for e in errors
            ), (field, errors)

    def test_network_disabled_combination_rejected(self) -> None:
        errors = _errors({"egress_mode": "deny-all", "network_disabled": True})
        assert any("network_disabled" in e and "deny-all" in e for e in errors)

    def test_host_access_without_egress_still_valid(self) -> None:
        # The gate only bites when an egress policy is declared.
        assert _errors({"privileged": True}) == []
