# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for evidence.assert scopes and operators.

Focuses on the line-scope machinery (every selected line must satisfy the
operator, min_lines guards vacuous passes) and the negative operators. The
canonical motivating case: ``show ip ospf neighbor`` where "output contains
'Full'" passes with one healthy adjacency among broken ones, but "every
neighbor row contains 'Full'" does not.
"""

from __future__ import annotations

from hegemony_steps_evidence.assert_check import AssertHandler

# FRR-style neighbor table: header + one row per adjacency, rows keyed by the
# Neighbor ID address in the first column.
_NEIGHBORS_ALL_FULL = """\
Neighbor ID     Pri State           Up Time         Dead Time Address         Interface
10.255.255.2      1 Full/DR         4m11s             34.077s 10.0.0.2        eth0:10.0.0.1
10.255.255.3      1 Full/BDR        4m09s             31.552s 10.0.1.2        eth1:10.0.1.1
"""
_NEIGHBORS_ONE_STUCK = """\
Neighbor ID     Pri State           Up Time         Dead Time Address         Interface
10.255.255.2      1 Full/DR         4m11s             34.077s 10.0.0.2        eth0:10.0.0.1
10.255.255.3      1 ExStart/BDR     0m02s             39.001s 10.0.1.2        eth1:10.0.1.1
"""
_NEIGHBORS_EMPTY = """\
Neighbor ID     Pri State           Up Time         Dead Time Address         Interface
"""
_ROW_FILTER = r"^\s*\d+\.\d+\.\d+\.\d+"


def _handler() -> AssertHandler:
    return AssertHandler()


class TestNegativeOperators:
    def test_not_contains(self) -> None:
        handler = _handler()
        assert handler._compare_values("all good here", "ERROR", "not_contains")[0] is True
        assert handler._compare_values("an ERROR happened", "ERROR", "not_contains")[0] is False
        # Non-container actual values fail conservatively, mirroring contains.
        assert handler._compare_values(17, "17", "not_contains")[0] is False

    def test_not_matches(self) -> None:
        handler = _handler()
        assert handler._compare_values("state Full/DR", r"(Init|ExStart)", "not_matches")[0] is True
        assert (
            handler._compare_values("state ExStart/DR", r"(Init|ExStart)", "not_matches")[0]
            is False
        )
        assert handler._compare_values(123, r"\d+", "not_matches")[0] is False


class TestOutputScope:
    def test_output_scope_is_the_default_and_keeps_old_behavior(self) -> None:
        handler = _handler()
        # The motivating bug: whole-output contains passes even with a stuck
        # adjacency, because SOME row says Full.
        passed, _, detail = handler._assert_content(
            _NEIGHBORS_ONE_STUCK, "Full", "contains", "output", "", 1
        )
        assert passed is True
        assert detail == {"match_scope": "output"}


class TestLineScope:
    def test_every_selected_line_must_match(self) -> None:
        handler = _handler()
        passed, _, detail = handler._assert_content(
            _NEIGHBORS_ALL_FULL, "Full", "contains", "lines", _ROW_FILTER, 1
        )
        assert passed is True
        assert detail["lines_selected"] == 2
        assert detail["lines_passed"] == 2

    def test_one_stuck_adjacency_fails_and_is_named(self) -> None:
        handler = _handler()
        passed, msg, detail = handler._assert_content(
            _NEIGHBORS_ONE_STUCK, "Full", "contains", "lines", _ROW_FILTER, 1
        )
        assert passed is False
        assert "1/2" in msg
        assert "ExStart" in detail["first_failed_line"]

    def test_empty_selection_fails_via_min_lines(self) -> None:
        # An empty neighbor table must not pass vacuously.
        handler = _handler()
        passed, msg, _ = handler._assert_content(
            _NEIGHBORS_EMPTY, "Full", "contains", "lines", _ROW_FILTER, 1
        )
        assert passed is False
        assert "expected at least 1" in msg

    def test_min_lines_zero_allows_empty_selection(self) -> None:
        handler = _handler()
        passed, _, _ = handler._assert_content(
            _NEIGHBORS_EMPTY, "Full", "contains", "lines", _ROW_FILTER, 0
        )
        assert passed is True

    def test_min_lines_can_pin_expected_row_count(self) -> None:
        handler = _handler()
        passed, msg, _ = handler._assert_content(
            _NEIGHBORS_ALL_FULL, "Full", "contains", "lines", _ROW_FILTER, 3
        )
        assert passed is False
        assert "only 2 line(s)" in msg

    def test_empty_filter_selects_non_empty_lines(self) -> None:
        handler = _handler()
        passed, _, detail = handler._assert_content(
            "a ok\n\nb ok\n", "ok", "contains", "lines", "", 1
        )
        assert passed is True
        assert detail["lines_selected"] == 2

    def test_line_scope_with_not_matches(self) -> None:
        # "No selected row may be in a transitional state" — the negation
        # composes with line scope.
        handler = _handler()
        passed, _, _ = handler._assert_content(
            _NEIGHBORS_ONE_STUCK,
            r"(Init|ExStart|Exchange|Loading|2-Way)",
            "not_matches",
            "lines",
            _ROW_FILTER,
            1,
        )
        assert passed is False
        passed, _, _ = handler._assert_content(
            _NEIGHBORS_ALL_FULL,
            r"(Init|ExStart|Exchange|Loading|2-Way)",
            "not_matches",
            "lines",
            _ROW_FILTER,
            1,
        )
        assert passed is True

    def test_invalid_filter_regex_fails_cleanly(self) -> None:
        handler = _handler()
        passed, msg, _ = handler._assert_content(
            _NEIGHBORS_ALL_FULL, "Full", "contains", "lines", "([", 1
        )
        assert passed is False
        assert "Invalid line_filter regex" in msg

    def test_non_string_content_fails_cleanly(self) -> None:
        handler = _handler()
        passed, msg, _ = handler._assert_content(123, "Full", "contains", "lines", "", 1)
        assert passed is False
        assert "needs text content" in msg


class TestLatestArtifact:
    """Duplicate step_id+name artifacts (loop iterations) must resolve to the newest."""

    def _dup(self, *contents_with_dates):
        return [
            {
                "step_id": "collect_state",
                "name": "dc1-core-01:show ip ospf neighbor",
                "content_text": text,
                **({"created_at": at} if at is not None else {}),
            }
            for text, at in contents_with_dates
        ]

    def test_picks_newest_by_created_at(self) -> None:
        from hegemony_steps_evidence.artifacts import latest_artifact

        artifacts = self._dup(
            ("% OSPF is not enabled in vrf default", "2026-07-27T19:00:00+00:00"),
            (_NEIGHBORS_ALL_FULL, "2026-07-27T19:01:30+00:00"),
        )
        picked = latest_artifact(
            artifacts, step_id="collect_state", name="dc1-core-01:show ip ospf neighbor"
        )
        assert picked is not None
        assert "Full/DR" in picked["content_text"]

    def test_created_at_wins_over_list_order(self) -> None:
        from hegemony_steps_evidence.artifacts import latest_artifact

        artifacts = self._dup(
            (_NEIGHBORS_ALL_FULL, "2026-07-27T19:01:30+00:00"),
            ("% OSPF is not enabled in vrf default", "2026-07-27T19:00:00+00:00"),
        )
        picked = latest_artifact(artifacts, step_id="collect_state")
        assert picked is not None
        assert "Full/DR" in picked["content_text"]

    def test_without_created_at_last_match_wins(self) -> None:
        # Older APIs omit created_at; the API returns oldest first, so the
        # last listed duplicate is the newest.
        from hegemony_steps_evidence.artifacts import latest_artifact

        artifacts = self._dup(
            ("% OSPF is not enabled in vrf default", None),
            (_NEIGHBORS_ALL_FULL, None),
        )
        picked = latest_artifact(artifacts, step_id="collect_state")
        assert picked is not None
        assert "Full/DR" in picked["content_text"]

    def test_filters_apply(self) -> None:
        from hegemony_steps_evidence.artifacts import latest_artifact

        artifacts = [
            {"step_id": "other", "name": "x", "created_at": "2026-07-27T20:00:00+00:00"},
            {"step_id": "collect_state", "name": "x", "created_at": "2026-07-27T19:00:00+00:00"},
        ]
        picked = latest_artifact(artifacts, step_id="collect_state")
        assert picked is not None and picked["step_id"] == "collect_state"
        assert latest_artifact(artifacts, step_id="missing") is None
        assert latest_artifact([], step_id="collect_state") is None

    def test_mixed_iso_forms_compare_correctly(self) -> None:
        # 'Z' vs '+00:00' must not be compared lexicographically ('Z' would
        # incorrectly beat any '+' offset for the same instant).
        from hegemony_steps_evidence.artifacts import latest_artifact

        # Lexical and chronological order disagree here: the lexically
        # smaller "-01:00" timestamp is the newer instant (19:30Z > 19:01Z).
        artifacts = self._dup(
            (_NEIGHBORS_ALL_FULL, "2026-07-27T18:30:00-01:00"),
            ("% OSPF is not enabled in vrf default", "2026-07-27T19:01:30Z"),
        )
        picked = latest_artifact(artifacts, step_id="collect_state")
        assert picked is not None
        assert "Full/DR" in picked["content_text"]

    def test_unparsable_created_at_falls_back_to_list_order(self) -> None:
        from hegemony_steps_evidence.artifacts import latest_artifact

        artifacts = self._dup(
            ("% OSPF is not enabled in vrf default", "not-a-date"),
            (_NEIGHBORS_ALL_FULL, 12345),
        )
        picked = latest_artifact(artifacts, step_id="collect_state")
        assert picked is not None
        assert "Full/DR" in picked["content_text"]


class TestScopeValidation:
    def test_unknown_match_scope_fails_cleanly(self) -> None:
        handler = _handler()
        passed, msg, detail = handler._assert_content(
            _NEIGHBORS_ALL_FULL, "Full", "contains", "every_line", "", 1
        )
        assert passed is False
        assert "Unknown match_scope" in msg
        assert detail["match_scope"] == "every_line"


def test_numeric_operators_reachable_in_config_schema() -> None:
    # gt/lt/ge/le are implemented in _compare_values and documented — the
    # config schema must actually offer them.
    from hegemony_steps_evidence.assert_check import AssertConfig

    for op in ("gt", "lt", "ge", "le"):
        assert AssertConfig(artifact_step_id="s", operator=op).operator == op


def test_regex_paths_are_input_capped() -> None:
    # Workflow-controlled regexes never run against more than the cap.
    from hegemony_steps_evidence.assert_check import _MAX_REGEX_INPUT_CHARS

    handler = _handler()
    huge = "a" * (_MAX_REGEX_INPUT_CHARS + 100) + "NEEDLE"
    # The needle sits beyond the cap, so the regex must not see it.
    passed, _ = handler._compare_values(huge, "NEEDLE", "matches")
    assert passed is False
    # Line scope marks the truncation in the evidence detail.
    passed, _, detail = handler._assert_content(huge, "a", "contains", "lines", "", 1)
    assert detail.get("truncated") is True


# ── Finding a command's output (netcli.collect_evidence artifacts) ───────────

# An artifact name keeps the command's first line, cut to 80 characters, so
# each pair below shares one artifact name.
_LONG_A = (
    "show ip bgp vpnv4 vrf CUSTOMER-PRODUCTION-BLUE-DC1 neighbors 192.168.100.100 "
    "advertised-routes | include 10."
)
_LONG_B = (
    "show ip bgp vpnv4 vrf CUSTOMER-PRODUCTION-BLUE-DC1 neighbors 192.168.100.100 "
    "advertised-routes | include 172."
)
_MULTI = "show run | section bgp\nshow ip bgp summary"
_SHORT = "show run | section bgp"
_TRAILING_SPACE = "show version "
_OUTPUTS = {
    _LONG_A: "ADVERTISED 10.0.0.0/8",
    _LONG_B: "RECEIVED 172.16.0.0/12",
    _SHORT: "router bgp 65000 (section only)",
    _MULTI: "router bgp 65000 ... + summary",
    _TRAILING_SPACE: "Cisco IOS XE Software, Version 17.12.01",
}
_R1 = {"id": "d1", "name": "r1"}


def _collected(step_id: str, outputs: dict[str, str], device=_R1) -> list[dict]:
    """Artifacts shaped as netcli.collect_evidence stores them."""
    from hegemony_step_sdk import command_label

    return [
        {
            "step_id": step_id,
            "kind": "cli_output",
            "name": f"{device['name']}:{command_label(command)}",
            "device_id": device["id"],
            "content_text": output,
            "content_json": {
                "device_id": device["id"],
                "device_name": device["name"],
                "command": command,
                "success": True,
                "exit_code": 0,
                "error": None,
            },
            "created_at": f"2026-10-05T10:00:{index:02d}+00:00",
        }
        for index, (command, output) in enumerate(outputs.items())
    ]


def test_command_names_collide_but_lookups_do_not() -> None:
    from hegemony_step_sdk import command_label

    assert command_label(_LONG_A) == command_label(_LONG_B)
    assert command_label(_MULTI) == command_label(_SHORT)


class TestFindCommandArtifact:
    def test_each_command_finds_its_own_output(self) -> None:
        from hegemony_steps_evidence.artifacts import find_command_artifact

        artifacts = _collected("collect", _OUTPUTS)
        for command, output in _OUTPUTS.items():
            found = find_command_artifact(artifacts, step_id="collect", device=_R1, command=command)
            assert found is not None, command
            assert found["content_text"] == output

    def test_surrounding_whitespace_is_ignored(self) -> None:
        from hegemony_steps_evidence.artifacts import find_command_artifact

        artifacts = _collected("collect", _OUTPUTS)
        found = find_command_artifact(
            artifacts, step_id="collect", device=_R1, command="show version"
        )
        assert found is not None and "17.12" in found["content_text"]

    def test_device_and_step_must_match(self) -> None:
        from hegemony_steps_evidence.artifacts import find_command_artifact

        r2 = {"id": "d2", "name": "r2"}
        artifacts = _collected("collect", {_SHORT: "r1 output"}) + _collected(
            "collect", {_SHORT: "r2 output"}, device=r2
        )
        found = find_command_artifact(artifacts, step_id="collect", device=r2, command=_SHORT)
        assert found is not None and found["content_text"] == "r2 output"
        assert find_command_artifact(artifacts, step_id="other", device=r2, command=_SHORT) is None

    def test_newest_capture_wins(self) -> None:
        from hegemony_steps_evidence.artifacts import find_command_artifact

        old, new = _collected("collect", {_LONG_A: "old"}), _collected("collect", {_LONG_A: "new"})
        new[0]["created_at"] = "2026-10-05T11:00:00+00:00"
        found = find_command_artifact(new + old, step_id="collect", device=_R1, command=_LONG_A)
        assert found is not None and found["content_text"] == "new"

    def test_artifacts_without_metadata_match_by_name(self) -> None:
        from hegemony_steps_evidence.artifacts import find_command_artifact

        artifacts = [
            {"step_id": "collect", "name": "r1:show version", "content_text": "short"},
            {"step_id": "collect", "name": "r1:" + _LONG_A[:79] + "…", "content_text": "long"},
        ]
        found = find_command_artifact(
            artifacts, step_id="collect", device=_R1, command="show version"
        )
        assert found is not None and found["content_text"] == "short"
        found = find_command_artifact(artifacts, step_id="collect", device=_R1, command=_LONG_A)
        assert found is not None and found["content_text"] == "long"


async def _assert_command(artifacts: list[dict], command: str, expected: str):
    from typing import cast

    from hegemony_step_sdk import HandlerContext, HandlerServices

    class _Response:
        status_code = 200

        def json(self) -> dict:
            return {"artifacts": artifacts}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc) -> bool:
            return False

        async def get(self, url: str) -> _Response:
            return _Response()

    class _Services:
        def open_api_client(self, timeout: float = 30) -> _Client:
            return _Client()

    ctx = HandlerContext(
        run_id="run-1",
        flow_id="f",
        step_run_id="sr-1",
        step_id="assert",
        config={
            "artifact_step_id": "collect",
            "target_role": "core",
            "command": command,
            "operator": "contains",
            "expected": expected,
        },
        target_roles=["core"],
        target_devices_by_role={"core": [_R1]},
        services=cast(HandlerServices, _Services()),
    )
    return await _handler().execute(ctx)


async def test_assert_reads_the_output_of_the_full_command() -> None:
    artifacts = _collected("collect", _OUTPUTS)
    for command, output in _OUTPUTS.items():
        result = await _assert_command(artifacts, command, output)
        assert result.success is True, (command, result.error)
    # The short command reads its own output, not the multi-line command's
    # output that shares its artifact name.
    result = await _assert_command(artifacts, _SHORT, "+ summary")
    assert result.success is False
    assert result.evidence[0]["content_json"]["actual"] == _OUTPUTS[_SHORT]


async def test_assert_fails_when_the_command_was_not_collected() -> None:
    result = await _assert_command(_collected("collect", {_LONG_A: "x"}), _LONG_B, "x")
    assert result.success is False
    assert "could not fetch artifact content" in (result.error or "")
