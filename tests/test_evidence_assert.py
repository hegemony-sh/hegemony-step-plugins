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

        artifacts = self._dup(
            (_NEIGHBORS_ALL_FULL, "2026-07-27T19:01:30Z"),
            ("% OSPF is not enabled in vrf default", "2026-07-27T19:00:00+00:00"),
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
