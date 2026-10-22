# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for evidence.compare mode + volatile-line filtering."""

from __future__ import annotations

import pytest

from hegemony_steps_evidence.compare import CompareEvidenceHandler

# Two routing-table captures that are identical except for OSPF uptime timers
# (the "00:0x:yz" columns) — the kind of volatile output that always differs.
_ROUTE_PRE = """\
O    10.255.255.1/32 [110/20] via 10.0.0.1, 00:01:11, eth0
O    10.255.255.2/32 [110/20] via 10.0.0.2, 00:03:47, eth1
"""
_ROUTE_POST_TIMERS_ONLY = """\
O    10.255.255.1/32 [110/20] via 10.0.0.1, 00:09:52, eth0
O    10.255.255.2/32 [110/20] via 10.0.0.2, 00:12:03, eth1
"""
# Same as _ROUTE_PRE but with the announced /32 added (the meaningful change),
# plus the same drifting timers.
_ROUTE_POST_REAL_CHANGE = """\
O    10.255.255.1/32 [110/20] via 10.0.0.1, 00:09:52, eth0
O    10.255.255.2/32 [110/20] via 10.0.0.2, 00:12:03, eth1
O    10.200.150.1/32 [110/20] via 10.0.0.1, 00:00:04, eth0
"""
# Regex that drops the volatile uptime column so only routes are compared.
_TIMER_PATTERN = r", \d\d:\d\d:\d\d,"


def _handler() -> CompareEvidenceHandler:
    return CompareEvidenceHandler()


def test_exact_mode_fails_on_diff_passes_on_match() -> None:
    handler = _handler()
    passed, _ = handler._compare("a\nb", "a\nb", "exact", [])
    assert passed is True
    passed, _ = handler._compare("a\nb", "a\nc", "exact", [])
    assert passed is False


def test_changed_mode_inverts_exact() -> None:
    """'changed' passes on a difference and fails when nothing changed."""
    handler = _handler()
    passed, _ = handler._compare("a\nb", "a\nc", "changed", [])
    assert passed is True
    passed, _ = handler._compare("a\nb", "a\nb", "changed", [])
    assert passed is False


def test_ignore_patterns_strip_volatile_timers() -> None:
    """Captures differing only by timers compare equal once timers are ignored."""
    handler = _handler()
    timers = handler._compile_ignore_patterns([_TIMER_PATTERN])
    # Without ignoring, the drifting timers always look like a change.
    passed, _ = handler._compare(_ROUTE_PRE, _ROUTE_POST_TIMERS_ONLY, "exact", [])
    assert passed is False
    # Ignoring the timer column, the two are identical → exact passes,
    # and 'changed' correctly reports no meaningful change.
    passed, _ = handler._compare(_ROUTE_PRE, _ROUTE_POST_TIMERS_ONLY, "exact", [], timers)
    assert passed is True
    passed, _ = handler._compare(_ROUTE_PRE, _ROUTE_POST_TIMERS_ONLY, "changed", [], timers)
    assert passed is False


def test_ignore_patterns_keep_real_change() -> None:
    """A genuine change (a new prefix) still registers once timers are ignored."""
    handler = _handler()
    timers = handler._compile_ignore_patterns([_TIMER_PATTERN])
    passed, _ = handler._compare(_ROUTE_PRE, _ROUTE_POST_REAL_CHANGE, "changed", [], timers)
    assert passed is True
    passed, _ = handler._compare(_ROUTE_PRE, _ROUTE_POST_REAL_CHANGE, "exact", [], timers)
    assert passed is False


def test_compile_ignore_patterns_masks_and_tolerates_bad_regex() -> None:
    handler = _handler()
    text = "keep me\nBytes: 123\nkeep me too"
    masked = handler._mask_ignored(text, handler._compile_ignore_patterns([r"Bytes: \d+"]))
    assert "Bytes:" not in masked
    assert "keep me" in masked and "keep me too" in masked
    # An invalid regex is dropped at compile time, not raised — the valid one
    # still applies.
    compiled = handler._compile_ignore_patterns(["(", r"Bytes: \d+"])
    assert len(compiled) == 1
    assert "Bytes:" not in handler._mask_ignored(text, compiled)


def test_ignore_patterns_are_bounded() -> None:
    """Guardrails: pattern count is capped and oversized text is left unmasked."""
    from hegemony_steps_evidence import compare as compare_mod

    handler = _handler()
    too_many = [rf"x{i}" for i in range(compare_mod._MAX_IGNORE_PATTERNS + 5)]
    assert len(handler._compile_ignore_patterns(too_many)) == compare_mod._MAX_IGNORE_PATTERNS
    # Text over the cap is returned unchanged instead of running the regex.
    big = "Bytes: 1\n" + ("y" * compare_mod._MAX_MASK_INPUT_CHARS)
    compiled = handler._compile_ignore_patterns([r"Bytes: \d+"])
    assert handler._mask_ignored(big, compiled) == big


# ── execute()-level coverage for artifact selection ──────────────────────────


def _artifact(name: str, text: str) -> dict:
    return {"name": name, "content_text": text}


def _ctx(**config):
    from types import SimpleNamespace

    return SimpleNamespace(config=config, step_id="cur", run_id="run-1", step_run_id="sr-1")


def _handler_with(
    pre: list[dict], post: list[dict], monkeypatch: pytest.MonkeyPatch
) -> CompareEvidenceHandler:
    """A handler whose run fetch returns ``pre`` and ``post`` as the two steps' artifacts."""
    handler = _handler()

    async def fake_fetch(ctx: object) -> list[dict]:
        return [{**a, "step_id": "precheck"} for a in pre] + [
            {**a, "step_id": "postcheck"} for a in post
        ]

    monkeypatch.setattr(handler, "_fetch_run_artifacts", fake_fetch)
    return handler


async def test_execute_pattern_selects_only_matching_artifacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """artifact_name_pattern compares only the running-config, not the route table."""
    pre = [
        _artifact("dc1:show running-config", "hostname dc1"),
        _artifact("dc1:show ip route ospf", "O 10.0.0.0/24"),
    ]
    post = [
        _artifact("dc1:show running-config", "hostname dc1\ninterface lo"),  # changed
        _artifact("dc1:show ip route ospf", "O 10.0.0.0/24"),  # unchanged
    ]
    handler = _handler_with(pre, post, monkeypatch)
    result = await handler.execute(
        _ctx(
            precheck_step_id="precheck",
            postcheck_step_id="postcheck",
            comparison_type="changed",
            artifact_name_pattern="*show running-config",
        )
    )
    # Only the (changed) running-config was compared → changed-mode passes;
    # the unchanged route table was excluded by the pattern.
    assert result.success is True


async def test_execute_pattern_no_precheck_match_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = _handler_with(
        [_artifact("dc1:show ip route ospf", "x")],
        [_artifact("dc1:show ip route ospf", "x")],
        monkeypatch,
    )
    result = await handler.execute(
        _ctx(
            precheck_step_id="precheck",
            postcheck_step_id="postcheck",
            artifact_name_pattern="*running-config",
        )
    )
    assert result.success is False
    assert "precheck" in (result.error or "") and "pattern" in (result.error or "")


async def test_execute_pattern_no_postcheck_match_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Symmetric check: an empty postcheck match names the postcheck side."""
    handler = _handler_with(
        [_artifact("dc1:show running-config", "x")],
        [_artifact("dc1:show ip route ospf", "y")],
        monkeypatch,
    )
    result = await handler.execute(
        _ctx(
            precheck_step_id="precheck",
            postcheck_step_id="postcheck",
            artifact_name_pattern="*running-config",
        )
    )
    assert result.success is False
    assert "postcheck" in (result.error or "") and "pattern" in (result.error or "")


async def test_execute_artifact_name_takes_precedence_over_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When both are set, the exact artifact_name wins over the glob."""
    pre = [
        _artifact("dc1:show running-config", "a"),
        _artifact("dc1:show ip route ospf", "same"),
    ]
    post = [
        _artifact("dc1:show running-config", "b"),  # changed
        _artifact("dc1:show ip route ospf", "same"),  # unchanged
    ]
    handler = _handler_with(pre, post, monkeypatch)
    result = await handler.execute(
        _ctx(
            precheck_step_id="precheck",
            postcheck_step_id="postcheck",
            comparison_type="changed",
            artifact_name="dc1:show running-config",
            artifact_name_pattern="*show ip route ospf",  # would pick the unchanged one
        )
    )
    # The exact name (changed) was used, not the pattern (unchanged) → success.
    assert result.success is True


async def test_execute_single_artifact_failure_counts_one_of_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: a failed exact-artifact compare reports 1 of 1, not 0 of 1."""
    handler = _handler_with(
        [_artifact("dc1:show running-config", "a")],
        [_artifact("dc1:show running-config", "b")],
        monkeypatch,
    )
    result = await handler.execute(
        _ctx(
            precheck_step_id="precheck",
            postcheck_step_id="postcheck",
            artifact_name="dc1:show running-config",  # exact, default exact mode
        )
    )
    assert result.success is False
    assert "1 of 1" in (result.summary or "")


# ── Pairing by device and full command (netcli.collect_evidence artifacts) ───

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


def _collected(outputs: dict[str, str], device_name: str = "r1") -> list[dict]:
    """Artifacts shaped as netcli.collect_evidence stores them."""
    from hegemony_step_sdk import command_label

    return [
        {
            "kind": "cli_output",
            "name": f"{device_name}:{command_label(command)}",
            "content_text": output,
            "content_json": {
                "device_id": f"id-{device_name}",
                "device_name": device_name,
                "command": command,
                "success": True,
                "exit_code": 0,
                "error": None,
            },
        }
        for command, output in outputs.items()
    ]


@pytest.mark.parametrize(("unchanged", "changed"), [(_LONG_A, _LONG_B), (_SHORT, _MULTI)])
async def test_commands_sharing_an_artifact_name_are_compared_separately(
    monkeypatch: pytest.MonkeyPatch, unchanged: str, changed: str
) -> None:
    pre = _collected({changed: "neighbor up", unchanged: "same"})
    post = _collected({changed: "neighbor down", unchanged: "same"})
    handler = _handler_with(pre, post, monkeypatch)
    result = await handler.execute(
        _ctx(precheck_step_id="precheck", postcheck_step_id="postcheck", comparison_type="exact")
    )
    assert result.success is False
    content = result.evidence[0]["content_json"]
    assert len(content["artifacts_compared"]) == 2
    assert sorted(entry["passed"] for entry in content["diff"].values()) == [False, True]


def test_capture_labels_read_like_artifact_names_and_stay_unique() -> None:
    from hegemony_steps_evidence.artifacts import capture_key, capture_labels

    artifacts = _collected({_LONG_A: "", _LONG_B: "", "show version": ""})
    labels = capture_labels(capture_key(artifact) for artifact in artifacts)
    assert sorted(labels.values()) == sorted(["r1:show version", f"r1:{_LONG_A}", f"r1:{_LONG_B}"])


# ── Items missing on one side ────────────────────────────────────────────────

_ROUTES = "O 10.0.0.0/24 via 10.1.1.1\nO 10.0.1.0/24 via 10.1.1.1"
_ROUTES_MINUS = "O 10.0.0.0/24 via 10.1.1.1"
_ROUTES_PLUS = _ROUTES + "\nO 10.0.2.0/24 via 10.1.1.1"


def _connection_error(device_name: str) -> dict:
    """The artifact netcli.collect_evidence stores for an unreachable device."""
    return {
        "kind": "error",
        "name": f"{device_name}:connection_error",
        "content_json": {
            "device_id": f"id-{device_name}",
            "device_name": device_name,
            "error": "timed out",
        },
    }


async def _compare(pre: list[dict], post: list[dict], monkeypatch, mode: str = "exact"):
    handler = _handler_with(pre, post, monkeypatch)
    return await handler.execute(
        _ctx(precheck_step_id="precheck", postcheck_step_id="postcheck", comparison_type=mode)
    )


async def test_a_device_missing_after_the_change_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    pre = _collected({"show ip route": _ROUTES}, "dc1-01") + _collected(
        {"show ip route": _ROUTES}, "dc1-02"
    )
    post = _collected({"show ip route": _ROUTES}, "dc1-01") + [_connection_error("dc1-02")]
    result = await _compare(pre, post, monkeypatch)
    assert result.success is False
    assert "missing in postcheck: dc1-02:show ip route" in (result.error or "")
    content = result.evidence[0]["content_json"]
    assert content["artifacts_compared"] == ["dc1-01:show ip route"]
    assert content["missing_in_postcheck"] == ["dc1-02:show ip route"]
    assert content["only_in_postcheck"] == ["dc1-02:connection_error"]
    assert "1 missing in postcheck" in (result.summary or "")
    assert "1 only in postcheck" in (result.summary or "")


@pytest.mark.parametrize("mode", ["exact", "changed"])
async def test_a_command_missing_after_the_change_fails(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    pre = _collected({"show ip route": _ROUTES, "show ip bgp summary": "Nbr Up"})
    post = _collected({"show ip route": _ROUTES_PLUS})
    result = await _compare(pre, post, monkeypatch, mode)
    assert result.success is False
    content = result.evidence[0]["content_json"]
    assert content["missing_in_postcheck"] == ["r1:show ip bgp summary"]
    assert content["only_in_postcheck"] == []


async def test_a_failed_postcheck_command_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    pre = _collected({"show ip route": _ROUTES})
    post = _collected({"show ip route": "% Invalid input detected at '^' marker."})
    post[0]["content_json"].update(success=False, exit_code=1, error="% Invalid input detected")
    # Under "Must differ" the error text differs from the routes, which used
    # to pass as the expected change.
    result = await _compare(pre, post, monkeypatch, "changed")
    assert result.success is False
    assert "postcheck capture failed for r1:show ip route" in (result.error or "")
    diff = result.evidence[0]["content_json"]["diff"]["r1:show ip route"]
    assert diff["diff"]["postcheck_error"] == "% Invalid input detected"


def _failed(captures: list[dict], error: str = "Connection timeout: timed out") -> list[dict]:
    """``captures`` as collect_evidence stores commands that could not run."""
    return [
        {
            **capture,
            "content_text": "",
            "content_json": {
                **capture["content_json"],
                "success": False,
                "exit_code": -1,
                "error": error,
            },
        }
        for capture in captures
    ]


@pytest.mark.parametrize("mode", ["exact", "changed", "subset", "superset", "json_diff"])
async def test_a_failed_precheck_command_fails(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    # The empty output of an unreachable device differs from the routes and
    # has no line the postcheck lacks, so 'changed', 'subset' and 'superset'
    # used to pass.
    pre = _failed(_collected({"show ip route": ""}))
    post = _collected({"show ip route": _ROUTES})
    result = await _compare(pre, post, monkeypatch, mode)
    assert result.success is False
    assert result.error == (
        "Evidence comparison failed: precheck capture failed for r1:show ip route"
    )
    assert result.summary == "1 precheck capture(s) failed"
    diff = result.evidence[0]["content_json"]["diff"]["r1:show ip route"]
    assert diff == {
        "passed": False,
        "diff": {"comparison_type": mode, "precheck_error": "Connection timeout: timed out"},
    }


async def test_failed_captures_on_both_sides_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    # Two identical errors used to compare equal under "Must match".
    pre = _failed(_collected({"show ip route": ""})) + [_connection_error("r2")]
    post = _failed(_collected({"show ip route": ""})) + [_connection_error("r2")]
    result = await _compare(pre, post, monkeypatch)
    assert result.success is False
    assert result.error == (
        "Evidence comparison failed: "
        "precheck capture failed for r1:show ip route, r2:connection_error; "
        "postcheck capture failed for r1:show ip route, r2:connection_error"
    )
    assert result.summary == "2 precheck capture(s) failed; 2 postcheck capture(s) failed"
    diff = result.evidence[0]["content_json"]["diff"]["r2:connection_error"]["diff"]
    assert diff["precheck_error"] == diff["postcheck_error"] == "timed out"


async def test_a_named_artifact_with_a_failed_precheck_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pre = _failed(_collected({"show ip route": ""}))
    post = _collected({"show ip route": _ROUTES})
    handler = _handler_with(pre, post, monkeypatch)
    result = await handler.execute(
        _ctx(
            precheck_step_id="precheck",
            postcheck_step_id="postcheck",
            comparison_type="changed",
            artifact_name="r1:show ip route",
        )
    )
    assert result.success is False
    assert result.error == (
        "Evidence comparison failed: precheck capture failed for r1:show ip route"
    )
    assert result.summary == "1 precheck capture(s) failed"


async def test_items_only_in_the_postcheck_do_not_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    pre = _collected({"show ip route": _ROUTES})
    post = _collected({"show ip route": _ROUTES, "show clock": "10:00"})
    result = await _compare(pre, post, monkeypatch)
    assert result.success is True
    assert result.evidence[0]["content_json"]["only_in_postcheck"] == ["r1:show clock"]
    assert "1 only in postcheck" in (result.summary or "")


async def test_nothing_in_common_still_records_both_sides(monkeypatch: pytest.MonkeyPatch) -> None:
    result = await _compare(
        _collected({"show ip route": _ROUTES}), [_connection_error("r1")], monkeypatch
    )
    assert result.success is False
    content = result.evidence[0]["content_json"]
    assert content["artifacts_compared"] == []
    assert content["missing_in_postcheck"] == ["r1:show ip route"]
    assert content["only_in_postcheck"] == ["r1:connection_error"]


class _RunApi:
    """Host services whose API serves one run's artifacts and counts the fetches."""

    status_code = 200

    def __init__(self, artifacts: list[dict]) -> None:
        self.artifacts = artifacts
        self.fetches = 0

    def open_api_client(self, timeout: float = 30) -> _RunApi:
        return self

    async def __aenter__(self) -> _RunApi:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False

    async def get(self, url: str) -> _RunApi:
        self.fetches += 1
        return self

    def json(self) -> dict:
        return {"artifacts": self.artifacts}


async def test_execute_fetches_the_run_artifacts_once() -> None:
    from typing import cast

    from hegemony_step_sdk import HandlerContext, HandlerServices

    outputs = {"show ip route": _ROUTES, "show clock": "10:00"}
    captures = _collected(outputs, "r1") + _collected(outputs, "r2")
    api = _RunApi(
        [{**artifact, "step_id": "precheck"} for artifact in captures]
        + [{**artifact, "step_id": "postcheck"} for artifact in captures]
        + [{**_artifact("r1:show ip route", "other step"), "step_id": "other"}]
    )
    ctx = HandlerContext(
        run_id="run-1",
        flow_id="f",
        step_run_id="sr-1",
        step_id="cur",
        config={"precheck_step_id": "precheck", "postcheck_step_id": "postcheck"},
        services=cast(HandlerServices, api),
    )
    result = await _handler().execute(ctx)
    assert result.success is True, result.error
    assert len(result.evidence[0]["content_json"]["artifacts_compared"]) == 4
    assert api.fetches == 1


# ── Subset, superset and JSON modes on text ──────────────────────────────────


@pytest.mark.parametrize(
    ("mode", "post", "expected"),
    [
        ("subset", _ROUTES, True),
        ("subset", _ROUTES_MINUS, False),
        ("subset", _ROUTES_PLUS, True),
        ("superset", _ROUTES, False),
        ("superset", _ROUTES_MINUS, False),
        ("superset", _ROUTES_PLUS, True),
    ],
)
def test_subset_and_superset_compare_text_lines(mode: str, post: str, expected: bool) -> None:
    passed, details = _handler()._compare(_ROUTES, post, mode, [])
    assert passed is expected
    removed = [] if post != _ROUTES_MINUS else ["O 10.0.1.0/24 via 10.1.1.1"]
    added = [] if post != _ROUTES_PLUS else ["O 10.0.2.0/24 via 10.1.1.1"]
    assert details["removed_lines"] == removed
    assert details["added_lines"] == added


def test_subset_ignores_line_order_blank_lines_and_masked_text() -> None:
    handler = _handler()
    timers = handler._compile_ignore_patterns([_TIMER_PATTERN])
    reordered = "\n".join(reversed(_ROUTE_POST_TIMERS_ONLY.splitlines())) + "\n\n"
    passed, details = handler._compare(_ROUTE_PRE, reordered, "subset", [], timers)
    assert passed is True
    assert details["removed_lines"] == []


def test_subset_and_superset_handle_lists_of_dicts() -> None:
    handler = _handler()
    pre = [{"prefix": "10.0.0.0/24"}]
    post = [{"prefix": "10.0.0.0/24"}, {"prefix": "10.0.1.0/24"}]
    assert handler._compare(pre, post, "subset", [])[0] is True
    assert handler._compare(pre, post, "superset", [])[0] is True
    assert handler._compare(post, pre, "subset", [])[0] is False
    assert handler._compare(pre, pre, "superset", [])[0] is False


def test_json_diff_parses_json_text() -> None:
    handler = _handler()
    pre = '{"neighbors": 2, "state": "up"}'
    reformatted = '{\n  "state": "up",\n  "neighbors": 2\n}'
    passed, details = handler._compare(pre, reformatted, "json_diff", [])
    assert passed is True
    assert details["json_parsed"] is True

    passed, details = handler._compare(pre, '{"neighbors": 1, "state": "up"}', "json_diff", [])
    assert passed is False
    assert details["json_diff"]["differences"] == [
        {"field": "neighbors", "change": "modified", "before": 2, "after": 1}
    ]

    passed, _ = handler._compare(pre, '{"neighbors": 1, "state": "up"}', "json_diff", ["neighbors"])
    assert passed is True


def test_json_diff_on_text_that_is_not_json_is_exact() -> None:
    handler = _handler()
    passed, details = handler._compare(_ROUTES, _ROUTES, "json_diff", [])
    assert passed is True
    assert details["json_parsed"] is False
    passed, details = handler._compare(_ROUTES, _ROUTES + "\n", "json_diff", [])
    assert passed is False
    assert details["json_parsed"] is False
