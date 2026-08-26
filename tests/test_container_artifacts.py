# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Harvesting files out of container.run's new-artifacts folder.

The folder takes text *and* binary files: text is inlined as a step artifact,
anything else is uploaded as a downloadable one up to the worker's per-file
cap. A file the harvest drops used to leave no trace on the run — only a
worker log line — so a step that wrote a too-large archive looked like it had
produced nothing. These tests pin the reporting that replaced that silence.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerServices
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_container.run import (
    SKIP_REASON_TOO_LARGE,
    SKIP_REASON_UNREADABLE,
    RunContainerHandler,
    _collect_generated_text_artifacts,
    _describe_skipped_artifacts,
)

# ---------------------------------------------------------------------------
# Harvest classification
# ---------------------------------------------------------------------------


def test_text_is_inlined_and_binary_is_queued_for_upload(tmp_path) -> None:
    (tmp_path / "report.txt").write_text("hello\n", encoding="utf-8")
    (tmp_path / "image.bin").write_bytes(b"\x00\x01\x02\x03")

    text_artifacts, binary_files, skipped = _collect_generated_text_artifacts(
        str(tmp_path), max_binary_size=1024
    )

    assert skipped == []
    assert [a["name"] for a in text_artifacts] == ["report.txt"]
    assert text_artifacts[0]["content_text"] == "hello\n"
    assert [b["name"] for b in binary_files] == ["image.bin"]
    assert binary_files[0]["size"] == 4


def test_oversized_binary_is_skipped_with_a_named_record(tmp_path) -> None:
    """The dropped file is reported by name and size, not as a bare count."""
    (tmp_path / "archive.tar").write_bytes(b"\x00" * 2048)

    text_artifacts, binary_files, skipped = _collect_generated_text_artifacts(
        str(tmp_path), max_binary_size=1024
    )

    assert text_artifacts == []
    assert binary_files == []
    assert skipped == [{"name": "archive.tar", "size": 2048, "reason": SKIP_REASON_TOO_LARGE}]


def test_no_cap_uploads_a_binary_of_any_size(tmp_path) -> None:
    (tmp_path / "archive.tar").write_bytes(b"\x00" * 2048)

    _text, binary_files, skipped = _collect_generated_text_artifacts(
        str(tmp_path), max_binary_size=None
    )

    assert skipped == []
    assert [b["name"] for b in binary_files] == ["archive.tar"]


def test_text_file_is_never_size_capped(tmp_path) -> None:
    """The cap guards uploads; inline text keeps its existing behavior."""
    (tmp_path / "big.log").write_text("x" * 4096, encoding="utf-8")

    text_artifacts, binary_files, skipped = _collect_generated_text_artifacts(
        str(tmp_path), max_binary_size=1024
    )

    assert skipped == []
    assert binary_files == []
    assert len(text_artifacts[0]["content_text"]) == 4096


def test_unreadable_file_is_reported_rather_than_dropped(tmp_path, monkeypatch) -> None:
    (tmp_path / "locked.bin").write_bytes(b"\x00\x01")
    real_getsize = os.path.getsize

    def failing_getsize(path):
        if str(path).endswith("locked.bin"):
            raise OSError("permission denied")
        return real_getsize(path)

    monkeypatch.setattr("os.path.getsize", failing_getsize)

    _text, binary_files, skipped = _collect_generated_text_artifacts(
        str(tmp_path), max_binary_size=1024
    )

    assert binary_files == []
    assert skipped == [{"name": "locked.bin", "size": None, "reason": SKIP_REASON_UNREADABLE}]


def test_missing_staging_root_harvests_nothing(tmp_path) -> None:
    text_artifacts, binary_files, skipped = _collect_generated_text_artifacts(
        str(tmp_path / "absent"), max_binary_size=1024
    )
    assert (text_artifacts, binary_files, skipped) == ([], [], [])


# ---------------------------------------------------------------------------
# The report the run actually shows
# ---------------------------------------------------------------------------


def test_skip_report_names_the_file_its_size_and_the_cap() -> None:
    artifact = _describe_skipped_artifacts(
        [{"name": "archive.tar", "size": 209_715_200, "reason": SKIP_REASON_TOO_LARGE}],
        step_id="build",
        new_artifacts_path="/artifacts/new",
        max_binary_size=52_428_800,
    )

    assert artifact["kind"] == "step_result"
    assert artifact["name"] == "skipped_artifacts_build"

    text = artifact["content_text"]
    assert "/artifacts/new" in text
    assert "archive.tar" in text
    assert "209715200 bytes" in text
    assert "52428800 bytes" in text
    assert "per-file artifact cap" in text

    assert artifact["content_json"] == {
        "new_artifacts_path": "/artifacts/new",
        "max_file_size_bytes": 52_428_800,
        "skipped": [{"name": "archive.tar", "size": 209_715_200, "reason": SKIP_REASON_TOO_LARGE}],
    }


def test_skip_report_handles_an_unset_cap_and_unknown_size() -> None:
    artifact = _describe_skipped_artifacts(
        [{"name": "odd.bin", "size": None, "reason": SKIP_REASON_UNREADABLE}],
        step_id="build",
        new_artifacts_path="/out",
        max_binary_size=None,
    )

    assert "no per-file cap configured" in artifact["content_text"]
    assert "size unknown" in artifact["content_text"]


# ---------------------------------------------------------------------------
# End to end through execute()
# ---------------------------------------------------------------------------


class _FakeServices:
    """Minimal HandlerServices stub for the container.run harvest path."""

    def __init__(self, artifact_max_file_size_bytes: int) -> None:
        self._cap = artifact_max_file_size_bytes
        self.uploaded: list[str] = []

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
            docker_host="",
            artifact_max_file_size_bytes=self._cap,
        )

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        return []

    async def fetch_run_step_outputs(self, run_id: str) -> dict[str, dict[str, Any]]:
        return {}

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        return []

    async def upload_binary_artifact(self, run_id: str, *, name: str, **kwargs: Any) -> bool:
        self.uploaded.append(name)
        return True


def _install_docker_mocks(monkeypatch, harvest: dict[str, bytes]) -> None:
    """Drive execute() offline, with ``harvest`` as the new-artifacts folder."""
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("disabled in tests")),
    )

    def fake_subprocess_run(cmd, *args, **kwargs):
        cmd = list(cmd)
        if len(cmd) >= 4 and cmd[1] == "cp" and ":/artifacts/new/." in cmd[2]:
            for name, payload in harvest.items():
                target = os.path.join(cmd[3], name)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as fh:
                    fh.write(payload)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_subprocess_run)

    async def fake_create_subprocess_exec(*argv, **kwargs):
        proc = AsyncMock()
        proc.stdout = AsyncMock()
        proc.stdout.readline = AsyncMock(return_value=b"")
        proc.stderr = AsyncMock()
        proc.stderr.readline = AsyncMock(return_value=b"")
        proc.wait = AsyncMock(return_value=0)
        proc.returncode = 0
        proc.kill = AsyncMock()
        return proc

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_create_subprocess_exec)


def _ctx(services: _FakeServices) -> HandlerContext:
    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="build",
        phase="IMPLEMENTATION",
        kind="ACTION",
        config={"image": "alpine:3.20", "command": ["echo hi"]},
        services=cast(HandlerServices, services),
    )


async def test_oversized_archive_surfaces_on_the_step_not_only_in_the_log(monkeypatch) -> None:
    """The 200 MB-tar case in miniature: dropped, but visibly so."""
    services = _FakeServices(artifact_max_file_size_bytes=1024)
    _install_docker_mocks(monkeypatch, {"archive.tar": b"\x00" * 2048})

    result = await RunContainerHandler().execute(_ctx(services))

    # Dropping an artifact never fails the step.
    assert result.success is True
    assert result.metrics is not None
    assert result.metrics["skipped_artifacts"] == 1
    assert "1 artifact(s) skipped" in result.summary
    assert services.uploaded == []

    assert result.evidence is not None
    report = next(a for a in result.evidence if a["name"] == "skipped_artifacts_build")
    assert report["content_json"]["max_file_size_bytes"] == 1024
    assert report["content_json"]["skipped"] == [
        {"name": "archive.tar", "size": 2048, "reason": SKIP_REASON_TOO_LARGE}
    ]


async def test_a_clean_harvest_reports_no_skips(monkeypatch) -> None:
    services = _FakeServices(artifact_max_file_size_bytes=1024)
    _install_docker_mocks(monkeypatch, {"report.txt": b"hello\n", "small.bin": b"\x00\x01\x02"})

    result = await RunContainerHandler().execute(_ctx(services))

    assert result.success is True
    assert result.metrics is not None
    assert result.metrics["skipped_artifacts"] == 0
    assert "skipped" not in result.summary
    assert services.uploaded == ["small.bin"]

    assert result.evidence is not None
    names = {a["name"] for a in result.evidence}
    assert "report.txt" in names
    assert not any(name.startswith("skipped_artifacts") for name in names)


# ---------------------------------------------------------------------------
# The editor copy that sent people down the wrong path
# ---------------------------------------------------------------------------


def test_new_artifacts_path_help_documents_binary_uploads() -> None:
    """Regression guard: the field help described a text-only harvest.

    It predated downloadable binary uploads by a release, so the flow editor
    told operators that only text files were collected — the opposite of what
    the handler does.
    """
    field = RunContainerHandler.config_model.model_fields["new_artifacts_path"]
    description = field.description or ""

    assert "downloadable" in description
    assert "cap" in description
    assert "UTF-8 text files" in description
