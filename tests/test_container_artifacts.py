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
import subprocess
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerServices
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_container.run import (
    MAX_ARTIFACT_NAME_LEN,
    SKIP_REASON_OUTSIDE_ROOT,
    SKIP_REASON_TOO_LARGE,
    SKIP_REASON_UNREADABLE,
    RunContainerHandler,
    _collect_generated_text_artifacts,
    _describe_skipped_artifacts,
    _read_harvested_text,
)

# ---------------------------------------------------------------------------
# Harvest classification
# ---------------------------------------------------------------------------


def test_text_is_inlined_and_binary_is_queued_for_upload(tmp_path) -> None:
    """The two halves of a clean harvest: text inline, binary for upload."""
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
    """An unset cap means no cap - the size check is skipped entirely."""
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
    """A file the worker cannot stat is reported, not silently passed over."""
    (tmp_path / "locked.bin").write_bytes(b"\x00\x01")
    real_getsize = os.path.getsize

    def failing_getsize(path):
        """Fail for the one file under test, delegate for the rest."""
        if str(path).endswith("locked.bin"):
            raise OSError("permission denied")
        return real_getsize(path)

    monkeypatch.setattr("os.path.getsize", failing_getsize)

    _text, binary_files, skipped = _collect_generated_text_artifacts(
        str(tmp_path), max_binary_size=1024
    )

    assert binary_files == []
    assert skipped == [{"name": "locked.bin", "size": None, "reason": SKIP_REASON_UNREADABLE}]


def test_symlink_escaping_the_harvest_is_rejected_unread(tmp_path) -> None:
    """A link out of the staging root is refused before it is ever opened.

    `docker cp` preserves symlinks instead of dereferencing them, so a
    container that writes `ln -s /etc/shadow /artifacts/new/x` hands the worker
    a link whose *relative* name is perfectly ordinary. Following it would
    publish a worker-host file as step evidence, so containment is decided on
    the resolved path.
    """
    staging = tmp_path / "staging"
    staging.mkdir()
    outside = tmp_path / "host"
    outside.mkdir()
    secret = outside / "worker_secret.txt"
    secret.write_text("HEGEMONY_DB_PASSWORD=hunter2\n", encoding="utf-8")

    (staging / "leak.txt").symlink_to(secret)

    text_artifacts, binary_files, skipped = _collect_generated_text_artifacts(
        str(staging), max_binary_size=1024
    )

    assert text_artifacts == []
    assert binary_files == []
    assert skipped == [{"name": "leak.txt", "size": None, "reason": SKIP_REASON_OUTSIDE_ROOT}]


def test_symlink_inside_the_harvest_is_still_collected(tmp_path) -> None:
    """Containment rejects escapes, not links that stay in the folder."""
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "real.txt").write_text("ok\n", encoding="utf-8")
    (staging / "alias.txt").symlink_to(staging / "real.txt")

    text_artifacts, _binary, skipped = _collect_generated_text_artifacts(
        str(staging), max_binary_size=1024
    )

    assert skipped == []
    assert {a["name"] for a in text_artifacts} == {"real.txt", "alias.txt"}


def test_dangling_symlink_is_reported_not_passed_over(tmp_path) -> None:
    """An unresolvable link produced no artifact, so it belongs in the report.

    `os.path.isfile` is False for a dangling link, which used to mean the loop
    skipped it before any record was made - the silence this change exists to
    remove.
    """
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "broken.txt").symlink_to(staging / "never_written.txt")

    text_artifacts, binary_files, skipped = _collect_generated_text_artifacts(
        str(staging), max_binary_size=1024
    )

    assert text_artifacts == []
    assert binary_files == []
    assert skipped == [{"name": "broken.txt", "size": None, "reason": SKIP_REASON_UNREADABLE}]


def test_skip_record_keeps_the_whole_path_that_the_name_bound_would_cut(tmp_path) -> None:
    """Two deep paths sharing a 255-character prefix must stay distinguishable.

    The artifact-name bound exists for the platform's name column; a skip
    record is JSON and carries the full path.
    """
    staging = tmp_path / "staging"
    deep = staging / ("a" * 100) / ("b" * 100) / ("c" * 100)
    deep.mkdir(parents=True)
    (deep / "archive.tar").write_bytes(b"\x00" * 2048)

    _text, _binary, skipped = _collect_generated_text_artifacts(str(staging), max_binary_size=1024)

    assert len(skipped) == 1
    name = skipped[0]["name"]
    assert len(name) > MAX_ARTIFACT_NAME_LEN
    assert name == f"{'a' * 100}/{'b' * 100}/{'c' * 100}/archive.tar"


def test_artifact_names_stay_within_the_platform_bound(tmp_path) -> None:
    """The bound still applies where the name becomes an artifact name."""
    staging = tmp_path / "staging"
    deep = staging / ("a" * 100) / ("b" * 100) / ("c" * 100)
    deep.mkdir(parents=True)
    (deep / "notes.txt").write_text("hi\n", encoding="utf-8")
    (deep / "blob.bin").write_bytes(b"\x00\x01")

    text_artifacts, binary_files, skipped = _collect_generated_text_artifacts(
        str(staging), max_binary_size=1024
    )

    assert skipped == []
    assert len(text_artifacts[0]["name"]) == MAX_ARTIFACT_NAME_LEN
    assert len(binary_files[0]["name"]) == MAX_ARTIFACT_NAME_LEN


def test_missing_staging_root_harvests_nothing(tmp_path) -> None:
    """No staging directory (the docker cp failed) is empty, not an error."""
    text_artifacts, binary_files, skipped = _collect_generated_text_artifacts(
        str(tmp_path / "absent"), max_binary_size=1024
    )
    assert (text_artifacts, binary_files, skipped) == ([], [], [])


class _CountingFile:
    """A binary file wrapper that totals how many bytes were actually read."""

    def __init__(self, fh, counter: list[int]) -> None:
        """Wrap ``fh``, accumulating read sizes into ``counter``."""
        self._fh = fh
        self._counter = counter

    def read(self, size: int = -1) -> bytes:
        """Read from the wrapped handle and record how much came back."""
        data = self._fh.read(size)
        self._counter[0] += len(data)
        return data

    def __enter__(self):
        """Enter the wrapped handle's context, yielding the counting wrapper."""
        self._fh.__enter__()
        return self

    def __exit__(self, *exc_info):
        """Close the wrapped handle."""
        return self._fh.__exit__(*exc_info)


def test_binary_classification_stops_at_the_first_nul(tmp_path, monkeypatch) -> None:
    """An oversized binary is never buffered whole just to be rejected.

    This is the 200 MB-tar case in miniature: the payload is not needed - a
    binary artifact uploads by streaming from its path - so reading it in full
    only to discard it would cost the worker its whole size in RSS.
    """
    payload = b"\x00" + b"A" * (4 * 1024 * 1024)
    target = tmp_path / "archive.tar"
    target.write_bytes(payload)

    read_total = [0]
    real_open = open

    def counting_open(file, mode="r", *args, **kwargs):
        """Wrap only the harvest's binary read; delegate everything else."""
        fh = real_open(file, mode, *args, **kwargs)
        if str(file) == str(target) and "b" in mode:
            return _CountingFile(fh, read_total)
        return fh

    monkeypatch.setattr("builtins.open", counting_open)

    assert _read_harvested_text(str(target)) is None
    # One chunk, not the whole 4 MB file.
    assert 0 < read_total[0] <= 1024 * 1024
    assert read_total[0] < len(payload)


def test_text_spanning_chunks_survives_a_split_multibyte_sequence(tmp_path) -> None:
    """Chunked decoding must not mistake a straddling character for binary."""
    target = tmp_path / "wide.txt"
    # Longer than one read chunk, all multi-byte, so a boundary lands mid-character.
    text = "é" * (1024 * 1024)
    target.write_text(text, encoding="utf-8")

    assert _read_harvested_text(str(target)) == text


def test_invalid_utf8_without_a_nul_is_binary(tmp_path) -> None:
    """A lone continuation byte is not text, even with no NUL to give it away."""
    target = tmp_path / "odd.bin"
    target.write_bytes(b"valid then \xff\xfe trailing")

    assert _read_harvested_text(str(target)) is None


# ---------------------------------------------------------------------------
# The report the run actually shows
# ---------------------------------------------------------------------------


def test_skip_report_names_the_file_its_size_and_the_cap() -> None:
    """The report has to answer "where did my 200 MB tar go?" on its own."""
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


def test_skip_report_flattens_control_characters_in_names() -> None:
    """A newline in a filename must not forge an extra line in the report."""
    artifact = _describe_skipped_artifacts(
        [
            {
                "name": "sneaky\n- forged.txt (1 bytes): larger than the cap",
                "size": 4096,
                "reason": SKIP_REASON_TOO_LARGE,
            }
        ],
        step_id="build",
        new_artifacts_path="/artifacts/new",
        max_binary_size=1024,
    )

    body = artifact["content_text"].rstrip("\n").split("\n")
    # Header, blank separator, and exactly one entry - the embedded newline
    # did not open a second one.
    assert len(body) == 3
    entry = body[2]
    assert entry.startswith("- sneaky?")
    # The real size and reason are the ones this line ends with; the forged
    # pair the filename carried is inert text inside the name.
    assert entry.endswith("(4096 bytes): larger than the worker's per-file artifact cap")
    # The record itself keeps the raw name for machine consumers.
    assert artifact["content_json"]["skipped"][0]["name"].startswith("sneaky\n")


def test_skip_report_handles_an_unset_cap_and_unknown_size() -> None:
    """Neither an absent cap nor an unknown size may render as None."""
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
        """Record the cap to advertise and start with nothing uploaded."""
        self._cap = artifact_max_file_size_bytes
        self.uploaded: list[str] = []

    def container_runtime(self) -> ContainerRuntime:
        """The runtime the handler reads its per-file artifact cap from."""
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
            docker_host="",
            artifact_max_file_size_bytes=self._cap,
        )

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        """No flow attachments: these tests only exercise the harvest."""
        return []

    async def fetch_run_step_outputs(self, run_id: str) -> dict[str, dict[str, Any]]:
        """No upstream step outputs to stage into the container."""
        return {}

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        """No upstream artifacts to mount under /artifacts."""
        return []

    async def upload_binary_artifact(self, run_id: str, *, name: str, **kwargs: Any) -> bool:
        """Record the upload so a test can assert what was, and was not, sent."""
        self.uploaded.append(name)
        return True


def _install_docker_mocks(monkeypatch, harvest: dict[str, bytes]) -> None:
    """Drive execute() offline, with ``harvest`` as the new-artifacts folder."""
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("disabled in tests")),
    )

    def fake_subprocess_run(cmd, *args, **kwargs):
        """Answer every docker call, materializing the harvest on the cp."""
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
        """A container that starts, produces no output, and exits 0."""
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
    """A minimal container.run step: default paths, trivial command."""
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
    """The common case stays quiet: no report artifact, no summary suffix."""
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


async def test_timeout_keeps_the_skipped_artifacts_metric(monkeypatch) -> None:
    """A timed-out step reports zero skips rather than omitting the key.

    The harvest never runs on this path - the container is killed first - but
    consumers of the metric should not have to special-case the shape of a
    timed-out step.
    """
    services = _FakeServices(artifact_max_file_size_bytes=1024)
    _install_docker_mocks(monkeypatch, {})

    async def timing_out_exec(*argv, **kwargs):
        """A container that never returns, as the handler's timeout sees it."""
        raise subprocess.TimeoutExpired(cmd="docker start -a", timeout=1)

    monkeypatch.setattr("asyncio.create_subprocess_exec", timing_out_exec)

    result = await RunContainerHandler().execute(_ctx(services))

    assert result.success is False
    assert result.metrics is not None
    assert result.metrics["skipped_artifacts"] == 0


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
