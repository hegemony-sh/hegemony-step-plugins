# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``git.commit``: settings, file selection, the run script and the result.

The run script is executed for real with the local ``/bin/sh`` and git
against bare repositories on disk (``file://``, which only tests allow), so
what it commits and pushes is checked, not just its text. The container run
itself is replaced by a fake that records the job.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices
from hegemony_step_sdk.docs import load_docs_bundle
from hegemony_steps_container.runner import ContainerJob, ContainerJobResult
from hegemony_steps_git.commit import (
    ASKPASS_SCRIPT,
    CA_FILE,
    CHANGED_FILES_OUT,
    CHANGED_OUT,
    COMMIT_OUT,
    DEFAULT_IMAGE,
    EXIT_NO_BRANCH,
    EXIT_PUSH_REJECTED,
    EXIT_UNSAFE_PATH,
    MANIFEST_FILE,
    MESSAGE_FILE,
    PASSWORD_FILE,
    RUN_SCRIPT,
    USERNAME_FILE,
    GitCommitConfig,
    GitCommitHandler,
    build_script,
    newest_captures,
    safe_segment,
    select_files,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")

TOKEN = "synthetic-git-token"
SECRETS = {"vault://orgs/acme/secrets/git/token": TOKEN}
ENV = {
    "GIT_AUTHOR_NAME": "Hegemony",
    "GIT_AUTHOR_EMAIL": "hegemony@localhost",
    "GIT_COMMITTER_NAME": "Hegemony",
    "GIT_COMMITTER_EMAIL": "hegemony@localhost",
}


def _artifact(
    device: str,
    command: str,
    text: str | None,
    *,
    step: str = "collect",
    created: str = "2026-11-20T10:00:00Z",
    **meta: Any,
) -> dict[str, Any]:
    return {
        "step_id": step,
        "name": f"{device}:{command}",
        "kind": "command_output",
        "created_at": created,
        "content_text": text,
        "content_json": {
            "device_id": f"id-{device}",
            "device_name": device,
            "command": command,
            **meta,
        },
    }


# --- Settings ----------------------------------------------------------------


def _valid(**extra: Any) -> dict[str, Any]:
    return {
        "repository_url": "https://git.example.com/netops/backups.git",
        "source_step": "collect",
        "username": "backup-bot",
        "password": "vault://orgs/acme/secrets/git/token",
        **extra,
    }


def test_valid_settings_pass():
    assert GitCommitHandler().validate_config(_valid()) == []
    assert GitCommitHandler().validate_config(_valid(username="", password="")) == []
    assert GitCommitHandler().validate_config(_valid(branch="backups/routers")) == []


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"repository_url": "http://git.example.com/x.git"}, "must be an https:// URL"),
        ({"repository_url": "ssh://git@git.example.com/x.git"}, "must be an https:// URL"),
        ({"repository_url": "https://bot:pw@git.example.com/x.git"}, "must not carry a login"),
        ({"repository_url": "https://git.example.com/x.git?a=1"}, "query"),
        ({"repository_url": ""}, "'repository_url' is required"),
        ({"branch": "refs/heads/main"}, "not a ref"),
        ({"branch": "-main"}, "not a valid branch"),
        ({"branch": "a..b"}, "not a valid branch"),
        ({"branch": "x.lock"}, "not a valid branch"),
        ({"branch": "a/.hidden"}, "not a valid branch"),
        ({"path_template": "/etc/{device}"}, "relative path"),
        ({"path_template": "../{device}.cfg"}, ".. segments"),
        ({"path_template": ".git/hooks/{device}"}, "reach into .git"),
        ({"path_template": "{host}.cfg"}, "unknown placeholder {host}"),
        ({"path_template": "{device.cfg"}, "unmatched"),
        ({"source_step": " "}, "'source_step' is required"),
        ({"password": "hunter2-in-clear"}, "'password' must be a secret reference"),
        ({"username": ""}, "'username' is required"),
        ({"author_name": "a\nb"}, "one line"),
    ],
)
def test_invalid_settings_are_refused(extra, message):
    errors = GitCommitHandler().validate_config(_valid(**extra))
    assert any(message in error for error in errors), errors


@pytest.mark.parametrize(
    "extra",
    [
        {"repository_url": "{{ vars.CONFIG_BACKUP_REPO_URL }}"},
        {"repository_url": "https://{{ vars.GIT_HOST }}/configs.git"},
        {"branch": "{{ vars.BACKUP_BRANCH }}"},
    ],
)
def test_templated_settings_pass_when_a_flow_is_saved(extra):
    """The worker renders templates before the step runs, where they are checked in full."""
    assert GitCommitHandler().validate_config(_valid(**extra)) == []


def test_a_written_out_scheme_other_than_https_is_refused_even_in_a_template():
    errors = GitCommitHandler().validate_config(
        _valid(repository_url="http://{{ vars.GIT_HOST }}/configs.git")
    )
    assert any("must be an https:// URL" in error for error in errors), errors


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ({"repository_url": "http://git.example.com/x.git"}, "must be an https:// URL"),
        ({"repository_url": "{{ not rendered }}"}, "still contains a template"),
        (
            {"repository_url": "https://git.example.com/{{ vars.REPO }}"},
            "still contains a template",
        ),
        ({"branch": "{{ not rendered }}"}, "not a valid branch"),
    ],
)
async def test_the_step_checks_the_rendered_settings_in_full(jobs, extra, message):
    """A value that still reads as a template when the step runs is refused, not excused."""
    recorded, _ = jobs
    services = _Services([_artifact("r1", "show run", "hostname r1\n")])
    result = await GitCommitHandler().execute(_ctx(_valid(**extra), services))
    assert not result.success
    assert message in (result.error or "")
    assert recorded == []


def test_the_login_reaches_the_handler_as_written():
    assert GitCommitHandler.raw_config_keys == frozenset({"username", "password"})
    assert GitCommitHandler.container_backed is True


# --- Choosing the files ------------------------------------------------------


def test_the_newest_capture_per_device_and_command_wins():
    artifacts = [
        _artifact("r1", "show run", "old", created="2026-11-20T10:00:00Z"),
        _artifact("r1", "show run", "new", created="2026-11-20T11:00:00+00:00"),
        _artifact("r1", "show run", "older", created="2026-11-20T09:00:00Z"),
        _artifact("r2", "show run", "r2", step="other"),
    ]
    newest = newest_captures(artifacts, "collect")
    assert [item["content_text"] for item in newest] == ["new"]


def test_files_follow_the_path_template_and_failed_captures_are_skipped():
    artifacts = [
        _artifact("r1", "show running-config", "hostname r1\n"),
        _artifact("core/sw 2", "show running-config", "hostname sw2\n"),
        _artifact("r3", "show running-config", "", success=False, error="timed out"),
        {
            "step_id": "collect",
            "name": "r4",
            "kind": "error",
            "content_json": {"error": "unreachable"},
        },
    ]
    selection = select_files(artifacts, "collect", "configs/{device}.cfg")
    assert selection.errors == []
    assert selection.files == {
        "configs/r1.cfg": "hostname r1\n",
        "configs/core_sw_2.cfg": "hostname sw2\n",
    }
    assert selection.skipped == ["r3:show running-config: timed out", "r4: unreachable"]


def test_two_captures_on_one_path_are_refused():
    artifacts = [_artifact("r1", "show run", "a"), _artifact("r1", "show version", "b")]
    selection = select_files(artifacts, "collect", "{device}.txt")
    assert any("would both be written to r1.txt" in error for error in selection.errors)


def test_device_placeholder_needs_a_device():
    artifacts = [{"step_id": "s", "name": "report", "content_text": "x", "content_json": {}}]
    selection = select_files(artifacts, "s", "{device}.txt")
    assert any("use {name}" in error for error in selection.errors)
    assert select_files(artifacts, "s", "reports/{name}.txt").files == {"reports/report.txt": "x"}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("r1", "r1"),
        ("show running-config", "show_running-config"),
        ("../../etc", "etc"),
        (".hidden", "hidden"),
        ("..", "_"),
        ("", "_"),
    ],
)
def test_segments_are_safe_file_names(value, expected):
    assert safe_segment(value) == expected


# --- The script --------------------------------------------------------------


def _git(*args: str, cwd: Path | None = None) -> str:
    env = {**os.environ, **ENV, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def remote(tmp_path: Path) -> Path:
    """A bare repository with one commit on main holding keep.txt."""
    bare = tmp_path / "remote.git"
    _git("init", "--quiet", "--bare", "--initial-branch=main", str(bare))
    seed = tmp_path / "seed"
    _git("clone", "--quiet", str(bare), str(seed))
    (seed / "keep.txt").write_text("keep\n")
    _git("add", "keep.txt", cwd=seed)
    _git("commit", "--quiet", "-m", "seed", cwd=seed)
    _git("push", "--quiet", "origin", "HEAD:refs/heads/main", cwd=seed)
    return bare


def _run(
    tmp_path: Path,
    url: str,
    files: dict[str, str],
    *,
    branch: str = "main",
    create_branch: bool = False,
    message: str = "backup\n",
    extra_env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """Stage the step's files under a temporary root and run the script there."""
    root = tmp_path / f"root-{time.monotonic_ns()}"
    out = root / "out"
    (root / "files").mkdir(parents=True)
    manifest = []
    for index, (path, content) in enumerate(sorted(files.items())):
        (root / "files" / str(index)).write_text(content)
        manifest.append(f"{index} {path}")
    (root / "manifest").write_text("\n".join(manifest) + "\n")
    (root / "message").write_text(message)
    script = build_script(
        url=url,
        branch=branch,
        create_branch=create_branch,
        deadline=int(time.time()) + 60,
        login=False,
        ca_bundle=False,
        root=str(root),
        out=str(out),
        allow_file_protocol=True,
    )
    (root / "run.sh").write_text(script)
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")} | ENV
    env |= extra_env or {}
    result = subprocess.run(
        ["/bin/sh", str(root / "run.sh")], env=env, capture_output=True, text=True, timeout=60
    )
    return result, out


def test_the_script_commits_and_pushes_a_change_then_nothing_the_second_time(tmp_path, remote):
    url = f"file://{remote}"
    files = {"configs/r1.cfg": "hostname r1\n", "configs/r2 b.cfg": "hostname r2\n"}
    result, out = _run(tmp_path, url, files)

    assert result.returncode == 0, result.stderr
    assert (out / "changed").read_text().strip() == "yes"
    head = _git("--git-dir", str(remote), "rev-parse", "main").strip()
    assert (out / "commit").read_text().strip() == head
    assert sorted((out / "changed-files").read_text().split("\0")[:-1]) == sorted(files)
    tree = _git("--git-dir", str(remote), "ls-tree", "-r", "--name-only", "main").splitlines()
    assert sorted(tree) == ["configs/r1.cfg", "configs/r2 b.cfg", "keep.txt"]
    assert _git("--git-dir", str(remote), "show", "main:configs/r1.cfg") == "hostname r1\n"
    assert _git("--git-dir", str(remote), "log", "-1", "--format=%s", "main").strip() == "backup"

    again, out2 = _run(tmp_path, url, files)
    assert again.returncode == 0, again.stderr
    assert (out2 / "changed").read_text().strip() == "no"
    assert (out2 / "commit").read_text().strip() == head
    assert _git("--git-dir", str(remote), "rev-parse", "main").strip() == head


def test_the_script_refuses_a_missing_branch_unless_told_to_create_it(tmp_path, remote):
    url = f"file://{remote}"
    result, _ = _run(tmp_path, url, {"r1.cfg": "x\n"}, branch="backups")
    assert result.returncode == EXIT_NO_BRANCH
    assert "does not exist" in result.stderr

    created, out = _run(tmp_path, url, {"r1.cfg": "x\n"}, branch="backups", create_branch=True)
    assert created.returncode == 0, created.stderr
    assert (out / "changed").read_text().strip() == "yes"
    # A new branch starts empty: only the step's file.
    assert _git("--git-dir", str(remote), "ls-tree", "-r", "--name-only", "backups").split() == [
        "r1.cfg"
    ]


def test_the_script_starts_a_branch_in_an_empty_repository(tmp_path):
    bare = tmp_path / "empty.git"
    _git("init", "--quiet", "--bare", str(bare))
    result, out = _run(tmp_path, f"file://{bare}", {"r1.cfg": "x\n"}, create_branch=True)
    assert result.returncode == 0, result.stderr
    assert _git("--git-dir", str(bare), "show", "main:r1.cfg") == "x\n"


def test_the_script_does_not_follow_a_symbolic_link_in_the_repository(tmp_path, remote):
    seed = tmp_path / "seed"
    os.symlink("/tmp", seed / "configs")
    _git("add", "configs", cwd=seed)
    _git("commit", "--quiet", "-m", "link", cwd=seed)
    _git("push", "--quiet", "origin", "HEAD:refs/heads/main", cwd=seed)

    result, out = _run(tmp_path, f"file://{remote}", {"configs/r1.cfg": "x\n"})
    assert result.returncode == EXIT_UNSAFE_PATH
    assert "symbolic link at configs" in result.stderr
    assert not (out / "changed").exists()


def test_the_script_runs_no_repository_hooks_and_keeps_other_files(tmp_path, remote):
    result, _ = _run(tmp_path, f"file://{remote}", {"r1.cfg": "x\n"})
    assert result.returncode == 0, result.stderr
    assert _git("--git-dir", str(remote), "show", "main:keep.txt") == "keep\n"
    script = build_script(
        url="https://h/x.git",
        branch="main",
        create_branch=False,
        deadline=1,
        login=True,
        ca_bundle=True,
    )
    settings = dict(re.findall(r"GIT_CONFIG_KEY_\d+=(\S+) GIT_CONFIG_VALUE_\d+=(\S*)", script))
    assert settings["core.hooksPath"] == "/dev/null"
    assert settings["protocol.allow"] == "never"
    assert settings["protocol.https.allow"] == "always"
    assert settings["protocol.file.allow"] == "never"
    assert settings["credential.helper"] == "''"
    assert f"GIT_CONFIG_COUNT={len(settings)}" in script
    assert 'GIT_ASKPASS="$root/askpass.sh"' in script
    assert 'GIT_SSL_CAINFO="$root/ca-bundle.pem"' in script


def test_the_script_is_posix_sh():
    script = build_script(
        url="https://h/x.git",
        branch="main",
        create_branch=True,
        deadline=1,
        login=True,
        ca_bundle=False,
    )
    checked = subprocess.run(["/bin/sh", "-n"], input=script, text=True, capture_output=True)
    assert checked.returncode == 0, checked.stderr


# --- The step ----------------------------------------------------------------


class _Services:
    def __init__(self, artifacts: list[dict[str, Any]]) -> None:
        self.artifacts = artifacts
        self.sources: list[str] = []

    async def fetch_run_artifacts(self, run_id: str) -> list[dict[str, Any]]:
        return self.artifacts

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        self.sources.append(source)
        for path, value in SECRETS.items():
            if ref and path in ref:
                return value
        return ""

    async def trusted_ca_certificates(self) -> str:
        return ""


def _ctx(config: dict[str, Any], services: Any) -> HandlerContext:
    return HandlerContext(
        run_id="run-1",
        flow_id="flow-1",
        flow_name="Configuration backup",
        step_run_id="sr",
        step_id="git",
        config=config,
        timeout_seconds=300,
        services=cast(HandlerServices, services),
    )


def _outcome(exit_code: int = 0, collected: dict[str, bytes] | None = None, **extra: Any):
    return ContainerJobResult(
        exit_code=exit_code,
        stdout=extra.pop("stdout", ""),
        stderr=extra.pop("stderr", ""),
        truncated=False,
        duration_seconds=1.0,
        image=DEFAULT_IMAGE,
        evidence=[{"kind": "container_output", "name": "container_output"}],
        skipped_artifacts=0,
        collected=collected or {},
    )


@pytest.fixture
def jobs(monkeypatch):
    recorded: list[ContainerJob] = []
    outcomes: list[Any] = []

    async def _fake(ctx, job):
        recorded.append(job)
        return outcomes.pop(0)

    monkeypatch.setattr("hegemony_steps_git.commit.run_container_job", _fake)
    return recorded, outcomes


async def test_the_step_stages_files_and_login_and_reports_the_commit(jobs):
    recorded, outcomes = jobs
    outcomes.append(
        _outcome(
            collected={
                CHANGED_OUT: b"yes\n",
                COMMIT_OUT: b"0123456789abcdef0123456789abcdef01234567\n",
                CHANGED_FILES_OUT: b"configs/r1.cfg\0",
            }
        )
    )
    services = _Services(
        [
            _artifact("r1", "show run", "hostname r1\n"),
            _artifact("r2", "show run", "hostname r2\n"),
            _artifact("r3", "show run", "", success=False, error="timed out"),
        ]
    )
    config = _valid(path_template="configs/{device}.cfg")
    result = await GitCommitHandler().execute(_ctx(config, services))

    assert result.success, result.error
    assert result.output == {
        "changed": True,
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "branch": "main",
        "files": ["configs/r1.cfg", "configs/r2.cfg"],
        "changed_files": ["configs/r1.cfg"],
        "skipped": ["r3:show run: timed out"],
    }
    assert result.summary.startswith("Committed 1 changed file(s) to main (0123456789ab)")
    assert set(result.output) == {field.name for field in GitCommitHandler.output_fields}

    (job,) = recorded
    staged = {item.path: item for item in job.files}
    assert staged[PASSWORD_FILE].content == TOKEN
    assert staged[USERNAME_FILE].content == "backup-bot"
    assert staged[ASKPASS_SCRIPT].mode == 0o755
    assert staged[MANIFEST_FILE].content == "0 configs/r1.cfg\n1 configs/r2.cfg\n"
    assert staged[MESSAGE_FILE].content == "Hegemony: Configuration backup run run-1\n"
    # The token reaches git only through the staged file.
    assert TOKEN not in staged[RUN_SCRIPT].content
    assert TOKEN not in repr(job.config)
    assert job.config["entrypoint"] == "/bin/sh"
    assert job.config["command"] == [f"exec sh {RUN_SCRIPT}"]
    assert job.config["image"] == DEFAULT_IMAGE
    assert job.config["env"]["GIT_AUTHOR_NAME"] == "Hegemony"
    assert job.handler_id == "git.commit"
    assert services.sources == ["git.commit"]


async def test_nothing_changed_is_a_success_without_a_commit(jobs):
    _, outcomes = jobs
    outcomes.append(_outcome(collected={CHANGED_OUT: b"no\n", COMMIT_OUT: b"abc\n"}))
    services = _Services([_artifact("r1", "show run", "x")])
    result = await GitCommitHandler().execute(_ctx(_valid(), services))
    assert result.success
    assert result.output["changed"] is False
    assert result.output["changed_files"] == []
    assert result.summary.startswith("No changes: 1 file(s) match main")


async def test_an_unreadable_result_fails_rather_than_guess(jobs):
    _, outcomes = jobs
    outcomes.append(_outcome(collected={}))
    result = await GitCommitHandler().execute(
        _ctx(_valid(), _Services([_artifact("r1", "show run", "x")]))
    )
    assert not result.success
    assert "could not be read" in (result.error or "")


@pytest.mark.parametrize(
    ("exit_code", "stderr", "message"),
    [
        (EXIT_NO_BRANCH, "", "turn on Create the branch"),
        (EXIT_UNSAFE_PATH, "", "symbolic link"),
        (EXIT_PUSH_REJECTED, "", "refused the push"),
        (128, "fatal: Authentication failed for 'https://h/x.git/'", "could not log in"),
        (
            128,
            "SSL certificate problem: unable to get local issuer",
            "Trust the organization's CAs",
        ),
        (128, "Could not resolve host: h", "network policy"),
        (1, "", "exited with code 1"),
    ],
)
async def test_script_failures_are_named(jobs, exit_code, stderr, message):
    _, outcomes = jobs
    outcomes.append(_outcome(exit_code=exit_code, stderr=stderr))
    result = await GitCommitHandler().execute(
        _ctx(_valid(), _Services([_artifact("r1", "show run", "x")]))
    )
    assert not result.success
    assert message in (result.error or "")


async def test_no_evidence_fails_before_any_container(jobs):
    recorded, _ = jobs
    services = _Services([_artifact("r1", "show run", "", success=False, error="timed out")])
    result = await GitCommitHandler().execute(_ctx(_valid(), services))
    assert not result.success
    assert "no text evidence" in (result.error or "")
    assert "timed out" in (result.error or "")
    assert recorded == []


async def test_without_a_login_nothing_is_staged_for_it(jobs):
    recorded, outcomes = jobs
    outcomes.append(_outcome(collected={CHANGED_OUT: b"no\n", COMMIT_OUT: b"abc\n"}))
    await GitCommitHandler().execute(
        _ctx(_valid(username="", password=""), _Services([_artifact("r1", "show run", "x")]))
    )
    paths = {item.path for item in recorded[0].files}
    assert PASSWORD_FILE not in paths and ASKPASS_SCRIPT not in paths
    assert "GIT_ASKPASS" not in next(i for i in recorded[0].files if i.path == RUN_SCRIPT).content


async def test_trusted_cas_stage_the_bundle_when_the_organization_has_cas(jobs, monkeypatch):
    recorded, outcomes = jobs
    outcomes.append(_outcome(collected={CHANGED_OUT: b"no\n", COMMIT_OUT: b"abc\n"}))

    async def _org_pem(services):
        return "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

    monkeypatch.setattr("hegemony_steps_git.commit.org_trusted_ca_pem", _org_pem)
    await GitCommitHandler().execute(
        _ctx(_valid(trusted_cas=True), _Services([_artifact("r1", "show run", "x")]))
    )
    staged = {item.path: item for item in recorded[0].files}
    assert "MIIB" in str(staged[CA_FILE].content)
    assert "GIT_SSL_CAINFO" in str(staged[RUN_SCRIPT].content)


def test_defaults_match_the_model():
    config = GitCommitConfig()
    assert config.branch == "main"
    assert config.create_branch is False
    assert config.path_template == "{device}/{command}.txt"
    assert GitCommitHandler.default_config["path_template"] == config.path_template


def test_the_docs_page_names_every_declared_output_field():
    text = load_docs_bundle("hegemony_steps_git")["git.commit"]
    for field in GitCommitHandler.output_fields:
        assert f"output.{field.name}`" in text, field.name


def test_git_variables_from_the_step_environment_cannot_undo_the_settings(tmp_path, remote):
    # Each of these would break or weaken the run if it reached git.
    hostile = {
        "GIT_DIR": str(tmp_path / "elsewhere"),
        "GIT_INDEX_FILE": str(tmp_path / "index"),
        "GIT_SSL_NO_VERIFY": "1",
        "GIT_ALLOW_PROTOCOL": "ext",
        "GIT_CONFIG_PARAMETERS": "'core.hookspath'='/tmp' 'credential.helper'='store'",
    }
    result, out = _run(tmp_path, f"file://{remote}", {"r1.cfg": "x\n"}, extra_env=hostile)
    assert result.returncode == 0, result.stderr
    assert (out / "changed").read_text().strip() == "yes"
    author = _git("--git-dir", str(remote), "log", "-1", "--format=%an <%ae>", "main").strip()
    assert author == "Hegemony <hegemony@localhost>"


def test_paths_are_staged_literally_not_as_patterns(tmp_path, remote):
    # ":(top)r1.cfg" as a pathspec would mean r1.cfg, which does not exist.
    result, _ = _run(tmp_path, f"file://{remote}", {":(top)r1.cfg": "x\n"})
    assert result.returncode == 0, result.stderr
    tree = _git("--git-dir", str(remote), "ls-tree", "-r", "--name-only", "main").splitlines()
    assert ":(top)r1.cfg" in tree


def test_a_device_that_failed_after_its_capture_keeps_its_old_file():
    artifacts = [
        _artifact("r1", "show run", "first read", created="2026-11-20T10:00:00Z"),
        {
            "step_id": "collect",
            "name": "r1:connection_error",
            "kind": "error",
            "created_at": "2026-11-20T11:00:00Z",
            "content_json": {"device_id": "id-r1", "device_name": "r1", "error": "timed out"},
        },
        _artifact("r2", "show run", "r2 read", created="2026-11-20T11:00:00Z"),
        {
            "step_id": "collect",
            "name": "r2:connection_error",
            "kind": "error",
            "created_at": "2026-11-20T10:00:00Z",
            "content_json": {"device_id": "id-r2", "device_name": "r2", "error": "refused"},
        },
    ]
    selection = select_files(artifacts, "collect", "{device}.cfg")
    # r1 failed after its capture: skipped. r2 recovered after its failure: written.
    assert selection.files == {"r2.cfg": "r2 read"}
    assert "r1:show run: a later attempt failed: timed out" in selection.skipped


async def test_a_push_with_an_incomplete_report_fails_rather_than_guess(jobs):
    _, outcomes = jobs
    outcomes.append(_outcome(collected={CHANGED_OUT: b"yes\n", COMMIT_OUT: b"\n"}))
    result = await GitCommitHandler().execute(
        _ctx(_valid(), _Services([_artifact("r1", "show run", "x")]))
    )
    assert not result.success
    assert "could not be read" in (result.error or "")
