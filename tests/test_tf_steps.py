# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""tf.plan and tf.apply: plan summaries, generated scripts, and step results."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
import stat
import subprocess
import tempfile
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from hegemony_step_sdk import (
    ContainerRuntime,
    HandlerContext,
    HandlerResult,
    HandlerServices,
    StateBackendAccess,
)
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_container.runner import ContainerJobResult
from hegemony_steps_tf.apply import (
    APPLIED_PLAN_FILE,
    APPLIED_PLAN_SUM_FILE,
    ERRORED_STATE_FILE,
    EXIT_NO_PLAN,
    EXIT_PLAN_CHANGED,
    NO_PLAN_MESSAGE,
    OUTPUTS_FILE,
    PLAN_CHANGED_MESSAGE,
    TfApplyHandler,
    apply_failure,
    build_apply_script,
)
from hegemony_steps_tf.common import (
    BACKEND_CONFIG_FILE,
    BACKEND_OVERRIDE_FILE,
    DEFAULT_IMAGES,
    DEFAULT_STOP_GRACE_SECONDS,
    HOLD_KEPT_NOTE,
    HOLD_NOT_ENDED_NOTE,
    HOLD_UNSUPPORTED_MESSAGE,
    KEEP_DIR,
    MAX_OUTPUT_VALUE_BYTES,
    PLAN_TEXT_MISSING_NOTE,
    RUN_SCRIPT,
    SECRET_ENV_FILE,
    SECRET_VARS_FILE,
    STATE_ACCESS_MARGIN_SECONDS,
    VARS_FILE,
    collect_failure,
    encryption_hcl,
    hcl_string,
    lock_conflict_error,
    lock_timeout_errors,
    public_outputs,
    tool_deadline,
    tool_kill_after,
    typed_variable,
    workdir_for,
)
from hegemony_steps_tf.plan import (
    EXIT_NO_BACKEND,
    LOCAL_WORKDIR,
    NO_BACKEND_MESSAGE,
    PLAN_JSON_DIR,
    PLAN_JSON_FILE,
    PLAN_OUTPUTS_DIR,
    PLAN_OUTPUTS_FILE,
    PLAN_SHA256_FILE,
    PLAN_SNAPSHOT_FILE,
    PLAN_TEXT_FILE,
    TfPlanConfig,
    TfPlanHandler,
    build_plan_script,
)
from hegemony_steps_tf.summary import MAX_LISTED_CHANGES, plan_line, summarize_plan

# ── plan summary ─────────────────────────────────────────────────────────────


def _rc(address: str, actions: list[str], **extra: Any) -> dict[str, Any]:
    change: dict[str, Any] = {"actions": actions, "before": {"secret": "s3cr3t"}}
    change.update(extra.pop("change", {}))
    return {"address": address, "change": change, **extra}


def test_summary_counts_like_the_cli_and_keeps_no_values():
    plan = {
        "resource_changes": [
            _rc("a.new", ["create"]),
            _rc("a.upd", ["update"]),
            _rc("a.gone", ["delete"]),
            _rc("a.repl", ["delete", "create"], action_reason="replace_by_request"),
            _rc("a.cbd", ["create", "delete"]),
            _rc("a.same", ["no-op"]),
            _rc("a.imp", ["no-op"], change={"importing": {"id": "i-1"}}),
            _rc("a.moved", ["no-op"], previous_address="a.old"),
            _rc("data.x", ["read"]),
        ],
        "output_changes": {"vpc_id": {"actions": ["create"]}, "same": {"actions": ["no-op"]}},
        "resource_drift": [{}],
    }
    summary = summarize_plan(plan)

    assert (summary["add"], summary["change"], summary["destroy"]) == (3, 1, 3)
    assert (summary["replace"], summary["import"], summary["move"], summary["read"]) == (2, 1, 1, 1)
    addresses = [item["address"] for item in summary["resource_changes"]]
    assert addresses == ["a.new", "a.upd", "a.gone", "a.repl", "a.cbd", "a.imp", "a.moved"]
    assert summary["resource_changes"][3]["reason"] == "replace_by_request"
    assert summary["output_changes"] == ["vpc_id"]
    assert summary["drift"] == 1
    assert "s3cr3t" not in json.dumps(summary)
    assert plan_line(summary) == "+3 ~1 -3 (2 replaced, 1 imported, 1 moved)"


def test_summary_counts_forgotten_resources():
    summary = summarize_plan(
        {"resource_changes": [_rc("a.gone", ["forget"]), _rc("a.again", ["forget", "create"])]}
    )
    assert (summary["forget"], summary["add"], summary["destroy"]) == (2, 1, 0)
    assert [item["actions"] for item in summary["resource_changes"]] == [
        ["forget"],
        ["forget", "create"],
    ]


def test_summary_lists_at_most_the_cap_but_counts_everything():
    changes = [_rc(f"a.r{index}", ["create"]) for index in range(MAX_LISTED_CHANGES + 1)]
    summary = summarize_plan({"resource_changes": changes})
    assert summary["add"] == MAX_LISTED_CHANGES + 1
    assert len(summary["resource_changes"]) == MAX_LISTED_CHANGES
    assert summary["resource_changes_truncated"] is True
    assert "resource_changes_truncated" not in summarize_plan({"resource_changes": changes[:1]})


def test_summary_of_an_empty_plan():
    summary = summarize_plan({"format_version": "1.2"})
    assert summary["add"] == summary["change"] == summary["destroy"] == 0
    assert summary["resource_changes"] == []
    assert plan_line(summary) == "+0 ~0 -0"


# ── helpers ──────────────────────────────────────────────────────────────────


def test_typed_variables():
    assert typed_variable('["r1", "r2"]') == ["r1", "r2"]
    assert typed_variable('{"a": 1}') == {"a": 1}
    assert typed_variable("true") is True
    assert typed_variable("10.0.0.1") == "10.0.0.1"
    assert typed_variable("42") == "42"
    assert typed_variable("[not json") == "[not json"


def test_hcl_strings_escape_templates():
    assert hcl_string('a"b${x}%{y}') == '"a\\"b$${x}%%{y}"'


def test_encryption_config_enforces_state_and_plan():
    hcl = encryption_hcl("correct-horse-battery")
    assert 'passphrase = "correct-horse-battery"' in hcl
    assert hcl.count("enforced = true") == 2


def test_public_outputs_drop_sensitive_values():
    raw = json.dumps(
        {
            "vpc_id": {"sensitive": False, "type": "string", "value": "vpc-1"},
            "db_password": {"sensitive": True, "type": "string", "value": "hunter2"},
        }
    ).encode()
    values, sensitive = public_outputs(raw)
    assert values == {"vpc_id": "vpc-1"}
    assert sensitive == ["db_password"]
    assert public_outputs(None) == ({}, [])


@pytest.mark.parametrize("raw", [b"not json", b"[1]", b'"text"', b'{"x": 1}'])
def test_public_outputs_of_unexpected_documents_are_empty(raw):
    assert public_outputs(raw) == ({}, [])


def test_public_outputs_leave_out_oversized_values_without_calling_them_sensitive():
    raw = json.dumps(
        {
            "big": {"sensitive": False, "value": "x" * (MAX_OUTPUT_VALUE_BYTES + 1)},
            "small": {"sensitive": False, "value": "y"},
        }
    ).encode()
    assert public_outputs(raw) == ({"small": "y"}, [])


# ── scripts ──────────────────────────────────────────────────────────────────


def _assert_parses(script: str) -> None:
    """The generated script is valid sh (a quoting slip shows only at run time)."""
    if shutil.which("sh") is None:
        pytest.skip("no sh")
    done = subprocess.run(["sh", "-n"], input=script, text=True, capture_output=True)
    assert done.returncode == 0, done.stderr


def test_plan_script_for_backend_state():
    config = TfPlanConfig.model_validate(
        {
            "state": "backend",
            "source_dir": "terraform/net",
            "backend_config": {"bucket": "b"},
            "targets": ["aws_vpc.main"],
            "replace": ["aws_instance.web"],
            "var_files": ["terraform/prod.tfvars"],
        }
    )
    script = build_plan_script(
        config, workdir="/shared/tf/plan", has_vars=True, has_secret_vars=True
    )

    assert "cp -R /attachments/terraform/net/. /shared/tf/plan/" in script
    assert f"tofu init -input=false -no-color -backend-config={BACKEND_CONFIG_FILE}" in script
    assert "if [ ! -f .terraform/terraform.tfstate ]" in script
    assert f'echo "{NO_BACKEND_MESSAGE}" >&2' in script
    assert f"exit {EXIT_NO_BACKEND}" in script
    assert BACKEND_OVERRIDE_FILE not in script
    plan = next(line for line in script.splitlines() if line.startswith("tofu plan"))
    for part in (
        "-detailed-exitcode",
        f"-out={PLAN_SNAPSHOT_FILE}",
        "-target=aws_vpc.main",
        "-replace=aws_instance.web",
        "-var-file=/attachments/terraform/prod.tfvars",
        f"-var-file={VARS_FILE}",
        f"-var-file={SECRET_VARS_FILE}",
    ):
        assert part in plan
    assert f"tofu show -json {PLAN_SNAPSHOT_FILE} > /hegemony/plan-json/plan.json" in script
    assert f". {SECRET_ENV_FILE}" in script
    _assert_parses(script)


def test_plan_script_for_ephemeral_state_and_terraform():
    config = TfPlanConfig.model_validate({"engine": "terraform", "state": "ephemeral"})
    script = build_plan_script(config, workdir=LOCAL_WORKDIR, has_vars=False, has_secret_vars=False)
    assert f"cp {BACKEND_OVERRIDE_FILE} {LOCAL_WORKDIR}/" in script
    assert "terraform init -input=false -no-color\n" in script
    assert ".terraform/terraform.tfstate" not in script
    assert "-var-file" not in script
    _assert_parses(script)


def test_plan_script_for_managed_state():
    config = TfPlanConfig.model_validate({"state_name": "core", "backend_config": {"x": "y"}})
    script = build_plan_script(
        config, workdir="/shared/tf/plan", has_vars=False, has_secret_vars=False
    )
    assert f"cp {BACKEND_OVERRIDE_FILE} /shared/tf/plan/" in script
    assert "tofu init -input=false -no-color\n" in script
    assert ".terraform/terraform.tfstate" not in script
    _assert_parses(script)


def test_plan_script_quotes_untrusted_values():
    config = TfPlanConfig.model_validate(
        {
            "state": "backend",
            "source_dir": "it's; rm -rf /",
            "backend_config": {"bucket": "b"},
            "var_files": ["a b/$(x).tfvars"],
            "targets": ['a.b["x\'; y"]'],
            "lock_timeout": "5m",
        }
    )
    script = build_plan_script(
        config, workdir="/shared/tf/pl an;x", has_vars=True, has_secret_vars=True
    )
    assert "cd '/shared/tf/pl an;x'" in script
    _assert_parses(script)


def test_apply_script():
    digest = "d" * 64
    script = build_apply_script("opentofu", "/shared/tf/plan", "5m", digest)
    assert "cd /shared/tf/plan" in script
    # The shared plan is copied out and checked; only the private copy is applied.
    assert f"cp plan.tfplan {APPLIED_PLAN_FILE}\n" in script
    assert f"printf '%s  %s\\n' {digest} {APPLIED_PLAN_FILE} > {APPLIED_PLAN_SUM_FILE}" in script
    assert f"if ! sha256sum -c {APPLIED_PLAN_SUM_FILE} > /dev/null 2>&1; then" in script
    assert f"  exit {EXIT_PLAN_CHANGED}\n" in script
    assert script.index("sha256sum -c") < script.index("tofu apply")
    assert f"tofu apply -input=false -no-color -lock-timeout=5m {APPLIED_PLAN_FILE}\n" in script
    assert "tofu output -json > /hegemony/out/outputs.json" in script
    _assert_parses(script)
    _assert_parses(build_apply_script("terraform", "/shared/tf/a b;c'd", "300s", digest))


@pytest.mark.parametrize("digest", ["", "d" * 63, "D" * 64, "d" * 63 + ";", "$(id)" + "d" * 59])
def test_apply_script_takes_only_a_sha256_digest(digest):
    with pytest.raises(ValueError, match="64 hex digits"):
        build_apply_script("opentofu", "/shared/tf/plan", "5m", digest)


def test_scripts_stop_the_tool_at_the_step_deadline():
    """A dead worker stops nothing: the script bounds every tool call itself."""
    apply = build_apply_script(
        "opentofu", "/shared/tf/plan", "5m", "d" * 64, deadline=1_900_000_000
    )
    assert "hegemony_deadline=1900000000" in apply
    assert "\nbounded tofu apply -input=false" in apply
    assert "bounded tofu output -json" in apply
    # Saving a stopped apply's state is what the time after the deadline is for.
    assert "bounded tofu state push" not in apply
    assert "tofu state push -lock=false errored.tfstate" in apply
    _assert_parses(apply)

    config = TfPlanConfig.model_validate({"state": "ephemeral"})
    plan = build_plan_script(
        config, workdir=LOCAL_WORKDIR, has_vars=False, has_secret_vars=False, deadline=1
    )
    for call in ("init", "validate", "plan", "show -no-color", "show -json", "output -json"):
        assert f"bounded tofu {call}" in plan
    _assert_parses(plan)
    unbounded = build_plan_script(
        config, workdir=LOCAL_WORKDIR, has_vars=False, has_secret_vars=False
    )
    assert "bounded" not in unbounded


# ── validation ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"source_dir": "/abs"}, "relative path"),
        ({"source_dir": "../up"}, "'..'"),
        ({"vars": {"bad name": "x"}}, "valid variable name"),
        ({"secret_env": {"HEGEMONY_X": "vault://a/b"}}, "reserved"),
        ({"secret_env": {"TF_HTTP_PASSWORD": "vault://a/b"}}, "reserved"),
        ({"backend_config": {"bad-key": "x"}}, "backend setting name"),
        ({"targets": ["a\nb"]}, "one resource address"),
        ({"replace": ["aws_instance.web\tx"]}, "one resource address"),
        ({"destroy": True, "refresh_only": True}, "cannot be combined"),
        ({"engine": "terraform", "state_encryption_key": "vault://k/x"}, "opentofu engine"),
        ({"lock_timeout": "soon"}, "lock_timeout"),
        ({"image": "/tmp/x"}, "Invalid image reference"),
        ({"state": "managed"}, "state_name"),
        ({"state_name": "-bad"}, "state_name"),
        ({"state": "cloud"}, "state"),
    ],
)
def test_plan_validation_rejects(config, message):
    errors = TfPlanHandler().validate_config(config)
    assert any(message in error for error in errors), errors


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"secret_env": {"HEGEMONY_X": "vault://a/b"}}, "reserved"),
        ({"secret_env": {"TF_HTTP_PASSWORD": "vault://a/b"}}, "reserved"),
        ({"secret_env": {"bad name": "vault://a/b"}}, "valid environment variable"),
        ({"lock_timeout": "soon"}, "lock_timeout"),
        ({"image": "/tmp/x"}, "Invalid image reference"),
        ({"plan_step": ""}, "plan_step"),
    ],
)
def test_apply_validation_rejects(config, message):
    errors = TfApplyHandler().validate_config({"plan_step": "plan", **config})
    assert any(message in error for error in errors), errors


def test_keyed_resource_instances_can_be_targeted_and_replaced():
    addresses = ['aws_instance.web["blue"]', 'module.site["prod east"].aws_vpc.main']
    config = {"state_name": "core", "targets": addresses, "replace": addresses[:1]}
    assert TfPlanHandler().validate_config(config) == []
    script = build_plan_script(
        TfPlanConfig.model_validate(config),
        workdir="/shared/tf/plan",
        has_vars=False,
        has_secret_vars=False,
    )
    assert """'-target=module.site["prod east"].aws_vpc.main'""" in script
    assert """'-replace=aws_instance.web["blue"]'""" in script
    _assert_parses(script)


def test_plan_validation_accepts_defaults():
    assert TfPlanHandler().validate_config({"state_name": "core"}) == []
    assert TfPlanHandler().validate_config({"state": "ephemeral"}) == []
    assert TfApplyHandler().validate_config({"plan_step": "plan"}) == []


# ── end to end ───────────────────────────────────────────────────────────────

#: The saved plan's digest, as tf.plan's script writes it with sha256sum.
_PLAN_SHA256 = hashlib.sha256(b"plan").hexdigest()
_PLAN_SUM = f"{_PLAN_SHA256}  plan.tfplan\n".encode()


class _Services:
    def __init__(
        self, step_outputs: dict[str, Any] | None = None, *, shared_workspaces: bool = True
    ) -> None:
        self.step_outputs = step_outputs or {}
        self.shared_workspaces = shared_workspaces
        self.shared_root = tempfile.mkdtemp(prefix="hegemony-tf-test-")
        # State access and container milestones in order (see _install_docker).
        self.events: list[Any] = []

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=self.shared_workspaces,
            # The runner creates the run's folder here, as the worker would.
            shared_workspace_root=self.shared_root,
            shared_workspace_volume="hegemony-shared",
            docker_host="tcp://dind:2375",
        )

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        return [{"filename": "main.tf", "content": 'resource "terraform_data" "x" {}\n'}]

    async def fetch_run_step_outputs(self, run_id: str) -> dict[str, Any]:
        return self.step_outputs

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        return []

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        assert ref is not None
        return "resolved-" + ref.split("/")[-1].split("'")[0] + "-long-enough"

    opened: list[tuple[str, int]] = []
    held: list[str] = []
    closed: list[str] = []
    state_error: str = ""

    @asynccontextmanager
    async def open_state_backend(
        self, name: str, *, ttl_seconds: int, hold_until_apply: bool = False
    ):
        if self.state_error:
            raise RuntimeError(self.state_error)
        self.opened = [*self.opened, (name, ttl_seconds)]
        if hold_until_apply:
            self.held = [*self.held, name]
        self.events.append(("open", name))
        try:
            yield StateBackendAccess(
                address=f"http://api:8000/tf-states/{name}/state",
                lock_address=f"http://api:8000/tf-states/{name}/lock",
                unlock_address=f"http://api:8000/tf-states/{name}/lock",
                username="run",
                password="hgm_run_token-value",
                extra_hosts={"api": "172.20.0.5"},
            )
        finally:
            self.closed = [*self.closed, name]
            self.events.append(("close", name))


def _install_docker(
    monkeypatch,
    *,
    out: dict[str, bytes | None],
    exit_code: int = 0,
    events: list[Any] | None = None,
    repo_digests: list[str] | None = None,
) -> dict[str, Any]:
    """Fake docker. ``events`` (a _Services' log) records the staging of the
    container's files and the container start among the state access events.
    ``repo_digests`` is the pulled image's RepoDigests (none by default).
    ``out`` gets the saved plan's digest unless it names ``plan.sha256``
    itself (None: not written)."""
    out = {"plan.sha256": _PLAN_SUM, **out}
    state: dict[str, Any] = {"roots": {}, "calls": [], "exec": 0, "collected": []}
    events = events if events is not None else []
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("off")),
    )

    def fake_run(cmd, *args, **kwargs):
        state["calls"].append(list(cmd))
        if cmd[1:3] == ["image", "inspect"] and "{{json .RepoDigests}}" in cmd:
            return SimpleNamespace(returncode=0, stdout=json.dumps(repo_digests or []), stderr="")
        if len(cmd) >= 4 and cmd[1] == "cp":
            src, dest = cmd[2], cmd[3]
            if dest.endswith(":/"):
                events.append("stage")
                root = src[: -len("/.")]
                for walk_root, _dirs, files in os.walk(root):
                    for name in files:
                        path = os.path.join(walk_root, name)
                        with open(path, encoding="utf-8") as fh:
                            state["roots"]["/" + os.path.relpath(path, root)] = fh.read()
            elif ":/" in src and src.endswith("/."):
                # A collected folder: ``out`` names files in /hegemony/out, or
                # anywhere by absolute path.
                folder = src.split(":", 1)[1][: -len("/.")]
                state["collected"].append(folder)
                for name, data in out.items():
                    path = name if name.startswith("/") else f"/hegemony/out/{name}"
                    if data is not None and posixpath.dirname(path) == folder:
                        with open(os.path.join(dest, posixpath.basename(path)), "wb") as fh:
                            fh.write(data)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    async def fake_exec(*argv, **kwargs):
        state["exec"] += 1
        events.append(argv[1])
        proc = AsyncMock()
        proc.stdout = AsyncMock()
        proc.stdout.read = AsyncMock(return_value=b"")
        proc.stderr = AsyncMock()
        proc.stderr.read = AsyncMock(return_value=b"")
        proc.wait = AsyncMock(return_value=exit_code)
        proc.kill = AsyncMock()
        return proc

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    return state


def _ctx(
    config: dict[str, Any], services: _Services, *, shared: bool = True, timeout: int = 300
) -> HandlerContext:
    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="plan",
        config=config,
        shared_workspace=shared,
        timeout_seconds=timeout,
        services=cast(HandlerServices, services),
    )


_PLAN_JSON = json.dumps(
    {
        "resource_changes": [
            {
                "address": "terraform_data.svc",
                "change": {"actions": ["create"], "after": {"x": "planned-secret-value"}},
            }
        ]
    }
).encode()


@pytest.mark.asyncio
async def test_plan_step_reports_changes(monkeypatch):
    state = _install_docker(
        monkeypatch,
        out={
            "plan-exitcode": b"2",
            "plan.txt": b"Plan: 1 to add, 0 to change, 0 to destroy.\n",
            PLAN_JSON_FILE: _PLAN_JSON,
        },
    )
    config = {
        "state": "ephemeral",
        "vars": {"routers": '["r1","r2"]'},
        "secret_vars": {"token": "vault://orgs/acme/secrets/tok"},
        "secret_env": {"AWS_SECRET_ACCESS_KEY": "vault://orgs/acme/secrets/aws"},
        "state_encryption_key": "vault://orgs/acme/secrets/enc",
    }
    result = await TfPlanHandler().execute(_ctx(config, _Services()))

    assert result.success is True, result.error
    assert result.summary == "Plan: +1 ~0 -0"
    assert result.output["has_changes"] is True
    assert result.output["handler"] == "tf.plan"
    assert result.output["apply_ready"] is True
    assert result.output["working_dir"] == "/shared/tf/plan"
    assert not any(e["name"] == "plan_only_plan" for e in result.evidence)
    assert result.output["image"] == DEFAULT_IMAGES["opentofu"]
    assert result.output["resource_changes"] == [
        {"address": "terraform_data.svc", "actions": ["create"]}
    ]
    assert "planned-secret-value" not in json.dumps(result.output)
    plan_artifact = next(e for e in result.evidence if e["name"] == "plan_plan.txt")
    assert "1 to add" in plan_artifact["content_text"]
    # The digest tf.apply checks, where an approver sees it.
    assert result.output["plan_sha256"] == _PLAN_SHA256
    assert plan_artifact["content_json"]["plan_sha256"] == _PLAN_SHA256
    assert plan_artifact["content_text"].endswith(
        f"\n\nSaved plan plan.tfplan, SHA-256: {_PLAN_SHA256}\n"
    )

    roots = state["roots"]
    assert json.loads(roots[VARS_FILE]) == {"routers": ["r1", "r2"]}
    assert json.loads(roots[SECRET_VARS_FILE]) == {"token": "resolved-tok-long-enough"}
    assert "export AWS_SECRET_ACCESS_KEY=resolved-aws-long-enough" in roots[SECRET_ENV_FILE]
    assert "TF_ENCRYPTION=" in roots[SECRET_ENV_FILE]
    assert 'backend "local"' in roots[BACKEND_OVERRIDE_FILE]
    assert "\nbounded tofu plan " in roots[RUN_SCRIPT]
    script = roots[RUN_SCRIPT]
    # The tool saves the plan in the container's own folder; the digest and
    # both readable forms come from that file, and only then is it shared.
    assert f" -out={PLAN_SNAPSHOT_FILE} " in script
    hashed = script.index(f"\nsha256sum {PLAN_SNAPSHOT_FILE} > {PLAN_SHA256_FILE}\n")
    shared = script.index(f"\ncp {PLAN_SNAPSHOT_FILE} plan.tfplan\n")
    assert script.index("\nbounded tofu plan ") < hashed < shared
    assert shared < script.index("\nbounded tofu show ")
    assert f"\nbounded tofu show -no-color {PLAN_SNAPSHOT_FILE} > " in script
    assert f"\nbounded tofu show -json {PLAN_SNAPSHOT_FILE} > " in script
    create = next(call for call in state["calls"] if call[1] == "create")
    assert "hegemony.handler_id=tf.plan" in create
    assert not any("resolved-" in part for part in create)
    assert "TF_IN_AUTOMATION=1" in create
    assert create[-1].endswith(f"exec sh {RUN_SCRIPT}")
    assert create[create.index("--stop-timeout") + 1] == str(DEFAULT_STOP_GRACE_SECONDS)
    # The exit code and the readable plan are collected before the JSON plan.
    assert state["collected"][:3] == ["/hegemony/out", PLAN_OUTPUTS_DIR, PLAN_JSON_DIR]


@pytest.mark.asyncio
async def test_a_refresh_only_plan_names_the_drift(monkeypatch):
    plan_json = json.dumps({"resource_drift": [{"address": "a.b"}, {"address": "a.c"}]})
    _install_docker(
        monkeypatch,
        out={"plan-exitcode": b"2", "plan.txt": b"drift\n", PLAN_JSON_FILE: plan_json.encode()},
    )
    config = {"state": "ephemeral", "refresh_only": True}
    result = await TfPlanHandler().execute(_ctx(config, _Services()))
    assert result.success is True, result.error
    assert result.summary == "Plan: +0 ~0 -0 (2 drifted)"
    assert result.output["drift"] == 2


@pytest.mark.asyncio
async def test_a_broken_json_plan_still_reports_changes(monkeypatch):
    """Changes come from the detailed exit code: a JSON plan that cannot be read
    costs the counts, never the has_changes a later approval depends on."""
    _install_docker(
        monkeypatch,
        out={"plan-exitcode": b"2", "plan.txt": b"Plan: 1 to add.\n", PLAN_JSON_FILE: b"{broken"},
    )
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services()))
    assert result.success is True, result.error
    assert result.output["has_changes"] is True
    assert result.summary == "Plan: changes"
    assert "add" not in result.output


@pytest.mark.asyncio
async def test_plan_step_records_the_outputs_it_found(monkeypatch):
    outputs = json.dumps(
        {
            "vpc_id": {"sensitive": False, "value": "vpc-1"},
            "db_password": {"sensitive": True, "value": "hunter2"},
        }
    ).encode()
    _install_docker(
        monkeypatch,
        out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n", PLAN_OUTPUTS_FILE: outputs},
    )
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services()))
    assert result.success is True, result.error
    assert result.output["outputs"] == {"vpc_id": "vpc-1"}
    assert result.output["sensitive_outputs"] == ["db_password"]
    assert "hunter2" not in json.dumps(result.output)


@pytest.mark.asyncio
async def test_plan_step_succeeds_without_its_outputs(monkeypatch):
    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services()))
    assert result.success is True, result.error
    assert (result.output["outputs"], result.output["sensitive_outputs"]) == ({}, [])


@pytest.mark.asyncio
async def test_plan_step_says_when_its_readable_plan_was_not_collected(monkeypatch):
    """Collection skips a file over the remaining budget: the approver must learn
    that there is no plan artifact to review."""
    _install_docker(monkeypatch, out={"plan-exitcode": b"2", PLAN_JSON_FILE: _PLAN_JSON})
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services()))
    assert result.success is True, result.error
    assert result.summary == "Plan: +1 ~0 -0 (the readable plan could not be collected)"
    assert result.output["summary"] == result.summary
    assert not any(e["name"] == "plan_plan.txt" for e in result.evidence)


@pytest.mark.asyncio
@pytest.mark.parametrize("secret", ['{"type": "service_account"}', "[1, 2]", "true"])
async def test_secret_variables_are_passed_as_written(monkeypatch, secret):
    """A secret is opaque: one that looks like JSON (a GCP service-account key)
    must still reach a string variable as a string."""
    state = _install_docker(monkeypatch, out={"plan-exitcode": b"0"})

    class JsonSecret(_Services):
        async def resolve_secret_ref(self, ref, *, source):
            return secret

    config = {"state": "ephemeral", "secret_vars": {"gcp_key": "vault://orgs/acme/secrets/sa"}}
    result = await TfPlanHandler().execute(_ctx(config, JsonSecret()))
    assert result.success is True, result.error
    assert json.loads(state["roots"][SECRET_VARS_FILE]) == {"gcp_key": secret}


@pytest.mark.asyncio
async def test_plan_step_without_shared_workspace_is_plan_only(monkeypatch):
    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services(), shared=False))
    assert result.success is True
    assert result.output["has_changes"] is False
    assert result.output["apply_ready"] is False
    assert result.output["working_dir"] == LOCAL_WORKDIR
    assert result.summary == "No changes: infrastructure matches the configuration"
    # The summary stays as is (plan-only is legitimate); the evidence says why
    # a tf.apply would refuse this plan.
    note = next(e for e in result.evidence if e["name"] == "plan_only_plan")
    assert "cannot be applied by tf.apply" in note["content_text"]


@pytest.mark.asyncio
async def test_plan_step_on_a_worker_without_shared_workspaces_is_plan_only(monkeypatch):
    """Shared affinity alone is not enough: the runner mounts /shared only when the
    worker has shared workspaces enabled, so the plan would die with its container."""
    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})
    services = _Services(shared_workspaces=False)
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, services))
    assert result.success is True
    assert result.output["apply_ready"] is False
    assert result.output["working_dir"] == LOCAL_WORKDIR


@pytest.mark.asyncio
async def test_apply_step_refuses_on_a_worker_without_shared_workspaces(monkeypatch):
    state = _install_docker(monkeypatch, out={})
    services = _Services(_plan_output(), shared_workspaces=False)
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, services))
    assert result.success is False
    assert "shared workspaces enabled" in (result.error or "")
    assert state["exec"] == 0


@pytest.mark.asyncio
async def test_plan_step_without_backend_block_fails(monkeypatch):
    _install_docker(monkeypatch, out={}, exit_code=EXIT_NO_BACKEND)
    result = await TfPlanHandler().execute(_ctx({"state": "backend"}, _Services()))
    assert result.success is False
    assert "no backend block" in (result.error or "")


@pytest.mark.asyncio
async def test_plan_step_with_managed_state(monkeypatch):
    services = _Services()
    state = _install_docker(
        monkeypatch,
        out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"},
        events=services.events,
    )
    result = await TfPlanHandler().execute(
        _ctx({"state_name": "core", "timeout_seconds": 900}, services)
    )

    assert result.success is True, result.error
    assert result.output["state"] == "managed"
    assert result.output["state_name"] == "core"
    assert services.opened == [("core", 900 + STATE_ACCESS_MARGIN_SECONDS)]
    assert services.closed == ["core"]
    # The run token is revoked when the access closes: the env file carrying it
    # is staged, and the container runs, while it is open.
    assert services.events == [("open", "core"), "stage", "start", ("close", "core")]
    roots = state["roots"]
    assert 'backend "http"' in roots[BACKEND_OVERRIDE_FILE]
    env = roots[SECRET_ENV_FILE]
    for line in (
        "export TF_HTTP_ADDRESS=http://api:8000/tf-states/core/state",
        "export TF_HTTP_LOCK_ADDRESS=http://api:8000/tf-states/core/lock",
        "export TF_HTTP_LOCK_METHOD=POST",
        "export TF_HTTP_UNLOCK_METHOD=DELETE",
        "export TF_HTTP_PASSWORD=hgm_run_token-value",
    ):
        assert line in env
    create = next(call for call in state["calls"] if call[1] == "create")
    assert create[create.index("--add-host") + 1] == "api:172.20.0.5"
    assert not any("hgm_run_" in part for part in create)


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [None, b"", b"1", b"garbage"])
async def test_plan_step_fails_without_a_valid_detailed_exit_code(monkeypatch, code):
    """The script exits 0 for a plan with changes too, and reading its detailed exit
    code back is best-effort: without it the step must not report "no changes"."""
    out = {"plan.txt": b"Plan: 1 to add, 0 to change, 0 to destroy.\n", PLAN_JSON_FILE: _PLAN_JSON}
    if code is not None:
        out["plan-exitcode"] = code
    _install_docker(monkeypatch, out=out)
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services()))
    assert result.success is False
    assert "detailed exit code" in (result.error or "")
    assert not result.output


@pytest.mark.asyncio
@pytest.mark.parametrize("digest", [None, b"", b"not-a-digest  plan.tfplan\n", b"abc  plan.tfplan"])
async def test_plan_step_fails_without_the_saved_plans_digest(monkeypatch, digest):
    """tf.apply could not tell the saved plan from one written over it later."""
    _install_docker(
        monkeypatch,
        out={"plan-exitcode": b"2", "plan.txt": b"Plan: 1 to add.\n", "plan.sha256": digest},
    )
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services()))
    assert result.success is False
    assert result.summary == "tofu plan result missing"
    assert "the saved plan's digest could not be read back" in (result.error or "")
    assert not result.output


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "config", "step_timeout", "expected"),
    [
        # No timeout in the step config (an imported or API-authored flow): the
        # runner uses the host's step timeout, and so must the state access.
        (TfPlanHandler, {"state_name": "core"}, 1800, 1800),
        (TfApplyHandler, {"plan_step": "plan"}, 3600, 3600),
        # A step or flow policy timeout reaches the handler as the step timeout.
        (TfApplyHandler, {"plan_step": "plan"}, 7200, 7200),
        # The step's own timeout wins, for the container and its state access alike.
        (TfPlanHandler, {"state_name": "core", "timeout_seconds": 900}, 3600, 900),
        (TfApplyHandler, {"plan_step": "plan", "timeout_seconds": 900}, 3600, 900),
    ],
)
async def test_state_access_lasts_as_long_as_the_container(
    monkeypatch, handler, config, step_timeout, expected
):
    jobs = []

    async def fake_run_container_job(ctx, job):
        jobs.append(job)
        return HandlerResult(success=False, error="stopped before the container")

    monkeypatch.setattr(f"{handler.__module__}.run_container_job", fake_run_container_job)
    services = _Services(_plan_output(state="managed", state_name="core"))
    await handler().execute(_ctx(config, services, timeout=step_timeout))

    assert services.opened == [("core", expected + STATE_ACCESS_MARGIN_SECONDS)]
    assert [job.config["timeout_seconds"] for job in jobs] == [expected]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "config", "grace"),
    [
        (TfPlanHandler, {"state": "ephemeral"}, DEFAULT_STOP_GRACE_SECONDS),
        (TfApplyHandler, {"plan_step": "plan"}, DEFAULT_STOP_GRACE_SECONDS),
        (TfApplyHandler, {"plan_step": "plan", "stop_grace_seconds": 600}, 600),
        (TfPlanHandler, {"state": "ephemeral", "stop_grace_seconds": 0}, 0),
    ],
)
async def test_tool_steps_stop_gracefully_as_pid_1(monkeypatch, handler, config, grace):
    """Cancelled mid-apply, the tool gets SIGTERM and the grace period (not docker rm -f)
    to save its state and unlock; exec makes the run script the PID 1 docker stop signals."""
    jobs = []

    async def fake_run_container_job(ctx, job):
        jobs.append(job)
        return HandlerResult(success=False, error="stopped before the container")

    monkeypatch.setattr(f"{handler.__module__}.run_container_job", fake_run_container_job)
    await handler().execute(_ctx(config, _Services(_plan_output(state="ephemeral")), timeout=3600))

    assert [job.stop_grace_seconds for job in jobs] == [grace]
    assert jobs[0].config["command"] == [f"exec sh {RUN_SCRIPT}"]
    script = next(str(file.content) for file in jobs[0].files if file.path == RUN_SCRIPT)
    assert f"-k {max(300, grace)} " in script


@pytest.mark.parametrize(
    ("timeout", "grace", "interrupt_after"),
    [
        (3600, 120, 3480),
        (3600, 0, 3600),
        # At most half the timeout goes to stopping.
        (600, 3600, 300),
        (1, 120, 1),
    ],
)
def test_the_tool_is_interrupted_a_grace_period_before_the_step_timeout(
    monkeypatch, timeout, grace, interrupt_after
):
    monkeypatch.setattr("hegemony_steps_tf.common.time.time", lambda: 1_000_000.0)
    assert tool_deadline(timeout, grace) == 1_000_000 + interrupt_after


@pytest.mark.parametrize(
    ("timeout", "grace", "kill_after"),
    [
        (3600, 120, 300),
        (3600, 0, 300),
        (3600, 600, 600),
        # The grace is capped at half the timeout, and so is the wait for the kill.
        (1200, 3600, 600),
        (400, 3600, 300),
    ],
)
def test_the_tool_is_killed_only_once_its_grace_period_has_passed(timeout, grace, kill_after):
    """SIGKILL must not cut a long stop grace short: the kill waits for all of it."""
    assert tool_kill_after(timeout, grace) == kill_after


@pytest.mark.parametrize("value", [-1, 3601])
def test_stop_grace_is_bounded(value):
    errors = TfPlanHandler().validate_config({"state": "ephemeral", "stop_grace_seconds": value})
    assert any("stop_grace_seconds" in error for error in errors), errors


@pytest.mark.parametrize(
    ("handler", "config", "refused"),
    [
        (TfPlanHandler, {"state_name": "core", "timeout_seconds": 85800}, False),
        (TfPlanHandler, {"state_name": "core", "timeout_seconds": 85801}, True),
        (TfPlanHandler, {"state_name": "core", "timeout_seconds": "86400"}, True),
        # Without managed state nothing limits the timeout.
        (TfPlanHandler, {"state": "backend", "timeout_seconds": 86400}, False),
        # The plan step decides whether the apply's state is managed.
        (TfApplyHandler, {"plan_step": "plan", "timeout_seconds": 85800}, False),
        (TfApplyHandler, {"plan_step": "plan", "timeout_seconds": 86400}, True),
    ],
)
def test_managed_state_limits_the_step_timeout(handler, config, refused):
    errors = handler().validate_config(config)
    assert any("must be at most 85800 with managed state" in e for e in errors) is refused, errors


@pytest.mark.asyncio
@pytest.mark.parametrize("handler", [TfPlanHandler, TfApplyHandler])
async def test_state_access_is_clamped_for_a_long_policy_timeout(monkeypatch, handler):
    """A policy or flow timeout is not validated with the step: the state access
    is clamped to what the platform grants, and the step says so."""
    jobs = []

    async def fake_run_container_job(ctx, job):
        jobs.append(job)
        return HandlerResult(success=False, error="stopped before the container")

    monkeypatch.setattr(f"{handler.__module__}.run_container_job", fake_run_container_job)
    services = _Services(_plan_output(state="managed", state_name="core"))
    ctx = _ctx({"plan_step": "plan", "state_name": "core"}, services, timeout=90000)
    progress: list[str] = []

    async def emit(message, device_id=None, attrs=None):
        progress.append(message)
        return True

    ctx._emit_progress = emit
    await handler().execute(ctx)

    assert services.opened == [("core", 86400)]
    assert [job.config["timeout_seconds"] for job in jobs] == [90000]
    assert any("limited to 86400 s" in message for message in progress)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("config", "held"),
    [
        ({"state_name": "core"}, False),
        ({"state_name": "core", "hold_until_apply": True}, True),
        # Hidden (and ignored) without managed state: no hold, and no error either.
        ({"state": "ephemeral", "hold_until_apply": True}, False),
    ],
)
async def test_plan_step_holds_the_state_until_apply_only_when_asked(monkeypatch, config, held):
    services = _Services()
    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})

    result = await TfPlanHandler().execute(_ctx(config, services))

    assert result.success is True, result.error
    assert services.held == (["core"] if held else [])
    assert result.output["state_held"] is held


@pytest.mark.asyncio
async def test_a_hold_on_a_platform_that_predates_it_fails_with_the_reason(monkeypatch):
    state = _install_docker(monkeypatch, out={})

    class OldPlatform(_Services):
        @asynccontextmanager
        async def open_state_backend(self, name: str, *, ttl_seconds: int):  # type: ignore[override]
            yield None

    old = OldPlatform()
    result = await TfPlanHandler().execute(
        _ctx({"state_name": "core", "hold_until_apply": True}, old)
    )
    assert result.success is False
    assert result.error == HOLD_UNSUPPORTED_MESSAGE
    assert state["calls"] == []
    # Without the hold, the same platform works as before.
    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})
    old_result = await TfPlanHandler().execute(_ctx({"state_name": "core"}, _Services()))
    assert old_result.success is True, old_result.error


class _ReleasingServices(_Services):
    """A platform that can end a run's hold on a state early."""

    def __init__(self, *args: Any, released: bool = True, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.released = released
        self.releases: list[str] = []

    async def release_state_hold(self, name: str) -> bool:
        self.releases.append(name)
        return self.released


_HOLD = {"state_name": "core", "hold_until_apply": True}


@pytest.mark.asyncio
async def test_a_plan_without_changes_ends_its_hold(monkeypatch):
    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})
    services = _ReleasingServices()
    progress: list[str] = []

    async def emit(message, device_id=None, attrs=None):
        progress.append(message)
        return True

    ctx = _ctx(_HOLD, services)
    ctx._emit_progress = emit
    result = await TfPlanHandler().execute(ctx)

    assert result.success is True, result.error
    assert services.held == ["core"]
    assert services.releases == ["core"]
    assert result.output["state_held"] is False
    assert result.summary == "No changes: infrastructure matches the configuration"
    assert "Ended the run's hold on managed state 'core': there is nothing to apply" in progress


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("config", "code"),
    [
        # Changes: the apply ends the hold.
        (_HOLD, b"2"),
        # No hold taken, or no managed state to hold.
        ({"state_name": "core"}, b"0"),
        ({"state": "ephemeral", "hold_until_apply": True}, b"0"),
    ],
)
async def test_a_plan_ends_only_a_hold_no_apply_will_end(monkeypatch, config, code):
    _install_docker(monkeypatch, out={"plan-exitcode": code, "plan.txt": b"plan\n"})
    services = _ReleasingServices()
    result = await TfPlanHandler().execute(_ctx(config, services))
    assert result.success is True, result.error
    assert services.releases == []
    assert result.output["state_held"] is (config is _HOLD)


class _NoReleaseServices(_ReleasingServices):
    async def release_state_hold(self, name: str) -> bool:
        await super().release_state_hold(name)
        raise NotImplementedError


class _BrokenReleaseServices(_ReleasingServices):
    async def release_state_hold(self, name: str) -> bool:
        await super().release_state_hold(name)
        raise RuntimeError("platform API unreachable")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("services", "note"),
    [
        # Older than the method, or without support for it.
        (_Services(), HOLD_KEPT_NOTE),
        (_NoReleaseServices(), HOLD_KEPT_NOTE),
        # A host that ended no hold (it logs why), or failed to.
        (_ReleasingServices(released=False), HOLD_NOT_ENDED_NOTE),
        (_BrokenReleaseServices(), HOLD_NOT_ENDED_NOTE),
    ],
)
async def test_a_hold_that_cannot_be_ended_lasts_until_the_run_ends(monkeypatch, services, note):
    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})
    result = await TfPlanHandler().execute(_ctx(_HOLD, services))
    assert result.success is True, result.error
    assert result.summary == "No changes: infrastructure matches the configuration" + note
    assert result.output["summary"] == result.summary
    # The apply tries again.
    assert result.output["state_held"] is True
    assert getattr(services, "releases", None) == (
        None if type(services) is _Services else ["core"]
    )


@pytest.mark.asyncio
async def test_plan_step_reports_unavailable_managed_state(monkeypatch):
    state = _install_docker(monkeypatch, out={})
    services = _Services()
    services.state_error = "managed state is not available: no encryption key is configured"
    result = await TfPlanHandler().execute(_ctx({"state_name": "core"}, services))
    assert result.success is False
    assert "no encryption key" in (result.error or "")
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_plan_step_short_encryption_key_is_refused(monkeypatch):
    state = _install_docker(monkeypatch, out={})

    class ShortKey(_Services):
        async def resolve_secret_ref(self, ref, *, source):
            return "short"

    result = await TfPlanHandler().execute(
        _ctx({"state": "ephemeral", "state_encryption_key": "vault://k/enc"}, ShortKey())
    )
    assert result.success is False
    assert "at least 16 characters" in (result.error or "")
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_plan_step_records_its_image_by_digest(monkeypatch):
    image = DEFAULT_IMAGES["opentofu"]
    repository = image.rsplit(":", 1)[0]
    state = _install_docker(
        monkeypatch,
        out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"},
        repo_digests=[f"{repository}@sha256:{'a' * 64}"],
    )
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services()))

    assert result.success is True, result.error
    assert result.output["image"] == image
    assert result.output["image_digest"] == f"{repository}@sha256:{'a' * 64}"
    # The plan ran the very image it hands to the apply.
    create = next(call for call in state["calls"] if call[1] == "create")
    assert f"{repository}@sha256:{'a' * 64}" in create


@pytest.mark.asyncio
async def test_plan_hands_its_cache_choice_to_the_apply(monkeypatch):
    """The apply pulls the plan's image the way the plan did (on by default)."""
    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services()))
    assert result.success is True, result.error
    assert result.output["cache_image"] is True

    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})
    result = await TfPlanHandler().execute(
        _ctx({"state": "ephemeral", "cache_image": False}, _Services())
    )
    assert result.success is True, result.error
    assert result.output["cache_image"] is False


def test_apply_reads_the_cache_choice_and_defaults_it_for_older_plans():
    from hegemony_steps_tf.apply import read_plan_handoff

    handoff = read_plan_handoff("plan", _plan_output(cache_image=False)["plan"]["output"])
    assert not isinstance(handoff, str)
    assert handoff.cache_image is False
    older = read_plan_handoff("plan", _plan_output()["plan"]["output"])
    assert not isinstance(older, str)
    assert older.cache_image is True


def _plan_output(**overrides: Any) -> dict[str, Any]:
    output = {
        "handler": "tf.plan",
        "has_changes": True,
        "summary": "Plan: +1 ~0 -0",
        "state": "ephemeral",
        "state_name": "",
        "engine": "opentofu",
        "image": "ghcr.io/opentofu/opentofu:1.12.6",
        "working_dir": "/shared/tf/plan",
        "apply_ready": True,
        "plan_sha256": _PLAN_SHA256,
    }
    output.update(overrides)
    return {"plan": {"success": True, "output": output}}


@pytest.mark.asyncio
async def test_apply_step_applies_the_saved_plan(monkeypatch):
    outputs = json.dumps(
        {
            "svc": {"sensitive": False, "value": "telemetry"},
            "pw": {"sensitive": True, "value": "hunter2"},
        }
    ).encode()
    state = _install_docker(monkeypatch, out={"outputs.json": outputs})
    services = _Services(_plan_output())
    result = await TfApplyHandler().execute(
        _ctx({"plan_step": "plan", "secret_env": {"TOKEN": "vault://a/tok"}}, services)
    )

    assert result.success is True, result.error
    assert result.summary == "Applied: +1 ~0 -0"
    assert result.output == {
        "applied": True,
        "outputs": {"svc": "telemetry"},
        "sensitive_outputs": ["pw"],
    }
    assert "hunter2" not in json.dumps(result.output)
    create = next(call for call in state["calls"] if call[1] == "create")
    assert "ghcr.io/opentofu/opentofu:1.12.6" in create
    assert "hegemony.handler_id=tf.apply" in create
    assert "cd /shared/tf/plan" in state["roots"][RUN_SCRIPT]
    assert "\nbounded tofu apply" in state["roots"][RUN_SCRIPT]


@pytest.mark.asyncio
async def test_apply_step_runs_the_plan_image_by_digest(monkeypatch):
    pinned = f"ghcr.io/hegemony-sh/opentofu-runner@sha256:{'b' * 64}"
    state = _install_docker(monkeypatch, out={"outputs.json": b"{}"})
    services = _Services(
        _plan_output(image="ghcr.io/hegemony-sh/opentofu-runner:0.6", image_digest=pinned)
    )
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, services))

    assert result.success is True, result.error
    create = next(call for call in state["calls"] if call[1] == "create")
    assert pinned in create
    assert "ghcr.io/hegemony-sh/opentofu-runner:0.6" not in create
    assert result.metrics["image"] == pinned
    assert {"image_served", "image_source", "image_cached"} <= result.metrics.keys()
    # The apply does not look the digest up again.
    assert not any("{{json .RepoDigests}}" in call for call in state["calls"])


def _without(key: str) -> dict[str, Any]:
    outputs = _plan_output()
    del outputs["plan"]["output"][key]
    return outputs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outputs", "shared", "message"),
    [
        ({}, True, "has not completed successfully"),
        ({"plan": {"success": False, "output": {"engine": "opentofu"}}}, True, "has not completed"),
        # Each cause names the step to fix.
        (
            _plan_output(apply_ready=False, working_dir=LOCAL_WORKDIR),
            True,
            "plan step 'plan' ran without a shared workspace",
        ),
        (_plan_output(), False, "this apply step has no shared workspace"),
        # The output of any other step is refused, whatever it carries.
        (_without("handler"), True, "is not a tf.plan step"),
        (_plan_output(handler="container.run"), True, "is not a tf.plan step"),
        (_plan_output(engine="pulumi"), True, "unusable plan: engine"),
        (_without("image"), True, "unusable plan: image"),
        (_plan_output(image=""), True, "unusable plan: image"),
        (_without("has_changes"), True, "unusable plan: has_changes"),
        (_plan_output(state="cloud"), True, "unusable plan: state"),
        (_plan_output(working_dir="/shared/other"), True, "working directory '/shared/other'"),
        # A plan from before tf.plan recorded the saved plan's digest.
        (_without("plan_sha256"), True, "older version of tf.plan, which did not record"),
        (_plan_output(plan_sha256="abc"), True, "unusable plan: plan_sha256"),
        (_plan_output(plan_sha256="$(id)" + "a" * 59), True, "unusable plan: plan_sha256"),
    ],
)
async def test_apply_step_refusals(monkeypatch, outputs, shared, message):
    state = _install_docker(monkeypatch, out={})
    result = await TfApplyHandler().execute(
        _ctx({"plan_step": "plan"}, _Services(outputs), shared=shared)
    )
    assert result.success is False
    assert message in (result.error or "")
    assert state["exec"] == 0


@pytest.mark.asyncio
async def test_apply_summary_leaves_out_the_plan_collection_note(monkeypatch):
    _install_docker(monkeypatch, out={"outputs.json": b"{}"})
    services = _Services(_plan_output(summary="Plan: +1 ~0 -0" + PLAN_TEXT_MISSING_NOTE))
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, services))
    assert result.summary == "Applied: +1 ~0 -0"


@pytest.mark.asyncio
async def test_apply_step_passes_the_state_encryption_key(monkeypatch):
    state = _install_docker(monkeypatch, out={"outputs.json": b"{}"})
    config = {"plan_step": "plan", "state_encryption_key": "vault://orgs/acme/secrets/enc"}
    result = await TfApplyHandler().execute(_ctx(config, _Services(_plan_output())))
    assert result.success is True, result.error
    env = state["roots"][SECRET_ENV_FILE]
    assert "TF_ENCRYPTION=" in env
    assert "resolved-enc-long-enough" in env
    create = next(call for call in state["calls"] if call[1] == "create")
    assert not any("resolved-" in part for part in create)


@pytest.mark.asyncio
async def test_apply_step_short_encryption_key_is_refused(monkeypatch):
    state = _install_docker(monkeypatch, out={})

    class ShortKey(_Services):
        async def resolve_secret_ref(self, ref, *, source):
            return "short"

    config = {"plan_step": "plan", "state_encryption_key": "vault://k/enc"}
    result = await TfApplyHandler().execute(_ctx(config, ShortKey(_plan_output())))
    assert result.success is False
    assert "at least 16 characters" in (result.error or "")
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_apply_step_reopens_managed_state(monkeypatch):
    services = _Services(_plan_output(state="managed", state_name="core"))
    state = _install_docker(monkeypatch, out={"outputs.json": b"{}"}, events=services.events)
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, services))

    assert result.success is True, result.error
    assert [name for name, _ttl in services.opened] == ["core"]
    assert services.closed == ["core"]
    assert services.events == [("open", "core"), "stage", "start", ("close", "core")]
    assert "export TF_HTTP_PASSWORD=hgm_run_token-value" in state["roots"][SECRET_ENV_FILE]
    create = next(call for call in state["calls"] if call[1] == "create")
    assert "--add-host" in create


@pytest.mark.asyncio
async def test_apply_step_refuses_managed_state_without_a_name(monkeypatch):
    state = _install_docker(monkeypatch, out={})
    services = _Services(_plan_output(state="managed"))
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, services))
    assert result.success is False
    assert "no name" in (result.error or "")
    assert state["exec"] == 0


@pytest.mark.asyncio
async def test_apply_step_skips_a_plan_without_changes(monkeypatch):
    state = _install_docker(monkeypatch, out={})
    plan = _plan_output(
        has_changes=False, outputs={"vpc_id": "vpc-1"}, sensitive_outputs=["db_password"]
    )
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, _Services(plan)))
    assert result.success is True
    # A flow reading steps.apply.output.outputs works on every run, not only
    # on the one that changed something.
    assert result.output == {
        "applied": False,
        "outputs": {"vpc_id": "vpc-1"},
        "sensitive_outputs": ["db_password"],
    }
    assert state["calls"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("plan", "releases"),
    [
        (
            _plan_output(has_changes=False, state="managed", state_name="core", state_held=True),
            ["core"],
        ),
        (_plan_output(has_changes=False, state="managed", state_name="core"), []),
        (_plan_output(has_changes=False, state="managed", state_name="core", state_held=False), []),
        (_plan_output(has_changes=False, state_held=True), []),
    ],
)
async def test_apply_without_changes_ends_a_hold_the_plan_kept(monkeypatch, plan, releases):
    state = _install_docker(monkeypatch, out={})
    services = _ReleasingServices(plan)
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, services))
    assert result.success is True, result.error
    assert result.summary == "Nothing to apply: the plan has no changes"
    assert services.releases == releases
    assert services.opened == []
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_apply_without_changes_succeeds_when_the_hold_cannot_be_ended(monkeypatch):
    _install_docker(monkeypatch, out={})
    plan = _plan_output(has_changes=False, state="managed", state_name="core", state_held=True)
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, _NoReleaseServices(plan)))
    assert result.success is True, result.error
    assert result.summary == "Nothing to apply: the plan has no changes" + HOLD_KEPT_NOTE


@pytest.mark.asyncio
async def test_apply_step_checks_the_plan_against_its_digest(monkeypatch):
    digest = "e" * 64
    state = _install_docker(monkeypatch, out={}, exit_code=EXIT_PLAN_CHANGED)
    services = _Services(_plan_output(plan_sha256=digest))
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, services))
    assert f"printf '%s  %s\\n' {digest} {APPLIED_PLAN_FILE}" in state["roots"][RUN_SCRIPT]
    assert result.success is False
    assert result.summary == "tofu apply failed"
    assert result.error == PLAN_CHANGED_MESSAGE


@pytest.mark.asyncio
async def test_apply_failure_names_no_cause_it_cannot_see(monkeypatch):
    """A generic failure no longer blames a stale plan."""
    _install_docker(monkeypatch, out={}, exit_code=1)
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, _Services(_plan_output())))
    assert result.success is False
    assert result.error == "tofu apply exited with code 1; see the container output"


def _job_result(exit_code: int, *, errored: bytes | None = None, stderr: str = "") -> Any:
    collected = {ERRORED_STATE_FILE: errored} if errored is not None else {}
    return ContainerJobResult(
        exit_code=exit_code,
        stdout="",
        stderr=stderr,
        truncated=False,
        duration_seconds=1.0,
        image="img",
        evidence=[],
        skipped_artifacts=0,
        collected=collected,
    )


def test_a_failed_copy_out_is_named_instead_of_a_missing_file():
    """The runner reports a collect root it could not copy; the tf steps say so
    rather than blame the step for not writing the file."""
    failed = ContainerJobResult(
        exit_code=0,
        stdout="",
        stderr="",
        truncated=False,
        duration_seconds=1.0,
        image="img",
        evidence=[],
        skipped_artifacts=0,
        collected={},
        collect_errors={"/hegemony/out": "docker cp timed out"},
    )
    assert collect_failure(failed, "/hegemony/out/outputs.json") == "docker cp timed out"
    assert collect_failure(_job_result(0), "/hegemony/out/outputs.json") is None

    applied = TfApplyHandler()._result("opentofu", "img", _plan_output()["plan"]["output"], failed)
    assert applied.success is True
    assert "could not be copied out of the container: docker cp timed out" in (
        applied.summary or ""
    )

    plan = TfPlanHandler()._result(
        _ctx({"state": "ephemeral"}, _Services()),
        TfPlanConfig.model_validate({"state": "ephemeral"}),
        "img",
        LOCAL_WORKDIR,
        failed,
    )
    assert plan.success is False
    assert "the copy out of the container failed (docker cp timed out)" in (plan.error or "")


_LOCKED = """
Error: Error acquiring the state lock

Error message: HTTP remote state already locked: ID=5c0e
Lock Info:
  ID:        5c0e
  Path:      
  Operation: OperationTypeApply
  Who:       root@9c1f2a3b4c5d
  Version:   1.12.6
  Created:   2026-09-28 10:00:00 +0000 UTC
  Info:      held by run:run-1/apply since 2026-09-28 10:00:00Z

OpenTofu acquires a state lock to protect the state from being written
by multiple users at the same time.
"""


def test_a_lock_conflict_names_the_holder():
    error = lock_conflict_error("tofu", "5m", "", _LOCKED)
    assert error == (
        "tofu could not acquire the state lock within 5m; it is held by "
        "Info: held by run:run-1/apply since 2026-09-28 10:00:00Z, Who: root@9c1f2a3b4c5d; "
        "see the container output"
    )
    # An empty Info line (a laptop's lock) is not a holder.
    laptop = _LOCKED.replace("held by run:run-1/apply since 2026-09-28 10:00:00Z", "")
    assert "held by Who: root@9c1f2a3b4c5d;" in (
        lock_conflict_error("tofu", "5m", laptop, "") or ""
    )
    assert lock_conflict_error("tofu", "5m", "Error: Invalid reference", "") is None


def test_a_plan_that_cannot_take_the_lock_says_who_holds_it():
    config = TfPlanConfig.model_validate({"state_name": "core", "lock_timeout": "60s"})
    result = TfPlanHandler()._result(
        _ctx({}, _Services()), config, "img", "/shared/tf/plan", _job_result(1, stderr=_LOCKED)
    )
    assert result.success is False
    assert (result.error or "").startswith("tofu could not acquire the state lock within 60s")
    assert "run:run-1/apply" in (result.error or "")


@pytest.mark.parametrize(
    ("result", "expected"),
    [
        (_job_result(EXIT_NO_PLAN), NO_PLAN_MESSAGE),
        (_job_result(1, stderr=_LOCKED), "it is held by Info: held by run:run-1/apply"),
        (_job_result(1, errored=b"kept"), "kept as the run artifact errored.tfstate.gz"),
        (_job_result(1, errored=b"recovered"), "saved it to managed state 'core' afterwards"),
        (_job_result(1, stderr="Error: Saved plan is stale\n"), "state changed since it was made"),
        (_job_result(1), "exited with code 1"),
    ],
)
def test_apply_failure_says_what_happened_to_the_state(result, expected):
    assert expected in apply_failure("tofu", result, "core")


@pytest.mark.asyncio
async def test_apply_keeps_an_unsaved_state_as_an_artifact(monkeypatch):
    state = _install_docker(monkeypatch, out={"errored-state": b"kept"}, exit_code=1)
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, _Services(_plan_output())))
    assert result.success is False
    assert "errored.tfstate.gz" in (result.error or "")
    # The runner harvests the kept state from this folder after the container exits.
    assert any(f"{KEEP_DIR}/." in " ".join(call) for call in state["calls"] if call[1] == "cp")


@pytest.mark.asyncio
async def test_apply_succeeds_when_only_its_outputs_cannot_be_read(monkeypatch):
    _install_docker(monkeypatch, out={}, exit_code=0)
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, _Services(_plan_output())))
    assert result.success is True
    assert result.output["applied"] is True
    assert result.output["outputs"] == {}
    assert "outputs could not be read" in (result.summary or "")


def _run_apply_script(
    tmp_path, *, apply_code: int, push_fails: int, output_code: int = 0, plan: str = "plan"
):
    """Run the generated apply script under sh with a fake tool and no real waits.

    The saved plan holds ``plan``; the script checks it against the digest of
    "plan". The tool writes the plan file it applies to ``applied``.
    """
    root = tmp_path / "root"
    workdir = root / "shared" / "tf" / "plan"
    workdir.mkdir(parents=True)
    (workdir / "plan.tfplan").write_text(plan)
    (root / "hegemony" / "tf").mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    pushes = tmp_path / "pushes"
    applied = tmp_path / "applied"
    tool = bin_dir / "tofu"
    tool.write_text(
        f"""#!/bin/sh
case "$1" in
  apply)
    for arg; do last=$arg; done; echo "$last" > {applied}
    if [ {apply_code} -ne 0 ]; then echo '{{"serial": 7}}' > errored.tfstate; fi
    exit {apply_code} ;;
  state)
    n=$(cat {pushes} 2>/dev/null || echo 0); n=$((n + 1)); echo $n > {pushes}
    if [ $n -le {push_fails} ]; then exit 1; fi
    exit 0 ;;
  output)
    echo '{{}}'; exit {output_code} ;;
esac
"""
    )
    (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
    for path in (tool, bin_dir / "sleep"):
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    script = build_apply_script(
        "opentofu", "/shared/tf/plan", "300s", _PLAN_SHA256, deadline=int(time.time()) + 600
    )
    for prefix in ("/hegemony/", "/shared/"):
        script = script.replace(prefix, f"{root}{prefix}")
    (tmp_path / "run.sh").write_text(script)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    done = subprocess.run(["sh", str(tmp_path / "run.sh")], env=env, capture_output=True, text=True)
    out = root / "hegemony" / "out"
    return done, out, root / KEEP_DIR.lstrip("/"), pushes


def test_apply_script_applies_a_private_copy_of_the_plan(tmp_path):
    done, _out, _keep, _pushes = _run_apply_script(tmp_path, apply_code=0, push_fails=0)
    assert done.returncode == 0, done.stderr
    private = tmp_path / "root" / APPLIED_PLAN_FILE.lstrip("/")
    assert (tmp_path / "applied").read_text().strip() == str(private)
    assert private.read_text() == "plan"


def test_apply_script_refuses_a_plan_that_changed(tmp_path):
    done, _out, _keep, _pushes = _run_apply_script(
        tmp_path, apply_code=0, push_fails=0, plan="plan with a resource added"
    )
    assert done.returncode == EXIT_PLAN_CHANGED
    assert PLAN_CHANGED_MESSAGE in done.stderr
    assert not (tmp_path / "applied").exists()


@pytest.mark.parametrize("output_code", [0, 1])
def test_plan_script_does_not_fail_on_its_outputs(tmp_path, output_code):
    """Run the generated plan script under sh with a fake tool: the outputs are
    written when the tool can read them, and their failure never fails the plan."""
    root = tmp_path / "root"
    (root / "attachments").mkdir(parents=True)
    (root / "attachments" / "main.tf").write_text("")
    (root / "hegemony" / "tf").mkdir(parents=True)
    (root / "hegemony" / "tf" / "zz_hegemony_backend_override.tf").write_text("")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    tool = bin_dir / "tofu"
    tool.write_text(
        f"""#!/bin/sh
case "$1" in
  plan) for arg; do case "$arg" in -out=*) out="${{arg#-out=}}" ;; esac; done
        echo plan > "$out"; exit 2 ;;
  show) for arg; do last="$arg"; done; cat "$last" ;;
  output) echo '{{"a": {{"value": 1}}}}'; exit {output_code} ;;
esac
"""
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    config = TfPlanConfig.model_validate({"state": "ephemeral"})
    script = build_plan_script(
        config,
        workdir="/shared/tf/plan",
        has_vars=False,
        has_secret_vars=False,
        deadline=int(time.time()) + 600,
    )
    for prefix in ("/hegemony/", "/shared/", "/attachments"):
        script = script.replace(prefix, f"{root}{prefix}")
    (tmp_path / "run.sh").write_text(script)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    done = subprocess.run(["sh", str(tmp_path / "run.sh")], env=env, capture_output=True, text=True)

    assert done.returncode == 0, done.stderr
    assert (root / "hegemony" / "out" / "plan-exitcode").read_text() == "2"
    digest = hashlib.sha256(b"plan\n").hexdigest()
    snapshot = root / PLAN_SNAPSHOT_FILE.lstrip("/")
    assert (root / PLAN_SHA256_FILE.lstrip("/")).read_text() == f"{digest}  {snapshot}\n"
    # The shared copy for tf.apply, and a readable plan of the same file.
    assert (root / "shared" / "tf" / "plan" / "plan.tfplan").read_text() == "plan\n"
    assert (root / PLAN_TEXT_FILE.lstrip("/")).read_text() == "plan\n"
    outputs = root / PLAN_OUTPUTS_FILE.lstrip("/")
    assert outputs.exists() is (output_code == 0)


def test_apply_script_saves_the_errored_state_again(tmp_path):
    done, out, keep, pushes = _run_apply_script(tmp_path, apply_code=1, push_fails=1)
    assert done.returncode == 1, done.stderr
    assert (out / "errored-state").read_text() == "recovered"
    assert pushes.read_text().strip() == "2"
    assert not (keep / "errored.tfstate.gz").exists()


def test_apply_script_keeps_the_errored_state_when_it_cannot_be_saved(tmp_path):
    done, out, keep, pushes = _run_apply_script(tmp_path, apply_code=1, push_fails=99)
    assert done.returncode == 1, done.stderr
    assert (out / "errored-state").read_text() == "kept"
    assert pushes.read_text().strip() == "3"
    import gzip

    assert json.loads(gzip.decompress((keep / "errored.tfstate.gz").read_bytes())) == {"serial": 7}


def test_apply_script_ignores_a_failed_outputs_read(tmp_path):
    done, out, _keep, _pushes = _run_apply_script(
        tmp_path, apply_code=0, push_fails=0, output_code=1
    )
    assert done.returncode == 0, done.stderr
    assert not (out / OUTPUTS_FILE.rsplit("/", 1)[-1]).exists()


def test_apply_script_refuses_a_missing_plan(tmp_path):
    done, out, _keep, _pushes = _run_apply_script(tmp_path, apply_code=0, push_fails=0)
    assert done.returncode == 0
    (tmp_path / "root" / "shared" / "tf" / "plan" / "plan.tfplan").unlink()
    env = {**os.environ, "PATH": f"{tmp_path / 'bin'}:{os.environ['PATH']}"}
    again = subprocess.run(
        ["sh", str(tmp_path / "run.sh")], env=env, capture_output=True, text=True
    )
    assert again.returncode == EXIT_NO_PLAN
    assert "saved plan is gone" in again.stderr


@pytest.mark.parametrize(
    ("step_id", "expected"),
    [
        (".", "/shared/tf/_."),
        ("..", "/shared/tf/_.."),
        ("", "/shared/tf/plan"),
        ("a/b", "/shared/tf/a_b"),
        ("plan.v2", "/shared/tf/plan.v2"),
    ],
)
def test_workdir_never_names_the_shared_root(step_id, expected):
    assert workdir_for(step_id) == expected


def test_handler_metadata():
    for handler in (TfPlanHandler, TfApplyHandler):
        assert handler.container_backed is True
        assert handler.platform_api_access is True
        # Refused in parallel loop bodies: state is keyed by node id.
        assert handler.node_scoped_state is True
        assert handler.targeting.roles is False
    assert TfPlanHandler.handler_id == "tf.plan"
    assert TfApplyHandler.handler_id == "tf.apply"
    # Secret fields reach the handler as written, so a secret whose value looks
    # like a reference is never resolved twice.
    assert TfPlanHandler.raw_config_keys == {"secret_vars", "secret_env", "state_encryption_key"}
    assert TfApplyHandler.raw_config_keys == {"secret_env", "state_encryption_key"}


@pytest.mark.parametrize(
    ("value", "normal"), [(None, "300s"), ("", "300s"), ("  ", "300s"), (" 5m ", "5m")]
)
def test_lock_timeout_blank_is_the_default_and_spaces_do_not_count(value, normal):
    """Validation and the scripts read the value the same way."""
    assert lock_timeout_errors(value) == []
    config = TfPlanConfig.model_validate({"state": "ephemeral", "lock_timeout": value})
    assert config.lock_timeout == normal
    script = build_plan_script(config, workdir=LOCAL_WORKDIR, has_vars=False, has_secret_vars=False)
    assert f"-lock-timeout={normal} " in script


@pytest.mark.parametrize("value", ["s", "5 m", "300", "5h", "-5m"])
def test_a_malformed_lock_timeout_is_refused(value):
    assert lock_timeout_errors(value) == ["'lock_timeout' must look like 300s or 5m"]
