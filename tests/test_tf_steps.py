# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""tf.plan and tf.apply: plan summaries, generated scripts, and step results."""

from __future__ import annotations

import json
import os
import tempfile
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from hegemony_step_sdk import ContainerRuntime, HandlerContext, HandlerServices
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_tf.apply import TfApplyHandler, build_apply_script, public_outputs
from hegemony_steps_tf.common import (
    BACKEND_CONFIG_FILE,
    BACKEND_OVERRIDE_FILE,
    DEFAULT_IMAGES,
    RUN_SCRIPT,
    SECRET_ENV_FILE,
    SECRET_VARS_FILE,
    VARS_FILE,
    encryption_hcl,
    hcl_string,
    typed_variable,
)
from hegemony_steps_tf.plan import (
    EXIT_NO_BACKEND,
    LOCAL_WORKDIR,
    TfPlanConfig,
    TfPlanHandler,
    build_plan_script,
)
from hegemony_steps_tf.summary import plan_line, summarize_plan

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


# ── scripts ──────────────────────────────────────────────────────────────────


def test_plan_script_for_backend_state():
    config = TfPlanConfig.model_validate(
        {
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
    assert f"exit {EXIT_NO_BACKEND}" in script
    assert BACKEND_OVERRIDE_FILE not in script
    plan = next(line for line in script.splitlines() if line.startswith("tofu plan"))
    for part in (
        "-detailed-exitcode",
        "-out=plan.tfplan",
        "-target=aws_vpc.main",
        "-replace=aws_instance.web",
        "-var-file=/attachments/terraform/prod.tfvars",
        f"-var-file={VARS_FILE}",
        f"-var-file={SECRET_VARS_FILE}",
    ):
        assert part in plan
    assert "tofu show -json plan.tfplan > /hegemony/out/plan.json" in script
    assert f". {SECRET_ENV_FILE}" in script


def test_plan_script_for_ephemeral_state_and_terraform():
    config = TfPlanConfig.model_validate({"engine": "terraform", "state": "ephemeral"})
    script = build_plan_script(config, workdir=LOCAL_WORKDIR, has_vars=False, has_secret_vars=False)
    assert f"cp {BACKEND_OVERRIDE_FILE} {LOCAL_WORKDIR}/" in script
    assert "terraform init -input=false -no-color\n" in script
    assert ".terraform/terraform.tfstate" not in script
    assert "-var-file" not in script


def test_apply_script():
    script = build_apply_script("opentofu", "/shared/tf/plan", "5m")
    assert "cd /shared/tf/plan" in script
    assert "tofu apply -input=false -no-color -lock-timeout=5m plan.tfplan" in script
    assert "tofu output -json > /hegemony/out/outputs.json" in script


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
        ({"targets": ["a b"]}, "one resource address"),
        ({"destroy": True, "refresh_only": True}, "cannot be combined"),
        ({"engine": "terraform", "state_encryption_key": "vault://k/x"}, "opentofu engine"),
        ({"lock_timeout": "soon"}, "lock_timeout"),
        ({"image": "/tmp/x"}, "Invalid image reference"),
        ({"state": "managed"}, "state"),
    ],
)
def test_plan_validation_rejects(config, message):
    errors = TfPlanHandler().validate_config(config)
    assert any(message in error for error in errors), errors


def test_plan_validation_accepts_defaults():
    assert TfPlanHandler().validate_config({}) == []
    assert TfApplyHandler().validate_config({"plan_step": "plan"}) == []


# ── end to end ───────────────────────────────────────────────────────────────


class _Services:
    def __init__(self, step_outputs: dict[str, Any] | None = None) -> None:
        self.step_outputs = step_outputs or {}
        self.shared_root = tempfile.mkdtemp(prefix="hegemony-tf-test-")

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=True,
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


def _install_docker(monkeypatch, *, out: dict[str, bytes], exit_code: int = 0) -> dict[str, Any]:
    state: dict[str, Any] = {"roots": {}, "calls": [], "exec": 0}
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("off")),
    )

    def fake_run(cmd, *args, **kwargs):
        state["calls"].append(list(cmd))
        if len(cmd) >= 4 and cmd[1] == "cp":
            src, dest = cmd[2], cmd[3]
            if dest.endswith(":/"):
                root = src[: -len("/.")]
                for walk_root, _dirs, files in os.walk(root):
                    for name in files:
                        path = os.path.join(walk_root, name)
                        with open(path, encoding="utf-8") as fh:
                            state["roots"]["/" + os.path.relpath(path, root)] = fh.read()
            elif src.endswith(":/hegemony/out/."):
                for name, data in out.items():
                    with open(os.path.join(dest, name), "wb") as fh:
                        fh.write(data)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    async def fake_exec(*argv, **kwargs):
        state["exec"] += 1
        proc = AsyncMock()
        proc.stdout = AsyncMock()
        proc.stdout.readline = AsyncMock(return_value=b"")
        proc.stderr = AsyncMock()
        proc.stderr.readline = AsyncMock(return_value=b"")
        proc.wait = AsyncMock(return_value=exit_code)
        proc.kill = AsyncMock()
        return proc

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    return state


def _ctx(config: dict[str, Any], services: _Services, *, shared: bool = True) -> HandlerContext:
    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="plan",
        config=config,
        shared_workspace=shared,
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
            "plan.json": _PLAN_JSON,
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
    assert result.output["apply_ready"] is True
    assert result.output["working_dir"] == "/shared/tf/plan"
    assert result.output["image"] == DEFAULT_IMAGES["opentofu"]
    assert result.output["resource_changes"] == [
        {"address": "terraform_data.svc", "actions": ["create"]}
    ]
    assert "planned-secret-value" not in json.dumps(result.output)
    plan_artifact = next(e for e in result.evidence if e["name"] == "plan_plan.txt")
    assert "1 to add" in plan_artifact["content_text"]

    roots = state["roots"]
    assert json.loads(roots[VARS_FILE]) == {"routers": ["r1", "r2"]}
    assert json.loads(roots[SECRET_VARS_FILE]) == {"token": "resolved-tok-long-enough"}
    assert "export AWS_SECRET_ACCESS_KEY=resolved-aws-long-enough" in roots[SECRET_ENV_FILE]
    assert "TF_ENCRYPTION=" in roots[SECRET_ENV_FILE]
    assert 'backend "local"' in roots[BACKEND_OVERRIDE_FILE]
    create = next(call for call in state["calls"] if call[1] == "create")
    assert "hegemony.handler_id=tf.plan" in create
    assert not any("resolved-" in part for part in create)
    assert "TF_IN_AUTOMATION=1" in create
    assert f"sh {RUN_SCRIPT}" in create[-1]


@pytest.mark.asyncio
async def test_plan_step_without_shared_workspace_is_plan_only(monkeypatch):
    _install_docker(monkeypatch, out={"plan-exitcode": b"0", "plan.txt": b"No changes.\n"})
    result = await TfPlanHandler().execute(_ctx({"state": "ephemeral"}, _Services(), shared=False))
    assert result.success is True
    assert result.output["has_changes"] is False
    assert result.output["apply_ready"] is False
    assert result.output["working_dir"] == LOCAL_WORKDIR
    assert result.summary == "No changes: infrastructure matches the configuration"


@pytest.mark.asyncio
async def test_plan_step_without_backend_block_fails(monkeypatch):
    _install_docker(monkeypatch, out={}, exit_code=EXIT_NO_BACKEND)
    result = await TfPlanHandler().execute(_ctx({}, _Services()))
    assert result.success is False
    assert "no backend block" in (result.error or "")


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


def _plan_output(**overrides: Any) -> dict[str, Any]:
    output = {
        "has_changes": True,
        "summary": "Plan: +1 ~0 -0",
        "engine": "opentofu",
        "image": "ghcr.io/opentofu/opentofu:1.12.6",
        "working_dir": "/shared/tf/plan",
        "apply_ready": True,
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outputs", "shared", "message"),
    [
        ({}, True, "has not completed successfully"),
        ({"plan": {"success": False, "output": {"engine": "opentofu"}}}, True, "has not completed"),
        (_plan_output(apply_ready=False), True, "shared (or explicit)"),
        (_plan_output(), False, "shared (or explicit)"),
        (_plan_output(engine="pulumi"), True, "unknown engine"),
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
async def test_apply_step_skips_a_plan_without_changes(monkeypatch):
    state = _install_docker(monkeypatch, out={})
    result = await TfApplyHandler().execute(
        _ctx({"plan_step": "plan"}, _Services(_plan_output(has_changes=False)))
    )
    assert result.success is True
    assert result.output["applied"] is False
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_apply_failure_mentions_stale_plans(monkeypatch):
    _install_docker(monkeypatch, out={}, exit_code=1)
    result = await TfApplyHandler().execute(_ctx({"plan_step": "plan"}, _Services(_plan_output())))
    assert result.success is False
    assert "stale plan" in (result.error or "")


def test_handler_metadata():
    for handler in (TfPlanHandler, TfApplyHandler):
        assert handler.container_backed is True
        assert handler.targeting.roles is False
    assert TfPlanHandler.handler_id == "tf.plan"
    assert TfApplyHandler.handler_id == "tf.apply"
