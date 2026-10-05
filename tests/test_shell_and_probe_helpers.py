# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for shell command composition and probe helpers."""

import pytest

from hegemony_steps_probe.dns_check import normalize_answer
from hegemony_steps_probe.http_check import parse_status_spec, status_matches
from hegemony_steps_shell.execute import ShellExecuteHandler, build_command


def test_build_command_default_passthrough():
    assert build_command("uname -a") == "uname -a"


def test_build_command_default_exports_quoted_env():
    composed = build_command("cd /tmp && echo $APP", env={"APP": "a b", "B": "1"})
    assert composed == "export APP='a b' B=1; cd /tmp && echo $APP"


def test_build_command_sh_family_keeps_env_prefix():
    composed = build_command("echo $APP", shell="sh", env={"APP": "a b"})
    assert composed == "env APP='a b' sh -c 'echo $APP'"


@pytest.mark.parametrize(
    "command",
    [
        "uname -a",
        "systemctl restart {{ inputs.service | quote }}",
        "echo {{- inputs.msg|quote -}} done",
        "{% if inputs.force %}rm -f /tmp/x{% endif %}",
        "cp {{ inputs.src | quote }} {{ inputs.dst | quote }}",
    ],
)
def test_template_errors_accepts_quoted_values(command):
    assert ShellExecuteHandler().template_errors({"commands": [command]}) == []


@pytest.mark.parametrize(
    "command",
    [
        "systemctl restart {{ inputs.service }}",
        "echo {{ inputs.msg | quote | upper }}",
        "cp {{ inputs.src | quote }} {{ inputs.dst }}",
        "ping -c1 {{ device.mgmt_host }}",
    ],
)
def test_template_errors_refuses_unquoted_values(command):
    errors = ShellExecuteHandler().template_errors({"commands": ["uname -a", command]})
    assert len(errors) == 1
    assert errors[0].startswith("commands line 2:")
    # Names the line, never echoes the template (it is stored with the result).
    assert "inputs." not in errors[0].replace("inputs.name", "")


def test_template_errors_ignores_non_list_commands():
    assert ShellExecuteHandler().template_errors({"commands": "echo {{ x }}"}) == []
    assert ShellExecuteHandler().template_errors({}) == []


def test_build_command_bash_wraps_and_quotes():
    composed = build_command("echo 'x y'", shell="bash")
    assert composed == "bash -c 'echo '\"'\"'x y'\"'\"''"


def test_build_command_pwsh_wraps():
    composed = build_command("Get-Service nginx", shell="pwsh")
    assert composed == "pwsh -NoProfile -Command 'Get-Service nginx'"


def test_build_command_pwsh_rejects_env():
    with pytest.raises(ValueError, match="pwsh"):
        build_command("Get-Date", shell="pwsh", env={"A": "1"})


def test_build_command_rejects_unknown_shell():
    with pytest.raises(ValueError, match="unsupported"):
        build_command("ls", shell="zsh")


async def test_shell_execute_rejects_pwsh_env_combo():
    from hegemony_step_sdk import HandlerContext

    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"commands": ["Get-Date"], "shell": "pwsh", "env": {"A": "1"}},
        target_roles=["primary"],
        target_devices_by_role={"primary": [{"id": "d1", "name": "h1", "mgmt_host": "192.0.2.1"}]},
        # services intentionally unbound: the config error returns first
    )
    result = await ShellExecuteHandler().execute(ctx)
    assert result.success is False
    assert "pwsh" in (result.error or "")


def test_parse_status_spec_ranges_and_codes():
    ranges = parse_status_spec("200-299,301,404")
    assert status_matches(204, ranges)
    assert status_matches(301, ranges)
    assert status_matches(404, ranges)
    assert not status_matches(500, ranges)


@pytest.mark.parametrize("bad", ["", "abc", "700", "300-200"])
def test_parse_status_spec_rejects_bad_entries(bad):
    with pytest.raises(ValueError):
        parse_status_spec(bad)


def test_normalize_answer():
    assert normalize_answer('"MX.Example.COM."') == "mx.example.com"
