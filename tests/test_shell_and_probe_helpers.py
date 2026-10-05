# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Unit tests for shell command composition and probe helpers."""

import shlex
import shutil
import subprocess

import jinja2
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


ACCEPTED = [
    "uname -a",
    "systemctl restart {{ inputs.service | quote }}",
    "echo {{- inputs.msg|quote -}} done",
    "{% if inputs.force %}rm -f /tmp/x{% endif %}",
    "cp {{ inputs.src | quote }} {{ inputs.dst | quote }}",
    "X={{ inputs.v | quote }} env",
    "echo $(printf '%s' {{ inputs.v | quote }})",
    "echo 'plain' {{ inputs.v | quote }} \"also plain\"",
    "cat <<EOF > {{ inputs.path | quote }}\nbody\nEOF",
    "cat <<'EOF'\nbody $x\nEOF\necho {{ inputs.v | quote }}",
    "{% for h in inputs.hosts %}ping -c1 {{ h | quote }}; {% endfor %}",
    "{% raw %}{{ not a template }}{% endraw %}",
]


@pytest.mark.parametrize("command", ACCEPTED)
def test_template_errors_accepts_quoted_unquoted_position_values(command):
    assert ShellExecuteHandler().template_errors({"commands": [command]}) == []


@pytest.mark.parametrize(
    "command",
    [
        "systemctl restart {{ inputs.service }}",
        "echo {{ inputs.msg | quote | upper }}",
        "cp {{ inputs.src | quote }} {{ inputs.dst }}",
        "ping -c1 {{ device.mgmt_host }}",
        # `| quote` inside a Jinja string does not quote the value next to it,
        # and filters bind tighter than `~`.
        'echo {{ "| quote }}" ~ inputs.msg }}',
        'echo {{ inputs.msg ~ "" | quote }}',
        "{{ 'constant' }}",
        "{{ inputs.msg | quote(1) }}",
    ],
)
def test_template_errors_refuses_values_not_ending_in_quote(command):
    errors = ShellExecuteHandler().template_errors({"commands": ["uname -a", command]})
    assert len(errors) == 1
    assert errors[0].startswith("commands line 2: a {{ }} value must end with | quote")


@pytest.mark.parametrize(
    "command",
    [
        # Inside quotes a quoted value can close them: "'"; id; #'" runs id.
        'echo "{{ inputs.msg | quote }}"',
        "echo '{{ inputs.msg | quote }}'",
        "echo $'{{ inputs.msg | quote }}'",
        # In a comment or an unquoted here-document a newline or $(...) runs.
        "# note {{ inputs.msg | quote }}",
        "echo hi # {{ inputs.msg | quote }}",
        "cat <<EOF\n{{ inputs.msg | quote }}\nEOF",
        "cat <<{{ inputs.msg | quote }}",
        "echo `cat {{ inputs.path | quote }}`",
        # An escape or a $ in front of the opening quote changes its meaning.
        "echo \\{{ inputs.msg | quote }}",
        "echo ${{ inputs.msg | quote }}",
        # Statements inside quotes, or branches that change the quoting.
        'echo "{% if inputs.a %}y{% endif %}"',
        "{% if inputs.a %}'{% endif %}{{ inputs.msg | quote }}",
        'echo "$(echo ")") {{ inputs.msg | quote }}"',
    ],
)
def test_template_errors_refuses_values_inside_quotes_comments_or_heredocs(command):
    errors = ShellExecuteHandler().template_errors({"commands": [command]})
    assert len(errors) == 1
    assert errors[0].startswith("commands line 1: a {{ }} value and every {% %} statement")


@pytest.mark.parametrize(
    "command",
    [
        '{% filter replace("\'", "") %}{{ inputs.msg | quote }}{% endfilter %}',
        '{% include "other" %}',
        "{% macro m() %}x{% endmacro %}{{ m() | quote }}",
    ],
)
def test_template_errors_refuses_statements_it_cannot_follow(command):
    errors = ShellExecuteHandler().template_errors({"commands": [command]})
    assert len(errors) == 1
    assert "not supported" in errors[0]


def test_template_errors_refuses_a_broken_template_without_quoting_it():
    errors = ShellExecuteHandler().template_errors({"commands": ["echo {{ inputs.x | quote"]})
    assert errors == ["commands line 1: is not a valid template"]


HOSTILE = [
    '"; touch {sentinel}; #',
    "'; touch {sentinel}; '",
    "$(touch {sentinel})",
    "`touch {sentinel}`",
    "a b\nc; touch {sentinel}",
    "trailing \\",
]


def _shells() -> list[str]:
    return [shell for shell in ("sh", "bash") if shutil.which(shell)]


@pytest.mark.parametrize("shell", _shells())
@pytest.mark.parametrize("raw", HOSTILE)
def test_env_values_stay_data_in_a_real_login_shell(tmp_path, shell, raw):
    """The default interpreter's exported env: the exact value, nothing run."""
    sentinel = tmp_path / "pwned"
    value = raw.format(sentinel=sentinel)
    composed = build_command('printf "%s" "$V"; cd / && printf "|%s" "$V"', env={"V": value})
    done = subprocess.run([shell, "-c", composed], capture_output=True, text=True, check=True)
    assert done.stdout == f"{value}|{value}"
    assert not sentinel.exists()


@pytest.mark.parametrize("shell", _shells())
@pytest.mark.parametrize("raw", HOSTILE)
@pytest.mark.parametrize(
    "command",
    [
        "printf '%s' {{ inputs.v | quote }}",
        "X={{ inputs.v | quote }}; printf '%s' \"$X\"",
        "echo $(printf '%s' {{ inputs.v | quote }}) >/dev/null",
    ],
)
def test_accepted_templates_render_values_as_data_in_a_real_shell(tmp_path, shell, raw, command):
    """What the check accepts, rendered as the host does, prints the value and runs nothing."""
    assert ShellExecuteHandler().template_errors({"commands": [command]}) == []
    sentinel = tmp_path / "pwned"
    value = raw.format(sentinel=sentinel)
    # The host's step environment: StrictUndefined, and quote = shlex.quote.
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters["quote"] = lambda item: shlex.quote(str(item))
    rendered = env.from_string(command).render(inputs={"v": value})
    done = subprocess.run([shell, "-c", rendered], capture_output=True, text=True, check=False)
    assert not sentinel.exists()
    if "$(" not in command:
        assert done.stdout == value


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
