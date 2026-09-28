# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ansible.playbook: generated inventory, credentials, run script, results."""

from __future__ import annotations

import json
import os
import shlex
import sys
import types
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from hegemony_step_sdk import (
    ContainerRuntime,
    DeviceCredentials,
    HandlerContext,
    HandlerServices,
    JumpHostSpec,
)
from hegemony_steps_ansible.inventory import (
    build_inventory,
    group_name,
    platform_connection,
)
from hegemony_steps_ansible.playbook import (
    DEFAULT_IMAGE,
    INVENTORY_FILE,
    KEYS_DIR,
    MAX_ERROR_MESSAGE_CHARS,
    MAX_OUTPUT_BYTES,
    MAX_OUTPUT_HOST_NAMES,
    RUN_SCRIPT,
    SECRETS_FILE,
    AnsiblePlaybookConfig,
    AnsiblePlaybookHandler,
    _bounded_output,
    _failure_detail,
    build_run_script,
    credential_host_vars,
)
from hegemony_steps_ansible.results import (
    CALLBACK_NAME,
    CALLBACK_SOURCE,
    MAX_DIFF_CHARS,
    MAX_MESSAGE_CHARS,
    MAX_RESULTS_BYTES,
    MAX_TASK_RECORDS,
    RESULTS_FILE,
    parse_results,
    render_host_report,
)
from hegemony_steps_container.pull_progress import EnginePullUnsupported
from hegemony_steps_container.runner import MAX_COLLECTED_BYTES


def _device(name: str, **extra: Any) -> dict[str, Any]:
    device: dict[str, Any] = {
        "id": f"id-{name}",
        "name": name,
        "mgmt_host": f"10.0.0.{len(name)}",
        "mgmt_port": 22,
        "platform": "ios-xe",
        "provider_id": "netbox:main",
        "tags": {"env": "prod"},
        "attributes": {},
        "site": {"id": "s1", "name": "ams01", "path": "emea/nl/ams01"},
        "access_config": {"ssh": {"username_ref": "admin", "password_ref": "x"}},
    }
    device.update(extra)
    return device


# ── inventory ────────────────────────────────────────────────────────────────


def test_inventory_groups_hosts_by_role_platform_site_tag_provider():
    r1 = _device("r1")
    srv = _device("srv-01", platform="linux", tags={}, site=None, provider_id="local")
    inventory = build_inventory({"core-routers": [r1], "servers": [srv]})
    document = inventory.document()

    hosts = document["all"]["hosts"]
    assert hosts["r1"]["ansible_host"] == r1["mgmt_host"]
    assert hosts["r1"]["ansible_connection"] == "ansible.netcommon.network_cli"
    assert hosts["r1"]["ansible_network_os"] == "cisco.ios.ios"
    assert hosts["r1"]["ansible_network_cli_ssh_type"] == "libssh"
    assert hosts["srv-01"]["ansible_connection"] == "ssh"
    assert "ansible_network_os" not in hosts["srv-01"]
    assert hosts["r1"]["hegemony"]["site"] == "emea/nl/ams01"
    assert "access_config" not in json.dumps(document)

    groups = document["all"]["children"]
    assert set(groups["core_routers"]["hosts"]) == {"r1"}
    assert set(groups["servers"]["hosts"]) == {"srv-01"}
    assert set(groups["platform_ios_xe"]["hosts"]) == {"r1"}
    assert set(groups["platform_linux"]["hosts"]) == {"srv-01"}
    assert set(groups["tag_env_prod"]["hosts"]) == {"r1"}
    assert set(groups["provider_netbox_main"]["hosts"]) == {"r1"}
    # Site hierarchy nests, and only the root is top level.
    assert "site_emea_nl" not in groups
    nl = groups["site_emea"]["children"]["site_emea_nl"]
    assert set(nl["children"]["site_emea_nl_ams01"]["hosts"]) == {"r1"}


def test_inventory_lists_a_device_in_two_roles_once():
    r1 = _device("r1")
    inventory = build_inventory({"a": [r1], "b": [dict(r1)]})
    assert [host.name for host in inventory.hosts] == ["r1"]
    assert {"a", "b"} <= inventory.hosts[0].groups


def test_inventory_host_names_are_file_safe_and_unique():
    inventory = build_inventory(
        {
            "r": [
                _device("../etc/passwd", id="a"),
                _device("core 1:22", id="b"),
                _device("core 1:22", id="c"),
            ]
        },
        group_by=[],
    )
    names = [host.name for host in inventory.hosts]
    assert names == ["_etc_passwd", "core_1_22", "core_1_22__2"]


def test_inventory_group_by_limits_derived_groups():
    inventory = build_inventory({"routers": [_device("r1")]}, group_by=["role"])
    assert set(inventory.document()["all"]["children"]) == {"routers"}


def test_device_ansible_vars_attribute_tunes_host_variables():
    device = _device(
        "fw1",
        platform="fortios",
        attributes={
            "ansible_vars": {
                "ansible_network_os": "fortinet.fortios.fortios",
                "ansible_python_interpreter": "/usr/bin/python3",
                "ntp_server": "10.0.0.1",
            }
        },
    )
    host = build_inventory({"fw": [device]}).hosts[0]
    assert host.variables["ansible_network_os"] == "fortinet.fortios.fortios"
    assert host.variables["ansible_python_interpreter"] == "/usr/bin/python3"
    assert host.variables["ntp_server"] == "10.0.0.1"
    assert host.ignored_vars == []


def test_device_ansible_vars_cannot_change_how_or_where_ansible_connects():
    """Inventory editors are not flow authors: `ansible_connection: local` would
    run the play in the step container, next to every credential of the run."""
    device = _device(
        "r1",
        attributes={
            "ansible_vars": {
                "ansible_connection": "local",
                "ansible_host": "10.9.9.9",
                "ansible_port": 2222,
                "ansible_user": "root",
                "ansible_password": "x",
                "ansible_ssh_private_key_file": "/etc/shadow",
                "ansible_become_exe": "sh -c id",
                "ansible_ssh_extra_args": "-o ProxyCommand=id",
                "ansible_ssh_common_args": "-o ProxyCommand=id",
                "ansible_libssh_proxy_command": "id",
                "ansible_shell_executable": "/tmp/x",
                "ANSIBLE_CONNECTION": "local",
                "hegemony": {"id": "spoofed"},
            }
        },
    )
    host = build_inventory({"r": [device]}).hosts[0]
    assert host.variables["ansible_connection"] == "ansible.netcommon.network_cli"
    assert host.variables["ansible_host"] == device["mgmt_host"]
    assert host.variables["ansible_port"] == 22
    assert host.variables["hegemony"]["id"] == "id-r1"
    for key in (
        "ansible_user",
        "ansible_password",
        "ansible_ssh_private_key_file",
        "ansible_become_exe",
        "ansible_ssh_extra_args",
        "ansible_ssh_common_args",
        "ansible_libssh_proxy_command",
        "ansible_shell_executable",
        "ANSIBLE_CONNECTION",
    ):
        assert key not in host.variables
    assert "ansible_connection" in host.ignored_vars
    assert "hegemony" in host.ignored_vars
    assert len(host.ignored_vars) == 13


@pytest.mark.parametrize(
    ("platform", "network_os", "connection"),
    [
        ("ios-xe", "cisco.ios.ios", "ansible.netcommon.network_cli"),
        ("IOS", "cisco.ios.ios", "ansible.netcommon.network_cli"),
        ("nxos", "cisco.nxos.nxos", "ansible.netcommon.network_cli"),
        ("ios-xr", "cisco.iosxr.iosxr", "ansible.netcommon.network_cli"),
        ("eos", "arista.eos.eos", "ansible.netcommon.network_cli"),
        ("junos", "junipernetworks.junos.junos", "ansible.netcommon.netconf"),
        ("linux", None, "ssh"),
        (None, None, "ssh"),
    ],
)
def test_platform_connections(platform, network_os, connection):
    settings = platform_connection(platform)
    assert settings.network_os == network_os
    assert settings.connection == connection


def test_group_names_are_valid_ansible_identifiers():
    assert group_name("", "core-routers") == "core_routers"
    assert group_name("tag", "env=prod") == "tag_env_prod"
    assert group_name("", "3rd floor") == "_3rd_floor"
    assert group_name("site", "") == "site"


# ── credentials ──────────────────────────────────────────────────────────────


def test_credentials_go_to_host_vars_with_private_key_files():
    host = build_inventory({"r": [_device("r1")]}).hosts[0]
    creds = DeviceCredentials(
        username="netops",
        password="pw-1",
        private_key="-----KEY-----",
        enable_password="en-1",
    )
    variables, files = credential_host_vars(host, creds, 0, "accept_new")

    assert variables["ansible_user"] == "netops"
    assert variables["ansible_password"] == "pw-1"
    assert variables["ansible_ssh_private_key_file"] == f"{KEYS_DIR}/host-0.pem"
    assert variables["ansible_become"] is True
    assert variables["ansible_become_method"] == "enable"
    assert variables["ansible_become_password"] == "en-1"
    assert "StrictHostKeyChecking=accept-new" in variables["ansible_ssh_common_args"]
    assert [(f.path, f.content) for f in files] == [
        ("/hegemony/ansible/keys/host-0.pem", "-----KEY-----\n")
    ]


def test_enable_password_is_not_become_on_servers():
    host = build_inventory({"s": [_device("srv", platform="linux")]}).hosts[0]
    variables, _ = credential_host_vars(
        host, DeviceCredentials(username="u", password="p", enable_password="e"), 0, "off"
    )
    assert "ansible_become" not in variables
    assert "StrictHostKeyChecking=no" in variables["ansible_ssh_common_args"]


def test_key_based_jump_host_becomes_a_proxy_command():
    host = build_inventory({"r": [_device("r1")]}).hosts[0]
    creds = DeviceCredentials(
        username="u",
        password="p",
        jump_host=JumpHostSpec(host="bastion", port=2222, username="jump", private_key="K"),
    )
    variables, files = credential_host_vars(host, creds, 3, "strict")

    proxy = variables["ansible_libssh_proxy_command"]
    assert proxy == f"ssh -W %h:%p -i {KEYS_DIR}/jump-3.pem -p 2222 -l jump bastion"
    assert variables["ansible_paramiko_proxy_command"] == proxy
    # Ansible splits the common args with shlex; the proxy stays one option value.
    assert shlex.split(variables["ansible_ssh_common_args"]) == ["-o", f"ProxyCommand={proxy}"]
    assert files[0].path.endswith("/jump-3.pem")


def test_jump_host_options_survive_both_quoting_layers():
    host = build_inventory({"r": [_device("r1")]}).hosts[0]
    creds = DeviceCredentials(
        username="u",
        jump_host=JumpHostSpec(host="fd00::1", port=22, username="ops.team+1", private_key="K"),
    )
    variables, _ = credential_host_vars(host, creds, 0, "accept_new")

    [flag, option, *known_hosts, proxy_flag, proxy_option] = shlex.split(
        variables["ansible_ssh_common_args"]
    )
    assert (flag, option, proxy_flag) == ("-o", "StrictHostKeyChecking=accept-new", "-o")
    proxy = proxy_option.removeprefix("ProxyCommand=")
    # What /bin/sh runs: the argv the step meant, nothing more.
    assert shlex.split(proxy) == [
        "ssh",
        "-W",
        "%h:%p",
        "-i",
        f"{KEYS_DIR}/jump-0.pem",
        "-p",
        "22",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        known_hosts[1],
        "-l",
        "ops.team+1",
        "fd00::1",
    ]


@pytest.mark.parametrize(
    ("jump", "message"),
    [
        (
            JumpHostSpec(host="bastion;cat /etc/passwd", username="j", private_key="K"),
            "not a host name",
        ),
        (JumpHostSpec(host="-oProxyCommand=id", username="j", private_key="K"), "not a host name"),
        (JumpHostSpec(host="b", username="j$(id)", private_key="K"), "user name"),
        (JumpHostSpec(host="b", username='j" x', private_key="K"), "user name"),
        (JumpHostSpec(host="b", username="-l", private_key="K"), "user name"),
        (JumpHostSpec(host="b", port=0, username="j", private_key="K"), "not a port"),
    ],
)
def test_jump_host_fields_from_device_records_are_refused_unless_plain(jump, message):
    host = build_inventory({"r": [_device("r1")]}).hosts[0]
    creds = DeviceCredentials(username="u", jump_host=jump)
    with pytest.raises(ValueError, match=message):
        credential_host_vars(host, creds, 0, "accept_new")


def test_password_only_jump_host_is_refused():
    host = build_inventory({"r": [_device("r1")]}).hosts[0]
    creds = DeviceCredentials(
        username="u", password="p", jump_host=JumpHostSpec(host="b", username="j", password="x")
    )
    with pytest.raises(ValueError, match="key-based jump hosts"):
        credential_host_vars(host, creds, 0, "accept_new")


# ── run script ───────────────────────────────────────────────────────────────


def test_run_script_builds_the_ansible_playbook_command():
    config = AnsiblePlaybookConfig.model_validate(
        {
            "playbook": "ansible/site.yml",
            "limit": "site_emea",
            "tags": ["base", "ntp"],
            "skip_tags": ["slow"],
            "check_mode": True,
            "diff": True,
            "verbosity": 2,
            "extra_inventory": ["ansible/extra.ini"],
            "requirements_file": "ansible/requirements.yml",
        }
    )
    script = build_run_script(
        config,
        has_extra_vars=True,
        has_secrets=True,
        vault_files={"": "/hegemony/ansible/vault/password-0", "prod": "/v/p1"},
    )

    assert "cd /attachments/ansible\n" in script
    assert "ansible-galaxy install -r /attachments/ansible/requirements.yml" in script
    command = script.strip().splitlines()[-1]
    assert command.startswith(f"exec ansible-playbook -i {INVENTORY_FILE}")
    for part in (
        "-i /attachments/ansible/extra.ini",
        "--limit site_emea",
        "--tags base,ntp",
        "--skip-tags slow",
        "--check",
        "--diff",
        "-vv",
        "-e @/hegemony/ansible/extra_vars.json",
        f"-e @{SECRETS_FILE}",
        "--vault-password-file /hegemony/ansible/vault/password-0",
        "--vault-id prod@/v/p1",
    ):
        assert part in command
    assert command.endswith(" site.yml")


def test_run_script_quotes_untrusted_values():
    config = AnsiblePlaybookConfig.model_validate({"playbook": "p.yml", "limit": "a;rm -rf /"})
    script = build_run_script(config, has_extra_vars=False, has_secrets=False, vault_files={})
    assert "--limit 'a;rm -rf /'" in script


# ── validation ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"playbook": "/etc/site.yml"}, "relative path"),
        ({"playbook": "../site.yml"}, "'..'"),
        ({"playbook": "site.yml", "tags": ["a b"]}, "one tag"),
        ({"playbook": "site.yml", "secrets": {"bad name": "x"}}, "'secrets' name"),
        ({"playbook": "site.yml", "group_secrets": {"nogroup": "x"}}, "GROUP:NAME"),
        ({"playbook": "site.yml", "vault_ids": {"a/b": "x"}}, "'vault_ids' label"),
        ({"playbook": "site.yml", "image": "/tmp/img"}, "Invalid image reference"),
        ({"playbook": "site.yml", "egress_mode": "allow-listed"}, "egress_allow"),
        ({"playbook": "site.yml", "forks": 0}, "forks"),
    ],
)
def test_validate_config_rejects(config, message):
    errors = AnsiblePlaybookHandler().validate_config(config)
    assert any(message in error for error in errors), errors


def test_validate_config_accepts_defaults():
    assert AnsiblePlaybookHandler().validate_config({"playbook": "site.yml"}) == []


# ── callback plugin ──────────────────────────────────────────────────────────


class _Named:
    def __init__(self, name: str, action: str = "debug") -> None:
        self._name = name
        self.action = action

    def get_name(self) -> str:
        return self._name


def _load_callback(monkeypatch, results_path: str):
    callback_mod = types.ModuleType("ansible.plugins.callback")

    class CallbackBase:
        def __init__(self, *args, **kwargs):
            pass

    setattr(callback_mod, "CallbackBase", CallbackBase)  # noqa: B010 - a stub module
    for name in ("ansible", "ansible.plugins"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "ansible.plugins.callback", callback_mod)
    namespace: dict[str, Any] = {}
    exec(
        compile(CALLBACK_SOURCE.replace(RESULTS_FILE, results_path), CALLBACK_NAME, "exec"),
        namespace,
    )
    return namespace["CallbackModule"]()


def test_callback_records_tasks_and_recap(monkeypatch, tmp_path):
    results_path = str(tmp_path / "out" / "results.json")
    plugin = _load_callback(monkeypatch, results_path)

    plugin.v2_playbook_on_play_start(_Named("Baseline"))
    # ansible-core 2.19 exposes public attributes; older cores only private ones.
    plugin.v2_runner_on_ok(
        SimpleNamespace(
            host=_Named("r1"), task=_Named("ntp"), result={"changed": True, "diff": {"a": 1}}
        )
    )
    plugin.v2_runner_on_failed(
        SimpleNamespace(_host=_Named("r2"), _task=_Named("ntp"), _result={"msg": "boom"})
    )
    plugin.v2_runner_on_unreachable(
        SimpleNamespace(_host=_Named("r3"), _task=_Named("ntp"), _result={"msg": "no route"})
    )
    plugin.v2_runner_on_skipped(
        SimpleNamespace(_host=_Named("r1"), _task=_Named("skip"), _result={})
    )

    class Stats:
        processed = {"r1": 1, "r2": 1, "r3": 1}
        custom = {"_run": {"rolled_out": 1}}

        def summarize(self, host):
            return {
                "ok": 1,
                "changed": int(host == "r1"),
                "failures": int(host == "r2"),
                "unreachable": int(host == "r3"),
                "skipped": 0,
                "rescued": 0,
                "ignored": 0,
            }

    plugin.v2_playbook_on_stats(Stats())

    with open(results_path, "rb") as fh:
        results = parse_results(fh.read())
    assert results.completed is True
    assert results.hosts_where("changed") == ["r1"]
    assert results.hosts_where("failures") == ["r2"]
    assert results.hosts_where("unreachable") == ["r3"]
    assert results.custom == {"_run": {"rolled_out": 1}}
    statuses = [(t["host"], t["status"]) for t in results.tasks]
    assert statuses == [
        ("r1", "changed"),
        ("r2", "failed"),
        ("r3", "unreachable"),
        ("r1", "skipped"),
    ]
    assert results.tasks[0]["play"] == "Baseline"
    assert results.tasks[1]["msg"] == "boom"
    assert '"a": 1' in results.tasks[0]["diff"]


def test_callback_keeps_its_results_file_within_the_collection_budget(monkeypatch, tmp_path):
    """The runner skips a collected file over its 8 MiB budget, which would leave
    the step without results: the callback trims, keeping the recap."""
    results_path = str(tmp_path / "out" / "results.json")
    plugin = _load_callback(monkeypatch, results_path)
    plugin.v2_playbook_on_play_start(_Named("Big"))
    for index in range(MAX_TASK_RECORDS):
        plugin.v2_runner_on_ok(
            SimpleNamespace(
                host=_Named(f"h{index % 50}"),
                task=_Named(f"t{index}"),
                result={"changed": True, "diff": "d" * 20_000, "msg": "m" * 2_000},
            )
        )

    class Stats:
        processed = {f"h{index}": 1 for index in range(50)}
        custom = {}

        def summarize(self, host):
            return {"ok": 1, "changed": 1, "failures": 0, "unreachable": 0, "skipped": 0}

    plugin.v2_playbook_on_stats(Stats())

    raw = (tmp_path / "out" / "results.json").read_bytes()
    assert len(raw) <= MAX_RESULTS_BYTES < MAX_COLLECTED_BYTES
    results = parse_results(raw)
    assert results.completed is True
    assert len(results.hosts_where("changed")) == 50
    assert results.trimmed[0] == "diffs"
    assert all("diff" not in task for task in results.tasks)


class _QuietStats:
    processed = {"r1": 1}
    custom: dict[str, Any] = {}

    def summarize(self, host):
        return {"ok": 1, "changed": 0, "failures": 0, "unreachable": 0, "skipped": 0}


def test_callback_records_an_ignored_failure_as_ignored(monkeypatch, tmp_path):
    results_path = str(tmp_path / "out" / "results.json")
    plugin = _load_callback(monkeypatch, results_path)
    plugin.v2_playbook_on_play_start(_Named("Rollout"))
    plugin.v2_runner_on_failed(
        SimpleNamespace(host=_Named("r1"), task=_Named("probe"), result={"msg": "no such"}),
        ignore_errors=True,
    )
    plugin.v2_playbook_on_stats(_QuietStats())

    results = parse_results((tmp_path / "out" / "results.json").read_bytes())
    assert [task["status"] for task in results.tasks] == ["ignored"]
    # The recap, not the task records, decides failed_hosts.
    assert results.hosts_where("failures") == []
    report = render_host_report("r1", results.hosts["r1"], results.tasks_for("r1"))
    assert "  failed (ignored)  probe — no such\n" in report


def test_callback_clips_long_messages_and_diffs(monkeypatch, tmp_path):
    results_path = str(tmp_path / "out" / "results.json")
    plugin = _load_callback(monkeypatch, results_path)
    plugin.v2_runner_on_failed(
        SimpleNamespace(
            host=_Named("r1"),
            task=_Named("t"),
            result={"msg": "m" * (MAX_MESSAGE_CHARS + 100), "diff": "d" * (MAX_DIFF_CHARS + 5)},
        )
    )
    plugin.v2_playbook_on_stats(_QuietStats())

    [task] = parse_results((tmp_path / "out" / "results.json").read_bytes()).tasks
    # The ellipsis survives the plugin source's template substitution as one character.
    assert len(task["msg"]) == MAX_MESSAGE_CHARS
    assert task["msg"].endswith("m\u2026")
    assert len(task["diff"]) == MAX_DIFF_CHARS
    assert task["diff"].endswith("d\u2026")


def test_callback_caps_task_records_and_counts_the_rest(monkeypatch, tmp_path):
    results_path = str(tmp_path / "out" / "results.json")
    plugin = _load_callback(monkeypatch, results_path)
    for index in range(MAX_TASK_RECORDS + 3):
        plugin.v2_runner_on_ok(
            SimpleNamespace(host=_Named("r1"), task=_Named(f"t{index}"), result={})
        )
    plugin.v2_playbook_on_stats(_QuietStats())

    results = parse_results((tmp_path / "out" / "results.json").read_bytes())
    assert len(results.tasks) == MAX_TASK_RECORDS
    assert results.tasks[-1]["task"] == f"t{MAX_TASK_RECORDS - 1}"
    assert results.dropped_task_records == 3


def test_host_report_renders_plays_tasks_messages_and_diffs():
    tasks = [
        {"play": "Base", "task": "ntp", "status": "changed", "diff": "-a\n+b"},
        {"play": "Base", "task": "dns", "status": "ok", "msg": "not shown when ok"},
        {"play": "Verify", "task": "probe", "status": "ignored", "msg": "timeout"},
        {"play": "Verify", "task": "check", "status": "failed", "msg": "boom"},
    ]
    counts = {"ok": 2, "changed": 1, "failures": 1, "unreachable": 0, "skipped": 0}
    assert render_host_report("r1", counts, tasks) == (
        "r1: ok=2 changed=1 failed=1 unreachable=0 skipped=0\n"
        "\n"
        "PLAY [Base]\n"
        "  changed           ntp\n"
        "    diff: -a\n+b\n"
        "  ok                dns\n"
        "PLAY [Verify]\n"
        "  failed (ignored)  probe — timeout\n"
        "  FAILED            check — boom\n"
    )


def test_bounded_output_caps_host_lists():
    names = [f"h{index:03d}" for index in range(MAX_OUTPUT_HOST_NAMES + 100)]
    output = _bounded_output(
        {"changed_hosts": list(names), "failed_hosts": ["a"], "unreachable_hosts": []}
    )
    assert output["changed_hosts"] == names[:MAX_OUTPUT_HOST_NAMES]
    assert output["changed_hosts_truncated"] is True
    assert output["failed_hosts"] == ["a"]
    assert "failed_hosts_truncated" not in output


def test_bounded_output_drops_the_host_map_before_the_stats():
    hosts = {f"host-{index}": {"ok": 1, "changed": 1} for index in range(2000)}
    output = _bounded_output(
        {"changed": True, "changed_hosts": ["host-1"], "hosts": hosts, "stats": {"k": "v"}}
    )
    assert "hosts" not in output
    assert output["hosts_truncated"] is True
    # What fits stays: the host lists and the set_stats data.
    assert output["changed_hosts"] == ["host-1"]
    assert output["stats"] == {"k": "v"}
    assert "stats_truncated" not in output
    assert len(json.dumps(output)) <= MAX_OUTPUT_BYTES


def test_bounded_output_drops_the_stats_last():
    output = _bounded_output(
        {
            "changed_hosts": ["h1"],
            "hosts": {"h1": {"ok": 1}},
            "stats": {"blob": "x" * MAX_OUTPUT_BYTES},
        }
    )
    assert "hosts" not in output and output["hosts_truncated"] is True
    assert "stats" not in output and output["stats_truncated"] is True
    assert output["changed_hosts"] == ["h1"]


def test_parse_results_tolerates_missing_or_broken_files():
    assert "no results file was collected" in (parse_results(None).problem or "")
    assert "not valid JSON" in (parse_results(b"{").problem or "")
    assert parse_results(b"[]").problem == "the results file is not a JSON object"


# ── end to end ───────────────────────────────────────────────────────────────


class _Services:
    def __init__(self) -> None:
        self.resolved: list[str] = []
        self.step_output_fetches = 0

    def container_runtime(self) -> ContainerRuntime:
        return ContainerRuntime(
            docker_bin="docker",
            shared_workspaces_enabled=False,
            shared_workspace_root="",
            shared_workspace_volume="",
            docker_host="tcp://dind:2375",
        )

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        return [{"filename": "ansible/site.yml", "content": "- hosts: all\n"}]

    async def fetch_run_step_outputs(self, run_id: str) -> dict[str, Any]:
        # Counted rather than raised: run_job would swallow an exception here.
        self.step_output_fetches += 1
        return {}

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        return []

    async def resolve_device_credentials(self, device: dict[str, Any]) -> DeviceCredentials:
        if device["name"] == "broken":
            raise ValueError("access_config.ssh.username_ref is required")
        return DeviceCredentials(username="netops", password=f"pw-{device['name']}")

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        assert ref is not None
        self.resolved.append(ref)
        return "resolved-" + ref.split("/")[-1].split("'")[0]


def _results_json(exit_hosts: dict[str, dict[str, int]]) -> bytes:
    return json.dumps(
        {
            "completed": True,
            "hosts": exit_hosts,
            "custom": {"_run": {"release": "1.2"}},
            "tasks": [
                {"host": "r1", "play": "p", "task": "ntp", "status": "changed"},
                {"host": "r2", "play": "p", "task": "ntp", "status": "failed", "msg": "boom"},
            ],
        }
    ).encode()


def _install_docker(
    monkeypatch,
    *,
    collected: bytes | None,
    exit_code: int,
    pull_returncode: int = 0,
    collect_returncode: int = 0,
) -> dict[str, Any]:
    state: dict[str, Any] = {"roots": {}, "calls": []}
    monkeypatch.setattr(
        "hegemony_steps_container.run.stream_pull",
        AsyncMock(side_effect=EnginePullUnsupported("off")),
    )

    def fake_run(cmd, *args, **kwargs):
        state["calls"].append(list(cmd))
        if cmd[1] == "pull" and pull_returncode:
            return SimpleNamespace(returncode=pull_returncode, stdout="", stderr="manifest unknown")
        if len(cmd) >= 4 and cmd[1] == "cp":
            src, dest = cmd[2], cmd[3]
            if dest.endswith(":/"):
                root = src[: -len("/.")]
                for walk_root, _dirs, files in os.walk(root):
                    for name in files:
                        path = os.path.join(walk_root, name)
                        rel = "/" + os.path.relpath(path, root)
                        with open(path, encoding="utf-8") as fh:
                            state["roots"][rel] = fh.read()
            elif src.endswith(":/hegemony/out/.") and collect_returncode:
                return SimpleNamespace(returncode=collect_returncode, stdout="", stderr="cp broke")
            elif src.endswith(":/hegemony/out/.") and collected is not None:
                with open(os.path.join(dest, "ansible-results.json"), "wb") as fh:
                    fh.write(collected)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    async def fake_exec(*argv, **kwargs):
        proc = AsyncMock()
        proc.stdout = AsyncMock()
        proc.stdout.readline = AsyncMock(side_effect=[b"PLAY RECAP\n", b""])
        proc.stderr = AsyncMock()
        proc.stderr.readline = AsyncMock(return_value=b"")
        proc.wait = AsyncMock(return_value=exit_code)
        proc.kill = AsyncMock()
        return proc

    monkeypatch.setattr("asyncio.create_subprocess_exec", fake_exec)
    return state


def _ctx(config: dict[str, Any], devices: list[dict[str, Any]]) -> HandlerContext:
    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="baseline",
        config=config,
        target_devices_by_role={"routers": devices, "other": [_device("x9")]},
        target_roles=["routers"],
        services=cast(HandlerServices, _Services()),
    )


@pytest.mark.asyncio
async def test_playbook_step_end_to_end(monkeypatch):
    collected = _results_json(
        {
            "r1": {"ok": 2, "changed": 1, "failures": 0, "unreachable": 0},
            "r2": {"ok": 1, "changed": 0, "failures": 1, "unreachable": 0},
        }
    )
    state = _install_docker(monkeypatch, collected=collected, exit_code=2)
    config = {
        "playbook": "ansible/site.yml",
        "secrets": {"db_password": "vault://orgs/acme/secrets/db/password"},
        "group_secrets": {"routers:api_key": "vault://orgs/acme/secrets/api"},
        "vault_password": "vault://orgs/acme/secrets/vaultpw",
        "extra_vars": {"release": "1.2"},
        "env": {"ANSIBLE_CALLBACKS_ENABLED": "profile_tasks"},
    }
    ctx = _ctx(config, [_device("r1"), _device("r2")])
    result = await AnsiblePlaybookHandler().execute(ctx)

    # A tool step mounts no upstream step outputs, so it never fetches them.
    assert cast(_Services, ctx.services).step_output_fetches == 0
    # Staged files: inventory without secrets, credentials in host_vars.
    roots = state["roots"]
    inventory = json.loads(roots[INVENTORY_FILE])
    assert set(inventory["all"]["hosts"]) == {"r1", "r2"}
    assert "pw-r1" not in roots[INVENTORY_FILE]
    assert (
        json.loads(roots["/hegemony/ansible/inventory/host_vars/r1.json"])["ansible_password"]
        == "pw-r1"
    )
    assert json.loads(roots[SECRETS_FILE]) == {"db_password": "resolved-password"}
    assert json.loads(roots["/hegemony/ansible/inventory/group_vars/routers.json"]) == {
        "api_key": "resolved-api"
    }
    assert roots["/hegemony/ansible/vault/password-0"] == "resolved-vaultpw\n"
    assert "/hegemony/ansible/callback_plugins/hegemony_results.py" in roots
    assert "exec ansible-playbook" in roots[RUN_SCRIPT]
    # Only the step's own role is in the inventory by default.
    assert "x9" not in roots[INVENTORY_FILE]

    create = next(call for call in state["calls"] if call[1] == "create")
    assert "hegemony.handler_id=ansible.playbook" in create
    assert "ANSIBLE_CALLBACKS_ENABLED=hegemony_results,profile_tasks" in create
    assert "ANSIBLE_HOST_KEY_CHECKING=True" in create
    assert create[create.index("--entrypoint") + 1] == "/bin/sh"
    assert not any("pw-r1" in part or "resolved-" in part for part in create)

    assert result.success is False
    # The error names the failed host and, with one, its failing task.
    assert result.error == (
        "ansible-playbook exited with code 2: 1 host(s) failed (r2); task 'ntp' failed: boom"
    )
    assert result.summary == "ansible/site.yml: 2 host(s), 1 changed, 1 failed, 0 unreachable"
    assert result.output["changed"] is True
    assert result.output["changed_hosts"] == ["r1"]
    assert result.output["failed_hosts"] == ["r2"]
    assert result.output["stats"] == {"_run": {"release": "1.2"}}
    per_device = {e["name"]: e for e in result.evidence if e["name"].startswith("ansible_r")}
    assert per_device["ansible_r1"]["device_id"] == "id-r1"
    assert "changed" in per_device["ansible_r1"]["content_text"]
    assert "boom" in per_device["ansible_r2"]["content_text"]
    assert any(e["kind"] == "container_output" for e in result.evidence)


@pytest.mark.asyncio
async def test_ignored_device_ansible_vars_are_reported(monkeypatch):
    state = _install_docker(monkeypatch, collected=_results_json({}), exit_code=0)
    device = _device("r1", attributes={"ansible_vars": {"ansible_connection": "local"}})
    result = await AnsiblePlaybookHandler().execute(_ctx({"playbook": "site.yml"}, [device]))

    inventory = json.loads(state["roots"][INVENTORY_FILE])
    assert inventory["all"]["hosts"]["r1"]["ansible_connection"] != "local"
    [note] = [e for e in result.evidence if e["name"] == "ansible_vars_ignored_baseline"]
    assert "- r1: ansible_connection\n" in note["content_text"]


@pytest.mark.asyncio
async def test_run_scope_includes_every_role(monkeypatch):
    state = _install_docker(monkeypatch, collected=_results_json({}), exit_code=0)
    result = await AnsiblePlaybookHandler().execute(
        _ctx({"playbook": "site.yml", "inventory_scope": "run"}, [_device("r1")])
    )
    inventory = json.loads(state["roots"][INVENTORY_FILE])
    assert set(inventory["all"]["hosts"]) == {"r1", "x9"}
    assert result.success is True


@pytest.mark.asyncio
async def test_run_scope_leaves_out_other_roles_devices_without_credentials(monkeypatch):
    """A device the step does not target, in the inventory only through run
    scope, does not block the play when it has no SSH credentials."""
    state = _install_docker(monkeypatch, collected=_results_json({}), exit_code=0)
    ctx = _ctx({"playbook": "site.yml", "inventory_scope": "run"}, [_device("r1")])
    ctx.target_devices_by_role["monitors"] = [
        _device("broken", site={"id": "s2", "name": "x", "path": "apac/sg"})
    ]
    result = await AnsiblePlaybookHandler().execute(ctx)

    assert result.success is True
    inventory = json.loads(state["roots"][INVENTORY_FILE])
    assert set(inventory["all"]["hosts"]) == {"r1", "x9"}
    groups = inventory["all"]["children"]
    # Groups only the left-out host was in are gone too.
    assert "monitors" not in groups
    assert "site_apac" not in groups
    assert "/hegemony/ansible/inventory/host_vars/broken.json" not in state["roots"]
    [note] = [e for e in result.evidence if e["name"] == "ansible_hosts_left_out_baseline"]
    assert "- broken: access_config.ssh.username_ref is required\n" in note["content_text"]


@pytest.mark.asyncio
async def test_run_scope_still_requires_credentials_for_the_steps_own_targets(monkeypatch):
    state = _install_docker(monkeypatch, collected=_results_json({}), exit_code=0)
    ctx = _ctx({"playbook": "site.yml", "inventory_scope": "run"}, [_device("broken")])
    # Also under a role the step does not target: its own role still decides.
    ctx.target_devices_by_role["monitors"] = [_device("broken")]
    result = await AnsiblePlaybookHandler().execute(ctx)

    assert result.success is False
    assert "device broken: access_config.ssh.username_ref is required" in (result.error or "")
    assert state["calls"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("check_mode", [True, False])
async def test_a_play_without_results_fails_rather_than_report_no_changes(monkeypatch, check_mode):
    """A missing results file (callback not run, file too big to collect) must not
    read as "nothing changed": a check-mode gate would skip its approval."""
    _install_docker(monkeypatch, collected=None, exit_code=0)
    result = await AnsiblePlaybookHandler().execute(
        _ctx({"playbook": "site.yml", "check_mode": check_mode}, [_device("r1")])
    )
    assert result.success is False
    assert "Whether any host changed is unknown" in (result.error or "")
    assert result.output["changed"] is None
    assert any(e["name"] == "ansible_results_missing_baseline" for e in result.evidence)


@pytest.mark.asyncio
async def test_results_that_could_not_be_copied_out_say_so(monkeypatch):
    _install_docker(monkeypatch, collected=_results_json({}), exit_code=0, collect_returncode=1)
    result = await AnsiblePlaybookHandler().execute(_ctx({"playbook": "site.yml"}, [_device("r1")]))
    assert result.success is False
    assert "could not be copied out of the container (docker cp failed: cp broke)" in (
        result.error or ""
    )
    [note] = [e for e in result.evidence if e["name"] == "ansible_results_missing_baseline"]
    assert "docker cp failed: cp broke" in note["content_text"]


@pytest.mark.asyncio
async def test_the_error_lists_failed_and_unreachable_hosts(monkeypatch):
    recap = {f"f{index}": {"ok": 1, "failures": 1} for index in range(7)}
    recap.update({"u1": {"ok": 0, "unreachable": 1}})
    _install_docker(monkeypatch, collected=_results_json(recap), exit_code=4)
    result = await AnsiblePlaybookHandler().execute(_ctx({"playbook": "site.yml"}, [_device("r1")]))
    assert result.error == (
        "ansible-playbook exited with code 4: 7 host(s) failed "
        "(f0, f1, f2, f3, f4, … 2 more); 1 unreachable (u1)"
    )


def test_failure_detail_clips_the_single_failure_message():
    results = parse_results(
        json.dumps(
            {
                "completed": True,
                "hosts": {"r1": {"failures": 1}},
                "tasks": [
                    {"host": "r1", "task": "a", "status": "ignored", "msg": "not this"},
                    {"host": "r1", "task": "b", "status": "failed", "msg": "x\n" * 400},
                ],
            }
        ).encode()
    )
    detail = _failure_detail(results, ["r1"], [])
    assert detail.startswith("1 host(s) failed (r1); task 'b' failed: x x x")
    assert detail.endswith("…")
    assert len(detail.split(": ", 1)[1]) == MAX_ERROR_MESSAGE_CHARS


@pytest.mark.asyncio
async def test_a_failed_play_without_results_reports_changes_as_unknown(monkeypatch):
    _install_docker(monkeypatch, collected=None, exit_code=4)
    result = await AnsiblePlaybookHandler().execute(_ctx({"playbook": "site.yml"}, [_device("r1")]))
    assert result.success is False
    assert "exited with code 4" in (result.error or "")
    assert result.output["changed"] is None


@pytest.mark.asyncio
async def test_default_image_pull_failure_says_how_to_get_the_image(monkeypatch):
    _install_docker(monkeypatch, collected=None, exit_code=0, pull_returncode=1)
    result = await AnsiblePlaybookHandler().execute(_ctx({"playbook": "site.yml"}, [_device("r1")]))
    assert result.success is False
    error = result.error or ""
    assert f"default execution image {DEFAULT_IMAGE} could not be pulled" in error
    assert f"docker push {DEFAULT_IMAGE}" in error
    # Docker's own reason is kept.
    assert "manifest unknown" in error


@pytest.mark.asyncio
async def test_own_image_pull_failure_is_reported_as_is(monkeypatch):
    _install_docker(monkeypatch, collected=None, exit_code=0, pull_returncode=1)
    result = await AnsiblePlaybookHandler().execute(
        _ctx({"playbook": "site.yml", "image": "registry.example.com/ansible:1"}, [_device("r1")])
    )
    assert result.success is False
    assert (result.error or "").startswith("Docker pull failed")
    assert "default execution image" not in (result.error or "")


@pytest.mark.asyncio
async def test_device_without_credentials_fails_before_docker(monkeypatch):
    state = _install_docker(monkeypatch, collected=None, exit_code=0)
    result = await AnsiblePlaybookHandler().execute(
        _ctx({"playbook": "site.yml"}, [_device("broken")])
    )
    assert result.success is False
    assert "device broken" in (result.error or "")
    assert state["calls"] == []


@pytest.mark.asyncio
async def test_device_credentials_can_be_turned_off(monkeypatch):
    state = _install_docker(monkeypatch, collected=_results_json({}), exit_code=0)
    result = await AnsiblePlaybookHandler().execute(
        _ctx({"playbook": "site.yml", "device_credentials": False}, [_device("broken")])
    )
    assert result.success is True
    host_vars = json.loads(state["roots"]["/hegemony/ansible/inventory/host_vars/broken.json"])
    assert "ansible_user" not in host_vars


def test_handler_metadata():
    handler = AnsiblePlaybookHandler
    assert handler.handler_id == "ansible.playbook"
    assert handler.container_backed is True
    # Secret fields reach the handler as written (never resolved twice).
    assert handler.raw_config_keys == {"secrets", "group_secrets", "vault_password", "vault_ids"}
    assert handler.targeting.roles is True and handler.targeting.ips is False
