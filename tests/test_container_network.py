# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Policy-network attachment (``ContainerRuntime.docker_network``).

The platform's egress enforcement provisions a policy-scoped network on the
sandbox daemon and hands its name to the handler through the runtime; the
handler must attach the step container to it with ``--network`` unless an
explicit (admin) ``network_mode`` overrides it. Empty means no policy
network — argv byte-identical to before the field existed.
"""

from __future__ import annotations

from hegemony_step_sdk import ContainerRuntime
from hegemony_steps_container.run import RunContainerHandler

_BASE_CONFIG = {"image": "alpine:3.20", "command": ["echo hi"]}


def _args(
    config: dict,
    docker_network: str = "",
    docker_ip: str = "",
    docker_ip6: str = "",
) -> list[str]:
    return RunContainerHandler().build_docker_args(
        config=config,
        container_name="hegemony-test",
        run_id="run-1",
        step_run_id="step-1",
        docker_network=docker_network,
        docker_ip=docker_ip,
        docker_ip6=docker_ip6,
    )


def _network_tokens(args: list[str]) -> list[str]:
    return [tok for tok in args if tok.startswith("--network")]


def test_runtime_docker_network_defaults_empty() -> None:
    runtime = ContainerRuntime(
        docker_bin="docker",
        shared_workspaces_enabled=False,
        shared_workspace_root="",
        shared_workspace_volume="",
    )
    assert runtime.docker_network == ""


def test_no_docker_network_leaves_argv_unchanged() -> None:
    assert _args(_BASE_CONFIG) == _args(_BASE_CONFIG, docker_network="")
    assert _network_tokens(_args(_BASE_CONFIG)) == []


def test_empty_memory_cpus_workdir_resolve_to_defaults() -> None:
    # A bare step's editor sends these at their empty defaults; they must
    # resolve to the documented defaults, never reach docker as e.g.
    # `--memory ""` (which docker create rejects).
    args = _args({**_BASE_CONFIG, "memory": "", "cpus": "  ", "working_dir": ""})
    assert args[args.index("--memory") + 1] == "512m"
    assert args[args.index("--cpus") + 1] == "1.0"
    assert args[args.index("-w") + 1] == "/workspace"
    # No flag is ever followed by an empty value.
    assert "" not in args


def test_blank_network_and_pid_mode_are_unset_not_literal() -> None:
    # Validation treats a whitespace-only optional field as absent, so a config
    # carrying one *passes* — the emitter must agree, or the step dies on an
    # opaque `--network=   ` / `--pid=   ` that docker create rejects. Blank
    # network_mode must also yield the policy network rather than shadowing it.
    handler = RunContainerHandler()
    for blank in ("", "   ", "\t\n"):
        config = {**_BASE_CONFIG, "network_mode": blank, "pid_mode": blank}
        assert handler.validate_config(config) == []
        args = _args(config, docker_network="hegemony-egress-0123456789abcdef")
        assert _network_tokens(args) == ["--network=hegemony-egress-0123456789abcdef"]
        assert not [tok for tok in args if tok.startswith("--pid")]
        assert not any(tok != tok.strip() for tok in args)


def test_pid_mode_is_passed_through_when_set() -> None:
    args = _args({**_BASE_CONFIG, "pid_mode": "host"})
    assert "--pid=host" in args


def test_docker_network_attaches_policy_network() -> None:
    args = _args(_BASE_CONFIG, docker_network="hegemony-egress-0123456789abcdef")
    assert _network_tokens(args) == ["--network=hegemony-egress-0123456789abcdef"]


def test_docker_network_none_disables_networking() -> None:
    args = _args(_BASE_CONFIG, docker_network="none")
    assert _network_tokens(args) == ["--network=none"]


def test_explicit_network_mode_wins_over_policy_network() -> None:
    args = _args(
        {**_BASE_CONFIG, "network_mode": "clab-demo"},
        docker_network="hegemony-egress-0123456789abcdef",
    )
    assert _network_tokens(args) == ["--network=clab-demo"]


def test_policy_network_wins_over_network_disabled() -> None:
    # The worker only passes a policy network when networking is meant to
    # exist; deny-all arrives as docker_network="none", not network_disabled.
    args = _args(
        {**_BASE_CONFIG, "network_disabled": True},
        docker_network="hegemony-egress-0123456789abcdef",
    )
    assert _network_tokens(args) == ["--network=hegemony-egress-0123456789abcdef"]


def test_network_disabled_still_works_without_policy_network() -> None:
    args = _args({**_BASE_CONFIG, "network_disabled": True})
    assert _network_tokens(args) == ["--network=none"]


# ── Per-container addresses ───────────────────────────────────────────────────
#
# A policy network is shared by every step under the policy, so the firewall
# counters written against its subnet belong to all of them at once. The
# platform reserves an address per step so it can scope a step's egress report
# to that step; the container has to actually take it, or the reservation
# counts nothing.


def test_reserved_addresses_are_pinned_on_the_policy_network() -> None:
    args = _args(
        _BASE_CONFIG,
        docker_network="hegemony-egress-0123456789abcdef",
        docker_ip="172.18.0.7",
        docker_ip6="fd00:1::7",
    )
    assert "--ip=172.18.0.7" in args
    assert "--ip6=fd00:1::7" in args


def test_addresses_are_omitted_when_the_platform_reserved_none() -> None:
    """The ordinary case, and the fallback when allocation did not work out:
    Docker assigns, and the step's report covers the policy network instead."""
    args = _args(_BASE_CONFIG, docker_network="hegemony-egress-0123456789abcdef")
    assert not [tok for tok in args if tok.startswith(("--ip=", "--ip6="))]


def test_one_family_can_be_pinned_without_the_other() -> None:
    args = _args(
        _BASE_CONFIG,
        docker_network="hegemony-egress-0123456789abcdef",
        docker_ip="172.18.0.7",
    )
    assert "--ip=172.18.0.7" in args
    assert not [tok for tok in args if tok.startswith("--ip6=")]


def test_deny_all_takes_no_address() -> None:
    """`none` is not a network an address can be allocated from; passing one
    would make docker reject the create outright."""
    args = _args(
        _BASE_CONFIG,
        docker_network="none",
        docker_ip="172.18.0.7",
        docker_ip6="fd00:1::7",
    )
    assert "--network=none" in args
    assert not [tok for tok in args if tok.startswith(("--ip=", "--ip6="))]


def test_host_access_network_mode_takes_no_address() -> None:
    """An admin `network_mode` wins over the policy network, and an address
    from a network the container is not on would fail the create."""
    args = _args(
        {**_BASE_CONFIG, "network_mode": "host"},
        docker_network="hegemony-egress-0123456789abcdef",
        docker_ip="172.18.0.7",
    )
    assert "--network=host" in args
    assert not [tok for tok in args if tok.startswith("--ip=")]


def test_runtime_addresses_default_empty() -> None:
    runtime = ContainerRuntime(
        docker_bin="docker",
        shared_workspaces_enabled=False,
        shared_workspace_root="",
        shared_workspace_volume="",
    )
    assert runtime.docker_ip == ""
    assert runtime.docker_ip6 == ""
