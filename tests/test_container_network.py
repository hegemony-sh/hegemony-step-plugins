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


def _args(config: dict, docker_network: str = "") -> list[str]:
    return RunContainerHandler().build_docker_args(
        config=config,
        container_name="hegemony-test",
        run_id="run-1",
        step_run_id="step-1",
        docker_network=docker_network,
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
