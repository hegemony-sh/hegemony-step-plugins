# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Platform services injected into step handlers at execution time.

An out-of-tree handler never imports the platform's SSH transport, template
resolver, notification pipeline, or settings. Instead the host binds a
:class:`HandlerServices` implementation onto ``HandlerContext.services`` and the
handler calls these methods; device access, secret resolution, and internal-API
access stay inside the platform.

This mirrors ``hegemony_notification_sdk.NotificationServices``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .probes import ProbeResult

if TYPE_CHECKING:
    import httpx


class CommandResult(Protocol):
    """One executed device command (structurally satisfied by the host's SSHResult)."""

    command: str
    output: str
    exit_code: int
    error: str | None
    latency_ms: float


class Transport(Protocol):
    """Device I/O surface returned by :meth:`HandlerServices.connect`.

    Structurally satisfied by the host's SSH transport today; future transports
    (scrapli, netmiko variants) and platform drivers implement the same surface,
    so handlers never name a concrete transport class.
    """

    async def execute_command(self, command: str) -> CommandResult: ...

    async def execute_commands(self, commands: list[str]) -> Sequence[CommandResult]: ...

    async def execute_command_timing(
        self,
        command: str,
        *,
        read_timeout: float = 120.0,
        delay_factor: int = 2,
        expect: list[str] | None = None,
        answers: dict[str, str] | None = None,
        wait_for_patterns: list[str] | None = None,
    ) -> CommandResult: ...

    async def scp_put(
        self,
        *,
        local_path: str,
        dest_fs: str,
        dest_filename: str,
        overwrite: bool = False,
    ) -> dict: ...

    async def http_transfer(
        self,
        *,
        url: str,
        dest_fs: str,
        dest_filename: str,
        timeout_seconds: int = 3600,
    ) -> dict: ...


@dataclass(frozen=True, slots=True)
class ShellResult:
    """Result of one exec-channel command on a remote host."""

    command: str
    exit_code: int
    stdout: str
    stderr: str


class ShellTransport(Protocol):
    """Remote shell-execution surface returned by :meth:`HandlerServices.open_shell`.

    Exec-channel semantics (meaningful exit codes, separate stdout/stderr) —
    distinct from :class:`Transport`'s interactive network-CLI channel. SSH
    today; WinRM slots in behind the same surface (transport comes from
    ``device.access_config``, never from handler ids or config).
    """

    async def run(self, command: str, *, timeout: float | None = None) -> ShellResult:
        """Run one command on the remote host and capture its result."""
        ...

    async def close(self) -> None:
        """Close the underlying connection (idempotent)."""
        ...


@dataclass(frozen=True, slots=True)
class ContainerRuntime:
    """Host container-execution environment served to the run_container handler."""

    docker_bin: str
    shared_workspaces_enabled: bool
    shared_workspace_root: str
    shared_workspace_volume: str
    # Daemon selection for flow-container work. Empty means inherit the worker's
    # environment (the host Docker socket) — today's behavior and the rollback
    # story. When set (e.g. ``tcp://dind:2375``), the handler points ``DOCKER_HOST``
    # at that daemon on every docker invocation it spawns — per invocation, never
    # process-wide, and never in the ``docker create`` argv (selection is
    # environment, not arguments).
    docker_host: str = ""
    # Files larger than this are skipped when harvesting generated artifacts.
    artifact_max_file_size_bytes: int = 52_428_800


@runtime_checkable
class HandlerServices(Protocol):
    """Host facilities injected into ``HandlerContext.services``.

    Handlers must reach platform functionality only through this interface
    (never by importing host modules), so handler code lives out-of-tree behind
    a stable ABI. The worker binds it host-side.
    """

    def connect(
        self,
        device: dict[str, Any],
        *,
        platform: str | None = None,
        connect_timeout: float | None = None,
        command_timeout: float | None = None,
        step_run_id: str | None = None,
    ) -> Transport:
        """Open a device transport, resolving credentials from ``device.access_config``.

        ``platform``/timeout arguments override the transport defaults only when
        given; ``step_run_id`` opts the connection into cancellation tracking.
        """
        ...

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        """Resolve a single ``{{ secret/env/file(...) }}`` reference (or pass ``None`` through)."""
        ...

    def validate_secret_ref(
        self, ref: Any, *, field_name: str, required: bool = False
    ) -> str | None:
        """Validate a reference string without resolving it; returns the normalized ref."""
        ...

    async def render_template(self, template: str) -> str:
        """Render a full Jinja template with the platform's resolver."""
        ...

    def contains_template(self, value: str) -> bool:
        """Whether ``value`` contains Jinja template syntax."""
        ...

    def open_api_client(self, *, timeout: float = 30.0) -> httpx.AsyncClient:
        """Build an ``httpx.AsyncClient`` scoped to the internal API (base URL + auth).

        Caller owns the client lifecycle (use ``async with``). Core handlers use it
        for internal endpoints (artifacts, child runs, notifications); the client is
        version-locked with the host, so those paths are not third-party ABI.
        """
        ...

    async def dispatch_notification(
        self,
        *,
        destination_type: str,
        destination_config: dict[str, Any],
        title: str,
        body: str,
    ) -> None:
        """Send a notification through the host's provider registry (raises on failure)."""
        ...

    async def format_run_notification(
        self,
        event: str,
        *,
        run_context: dict[str, Any],
        overrides: dict[str, str] | None = None,
        steps: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Render a notification ``(title, body)`` with the host's notification renderer.

        ``overrides`` replace the shared default templates for this send; templates
        get the full notification context (run.*, event, ui_base_url, step outputs,
        secret()/env() helpers) in a single just-in-time pass.
        """
        ...

    async def create_child_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create a child flow run; returns the creation response (``run_id``, …)."""
        ...

    async def fetch_run(self, run_id: str) -> dict[str, Any]:
        """Fetch a compact run status payload (``status``, ``error_message``, …)."""
        ...

    async def fetch_run_outputs(self, run_id: str) -> dict[str, Any]:
        """Fetch evaluated flow outputs for a terminal run."""
        ...

    async def cancel_run(self, run_id: str) -> bool:
        """Best-effort cancellation of a run; returns whether the API accepted it."""
        ...

    def container_runtime(self) -> ContainerRuntime:
        """Describe the host's container-execution environment (docker binary, workspaces)."""
        ...

    async def open_shell(
        self,
        device: dict[str, Any],
        *,
        connect_timeout: float | None = None,
    ) -> ShellTransport:
        """Open a remote shell-execution channel to ``device``.

        Credentials come from ``device.access_config`` (``ssh`` today; a
        ``winrm`` section selects the WinRM transport once the host implements
        it). Caller owns the transport lifecycle (``close()`` in a finally).
        """
        ...

    async def run_probe(
        self,
        check_type: str,
        address: str,
        options: dict[str, Any],
    ) -> ProbeResult:
        """Run a registered probe (``tcp_connect``/``icmp_ping``/``http_health``/
        ``dns_resolve``/…) against ``address``.

        The probe implementation comes from the host's ``hegemony.probes``
        registry — the same probes the background monitor uses — so one-shot
        ``probe.*`` handlers share a single implementation with monitors.
        Raises ``KeyError`` if ``check_type`` is not registered.
        """
        ...

    def is_check_registered(self, check_id: str) -> bool:
        """Whether ``check_id`` is a known, registered probe/check type.

        Backs ``monitor.*`` config validation without the handler importing the
        host probe registry.
        """
        ...

    async def start_monitor(
        self,
        config: dict[str, Any],
        resolved_targets: list[dict[str, Any]],
        *,
        run_id: str,
        step_id: str | None,
        step_run_id: str | None,
        phase: str | None,
    ) -> str:
        """Start a background connectivity monitor and return its db id.

        The host owns the monitor machinery (``MonitorManager`` + the engine's
        until-join / run-cleanup semantics stay host forever); the ``monitor.*``
        handler shells assemble ``config`` and the resolved target dicts
        (``{instance_id, selector_index, selector_type, role, device_id,
        address}``) and hand them here. Raises on failure.
        """
        ...

    async def stop_monitor(self, monitor_id: str, *, reason: str = "step_requested") -> bool:
        """Stop a running background monitor; returns whether one was stopped."""
        ...

    async def fetch_run_attachments(self, run_id: str) -> list[dict]:
        """Fetch the attachments resolved for a run (``filename``/``content`` dicts)."""
        ...

    async def fetch_run_step_outputs(self, run_id: str) -> dict[str, dict[str, Any]]:
        """Fetch completed step outputs for a run, keyed by step id."""
        ...

    async def fetch_run_artifacts(self, run_id: str) -> list[dict]:
        """Fetch the evidence artifacts produced during a run."""
        ...

    async def upload_binary_artifact(
        self,
        run_id: str,
        name: str,
        file_path: str,
        *,
        step_run_id: str | None = None,
        step_id: str | None = None,
        phase: str | None = None,
        content_type: str | None = None,
        kind: str = "downloadable_file",
        target_role: str | None = None,
        device_id: str | None = None,
    ) -> bool:
        """Stream a file to run artifact storage; best-effort, returns success."""
        ...
