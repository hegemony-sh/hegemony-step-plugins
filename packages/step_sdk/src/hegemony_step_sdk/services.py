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

from collections.abc import Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .probes import ProbeResult

if TYPE_CHECKING:
    import httpx

    from .transports import DeviceCredentials


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
class ImageCache:
    """The platform registry a step may keep copies of the images it pulls in.

    Served inside :class:`ContainerRuntime` when the platform runs its own
    registry. A step with ``cache_image`` on (the default) looks for a copy of
    its image under ``namespace`` first, then under each of ``read_namespaces``,
    and pulls from upstream only when none holds the image's current digest;
    the copy it then saves goes under ``namespace`` alone. The host writes the
    registry's login (a short-lived step token) into the step's Docker
    configuration (``ContainerRuntime.docker_config_dir``), so the daemon's
    pulls and the handler's pushes authenticate with it and the handler's own
    HTTP calls to ``api_url`` reuse it.
    """

    # Host name image references use for the platform registry, as the
    # sandbox daemon pulls from it (``registry.hegemony.internal``).
    registry: str
    # Base URL the handler reaches the registry's HTTP API at from the worker
    # (``http://registry.hegemony.internal``); scheme included, no path.
    api_url: str
    # Repository prefix the step reads first and writes its copies under
    # (``orgs/acme``). Copies live at ``<namespace>/<upstream host>/<repo>``.
    namespace: str
    # Read-only prefixes consulted after ``namespace``, in order (``global``).
    read_namespaces: tuple[str, ...] = ()


#: :attr:`ImageBuild.network` values: the network a build's ``RUN``
#: instructions get. ``default`` is the sandbox daemon's default network.
BUILD_NETWORK_DEFAULT = "default"
BUILD_NETWORK_NONE = "none"


@dataclass(frozen=True, slots=True)
class ImageBuild:
    """How a step that builds an image names it, where it may push it, and its build's network.

    Served inside :class:`ContainerRuntime` to handlers that declare
    ``builds_images`` (``container.build``). An image the step names without
    a registry host goes under ``<registry>/<namespace>/<name>:<tag>``. With
    ``push`` the platform runs its registry and granted the step push access
    to its organization's image names: the host writes the step's registry
    login (a short-lived token whose grant covers those names) into the step's
    Docker configuration (``ContainerRuntime.docker_config_dir``), which the
    build's push reads. Without it the platform runs no registry, and the
    image is built into the sandbox daemon only, under the name it would have
    there. An image named with its own registry host (``ghcr.io/acme/tool``)
    is pushed to that registry with the organization's login for the host
    from the same Docker configuration, and only when ``external_push`` says
    the step may.
    """

    # Host name image references use for the platform registry
    # (``registry.hegemony.internal``), also when the platform runs none: the
    # images built into the sandbox then carry the name they would have there.
    registry: str
    # Repository prefix the image goes under (``orgs/acme``). The name the
    # step gives goes after it; a first segment shaped like a registry host
    # (a dot, or ``localhost``) is reserved for cached copies and refused.
    namespace: str
    # The network the build's RUN instructions get: ``default`` when the flow's
    # egress policy for the step is open (open mode, no deny rules), ``none``
    # otherwise. The host decides; the handler only applies it. Fail closed:
    # anything but ``default`` builds without network.
    network: str = BUILD_NETWORK_NONE
    # Whether the platform registry takes the image: False when the platform
    # runs none, and the image stays in the sandbox daemon, unpushed. True by
    # default because a host older than the field serves this value only with
    # a push grant.
    push: bool = True
    # Whether the step may push to a registry other than the platform's (an
    # image named with its own registry host). The sandbox daemon pushes it,
    # outside the egress policy the step's containers are held to, so a host
    # allows it only when that policy lets the step reach the network (as for
    # ``network``). Fail closed: a host older than the field allows none.
    external_push: bool = False


@dataclass(frozen=True, slots=True)
class ContainerRuntime:
    """The platform's container-execution environment served to the run_container handler."""

    docker_bin: str
    shared_workspaces_enabled: bool
    shared_workspace_root: str
    shared_workspace_volume: str
    # The sandbox Docker daemon every flow container runs on (e.g.
    # ``tcp://dind:2375``, or an explicit ``unix:///path/to/docker.sock``).
    # Required and non-empty: ``container.run`` refuses an empty value or a bare
    # ``unix://`` rather than inheriting the worker's own environment, which
    # would reach the worker's Docker daemon instead of the sandbox. The handler
    # points ``DOCKER_HOST`` at this daemon on every docker invocation it spawns
    # — per invocation, never process-wide, and never in the ``docker create``
    # argv (selection is environment, not arguments).
    docker_host: str
    # Files larger than this are skipped when harvesting generated artifacts.
    artifact_max_file_size_bytes: int = 52_428_800
    # Docker network to attach the step container to (``--network``), used by
    # the platform's egress-policy enforcement: the worker provisions a
    # policy-scoped network on the sandbox daemon and names it here (``none``
    # for deny-all). Empty means no policy network — default networking.
    # An explicit config-level ``network_mode`` (admin host access) wins.
    docker_network: str = ""
    # Hardware address the container must take on ``docker_network``
    # (``--mac-address``). The worker derives it from the step run's own id so
    # it can scope this step's egress packet counters to this container alone;
    # a policy network is shared by every step under the policy, so counters
    # written against the subnet belong to all of them at once. Empty means let
    # Docker choose one — the step runs identically, and its egress report
    # covers the whole policy network instead of just itself.
    docker_mac: str = ""
    # Directory holding the Docker configuration (``config.json``) for this
    # step: the run organization's logins for external container registries,
    # written by the host before the step and removed when it ends. The
    # handler points ``DOCKER_CONFIG`` at it on every docker invocation, so
    # both pull paths (Engine API and the ``docker pull`` fallback) find the
    # login for the image's host. Empty means the worker's own configuration
    # applies, as before: pulls run anonymously unless it says otherwise.
    docker_config_dir: str = ""
    # The platform registry a step may cache its image in (see
    # :class:`ImageCache`). None means the platform has no registry: images
    # are pulled from their own registry every time, as before, and a step's
    # ``cache_image`` option has no effect.
    image_cache: ImageCache | None = None
    # How a step that builds an image names it and where it may push it (see
    # :class:`ImageBuild`). None means the step may not build: the handler
    # does not declare ``builds_images``, the host could not grant the step
    # access to the platform registry it runs, or the host predates builds
    # without a registry (it served the value only with one). A building
    # handler fails then.
    image_build: ImageBuild | None = None


@dataclass(frozen=True, slots=True)
class StateBackendAccess:
    """How a step container reaches one platform-managed Terraform/OpenTofu state.

    Served by :meth:`HandlerServices.open_state_backend` for the tools' ``http``
    backend: the addresses and methods map one-to-one onto its ``TF_HTTP_*``
    settings. ``password`` is a short-lived token limited to this state and this
    step; the host registers it for redaction and revokes it when the context
    exits (and again when the run ends). ``extra_hosts`` maps host names in the
    addresses to IP addresses the container must be given (``--add-host``),
    because a sandbox container may not resolve the platform's service names.
    """

    address: str
    lock_address: str
    unlock_address: str
    username: str
    password: str = field(repr=False)
    lock_method: str = "POST"
    unlock_method: str = "DELETE"
    extra_hosts: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SecretWriteResult:
    """What :meth:`HandlerServices.write_secret` stored, never the values themselves.

    ``path`` is the path the step asked for, relative to the run organization's
    secret root (``certs/web``). ``reference`` is how a later step reads the
    secret back, without the key segment: append ``/<key>`` and use it as a
    bare reference or inside ``{{ secret('...') }}``
    (``vault://orgs/acme/secrets/certs/web`` + ``/cert``). ``keys`` names every
    key the secret holds after the write, sorted: the keys written, plus the
    keys kept when the write merged. ``created`` is True when no secret existed
    at the path before the write.
    """

    path: str
    reference: str
    keys: tuple[str, ...]
    created: bool


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

    async def resolve_device_credentials(self, device: dict[str, Any]) -> DeviceCredentials:
        """Resolve ``device.access_config`` into login material for an external tool.

        For handlers that hand credentials to a tool running in a step container
        (an Ansible inventory, say) instead of dialling the device through
        :meth:`connect`. The host resolves the references in the run's org and
        registers every secret value for redaction before returning.

        Raises ``ValueError`` when the device's references are missing or
        malformed (no username, neither a password nor a private key, a broken
        jump-host block).
        """
        ...

    # --- Secret store writes -------------------------------------------------
    #
    # Backend-neutral access to the run organization's own secret store, for
    # handlers declaring ``writes_secrets`` (``secret.write``). The contract
    # below binds the HOST; it is shared by all three methods:
    #
    # - ``path`` is relative to the run organization's own secret root:
    #   slash-separated segments, no leading slash, no ``..`` segment, no
    #   ``scheme://``. The host builds the backend path from it (for example
    #   ``orgs/<org>/secrets/<path>`` on the organization's writable backend);
    #   a handler never names a backend, a scheme, or another organization.
    # - The host refuses, with ``PermissionError``: a handler that does not
    #   declare ``writes_secrets``; an organization whose admins have not
    #   enabled secret writes by steps; a path outside the prefixes the
    #   organization allows steps to write (an admin setting); a path that
    #   would land in another organization's namespace or in the platform's
    #   shared organization; and, for writes and deletes, a backend marked
    #   read-only. Reads follow the same path rules, so a step reads back only
    #   what it may write.
    # - A malformed path (or, for writes, malformed values) raises
    #   ``ValueError``; a store that cannot be reached or is not configured
    #   (no writable backend, backend error) raises ``RuntimeError``. Messages
    #   name paths and key names, never values.
    # - Every value read or written is registered for redaction from the
    #   step's output, events, and artifacts before the call returns, and
    #   before the host emits anything about it.
    # - Every call records an audit event naming the run, the step, the
    #   path and, for writes, the key names (never values).
    # - A write or delete that raises may still have been applied (the
    #   backend stored the values and then timed out, or the audit event
    #   failed afterwards). A caller that needs to know what the store holds
    #   after an error reads it back with ``read_secret``.
    # - On a store that keeps versions (a KV v2 engine, say), a replaced or
    #   deleted secret's old values must not stay readable through the
    #   store's history: the host destroys the versions it replaces or
    #   deletes, or keeps at most one version. ``read_secret`` treats a
    #   secret whose latest version is deleted (soft-deleted) as absent.
    # - Hosts older than this SDK version lack these methods. A handler checks
    #   ``getattr(services, "write_secret", None)`` (and the others it uses)
    #   before calling, and fails with a clear message when they are missing.
    #   A host that has them but does not support secret writes raises
    #   ``NotImplementedError`` (the default here), which a handler reports
    #   the same way.

    async def read_secret(self, path: str) -> dict[str, str] | None:
        """Read every key of the secret at ``path`` in the run organization's store.

        Returns ``{key: value}``, or None when no secret exists at ``path``.
        On a store that keeps versions, a secret whose latest version is
        deleted (soft-deleted) does not exist: None, never an older version.
        The values are registered for redaction before this returns. Only for
        handlers declaring ``writes_secrets``; the path rules and errors are
        those of :meth:`write_secret` (a read-only backend is not refused).

        Raises ``PermissionError`` (refused), ``ValueError`` (malformed path)
        or ``RuntimeError`` (store unavailable). Hosts without support raise
        ``NotImplementedError``; a platform older than this method has no
        such attribute at all, so look it up with ``getattr``.
        """
        raise NotImplementedError

    async def write_secret(
        self, path: str, values: Mapping[str, str], *, merge: bool = False
    ) -> SecretWriteResult:
        """Store ``values`` as the keys of the secret at ``path`` in the run organization's store.

        ``path`` is relative to the organization's own secret root
        (``certs/web``: slash-separated segments, no leading slash, no ``..``,
        no scheme); the host builds the backend path. ``values`` maps key
        names to string values and holds at least one key. With ``merge``
        False the secret holds exactly ``values`` afterwards: keys it had
        that are not in ``values`` are removed. With ``merge`` True the keys
        in ``values`` are set and every other key the secret holds is kept
        (the host reads and writes the secret; that is not atomic against
        another writer of the same path).

        The host registers every value for redaction before anything is
        emitted, refuses a handler without ``writes_secrets``, an
        organization without step secret writes enabled, a path outside the
        organization's allowed prefixes, another organization's namespace,
        the platform's shared organization and a read-only backend, and
        records an audit event naming the run and step, the path and the key
        names. Returns what was stored as a :class:`SecretWriteResult`,
        which carries the reference later steps read the keys through and
        never the values.

        On a store that keeps versions, the values this write replaces must
        not stay readable through the store's history: the host destroys the
        version it replaces, or keeps at most one.

        Raises ``PermissionError`` (refused), ``ValueError`` (malformed path,
        no keys, an invalid key name, a non-string value) or ``RuntimeError``
        (store unavailable). A call that raised may still have stored the
        values (the backend committed and then timed out, or the audit event
        failed afterwards): read the secret back to learn what it holds.
        Hosts without support raise ``NotImplementedError``; a platform older
        than this method has no such attribute at all, so look it up with
        ``getattr`` and fail clearly.
        """
        raise NotImplementedError

    async def delete_secret(self, path: str) -> bool:
        """Delete the secret at ``path`` in the run organization's store, every key of it.

        Returns True when a secret was deleted, False when none existed at
        ``path``. On a store that keeps versions, every version is destroyed,
        not only marked deleted, so no old value stays readable through the
        store's history. Only for handlers declaring ``writes_secrets``; the
        path rules, refusals (a read-only backend included), audit event and
        errors are those of :meth:`write_secret`, and like a write, a delete
        that raised may still have been applied: read the path back to learn
        whether the secret is gone. Hosts without support raise
        ``NotImplementedError``; a platform older than this method has no
        such attribute at all, so look it up with ``getattr``.
        """
        raise NotImplementedError

    async def sync_inventory(
        self, provider: str, *, max_age_seconds: int | None = None
    ) -> Mapping[str, Any]:
        """Sync one of the run organization's inventory providers now.

        For handlers declaring ``syncs_inventory`` (``inventory.sync``), so a
        flow can see what its source of truth holds right now (a device a
        previous step just created there). ``provider`` is the provider's id
        (``netbox:primary``) or its name (``primary``); the host finds only
        the run organization's own providers. With ``max_age_seconds``, no
        sync runs when the provider's last sync succeeded no longer ago than
        that.

        Returns a mapping with ``status``: ``ok``, ``partial`` (devices and
        sites synced, some other object type failed) or ``error`` for a sync
        that ran; ``fresh`` when none ran because the last one is recent
        enough; ``busy`` when none ran because another sync of the provider
        is running (ask again later). Also ``provider_id``,
        ``provider_name``, ``provider_type`` and ``last_sync_at`` (ISO 8601,
        when the provider's last sync ended), and for a sync that ran
        ``history_id``, ``started_at``, ``finished_at``, ``duration_ms``,
        ``counts`` (``items_added``, ``items_updated``, ``items_unchanged``,
        ``items_stale``, ``items_restored`` and the same for ``sites_``) and
        ``error_message``. These key names are the contract between host and
        handler: a host may add keys, but never renames or removes one.

        The call returns when the sync has ended, which can take as long as
        the host's sync deadline. The host refuses, with
        ``PermissionError``, a handler without ``syncs_inventory`` and a
        provider an administrator has not opened to flows; raises
        ``LookupError`` for a provider the organization does not have,
        ``ValueError`` for a malformed request or a name several providers
        share, and ``RuntimeError`` when it cannot be reached, the provider
        is disabled, or the step or run has ended. Each sync is audited with
        the run and step as the actor. Hosts without support raise
        ``NotImplementedError``; a platform older than this method has no
        such attribute at all, so look it up with ``getattr``.
        """
        raise NotImplementedError

    def open_state_backend(
        self, name: str, *, ttl_seconds: int, hold_until_apply: bool = False
    ) -> AbstractAsyncContextManager[StateBackendAccess]:
        """Open access to the run org's managed state ``name`` for this step's container.

        Only for handlers declaring ``platform_api_access``. The state is created
        on first write. Access lasts at most ``ttl_seconds`` and is revoked when
        the context exits. Raises ``RuntimeError`` when the platform cannot serve
        managed state (no encryption key configured, API unreachable).

        With ``hold_until_apply``, the lock the step's tool takes also holds the
        state for the run until the run applies or ends: meanwhile only the run's
        own steps can lock or write it. A platform older than this parameter
        raises ``TypeError``; pass it only when set.
        """
        ...

    async def release_state_hold(self, name: str, *, taken_by: str | None = None) -> bool:
        """End this run's hold on the managed state ``name`` early.

        For a hold taken with ``open_state_backend(..., hold_until_apply=True)``
        that no apply will end, e.g. when there is nothing to apply. ``name``
        is the state name given to ``open_state_backend``. A hold records the
        step whose lock took it: with ``taken_by`` (a step id of this run),
        the host ends the hold only when that step took it, and leaves alone
        a hold another step took, which another plan may still need. Returns
        True if a hold was released, False otherwise (the run held none,
        another step took it, or the host could not end it, which it logs).
        Hosts without support raise ``NotImplementedError``; a platform older
        than this method has no such attribute at all, so look it up with
        ``getattr``. A platform older than ``taken_by`` raises ``TypeError``
        when it is passed.
        """
        raise NotImplementedError

    async def trusted_ca_certificates(self) -> str:
        """PEM text of the run organization's trusted CA certificates.

        Administrators keep this list per organization (Settings, Trusted
        CAs) for private CAs the worker's system store does not hold. A
        handler that verifies TLS adds these certificates to the system store
        (see :mod:`hegemony_step_sdk.trust`); a ``ca_bundle`` the step sets
        replaces both, as before.

        The list is the run organization's own: the organization the run
        belongs to, which for a flow shared from the platform's shared
        organization is the organization that runs it. The shared
        organization's list never applies to another organization's run, and
        two organizations' lists are never combined. Returns ``""`` when the
        organization trusts no extra CA. The certificates are public, so
        nothing is registered for redaction.

        Raises ``RuntimeError`` when the list cannot be loaded. Hosts without
        support raise ``NotImplementedError``; a platform older than this
        method has no such attribute at all. Use
        :func:`hegemony_step_sdk.trust.org_trusted_ca_pem`, which treats both
        as "no extra CA".
        """
        raise NotImplementedError

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
        """Describe the platform's container-execution environment (docker binary, workspaces).

        For a handler declaring ``builds_images`` the runtime also carries
        :attr:`ContainerRuntime.image_build`: how the step names what it builds
        and where it may push it.
        """
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

    async def enforce_egress(
        self,
        host: str,
        port: int | None = None,
        *,
        proto: str | None = None,
        kind: str = "connection",
    ) -> None:
        """Refuse ``host``[:``port``] if the flow's egress policy forbids it.

        ``run_probe`` and ``open_shell`` already gate what they dial. A handler
        that opens its own socket — an httpx client, a raw connection — is
        outside that seam, so the policy would not see its target at all. Call
        this immediately before dialling.

        Raises the host's egress-denial error when the policy forbids the
        target; returns None when the policy permits it or none is in force.
        Hosts that implement no policy make this a no-op.
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
