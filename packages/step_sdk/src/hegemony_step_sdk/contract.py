# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The step-handler contract: context, result, and base class.

A handler implements the work one flow step performs. The host resolves
templates/secrets just-in-time, builds a :class:`HandlerContext` (targets,
resolved config/params, injected :class:`~hegemony_step_sdk.services.HandlerServices`),
calls :meth:`BaseHandler.execute`, and persists the returned
:class:`HandlerResult` (summary, metrics, evidence artifacts, chainable output).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, TypeVar
from uuid import UUID

from .enums import StepKind
from .services import HandlerServices

if TYPE_CHECKING:
    from pydantic import BaseModel

_ConfigT = TypeVar("_ConfigT", bound="BaseModel")

#: Maximum characters per stdout/stderr field stored in output for step chaining.
MAX_CHAIN_OUTPUT_CHARS = 4096

#: Platform string assumed for device transports when a step doesn't specify one.
DEFAULT_DEVICE_PLATFORM = "ios-xe"

#: ``attrs.milestone`` value the UI's Logs tab keys on for terminal output.
OUTPUT_MILESTONE = "output"

#: Preferred maximum characters per emitted output event (split on line
#: boundaries). Each event is one HTTP POST plus one row-locked insert
#: host-side, so emissions batch whole command results rather than lines.
OUTPUT_EVENT_CHUNK_CHARS = 8_192

#: Cap on total characters emitted per call to
#: :meth:`HandlerContext.emit_output`. Full output always remains available
#: in the step's evidence artifacts; the event stream is a live view.
OUTPUT_EVENT_MAX_CHARS = 65_536

#: Marker line appended when an emission is cut at OUTPUT_EVENT_MAX_CHARS.
OUTPUT_TRUNCATION_NOTICE = "… [output truncated — full output in artifacts]"

#: Default for :attr:`BaseHandler.run_timeout_margin_seconds`: the time a
#: handler gets past its own time limit to save its output and report back.
DEFAULT_RUN_TIMEOUT_MARGIN_SECONDS = 60


def _chunk_on_line_boundaries(text: str, chunk_chars: int) -> list[str]:
    """Split ``text`` into chunks of at most ``chunk_chars``, preferring newlines.

    A single line longer than ``chunk_chars`` is hard-split rather than
    emitted oversized.
    """
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in text.splitlines(keepends=True):
        while len(line) > chunk_chars:
            if current:
                chunks.append("".join(current))
                current, current_len = [], 0
            chunks.append(line[:chunk_chars])
            line = line[chunk_chars:]
        if current_len + len(line) > chunk_chars and current:
            chunks.append("".join(current))
            current, current_len = [], 0
        current.append(line)
        current_len += len(line)
    if current:
        chunks.append("".join(current))
    return chunks


@dataclass
class HandlerResult:
    """Result from handler execution."""

    success: bool
    summary: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    output: dict[str, Any] = field(default_factory=dict)


class InvalidConfigError(ValueError):
    """A step's config failed its handler's validation (see :meth:`BaseHandler.parse_config`)."""

    def __init__(self, handler_id: str, errors: list[str]) -> None:
        self.handler_id = handler_id
        self.errors = list(errors)
        super().__init__(f"Invalid {handler_id or 'step'} config: {'; '.join(self.errors)}")

    def result(self) -> HandlerResult:
        """The failed step result that reports these errors."""
        return HandlerResult(success=False, error=str(self), summary="Config validation failed")


@dataclass(frozen=True, slots=True)
class HandlerTargeting:
    """Which target selectors a handler's steps support in the flow editor.

    ``roles`` shows the target picker, ``ips`` the additional-IP list,
    ``multi_role`` allows selecting more than one target.
    """

    roles: bool = True
    ips: bool = True
    multi_role: bool = True


def _device_identity_key(device: dict[str, Any]) -> tuple[str, str] | None:
    """Return a stable target-device identity key when one is available."""
    device_id = device.get("id")
    if isinstance(device_id, str) and device_id.strip():
        return ("id", device_id.strip())

    provider_id = device.get("provider_id")
    external_id = device.get("external_id")
    if (
        isinstance(provider_id, str)
        and provider_id.strip()
        and isinstance(external_id, str)
        and external_id.strip()
    ):
        return ("provider_external", f"{provider_id.strip()}:{external_id.strip()}")

    for field_name in ("external_id", "hostname", "mgmt_host", "name"):
        value = device.get(field_name)
        if isinstance(value, str) and value.strip():
            return (field_name, value.strip())

    return None


def resolve_target_devices_for_roles(
    target_devices_by_role: dict[str, list[dict[str, Any]]],
    target_roles: list[str],
) -> list[dict[str, Any]]:
    """Resolve role-scoped target devices while preserving order and uniqueness."""
    devices: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    for role in target_roles:
        for device in target_devices_by_role.get(role, []):
            identity_key = _device_identity_key(device)
            if identity_key is not None:
                if identity_key in seen_keys:
                    continue
                seen_keys.add(identity_key)
            devices.append(device)
    return devices


@dataclass
class HandlerContext:
    """Context provided to handlers during execution."""

    # Run context
    run_id: str
    flow_id: str
    step_run_id: str
    step_id: str

    # Flow/run names for templating
    flow_name: str = ""
    run_name: str = ""

    # Target devices grouped by role: role_name -> list of device dicts
    target_devices_by_role: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    # Step's target roles (which roles this step should run against)
    target_roles: list[str] = field(default_factory=list)
    # Full target selectors (includes IP targets, not just roles)
    target_selectors: list[dict[str, Any]] = field(default_factory=list)
    # Direct IP targets resolved by API target selectors (from `ip` selectors).
    step_target_ips: list[str] = field(default_factory=list)

    # Handler configuration: merged from step.config + step.params
    # This contains handler-specific settings like commands, check_type, etc.
    config: dict[str, Any] = field(default_factory=dict)

    # Flow-level inputs: template variables like target_version, interface_name
    # Use for Jinja2 template rendering in commands, not for handler settings
    params: dict[str, Any] = field(default_factory=dict)

    # Completed outputs of preceding steps, keyed by node id (for handlers that
    # render their own templates with {{ steps['node'].summary }} access).
    step_outputs: dict[str, Any] = field(default_factory=dict)

    # Timeout
    timeout_seconds: int = 300
    # Attempt number for this step execution (1-based)
    attempt: int = 1
    # File attachment selection (null = all, [] = none, entries = selective)
    mounted_files: list[str] | None = None

    # Whether the run's shared workspace should be mounted at /shared for
    # container steps (set when the step is pinned to a shared/explicit worker).
    shared_workspace: bool = False

    # Host facilities (device transports, secret/template resolution, internal
    # API access) — set by the host; None only in unit tests that don't use them.
    services: HandlerServices | None = None

    # Progress callback (set by the host's execute_step activity)
    # Signature: async (message: str, device_id: str | None, attrs: dict | None) -> bool
    _emit_progress: Any = None

    # The step's free-form key=value tags, exactly as the author wrote them
    # on the node (``env=prod``, ``risk=high``, ``phase=VERIFY`` ...).
    # ``phase`` and ``kind`` are ordinary keys of this map, not fields of
    # their own: ``ctx.tags.get("phase", "")``. Treat the map as read-only:
    # nothing enforces that, but a change here stays local to this context
    # instance and never reaches the platform. Empty when the step has none.
    tags: dict[str, str] = field(default_factory=dict)

    async def emit_progress(
        self,
        message: str,
        device_id: str | None = None,
        attrs: dict[str, Any] | None = None,
    ) -> bool:
        """Emit a progress event for real-time UI updates.

        Use this to provide visibility into long-running operations like:
        - File transfers (starting, progress, complete)
        - Install stages (extracting, verifying, activating)
        - Reboot/reconnect status
        - Verification steps

        Args:
            message: Human-readable progress message
            device_id: Optional device ID this progress relates to
            attrs: Optional additional attributes (e.g., {'progress_pct': 50})

        Returns:
            True if event was emitted successfully
        """
        if self._emit_progress:
            return await self._emit_progress(message, device_id, attrs)
        return False

    async def emit_output(
        self,
        text: str,
        *,
        stream: str = "stdout",
        device: dict[str, Any] | None = None,
        command: str | None = None,
    ) -> bool:
        """Emit command/session output for the UI's live terminal (Logs tab).

        Events carry ``attrs={"milestone": "output", "stream": ...}`` — the
        shape the Logs tab streams, established by ``container.run``. Long
        text is split on line boundaries into events of at most
        :data:`OUTPUT_EVENT_CHUNK_CHARS` and capped at
        :data:`OUTPUT_EVENT_MAX_CHARS` with a truncation marker; evidence
        artifacts remain the durable, uncapped record.

        Best-effort like :meth:`emit_progress`: never raises, returns
        ``True`` only if every chunk was accepted.

        Args:
            text: Raw output text (batched per command/attempt, not per line).
            stream: ``"stdout"`` or ``"stderr"``.
            device: Optional device dict; its ``id`` is forwarded as the
                event's ``device_id`` only when it is a valid UUID (the host
                rejects the whole event otherwise), and its name is carried
                in ``attrs.device_name`` for display.
            command: Optional command this output belongs to (labelled into
                ``attrs.command``).
        """
        if not text:
            return False

        if len(text) > OUTPUT_EVENT_MAX_CHARS:
            text = text[:OUTPUT_EVENT_MAX_CHARS].rstrip("\n") + "\n" + OUTPUT_TRUNCATION_NOTICE

        attrs: dict[str, Any] = {"milestone": OUTPUT_MILESTONE, "stream": stream}
        device_id: str | None = None
        if device is not None:
            raw_id = device.get("id")
            try:
                device_id = str(UUID(str(raw_id)))
            except (ValueError, TypeError, AttributeError):
                device_id = None
            name = device.get("name") or device.get("mgmt_host")
            if name:
                attrs["device_name"] = str(name)
        if command:
            attrs["command"] = command_label(command)

        # Chunks are forwarded verbatim (no synthetic newlines) so the live
        # log stays a faithful view of the underlying output, matching
        # container.run's raw pass-through. The UI renders an event's final
        # unterminated fragment as its own line either way.
        ok = True
        for chunk in _chunk_on_line_boundaries(text, OUTPUT_EVENT_CHUNK_CHARS):
            try:
                sent = await self.emit_progress(chunk, device_id, dict(attrs))
            except Exception:  # noqa: BLE001 - output streaming must never fail the step
                sent = False
            ok = ok and sent
        return ok

    def require_services(self) -> HandlerServices:
        """Return the injected services, failing fast when the host didn't bind them.

        The host always binds services during step execution; only a context
        built by hand (e.g. a unit test exercising a non-device code path) may
        omit them.
        """
        if self.services is None:
            raise RuntimeError(
                "HandlerContext.services is not bound; step execution must inject HandlerServices"
            )
        return self.services

    def get_target_devices(self) -> list[dict[str, Any]]:
        """Get devices this step should target based on ``target_roles``.

        Resolved from ``target_devices_by_role`` for the roles listed in
        ``target_roles``. Handlers that require devices should validate the
        result and fail explicitly when empty.
        """
        return resolve_target_devices_for_roles(self.target_devices_by_role, self.target_roles)

    def get_target_ips(self) -> list[str]:
        """Get direct IP targets resolved by API ``ip`` selectors."""
        return list(self.step_target_ips)


class BaseHandler(ABC):
    """Base class for all step handlers.

    Handlers implement the actual logic for step execution.
    Each handler must:
    - Define its ID (used for registry lookup)
    - Implement execute() method
    - Return HandlerResult with success/failure and evidence
    """

    # Handler ID used for registry lookup (e.g., "checks.connectivity")
    handler_id: str = ""

    # Step kinds the handler suits. Informational only: the platform lists
    # them as the plugin's capabilities, and neither the engine nor the flow
    # editor reads them. A step's ``kind`` tag is free-form and changes nothing
    # about how the step runs (timeouts, retries, approvals).
    supported_kinds: list[StepKind] = []

    # Config keys that must NOT be pre-resolved by the step template engine and
    # instead reach the handler as raw templates (the handler renders them itself
    # with its own context, e.g. the notification single-JIT renderer).
    raw_config_keys: frozenset[str] = frozenset()

    # --- Registry/editor metadata (served via the step-handler-types endpoint) ---

    # Human-readable name for editor pickers; falls back to handler_id when empty.
    display_name: str = ""
    # One-line description shown alongside the display name.
    description: str = ""
    # Editor grouping (e.g. "Checks", "Actions", "Upgrade", "Monitors").
    category: str = ""
    # Hidden handlers stay registered and executable (existing flow definitions
    # keep resolving) but are omitted from editor pickers — internal handlers.
    hidden: bool = False
    # Built-in step timeout for this handler when neither the step policy nor
    # the flow sets one. Long-running handlers (device upgrades, child flows)
    # declare hours here; the engine also derives its heartbeat treatment from
    # it, instead of string-matching on handler ids. None -> engine default.
    default_timeout_seconds: int | None = None
    # Config field holding the handler's own time limit for the whole step, in
    # seconds (container.run's ``timeout_seconds``, probe.wait_reachable's
    # ``max_wait_seconds``). The handler stops its work at that limit; the host
    # raises the step's timeout to the limit plus ``run_timeout_margin_seconds``
    # so the step is not cancelled first, with its output lost. Declare it only
    # for a field the handler enforces itself and that ``config_model`` has.
    # A per-operation limit (one command, one probe attempt) is not one.
    run_timeout_field: str | None = None
    # Time the handler needs past its own limit to save its output and report.
    run_timeout_margin_seconds: int = DEFAULT_RUN_TIMEOUT_MARGIN_SECONDS
    # Which target selectors the editor offers for this handler's steps.
    targeting: HandlerTargeting = HandlerTargeting()
    # True for handlers that launch step containers on the platform's sandbox
    # (container.run and the tool handlers built on its runner). The host gives
    # such steps the container treatment: the flow's egress policy is enforced
    # on the container's network, options must live in the step's params, and
    # the editor renders the egress policy editor. Worker-side handlers keep
    # False; their own dials go through ``services.enforce_egress``.
    container_backed: bool = False
    # True for container-backed handlers whose container calls the platform API
    # itself (tf.* steps use the managed state backend). The host lets such a
    # step's container reach the API endpoint through the flow's egress policy;
    # what the container may do there is limited by the short-lived token it
    # gets from ``services.open_state_backend``.
    platform_api_access: bool = False
    # True for container-backed handlers that build an image (container.build)
    # and push it into the organization's namespace of the platform registry,
    # to another registry, or nowhere. The host then asks for the step's
    # registry token with push rights on the organization's own image names
    # when it runs a registry, decides from the flow's egress policy the
    # network the build's RUN instructions get and whether the step may push
    # to other registries, and serves all of it as
    # ``ContainerRuntime.image_build``.
    builds_images: bool = False
    # True for handlers that keep run-scoped state keyed by the step's node id
    # (tf.plan's working directory under /shared, tf.apply's lookup of the
    # plan step's output). Two executions of one node at the same time would
    # share that state, so the host refuses such steps in the body of a loop
    # with parallel iterations, as it does for set_vars.
    node_scoped_state: bool = False
    # Pydantic model describing the handler's config: the single source for UI
    # field rendering (JSON schema + x_widget/x_show_when extensions), for
    # save/run-time validation, and, through :meth:`parse_config`, for the
    # values the handler runs with. Its defaults are the handler's defaults.
    # None until a handler declares one.
    config_model: type[BaseModel] | None = None
    # Initial config the editor seeds for a newly added step of this handler.
    default_config: dict[str, Any] = {}

    @abstractmethod
    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Execute the handler logic.

        Args:
            ctx: Execution context with targets, config, params

        Returns:
            HandlerResult with success/failure and evidence
        """
        pass

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate handler-specific configuration against ``config_model``.

        Handlers without a ``config_model`` accept any config. Override only for
        semantic checks a schema cannot express.

        Returns:
            List of validation error messages (empty if valid)
        """
        if self.config_model is None:
            return []
        from pydantic import ValidationError

        try:
            self.config_model.model_validate(config)
        except ValidationError as exc:
            return [
                ".".join(str(part) for part in error["loc"]) + f": {error['msg']}"
                if error["loc"]
                else error["msg"]
                for error in exc.errors()
            ]
        return []

    def parse_config(self, config: Mapping[str, Any], model: type[_ConfigT]) -> _ConfigT:
        """Validate a step's config and return it parsed as ``model``.

        Runs :meth:`validate_config` (the schema and any semantic checks), then
        ``model.model_validate``. Read the settings from the result rather than
        with ``ctx.config.get``: the result carries the model's defaults, its
        type conversion (a rendered template is a string), and the old names a
        field still accepts through ``validation_alias``. ``model`` is normally
        :attr:`config_model`.

        Raises:
            InvalidConfigError: the config is invalid; ``exc.result()`` is the
                failed step result that reports it.
        """
        errors = self.validate_config(dict(config))
        if errors:
            raise InvalidConfigError(self.handler_id, errors)
        return model.model_validate(dict(config))

    def template_errors(self, config: dict[str, Any]) -> list[str]:
        """Refuse template uses in ``config`` that would be unsafe once rendered.

        The host calls this with the step's config as written, before it renders
        any ``{{ }}`` template, every time the step runs, and fails the step on
        any error. Override it when a rendered value could change what the step
        does, e.g. a value spliced unquoted into a shell command line. The
        messages are stored with the step's result, so they should name the
        field and line, not quote the template.

        Returns:
            List of error messages (empty if the templates are acceptable)
        """
        return []


def command_label(command: str, max_len: int = 80) -> str:
    """Short single-line display label for a command-derived artifact name.

    Script-shaped commands (multi-line bodies, long one-liners) make unwieldy
    artifact names and download filenames; the full command stays in the
    artifact content. Takes the first non-empty line, ellipsized to
    ``max_len``.
    """
    stripped = command.strip()
    first_line = stripped.splitlines()[0].strip() if stripped else stripped
    if len(first_line) > max_len:
        return first_line[: max_len - 1].rstrip() + "\u2026"
    return first_line
