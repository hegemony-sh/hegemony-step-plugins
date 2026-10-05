# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""RunContainerHandler: run commands inside Docker containers with provisioning."""

import asyncio
import codecs
import contextlib
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_CHAIN_OUTPUT_CHARS,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    ImageCache,
    StepKind,
)

from .image_cache import (
    AcquiredImage,
    CachePlan,
    RegistryClient,
    RegistryDenied,
    RegistryUnavailable,
    cache_key_tag,
    login_for,
    parse_reference,
    pin_reference,
    plan_cache,
    upstream_api_url,
)
from .pull_progress import (
    BYTES_UNKNOWN,
    EnginePullError,
    PullOutcome,
    format_size,
    parse_image_reference,
    require_docker_host,
    stream_pull,
)
from .runner import (
    COLLECT_GRACE_SECONDS,
    CONTEXT_PATH,
    MAX_COLLECTED_BYTES,
    MAX_STOP_GRACE_SECONDS,
    OUTPUT_DIR,
    SECRET_FILES_DIR,
    ContainerJob,
    ContainerJobResult,
    StagedFile,
    resolve_secret_values,
    secret_map_errors,
)
from .streams import KILL_WAIT_SECONDS, read_lines

logger = logging.getLogger(__name__)

# The image-size lookup is a caption, not a step operation: bounded well below
# any step deadline so a wedged daemon costs a missing number, not the step.
_IMAGE_INSPECT_TIMEOUT = 15.0
#: Saving a copy to the platform registry: keep this much of the step's deadline
#: for the step itself, never spend more than the cap, and skip below the floor.
_COPY_RESERVE_SECONDS = 20.0
_COPY_MAX_SECONDS = 600.0
_COPY_MIN_SECONDS = 15.0
#: Tagging the pulled image for its copy is local and quick; this is the most a
#: wedged daemon may spend on it, inside whatever the copy budget still allows.
_TAG_TIMEOUT_SECONDS = 30.0


def _registry_transport(base_url: str) -> httpx.AsyncBaseTransport | None:
    """Test seam: the transport registry lookups to ``base_url`` use (None: real HTTP)."""
    return None


def _familiar_repository(name: str) -> str:
    """``name`` as the daemon writes Docker Hub repositories: ``python``, ``me/app``."""
    for prefix in ("docker.io/", "index.docker.io/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            return name.removeprefix("library/")
    return name


def repo_digest_for(image: str, repo_digests: list[str]) -> str:
    """The ``repository@sha256:...`` entry of ``repo_digests`` for ``image``'s repository.

    ``repo_digests`` is ``docker image inspect``'s RepoDigests. The result
    keeps ``image``'s spelling of the repository; "" when no entry matches.
    """
    repository = parse_image_reference(image)[0]
    wanted = _familiar_repository(repository)
    for entry in repo_digests:
        name, sep, digest = entry.partition("@")
        if sep and digest.startswith("sha256:") and _familiar_repository(name) == wanted:
            return f"{repository}@{digest}"
    return ""


def _docker_env(docker_host: str, docker_config_dir: str = "") -> dict[str, str]:
    """Environment for a docker subprocess, selecting the sandbox daemon.

    ``docker_host`` is the worker's ``container_docker_host`` setting, surfaced
    as :attr:`ContainerRuntime.docker_host`: every docker invocation the handler
    spawns gets ``DOCKER_HOST`` pointing at the sandbox daemon on top of the
    inherited process environment. A value that names no daemon (empty, or a
    bare ``unix://``) raises :class:`ValueError` (see
    :func:`require_docker_host`): there is no environment to inherit instead,
    since the inherited one reaches the worker's own daemon.
    Daemon selection is environment, never argv, so the ``docker create`` args
    are identical whichever daemon is selected.

    ``docker_config_dir`` is :attr:`ContainerRuntime.docker_config_dir`: the
    step's own Docker configuration, holding the run organization's registry
    logins. When set it becomes ``DOCKER_CONFIG`` for the same invocations, so
    the Engine API pull (which reads ``config.json`` for its auth header) and
    the ``docker pull`` fallback agree on the login for the image's host.
    Empty leaves the inherited configuration in place.

    The override is deliberately per invocation: exporting ``DOCKER_HOST``
    process-wide would also redirect the worker's own daemon queries (e.g. the
    worker-id derivation), which must keep targeting the daemon that runs the
    worker container.

    Any inherited ``DOCKER_CONTEXT`` is dropped alongside the override: the
    docker CLI resolves ``DOCKER_HOST`` ahead of ``DOCKER_CONTEXT``, but
    carrying a context name next to a forced host is ambiguous at best (and
    other docker-compatible tooling may resolve them differently) — daemon
    selection here must have exactly one source of truth.
    """
    docker_host = require_docker_host(docker_host)
    env = {key: value for key, value in os.environ.items() if key != "DOCKER_CONTEXT"}
    env["DOCKER_HOST"] = docker_host
    if docker_config_dir and docker_config_dir.strip():
        env["DOCKER_CONFIG"] = docker_config_dir.strip()
    return env


class RunContainerConfig(BaseModel):
    """Config for ``container.run``.

    Security-sensitive semantic checks (image reference pattern, entrypoint
    shape, env key policy) live in :meth:`RunContainerHandler.validate_config`.
    """

    model_config = ConfigDict(extra="allow")

    image: str = Field(
        min_length=1,
        title="Docker Image",
        description="Full image reference including tag (e.g., registry.example.com/tools:v1)",
        json_schema_extra={"x_placeholder": "python:3.12-slim"},
    )
    cache_image: bool = Field(
        default=True,
        title="Cache image",
        description=(
            "Keep a copy of the pulled image in the platform registry, under this "
            "organization, and use it on later runs. A tag is still checked against the "
            "image's registry by digest, and the copy serves when that registry is "
            "unreachable. Turn off for an image that must come straight from its registry "
            "every time. No effect when the platform runs no registry."
        ),
    )
    command: list[str] = Field(
        default_factory=list,
        title="Command",
        description=(
            "Shell script lines joined with newlines under set -e. With no entrypoint "
            "override, the handler appends sh -c <script>; with entrypoint /bin/sh, it "
            "passes -c <script> to that shell. Leave empty to add no script."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "pwd\nprintenv\ntime sleep 5",
            "x_rows": 3,
            "x_col_span": 2,
        },
    )
    entrypoint: str | list[str] | None = Field(
        default=None,
        title="Entrypoint override",
        description=(
            "Optional Docker --entrypoint. Leave empty to use the image entrypoint. Set "
            "/bin/sh for tool images such as hashicorp/terraform so Command runs as a "
            'shell script. Advanced YAML may use list form, e.g. ["/usr/bin/env", "bash", "-lc"].'
        ),
        json_schema_extra={"x_placeholder": "/bin/sh", "x_col_span": 2},
    )
    working_dir: str = Field(
        default="/workspace",
        title="Working Directory",
        description="Working directory inside the container (default: /workspace)",
    )
    timeout_seconds: int = Field(
        default=300,
        ge=1,
        title="Timeout (seconds)",
        description="Max execution time in seconds",
    )
    memory: str = Field(
        default="",
        title="Memory Limit",
        description="e.g., 256m, 1g",
        json_schema_extra={"x_placeholder": "512m", "x_advanced": True},
    )
    cpus: str = Field(
        default="",
        title="CPU Limit",
        description="e.g., 0.5, 2.0",
        json_schema_extra={"x_placeholder": "1.0", "x_advanced": True},
    )
    network_disabled: bool = Field(
        default=False,
        title="Disable network access",
        description=(
            "Off by default to preserve Docker networking. Turn on only when this step "
            "should run with --network=none."
        ),
        json_schema_extra={
            "x_advanced": True,
            "x_col_span": 2,
            "x_disabled_when": {"field": "network_mode", "is_not_empty": True},
        },
    )
    network_mode: str = Field(
        default="",
        title="Network mode",
        description=(
            "Optional. Use to attach to a specific Docker network (e.g. clab-mylab) or "
            "share another container's namespace (host shares the Docker-in-Docker "
            "sandbox's, not the machine's). Disabled when network access is disabled; "
            "leave empty for default Docker networking."
        ),
        json_schema_extra={
            "x_placeholder": "host | bridge | <docker-network> | container:<name>",
            "x_advanced": True,
            "x_admin_only": True,
            "x_col_span": 2,
            "x_disabled_when": {"field": "network_disabled", "value": True},
        },
    )
    attach_docker_socket: bool = Field(
        default=False,
        title="Attach sandbox Docker socket",
        description=(
            "Mounts the Docker-in-Docker sandbox daemon's /var/run/docker.sock into the "
            "container, giving it full control of the sandbox daemon (not the host's). "
            "Required by tools that start their own containers, like containerlab. "
            "Off by default."
        ),
        json_schema_extra={"x_advanced": True, "x_admin_only": True, "x_col_span": 2},
    )
    privileged: bool = Field(
        default=False,
        title="Run as privileged",
        description=(
            "Runs the container with --privileged, granting all capabilities and access "
            "to /proc/sys inside the Docker-in-Docker sandbox (needed by containerlab to "
            "adjust rp_filter, etc.). The sandbox itself runs privileged, so the step "
            "becomes a sandbox admin. Off by default."
        ),
        json_schema_extra={"x_advanced": True, "x_admin_only": True, "x_col_span": 2},
    )
    pid_mode: str = Field(
        default="",
        title="PID namespace",
        description=(
            "Optional. Share the PID namespace of the Docker-in-Docker sandbox (host) or "
            "of another container (container:<name>). Required by containerlab-in-Docker "
            "so it can resolve sibling container PIDs. Leave empty for default isolation."
        ),
        json_schema_extra={
            "x_placeholder": "host | container:<name>",
            "x_advanced": True,
            "x_admin_only": True,
            "x_col_span": 2,
        },
    )
    extra_mounts: list[str] = Field(
        default_factory=list,
        title="Extra bind mounts",
        description=(
            "One per line, format <abs-src>:<abs-dst>[:opts]. Sources resolve inside the "
            "Docker-in-Docker sandbox, not on the host. Bypasses workspace isolation; use "
            "sparingly (e.g. containerlab needs /var/run/netns shared)."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "/var/run/netns:/var/run/netns:shared\n/srv/data:/data:ro",
            "x_rows": 3,
            "x_advanced": True,
            "x_admin_only": True,
            "x_col_span": 2,
        },
    )
    egress_mode: str = Field(
        default="",
        title="Egress policy mode",
        description=(
            "Outbound firewall for this step's container, enforced on the sandbox "
            "daemon: 'open' allows everything except Deny rules, 'allow-listed' "
            "allows only Allow rules (minus Deny), 'deny-all' blocks all network "
            "access. Leave empty to inherit the flow's network policy. Cannot be "
            "combined with host-access options or 'Disable network access'."
        ),
        json_schema_extra={
            "x_placeholder": "open | allow-listed | deny-all",
            "x_advanced": True,
            "x_col_span": 2,
        },
    )
    egress_allow: list[str] = Field(
        default_factory=list,
        title="Egress allow rules",
        description=(
            "One rule per line, used with allow-listed mode: "
            "CIDR[:port[-port]][/tcp|udp] or service:port "
            "(e.g. 172.20.30.0/24, 0.0.0.0/0:443/tcp, dind:3000)."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "172.20.30.0/24\n0.0.0.0/0:443/tcp\ndind:3000",
            "x_rows": 3,
            "x_advanced": True,
            "x_col_span": 2,
        },
    )
    egress_deny: list[str] = Field(
        default_factory=list,
        title="Egress deny rules",
        description=(
            "One rule per line, same format as Allow rules. Deny always wins "
            "over Allow and is unioned with the flow policy's Deny rules."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "169.254.169.254/32",
            "x_rows": 3,
            "x_advanced": True,
            "x_col_span": 2,
        },
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        title="Environment Variables",
        description=(
            "KEY=VALUE format, one per line. Keys starting with HEGEMONY_ are reserved "
            "and will be ignored."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "MY_VAR=value\nANOTHER=123",
            "x_rows": 3,
            "x_col_span": 2,
        },
    )
    secrets: dict[str, str] = Field(
        default_factory=dict,
        title="Secret files",
        description=(
            "NAME=secret reference, one per line (a {{ secret('...') }} template or a "
            "bare reference such as vault://orgs/acme/secrets/db/password). Each value "
            "is written to /run/secrets/NAME inside the container and redacted from "
            "output; unlike environment variables, it never appears in the sandbox's "
            "container metadata."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "db_password={{ secret('vault://orgs/acme/secrets/db/password') }}",
            "x_rows": 2,
            "x_col_span": 2,
            "x_advanced": True,
        },
    )
    mounted_artifacts: list[str] | None = Field(
        default=None,
        title="Artifacts",
        description=(
            "Select which upstream step artifacts are copied into the container. Leave "
            "at All to make every upstream step artifact available by default."
        ),
        json_schema_extra={"x_widget": "mounted-artifacts", "x_col_span": 2},
    )
    mounted_step_outputs: list[str] | None = Field(
        default=None,
        title="Step Outputs",
        description=(
            "Select which upstream step output snapshots are copied into the container. "
            "Leave at All to make every upstream predecessor step output available by "
            "default."
        ),
        json_schema_extra={"x_widget": "mounted-step-outputs", "x_col_span": 2},
    )
    # Rendered by the editor's attachments widget; the selection is stored as
    # step-level data (mounted_files on the step, resolved to ctx.mounted_files),
    # not inside this config. Declared here so the schema-driven editor offers it.
    mounted_files: list[str] | None = Field(
        default=None,
        title="Attachments",
        description=(
            "Select which flow attachments are copied into the container under the "
            "attachments mount path. Leave at All to copy every flow attachment; a "
            "selector ending in / includes that folder recursively."
        ),
        json_schema_extra={"x_widget": "mounted-files", "x_advanced": True, "x_col_span": 2},
    )
    artifacts_path: str = Field(
        default="",
        title="Artifacts mount path",
        description=(
            "Absolute path inside the container where upstream step artifacts are "
            "copied. Defaults to /artifacts."
        ),
        json_schema_extra={"x_placeholder": "/artifacts", "x_advanced": True, "x_col_span": 2},
    )
    new_artifacts_path: str = Field(
        default="",
        title="New artifacts upload path",
        description=(
            "Absolute path inside the container where newly created files are harvested "
            "after the container exits: UTF-8 text files become step artifacts, and every "
            "other file is uploaded as a downloadable artifact up to the worker's per-file "
            "cap (50 MiB by default). Files the harvest drops are listed in the step's "
            "skipped-artifacts report. Defaults to /artifacts/new, or <artifacts_path>/new "
            "when you change the artifacts root."
        ),
        json_schema_extra={"x_placeholder": "/artifacts/new", "x_advanced": True, "x_col_span": 2},
    )
    attachments_path: str = Field(
        default="",
        title="Attachments mount path",
        description=(
            "Absolute path inside the container where attachments are copied. Defaults "
            "to /attachments."
        ),
        json_schema_extra={"x_placeholder": "/attachments", "x_advanced": True, "x_col_span": 2},
    )
    step_outputs_path: str = Field(
        default="",
        title="Step outputs mount path",
        description=(
            "Absolute path inside the container where completed step output snapshots "
            "are copied. Defaults to /step_outputs."
        ),
        json_schema_extra={"x_placeholder": "/step_outputs", "x_advanced": True, "x_col_span": 2},
    )
    shared_path: str = Field(
        default="",
        title="Shared workspace mount path",
        description=(
            "Absolute path inside the container where the shared run workspace is "
            "mounted when this step uses shared or explicit execution affinity. "
            "Defaults to /shared."
        ),
        json_schema_extra={"x_placeholder": "/shared", "x_advanced": True, "x_col_span": 2},
    )


_SET_E_RE = re.compile(r"^\s*set\s+-[^\n;]*e")

# Egress policy vocabulary shared with the platform's flow-level
# network_policy block. Rules are CIDR[:port[-port]][/tcp|udp] or a
# compose-service shorthand name:port resolved at enforcement time.
EGRESS_MODES = ("open", "allow-listed", "deny-all")
_EGRESS_SERVICE_RULE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9._-]{0,253}:\d{1,5}$")
_EGRESS_CIDR_RULE_RE = re.compile(
    r"^(?P<addr>\d{1,3}(?:\.\d{1,3}){3})(?:/(?P<prefix>\d{1,2}))?"
    r"(?::(?P<port>\d{1,5})(?:-(?P<port_end>\d{1,5}))?)?"
    r"(?:/(?P<proto>tcp|udp))?$"
)
# IPv6 rules bracket the address so the port colon is unambiguous; ipaddress
# does the real validation of the loosely-matched address body.
_EGRESS_CIDR6_RULE_RE = re.compile(
    r"^\[(?P<addr>[0-9A-Fa-f:]+)(?:/(?P<prefix>\d{1,3}))?\]"
    r"(?::(?P<port>\d{1,5})(?:-(?P<port_end>\d{1,5}))?)?"
    r"(?:/(?P<proto>tcp|udp))?$"
)


def _egress_port_error(rule: str, match: "re.Match[str]") -> str | None:
    """Validate the shared ``port``/``port_end`` groups; error string or None."""
    port = match.group("port")
    port_end = match.group("port_end")
    if port is not None:
        start = int(port)
        end = int(port_end) if port_end is not None else start
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            return f"egress rule {rule!r} port out of range (1-65535)"
        if end < start:
            return f"egress rule {rule!r} has an inverted port range"
    elif port_end is not None:  # pragma: no cover - regex prevents this
        return f"egress rule {rule!r} has a port range without a start"
    return None


def egress_rule_error(rule: str) -> str | None:
    """Validate one egress rule string; return an error message or None.

    Accepted forms: IPv4 ``CIDR[:port[-port]][/tcp|udp]``, IPv6
    ``[CIDR][:port[-port]][/tcp|udp]`` (bracketed), or the compose-service
    shorthand ``name:port`` (resolved against the stack's DNS at enforcement
    time). Kept in the wheel so the handler's config validation and the
    platform's flow-level policy validation agree on one vocabulary.
    """
    if not isinstance(rule, str) or not rule.strip():
        return "egress rule must be a non-empty string"
    rule = rule.strip()
    import ipaddress

    match = _EGRESS_CIDR_RULE_RE.match(rule)
    if match:
        prefix = match.group("prefix")
        try:
            ipaddress.IPv4Network(
                f"{match.group('addr')}/{prefix if prefix is not None else 32}",
                strict=False,
            )
        except ValueError as exc:
            return f"invalid CIDR in egress rule {rule!r}: {exc}"
        return _egress_port_error(rule, match)
    match6 = _EGRESS_CIDR6_RULE_RE.match(rule)
    if match6:
        prefix6 = match6.group("prefix")
        try:
            ipaddress.IPv6Network(
                f"{match6.group('addr')}/{prefix6 if prefix6 is not None else 128}",
                strict=False,
            )
        except ValueError as exc:
            return f"invalid IPv6 CIDR in egress rule {rule!r}: {exc}"
        return _egress_port_error(rule, match6)
    if _EGRESS_SERVICE_RULE_RE.match(rule):
        port = int(rule.rsplit(":", 1)[1])
        if not 1 <= port <= 65535:
            return f"egress rule {rule!r} port out of range (1-65535)"
        return None
    return (
        f"invalid egress rule {rule!r} (expected 'CIDR[:port[-port]][/tcp|udp]', "
        "'[IPv6CIDR][:port[-port]][/tcp|udp]', or 'service:port')"
    )


def _with_fail_fast_shell(command: str) -> str | None:
    """Return a stripped shell command that fails fast on intermediate errors."""
    stripped = command.strip()
    if not stripped:
        return None
    if _SET_E_RE.match(stripped):
        return stripped
    return "set -e\n" + stripped


def _matches_mounted_files(filename: str, selectors: list[str]) -> bool:
    """Check if a filename matches any mounted_files selector.

    - Selector ending with "/" → folder prefix match (recursive)
    - Selector without trailing "/" → exact file match
    """
    # Normalize filename: forward slashes only
    normalized = filename.replace("\\", "/")
    if normalized.startswith("/"):
        raise ValueError(f"Absolute paths are not allowed: {filename}")
    for sel in selectors:
        if sel.endswith("/"):
            if normalized.startswith(sel) or normalized + "/" == sel:
                return True
        else:
            if normalized == sel:
                return True
    return False


_ARTIFACT_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _sanitize_artifact_filename(name: str) -> str:
    """Turn an artifact name into a safe filesystem fragment."""
    cleaned = _ARTIFACT_FILENAME_RE.sub("_", name or "").strip("._-") or "artifact"
    return cleaned[:200]


def _normalize_container_root(value: Any, default: str) -> str:
    """Return a normalized absolute container root path."""
    if not isinstance(value, str) or not value.strip():
        return default
    normalized = value.strip().rstrip("/")
    return normalized or "/"


def _is_unset(value: Any) -> bool:
    """True for an absent or empty/whitespace-only optional field.

    These optional fields default to "" and the handler resolves that to the
    documented default at run time, so validation must treat "" the same as
    absent — otherwise a step that just fills in image + command (leaving the
    optional paths/modes at their empty defaults) fails against its own
    defaults.
    """
    return value is None or (isinstance(value, str) and not value.strip())


def _optional_str(value: Any, default: str = "") -> str:
    """The effective value of an optional string field.

    The inverse of :func:`_is_unset` on the emitting side: whitespace-only is
    "unset — use the default", never a literal to hand to docker. Without this
    a config that *passed* validation (which treats "   " as absent) would
    still emit ``--network=   `` and fail the create with an opaque docker
    error. Non-strings resolve to the default too; validation rejects them, so
    reaching here at all means the caller skipped it.
    """
    return value.strip() if isinstance(value, str) and value.strip() else default


_HOST_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


def _valid_host_name(name: str) -> str:
    """A host name for ``--add-host``; anything else is a platform bug, not user input."""
    if not isinstance(name, str) or not _HOST_NAME_RE.match(name):
        raise ValueError(f"invalid extra host name {name!r}")
    return name


def _valid_ip(address: str) -> str:
    """An IP address for ``--add-host`` (IPv6 in brackets, as docker expects)."""
    parsed = ipaddress.ip_address(address)
    return f"[{parsed}]" if parsed.version == 6 else str(parsed)


def _validate_absolute_container_path(field_name: str, value: Any, errors: list[str]) -> None:
    """Validate an absolute container path setting like /attachments or /artifacts.

    An empty/whitespace value means "unset — use the documented default"; only a
    provided value is checked for absoluteness.
    """
    if _is_unset(value):
        return
    if not isinstance(value, str) or not value.startswith("/"):
        errors.append(f"'{field_name}' must be an absolute path (start with '/')")
    elif "\0" in value:
        errors.append(f"'{field_name}' must not contain NUL bytes")
    elif ".." in value.split("/"):
        errors.append(f"'{field_name}' must not contain '..'")


def _join_container_path(base_path: str, relative_path: str) -> str:
    """Join an absolute container root with a relative path fragment."""
    clean_base = _normalize_container_root(base_path, "/")
    clean_relative = relative_path.strip().lstrip("/").rstrip("/")
    if not clean_relative:
        return clean_base
    return f"/{clean_relative}" if clean_base == "/" else f"{clean_base}/{clean_relative}"


def _resolve_new_artifacts_path(config: dict[str, Any], artifacts_path: str) -> str:
    """Resolve the absolute path used for current-step artifact uploads."""
    return _normalize_container_root(
        config.get("new_artifacts_path"), _join_container_path(artifacts_path, "new")
    )


def _stage_container_root_dir(staging_root: str, container_path: str) -> None:
    """Create an empty directory tree mirroring an absolute container path."""
    relative_path = container_path.strip().lstrip("/")
    if not relative_path:
        return

    local_path = os.path.normpath(os.path.join(staging_root, relative_path))
    if not local_path.startswith(staging_root + os.sep):
        raise ValueError(f"Invalid container path staging target: {container_path!r}")

    os.makedirs(local_path, exist_ok=True)


def _write_staged_text_file(path: str, content: Any) -> None:
    """Write a plain-text snapshot file into the staging directory."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("" if content is None else str(content))


def _write_staged_json_file(path: str, payload: Any) -> None:
    """Write a JSON snapshot file into the staging directory."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True, default=str, ensure_ascii=False)
        fh.write("\n")


# Harvested files are read in chunks so a binary payload can be abandoned as
# soon as it proves binary, rather than after it is already in memory.
_HARVEST_READ_CHUNK_BYTES = 1024 * 1024


def _read_harvested_text(file_path: str) -> str | None:
    """Return the file's UTF-8 text, or None as soon as it proves binary.

    Classification is incremental because the caller may be about to reject the
    file for exceeding the artifact cap: reading a 200 MB archive in full only
    to discard it costs the worker 200 MB of RSS for nothing, and the bytes are
    never needed anyway - a binary artifact is uploaded by streaming from its
    path. The first NUL byte or invalid sequence therefore ends the read.

    Text is still accumulated in full. Inline text artifacts are uncapped, and
    bounding them here would silently truncate ones that work today.

    Raises ``OSError`` for an unreadable file; the caller records that.
    """
    decoder = codecs.getincrementaldecoder("utf-8")()
    chunks: list[str] = []
    try:
        with open(file_path, "rb") as fh:
            while True:
                chunk = fh.read(_HARVEST_READ_CHUNK_BYTES)
                if not chunk:
                    break
                if b"\0" in chunk:
                    return None
                chunks.append(decoder.decode(chunk))
            # A trailing partial sequence is only an error once it is final.
            chunks.append(decoder.decode(b"", final=True))
    except UnicodeDecodeError:
        return None
    return "".join(chunks)


# The platform's RunArtifact.name column bounds an artifact name; a skip
# record is JSON and has no such limit.
MAX_ARTIFACT_NAME_LEN = 255

SKIP_REASON_UNREADABLE = "unreadable"
SKIP_REASON_OUTSIDE_ROOT = "outside_staging_root"
SKIP_REASON_TOO_LARGE = "too_large"

_SKIP_REASON_LABELS = {
    SKIP_REASON_UNREADABLE: "could not be read out of the harvest staging directory",
    SKIP_REASON_OUTSIDE_ROOT: "resolved outside the harvest staging directory",
    SKIP_REASON_TOO_LARGE: "larger than the worker's per-file artifact cap",
}

# Control characters are legal in filenames and would otherwise break the
# one-line-per-file skip report, or forge entries in it.
_ARTIFACT_DISPLAY_UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f]")

# The harvest log carries a sample of the skip records; the full list is on the
# step itself. An unbounded list would let one step emit a huge log entry.
_MAX_LOGGED_SKIP_RECORDS = 20


def _display_name(name: Any) -> str:
    """Flatten a harvested name for rendering into the skip report."""
    return _ARTIFACT_DISPLAY_UNSAFE_RE.sub("?", str(name))


def _is_within_directory(root: str, candidate: str) -> bool:
    """True when ``candidate`` is ``root`` itself or lives beneath it.

    Both arguments must already be resolved: this is a containment test, not a
    normalization step.
    """
    return candidate == root or candidate.startswith(root.rstrip(os.sep) + os.sep)


def _collect_generated_text_artifacts(
    staging_root: str, max_binary_size: int | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Read files harvested from the container's new-artifacts subfolder.

    Returns a tuple of ``(text_artifacts, binary_files, skipped_files)``:
    - ``text_artifacts``: UTF-8 text files as inline ``step_result`` artifacts.
    - ``binary_files``: metadata for non-text files to upload for download,
      each ``{"name", "path", "size", "content_type"}``.
    - ``skipped_files``: one ``{"name", "size", "reason"}`` record per file that
      produced no artifact - unreadable, resolved outside the staging root, or a
      binary file over ``max_binary_size``. Records, not a bare count, so the
      caller can name the dropped file and the cap it hit; a step that wrote a
      too-large archive otherwise looks like it produced nothing at all.
    """
    import mimetypes

    artifacts: list[dict[str, Any]] = []
    binary_files: list[dict[str, Any]] = []
    skipped_files: list[dict[str, Any]] = []

    if not os.path.isdir(staging_root):
        return artifacts, binary_files, skipped_files

    resolved_root = os.path.realpath(staging_root)

    for root, dirs, files in os.walk(staging_root):
        dirs.sort()
        files.sort()

        for file_name in files:
            file_path = os.path.join(root, file_name)
            # Reported in full: a skip record is JSON, so it carries the whole
            # path. Only an artifact *name* is bounded, at the point of use.
            relative_name = os.path.relpath(file_path, staging_root).replace(os.sep, "/")

            # Containment is decided on the resolved path, before the file is
            # touched at all. `docker cp` preserves symlinks rather than
            # dereferencing them, so a container that drops a symlink into its
            # new-artifacts folder would otherwise have the worker open the
            # link's target on the *host* and publish it as step evidence. A
            # lexical check cannot see that: the link's relative name is
            # perfectly ordinary.
            if not _is_within_directory(resolved_root, os.path.realpath(file_path)):
                skipped_files.append(
                    {"name": relative_name, "size": None, "reason": SKIP_REASON_OUTSIDE_ROOT}
                )
                continue

            # Not a regular file: a dangling symlink, a fifo, a device node.
            # Unharvestable, but not nothing - it was written to the folder and
            # produced no artifact, which is exactly what this report is for.
            if not os.path.isfile(file_path):
                skipped_files.append(
                    {"name": relative_name, "size": None, "reason": SKIP_REASON_UNREADABLE}
                )
                continue

            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                skipped_files.append(
                    {"name": relative_name, "size": None, "reason": SKIP_REASON_UNREADABLE}
                )
                continue

            try:
                content_text = _read_harvested_text(file_path)
            except OSError:
                skipped_files.append(
                    {"name": relative_name, "size": file_size, "reason": SKIP_REASON_UNREADABLE}
                )
                continue

            if content_text is not None:
                artifacts.append(
                    {
                        "kind": "step_result",
                        "name": relative_name[:MAX_ARTIFACT_NAME_LEN],
                        "content_text": content_text,
                    }
                )
                continue

            # Binary file: schedule for upload unless it exceeds the size cap.
            # The size decides on its own - the payload was never read past the
            # point it proved binary, and the upload streams from the path.
            if max_binary_size is not None and file_size > max_binary_size:
                skipped_files.append(
                    {"name": relative_name, "size": file_size, "reason": SKIP_REASON_TOO_LARGE}
                )
                continue

            content_type, _ = mimetypes.guess_type(file_name)
            binary_files.append(
                {
                    "name": relative_name[:MAX_ARTIFACT_NAME_LEN],
                    "path": file_path,
                    "size": file_size,
                    "content_type": content_type or "application/octet-stream",
                }
            )

    return artifacts, binary_files, skipped_files


def _describe_skipped_artifacts(
    skipped_files: list[dict[str, Any]],
    *,
    step_id: str,
    new_artifacts_path: str,
    max_binary_size: int | None,
) -> dict[str, Any]:
    """Render dropped harvest files as a ``step_result`` artifact.

    The harvest is best-effort, so a dropped file used to leave no trace on the
    run at all - only a worker log line nobody reading the run can see. This
    puts the file name, its size, and the cap it exceeded on the step itself.
    """
    cap_note = (
        f"per-file cap {max_binary_size} bytes"
        if max_binary_size is not None
        else "no per-file cap configured"
    )
    lines = [
        f"{len(skipped_files)} file(s) written to {new_artifacts_path} produced no artifact "
        f"({cap_note}).",
        "",
    ]
    for entry in skipped_files:
        size = entry.get("size")
        size_note = f"{size} bytes" if isinstance(size, int) else "size unknown"
        reason = str(entry.get("reason", ""))
        lines.append(
            f"- {_display_name(entry.get('name'))} ({size_note}): "
            f"{_SKIP_REASON_LABELS.get(reason, reason)}"
        )

    return {
        "kind": "step_result",
        "name": f"skipped_artifacts_{step_id}",
        "content_text": "\n".join(lines) + "\n",
        "content_json": {
            "new_artifacts_path": new_artifacts_path,
            "max_file_size_bytes": max_binary_size,
            "skipped": skipped_files,
        },
    }


async def _upload_generated_binary_artifacts(ctx: Any, binary_files: list[dict[str, Any]]) -> int:
    """Upload harvested binary files as downloadable run artifacts.

    Best-effort: failures are logged and skipped without failing the step.
    Returns the count of files successfully uploaded.
    """
    if not binary_files:
        return 0

    services = ctx.require_services()

    uploaded = 0
    for entry in binary_files:
        try:
            ok = await services.upload_binary_artifact(
                ctx.run_id,
                name=entry["name"],
                file_path=entry["path"],
                step_run_id=ctx.step_run_id,
                step_id=ctx.step_id,
                phase=ctx.tags.get("phase"),
                content_type=entry.get("content_type"),
                kind="downloadable_file",
            )
        except Exception as exc:  # noqa: BLE001 - upload must not fail the step
            logger.warning(
                "Failed to upload generated binary artifact",
                extra={
                    "run_id": ctx.run_id,
                    "step_id": ctx.step_id,
                    "step_run_id": ctx.step_run_id,
                    "name": entry.get("name"),
                    "error": str(exc),
                },
            )
            continue
        if ok:
            uploaded += 1
    return uploaded


def _stage_step_output_snapshots(staging_root: str, step_outputs: dict[str, Any]) -> int:
    """Materialize completed step outputs as per-step snapshot files."""
    staged_files = 0
    for step_id in sorted(step_outputs):
        if not isinstance(step_id, str) or not step_id.strip():
            continue

        raw_summary = step_outputs.get(step_id)
        summary = raw_summary if isinstance(raw_summary, dict) else {}
        safe_step_dir_name = _sanitize_artifact_filename(step_id)
        step_dir = os.path.normpath(os.path.join(staging_root, safe_step_dir_name))
        if not step_dir.startswith(staging_root + os.sep) and step_dir != staging_root:
            raise ValueError(f"Invalid step output staging target for step_id={step_id!r}")

        os.makedirs(step_dir, exist_ok=True)

        output_payload = summary.get("output", {})
        if not isinstance(output_payload, dict):
            output_payload = {}

        metrics_payload = summary.get("metrics", {})
        if not isinstance(metrics_payload, dict):
            metrics_payload = {}

        _write_staged_text_file(os.path.join(step_dir, "step_id.txt"), step_id)
        _write_staged_text_file(os.path.join(step_dir, "status.txt"), summary.get("status", ""))
        _write_staged_text_file(os.path.join(step_dir, "summary.txt"), summary.get("summary", ""))
        _write_staged_json_file(os.path.join(step_dir, "details.json"), summary)
        _write_staged_json_file(os.path.join(step_dir, "output.json"), output_payload)
        _write_staged_json_file(os.path.join(step_dir, "metrics.json"), metrics_payload)
        staged_files += 6

    return staged_files


#: Largest ``output.json`` a container.run step may hand back as ``output.data``.
#: Step outputs are chained into later steps' templates and snapshots, so they
#: stay small; bulk results belong in the new-artifacts folder.
MAX_OUTPUT_DATA_BYTES = 64 * 1024

#: Collected file that becomes a container.run step's ``output.data``.
OUTPUT_DATA_PATH = f"{OUTPUT_DIR}/output.json"


def _context_file(ctx: HandlerContext) -> StagedFile:
    """The step I/O contract's context file: which run and step this is.

    No flow inputs: ``ctx.params`` holds every input of the run, including
    values the step never references and plaintext resolved from secret
    templates, and lacks the defaults ``{{ inputs.NAME }}`` applies. A step
    that needs an input passes it through its own templated config (``env``).
    """
    payload = {
        "run_id": ctx.run_id,
        "flow_id": ctx.flow_id,
        "flow_name": ctx.flow_name,
        "run_name": ctx.run_name,
        "step_id": ctx.step_id,
        "step_run_id": ctx.step_run_id,
        "attempt": ctx.attempt,
        "tags": dict(ctx.tags),
    }
    return StagedFile(
        path=CONTEXT_PATH,
        content=json.dumps(payload, indent=2, sort_keys=True, default=str, ensure_ascii=False)
        + "\n",
    )


def _write_job_file(staging_root: str, staged_file: StagedFile) -> None:
    """Write one job file into the root staging tree at its container path."""
    path = staged_file.path
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise ValueError(f"Job file path must be absolute: {path!r}")
    if ".." in path.split("/"):
        raise ValueError(f"Job file path must not contain '..': {path!r}")
    local_path = os.path.normpath(os.path.join(staging_root, path.lstrip("/")))
    if not local_path.startswith(staging_root + os.sep):
        raise ValueError(f"Invalid job file staging target: {path!r}")
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    content = staged_file.content
    if isinstance(content, str):
        content = content.encode("utf-8")
    with open(local_path, "wb") as fh:
        fh.write(content)
    os.chmod(local_path, staged_file.mode)


def _read_output_data(collected: dict[str, bytes]) -> tuple[dict[str, Any] | None, str | None]:
    """Parse ``/hegemony/out/output.json``; returns ``(data, problem)``."""
    raw = collected.get(OUTPUT_DATA_PATH)
    if raw is None:
        return None, None
    if len(raw) > MAX_OUTPUT_DATA_BYTES:
        return None, (
            f"{OUTPUT_DATA_PATH} is {len(raw)} bytes, over the {MAX_OUTPUT_DATA_BYTES}-byte "
            "limit for step output; write bulk results to the new-artifacts folder instead."
        )
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        return None, f"{OUTPUT_DATA_PATH} is not valid UTF-8 JSON: {exc}"
    if not isinstance(data, dict):
        return None, f"{OUTPUT_DATA_PATH} must contain a JSON object, not {type(data).__name__}."
    return data, None


def _container_run_result(ctx: HandlerContext, outcome: ContainerJobResult) -> HandlerResult:
    """Map a completed container run onto ``container.run``'s step result."""
    exit_code = outcome.exit_code
    success = exit_code == 0
    summary = (
        f"Container exited with code {exit_code}"
        if success
        else f"Container failed with exit code {exit_code}"
    )
    if outcome.skipped_artifacts:
        summary += f" ({outcome.skipped_artifacts} artifact(s) skipped)"

    output: dict[str, Any] = {
        "stdout": outcome.stdout[:MAX_CHAIN_OUTPUT_CHARS],
        "stderr": outcome.stderr[:MAX_CHAIN_OUTPUT_CHARS],
    }
    evidence = list(outcome.evidence)
    data, problem = _read_output_data(outcome.collected)
    if data is not None:
        output["data"] = data
    if outcome.collect_errors:
        evidence.append(
            {
                "kind": "step_result",
                "name": f"output_not_collected_{ctx.step_id}",
                "content_text": "Could not copy the step's results out of the container, so "
                "output.data may be missing:\n"
                + "".join(
                    f"- {path}: {reason}\n"
                    for path, reason in sorted(outcome.collect_errors.items())
                ),
            }
        )
    if problem is not None:
        evidence.append(
            {
                "kind": "step_result",
                "name": f"output_data_rejected_{ctx.step_id}",
                "content_text": problem + "\n",
            }
        )

    return HandlerResult(
        success=success,
        summary=summary,
        error=None if success else f"Exit code {exit_code}",
        metrics={
            "exit_code": exit_code,
            "duration_seconds": outcome.duration_seconds,
            "image": outcome.image,
            "image_digest": outcome.image_digest,
            "image_served": outcome.image_served,
            "image_source": outcome.image_source,
            "image_cached": outcome.image_cached,
            "skipped_artifacts": outcome.skipped_artifacts,
        },
        evidence=evidence,
        output=output,
    )


class RunContainerHandler(BaseHandler):
    """Handler for running commands inside Docker containers.

    Executes user-defined scripts/commands in arbitrary Docker images
    with file provisioning, environment variables, and output capture.
    """

    handler_id = "container.run"
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "Run Container"
    description = "Run a command inside a Docker container on the Docker-in-Docker sandbox."
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    container_backed = True
    # Secret references reach the handler as written (see resolve_secret_values).
    raw_config_keys = frozenset({"secrets"})
    config_model = RunContainerConfig
    default_config = {"timeout_seconds": 300}

    _IMAGE_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._\-/:@]*[a-zA-Z0-9])?$")
    _MAX_OUTPUT_BYTES = 5 * 1024 * 1024  # 5 MB
    # Allowed values for `network_mode`: host, bridge, default, a Docker network
    # name (e.g. `clab-mylab`), or `container:<name>` to share a namespace.
    # `none` is intentionally excluded — use `network_disabled: true` for that.
    _NETWORK_MODE_PATTERN = re.compile(
        r"^(host|bridge|default|container:[a-zA-Z0-9][a-zA-Z0-9._\-]*|[a-zA-Z0-9][a-zA-Z0-9._\-]*)$"
    )
    # `pid_mode`: only `host` or `container:<name>` are accepted. Required by
    # clab-in-Docker to resolve sibling container PIDs in the sandbox's PID namespace.
    _PID_MODE_PATTERN = re.compile(r"^(host|container:[a-zA-Z0-9][a-zA-Z0-9._\-]*)$")
    # `extra_mounts` entries: `<src>:<dst>` or `<src>:<dst>:<opts>` where both
    # paths are absolute and opts are a comma list of alnum tokens (e.g.
    # `ro,shared`). No spaces, no `..` traversal, no leading dashes.
    _EXTRA_MOUNT_PATTERN = re.compile(r"^(/[^:\s]+):(/[^:\s]+)(?::([a-zA-Z][a-zA-Z0-9,]*))?$")

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate container handler configuration."""
        errors: list[str] = []
        image = config.get("image")
        if not image:
            errors.append("'image' is required")
        elif not isinstance(image, str):
            errors.append("'image' must be a string")
        else:
            # Reject dangerous image references
            if image.startswith((".", "/", "file://", "docker://", "docker-daemon://", "tar://")):
                errors.append(f"Invalid image reference: {image}")
            elif not self._IMAGE_PATTERN.match(image):
                errors.append(f"Invalid image reference format: {image}")

        # Validate env - must be dict[str, str]
        env = config.get("env")
        if env is not None:
            if not isinstance(env, dict):
                errors.append("'env' must be an object mapping string keys to string values")
            else:
                for key, val in env.items():
                    if not isinstance(key, str):
                        errors.append(f"'env' keys must be strings (invalid key: {key!r})")
                        continue
                    if not isinstance(val, str):
                        errors.append(f"'env' values must be strings (key: {key})")
                        continue

        # Inline files are intentionally unsupported (flow attachments only).
        if "files" in config:
            errors.append("'files' is no longer supported; use flow attachments + mounted_files")

        errors.extend(secret_map_errors("secrets", config.get("secrets")))

        entrypoint = config.get("entrypoint")
        if entrypoint is not None:
            if isinstance(entrypoint, str):
                if not entrypoint.strip():
                    errors.append("'entrypoint' must be a non-empty string or list of strings")
                elif "\0" in entrypoint:
                    errors.append("'entrypoint' must not contain NUL bytes")
            elif isinstance(entrypoint, list):
                if not entrypoint:
                    errors.append("'entrypoint' must be a non-empty string or list of strings")
                else:
                    for i, part in enumerate(entrypoint):
                        if not isinstance(part, str) or not part.strip():
                            errors.append(f"'entrypoint[{i}]' must be a non-empty string")
                            continue
                        if "\0" in part:
                            errors.append(f"'entrypoint[{i}]' must not contain NUL bytes")
            else:
                errors.append("'entrypoint' must be a non-empty string or list of strings")

        # Validate attachments_path (optional). Where flow attachments are copied
        # inside the container. Defaults to /attachments. Must be an absolute path.
        attachments_path = config.get("attachments_path")
        if attachments_path is not None:
            _validate_absolute_container_path("attachments_path", attachments_path, errors)

        # Validate artifacts_path (optional). Where upstream step artifacts are
        # copied inside the container. Defaults to /artifacts.
        artifacts_path = config.get("artifacts_path")
        if artifacts_path is not None:
            _validate_absolute_container_path("artifacts_path", artifacts_path, errors)

        # Validate new_artifacts_path (optional). A dedicated absolute folder
        # where this step can drop new text files for automatic artifact
        # upload after the container exits. Defaults to {artifacts_path}/new.
        new_artifacts_path = config.get("new_artifacts_path")
        if new_artifacts_path is not None:
            _validate_absolute_container_path("new_artifacts_path", new_artifacts_path, errors)

        # Validate step_outputs_path (optional). Where completed step output
        # snapshots are copied inside the container. Defaults to /step_outputs.
        step_outputs_path = config.get("step_outputs_path")
        if step_outputs_path is not None:
            _validate_absolute_container_path("step_outputs_path", step_outputs_path, errors)

        # Validate shared_path (optional). Where the shared run workspace is
        # mounted inside the container when shared/explicit execution is used.
        shared_path = config.get("shared_path")
        if shared_path is not None:
            _validate_absolute_container_path("shared_path", shared_path, errors)

        mounted_artifacts = config.get("mounted_artifacts")
        if mounted_artifacts is not None:
            if not isinstance(mounted_artifacts, list):
                errors.append("'mounted_artifacts' must be a list of upstream step ids")
            else:
                for i, step_id in enumerate(mounted_artifacts):
                    if not isinstance(step_id, str) or not step_id.strip():
                        errors.append(
                            f"'mounted_artifacts[{i}]' must be a non-empty upstream step id"
                        )

        mounted_step_outputs = config.get("mounted_step_outputs")
        if mounted_step_outputs is not None:
            if not isinstance(mounted_step_outputs, list):
                errors.append("'mounted_step_outputs' must be a list of upstream step ids")
            else:
                for i, step_id in enumerate(mounted_step_outputs):
                    if not isinstance(step_id, str) or not step_id.strip():
                        errors.append(
                            f"'mounted_step_outputs[{i}]' must be a non-empty upstream step id"
                        )

        # Validate network_mode (optional). Mutually exclusive with network_disabled=true.
        network_disabled = config.get("network_disabled")
        if network_disabled is not None and not isinstance(network_disabled, bool):
            errors.append("'network_disabled' must be a boolean")

        network_mode = config.get("network_mode")
        if not _is_unset(network_mode):
            if not isinstance(network_mode, str):
                errors.append("'network_mode' must be a string")
            elif network_mode == "none":
                errors.append(
                    "'network_mode' may not be 'none'; use 'network_disabled: true' instead"
                )
            elif not self._NETWORK_MODE_PATTERN.match(network_mode):
                errors.append(f"Invalid 'network_mode' value: {network_mode!r}")
            elif config.get("network_disabled") is True:
                errors.append("'network_mode' cannot be combined with 'network_disabled: true'")

        attach_socket = config.get("attach_docker_socket")
        if attach_socket is not None and not isinstance(attach_socket, bool):
            errors.append("'attach_docker_socket' must be a boolean")

        privileged = config.get("privileged")
        if privileged is not None and not isinstance(privileged, bool):
            errors.append("'privileged' must be a boolean")

        pid_mode = config.get("pid_mode")
        if not _is_unset(pid_mode):
            if not isinstance(pid_mode, str):
                errors.append("'pid_mode' must be a string")
            elif not self._PID_MODE_PATTERN.match(pid_mode):
                errors.append(
                    f"Invalid 'pid_mode' value: {pid_mode!r} (allowed: 'host', 'container:<name>')"
                )

        extra_mounts = config.get("extra_mounts")
        if extra_mounts is not None:
            if not isinstance(extra_mounts, list):
                errors.append("'extra_mounts' must be a list of strings")
            else:
                for i, m in enumerate(extra_mounts):
                    if not isinstance(m, str) or not m:
                        errors.append(f"'extra_mounts[{i}]' must be a non-empty string")
                        continue
                    if ".." in m:
                        errors.append(f"'extra_mounts[{i}]' must not contain '..': {m!r}")
                        continue
                    if not self._EXTRA_MOUNT_PATTERN.match(m):
                        errors.append(
                            f"Invalid 'extra_mounts[{i}]' entry: {m!r} "
                            "(expected '<abs-src>:<abs-dst>' or '<abs-src>:<abs-dst>:<opts>')"
                        )

        # Egress policy fields. Enforced on the sandbox daemon (E2); admission
        # here keeps declarations coherent and refuses combinations that could
        # never be enforced.
        egress_mode = config.get("egress_mode")
        egress_allow = config.get("egress_allow")
        egress_deny = config.get("egress_deny")
        if egress_mode is not None and not isinstance(egress_mode, str):
            errors.append("'egress_mode' must be a string")
            egress_mode = None
        mode = (egress_mode or "").strip()
        if mode and mode not in EGRESS_MODES:
            errors.append(
                f"Invalid 'egress_mode' value: {mode!r} (allowed: {', '.join(EGRESS_MODES)})"
            )
        rule_lists: dict[str, list[str]] = {}
        for field_name, value in (("egress_allow", egress_allow), ("egress_deny", egress_deny)):
            if value is None:
                rule_lists[field_name] = []
                continue
            if not isinstance(value, list):
                errors.append(f"'{field_name}' must be a list of rule strings")
                rule_lists[field_name] = []
                continue
            cleaned: list[str] = []
            for i, rule in enumerate(value):
                rule_error = egress_rule_error(rule) if isinstance(rule, str) else None
                if not isinstance(rule, str):
                    errors.append(f"'{field_name}[{i}]' must be a string")
                elif rule_error:
                    errors.append(f"'{field_name}[{i}]': {rule_error}")
                else:
                    cleaned.append(rule.strip())
            rule_lists[field_name] = cleaned

        egress_declared = (
            bool(mode) or bool(rule_lists["egress_allow"]) or bool(rule_lists["egress_deny"])
        )
        if egress_declared:
            if not mode:
                errors.append("'egress_allow'/'egress_deny' require an explicit 'egress_mode'")
            elif mode == "deny-all" and (rule_lists["egress_allow"] or rule_lists["egress_deny"]):
                errors.append("'egress_mode: deny-all' does not take allow/deny rules")
            elif mode == "allow-listed" and not rule_lists["egress_allow"]:
                errors.append(
                    "'egress_mode: allow-listed' requires at least one 'egress_allow' rule "
                    "(use 'deny-all' to block everything)"
                )
            elif mode == "open" and rule_lists["egress_allow"]:
                errors.append(
                    "'egress_mode: open' does not take 'egress_allow' rules "
                    "(everything not denied is already allowed)"
                )
            # Host-access options make the step sandbox-admin (or hand it
            # firewall-bypass capability), so an egress policy on the same step
            # could never be enforced honestly.
            host_access_enabled = {
                "network_mode": isinstance(network_mode, str) and bool(network_mode.strip()),
                "attach_docker_socket": attach_socket is True,
                "privileged": privileged is True,
                "pid_mode": isinstance(pid_mode, str) and bool(pid_mode.strip()),
                "extra_mounts": isinstance(extra_mounts, list) and bool(extra_mounts),
            }
            blocked_by = [name for name, enabled in host_access_enabled.items() if enabled]
            if blocked_by:
                errors.append(
                    "egress policy cannot be combined with host-access options: "
                    + ", ".join(sorted(blocked_by))
                )
            if config.get("network_disabled") is True:
                errors.append(
                    "egress policy cannot be combined with 'network_disabled: true' "
                    "(use 'egress_mode: deny-all' instead)"
                )

        mount_step_artifacts = config.get("mount_step_artifacts")
        if mount_step_artifacts is not None:
            if not isinstance(mount_step_artifacts, list):
                errors.append("'mount_step_artifacts' must be a list of objects")
            else:
                for i, entry in enumerate(mount_step_artifacts):
                    if not isinstance(entry, dict):
                        errors.append(f"'mount_step_artifacts[{i}]' must be an object")
                        continue
                    step = entry.get("step")
                    if not isinstance(step, str) or not step.strip():
                        errors.append(
                            f"'mount_step_artifacts[{i}].step' is required (upstream step id)"
                        )
                    as_path = entry.get("as")
                    if as_path is not None:
                        if not isinstance(as_path, str) or not as_path.strip():
                            errors.append(
                                f"'mount_step_artifacts[{i}].as' must be a non-empty string"
                            )
                        elif as_path.startswith("/") or ".." in as_path.split("/"):
                            errors.append(
                                f"'mount_step_artifacts[{i}].as' must be a relative path without '..'"
                            )
                    kind = entry.get("kind")
                    if kind is not None and (not isinstance(kind, str) or not kind.strip()):
                        errors.append(
                            f"'mount_step_artifacts[{i}].kind' must be a non-empty string"
                        )

        return errors

    def build_docker_args(
        self,
        config: dict[str, Any],
        container_name: str,
        run_id: str,
        step_run_id: str,
        shared_workspace_path: str | None = None,
        shared_workspace_volume: str | None = None,
        docker_network: str = "",
        docker_mac: str = "",
        handler_id: str = "container.run",
        extra_hosts: dict[str, str] | None = None,
        stop_grace_seconds: int = 0,
    ) -> list[str]:
        """Build the docker create command args from config.

        This is a pure function extracted for testability.
        Returns the list of docker args (excluding the docker binary itself).

        Shared-workspace mounting (for steps with shared/explicit affinity):

        - When ``shared_workspace_volume`` is provided, only the run's
          subdirectory of that Docker volume is mounted at ``/shared`` using
          ``--mount type=volume,...,volume-subpath=<run_id>`` (Docker 26.1+).
          This is the preferred mode: no host path, no root, per-run isolation.
        - Otherwise, when ``shared_workspace_path`` is provided, that path is
          bind-mounted at ``/shared`` (legacy mode: bind sources resolve on the
          sandbox daemon's filesystem, so the worker's path must exist at the
          identical path there).

        ``docker_mac`` pins the container's hardware address on the policy
        network. The platform derives it from this step run's own id before
        programming the firewall, so that this step's packet counters can be
        scoped to this container rather than to every step sharing the policy.
        It is empty for the ordinary step, which declares no egress policy.
        """
        image = config.get("image", "")
        command = config.get("command", [])
        entrypoint = config.get("entrypoint")
        env_vars = config.get("env", {})
        # These fields default to "" in the schema and resolve to the documented
        # default at run time, so an empty/whitespace value means "use the
        # default" — `.get(key, default)` would return "" (present but empty)
        # and pass e.g. `--memory ""`, which docker rejects. Read every one of
        # them through _optional_str so the emitted argv agrees with what
        # validation accepted (_is_unset treats whitespace-only as absent).
        memory = _optional_str(config.get("memory"), "512m")
        cpus = _optional_str(config.get("cpus"), "1.0")
        working_dir = _optional_str(config.get("working_dir"), "/workspace")
        network_disabled = config.get("network_disabled") is True
        network_mode = _optional_str(config.get("network_mode"))
        attach_docker_socket = bool(config.get("attach_docker_socket", False))
        privileged = bool(config.get("privileged", False))
        pid_mode = _optional_str(config.get("pid_mode"))
        extra_mounts = config.get("extra_mounts") or []
        shared_mount_path = _normalize_container_root(config.get("shared_path"), "/shared")

        args = [
            "create",
            "--name",
            container_name,
        ]

        # `network_mode` (admin host access) takes precedence, then the
        # platform's policy network (``docker_network``, provisioned by egress
        # enforcement — ``none`` for deny-all), then `network_disabled`. When
        # none are set, preserve legacy Docker networking behavior; network
        # isolation requires explicit `network_disabled: true`.
        if network_mode:
            args.append(f"--network={network_mode}")
        elif docker_network:
            args.append(f"--network={docker_network}")
            # Only meaningful on a policy network: it is what lets the
            # worker count this container's egress separately from every other
            # step running under the same policy. `none` has no interface to
            # give an address to.
            if docker_network != "none" and docker_mac:
                args.append(f"--mac-address={docker_mac}")
        elif network_disabled:
            args.append("--network=none")

        # Platform-supplied /etc/hosts entries (never from step config): names
        # a sandbox container cannot resolve itself, such as the platform API.
        for host_name, address in sorted((extra_hosts or {}).items()):
            args.extend(["--add-host", f"{_valid_host_name(host_name)}:{_valid_ip(address)}"])

        # A job that stops gracefully gets SIGTERM whatever STOPSIGNAL its image
        # declares, and the same grace from any `docker stop` without -t.
        if stop_grace_seconds > 0:
            args.extend(["--stop-signal", "SIGTERM", "--stop-timeout", str(stop_grace_seconds)])

        args.extend(
            [
                "--memory",
                memory,
                "--cpus",
                cpus,
                "-w",
                working_dir,
                "--label",
                f"hegemony.run_id={run_id}",
                "--label",
                f"hegemony.step_run_id={step_run_id}",
                "--label",
                f"hegemony.handler_id={handler_id}",
            ]
        )

        # Stack discriminator: the id labels alone cannot tell the flow
        # containers of several compose stacks (dev/prod/demo) apart on one
        # daemon. Each stack runs its own sandbox daemon, so this is defense in
        # depth: the worker sets HEGEMONY_STACK_NAME (its compose project name)
        # so stack-scoped cleanup — the platform's startup janitor and demo
        # reset — only ever touches its own stack's containers.
        stack_name = os.environ.get("HEGEMONY_STACK_NAME", "").strip()
        if stack_name:
            args.extend(["--label", f"hegemony.stack={stack_name}"])

        # Add env vars (filter out platform-owned variables)
        if isinstance(env_vars, dict):
            for key, val in env_vars.items():
                if not key.startswith("HEGEMONY_"):
                    args.extend(["-e", f"{key}={val}"])

        # Force unbuffered output for common runtimes so streaming is real-time
        args.extend(["-e", "PYTHONUNBUFFERED=1"])

        # Advanced: expose the Docker socket (containerlab and other tools that
        # start their own containers). The bind source resolves on the sandbox
        # daemon's filesystem, so this is the sandbox daemon's own socket: full
        # control of the sandbox daemon, not the host's. Opt-in only.
        if attach_docker_socket:
            args.extend(["-v", "/var/run/docker.sock:/var/run/docker.sock"])

        # Advanced: run the container with full privileges inside the sandbox,
        # which itself runs privileged. Required for tools that need to write
        # to /proc/sys (e.g. containerlab adjusting rp_filter) or manage
        # devices. Opt-in only.
        if privileged:
            args.append("--privileged")

        # Advanced: share a PID namespace (``host`` is the sandbox's) so the
        # container can resolve sibling container PIDs (clab-in-Docker needs
        # this to inspect netns paths of containers it creates via the attached
        # sandbox Docker socket).
        if pid_mode:
            args.append(f"--pid={pid_mode}")

        # Advanced: arbitrary bind mounts (validated above). Sources resolve
        # on the sandbox daemon's filesystem; used to share paths like
        # /var/run/netns:/var/run/netns:shared with the sandbox.
        if isinstance(extra_mounts, list):
            for m in extra_mounts:
                if isinstance(m, str) and m:
                    args.extend(["-v", m])

        # Shared workspace: expose the run's shared directory at the configured
        # mount path (default /shared) so pinned steps can persist files (e.g.
        # terraform state) across container boundaries. Prefer a named-volume
        # subpath mount (isolated, no host path, no root); fall back to a bind
        # mount when no volume is configured.
        if shared_workspace_volume:
            args.extend(
                [
                    "--mount",
                    f"type=volume,source={shared_workspace_volume}"
                    f",target={shared_mount_path},volume-subpath={run_id}",
                ]
            )
        elif shared_workspace_path:
            args.extend(["-v", f"{shared_workspace_path}:{shared_mount_path}"])

        entrypoint_configured = False
        entrypoint_args: list[str] = []
        if isinstance(entrypoint, str) and entrypoint.strip():
            args.extend(["--entrypoint", entrypoint])
            entrypoint_configured = True
        elif isinstance(entrypoint, list) and entrypoint:
            first = entrypoint[0]
            if isinstance(first, str) and first.strip():
                args.extend(["--entrypoint", first])
                entrypoint_args = [p for p in entrypoint[1:] if isinstance(p, str) and p.strip()]
                entrypoint_configured = True

        args.append(image)

        # The UI stores command as shell command lines (one per line), not argv tokens.
        # Each list entry may itself be a multi-line shell snippet (YAML block scalar),
        # so we cannot join with " && " — a trailing newline in one entry would yield
        # a line that starts with "&&" and break the shell parser. Instead, run the
        # entries as sequential statements under `set -e` so the first non-zero exit
        # still aborts execution.
        shell_command: str | None = None
        if isinstance(command, list) and command:
            parts = [p.strip() for p in command if isinstance(p, str) and p.strip()]
            if parts:
                shell_command = "set -e\n" + "\n".join(parts)
        elif isinstance(command, str):
            shell_command = _with_fail_fast_shell(command)

        if entrypoint_args:
            args.extend(entrypoint_args)

        if shell_command:
            if not entrypoint_configured:
                args.extend(["sh", "-c", shell_command])
            elif entrypoint_args:
                args.append(shell_command)
            else:
                args.extend(["-c", shell_command])

        return args

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Execute command in a Docker container."""
        # Validate config before execution (fail fast with clear errors)
        validation_errors = self.validate_config(ctx.config)
        if validation_errors:
            return HandlerResult(
                success=False,
                error=f"Invalid container config: {'; '.join(validation_errors)}",
                summary="Config validation failed",
            )

        try:
            secrets = await resolve_secret_values(
                ctx, ctx.config.get("secrets"), source="container.run.secrets"
            )
            files = [
                _context_file(ctx),
                *(
                    StagedFile(path=f"{SECRET_FILES_DIR}/{name}", content=value)
                    for name, value in secrets.items()
                ),
            ]
        except ValueError as e:
            return HandlerResult(
                success=False,
                error=f"Invalid container config: {e}",
                summary="Config validation failed",
            )
        job = ContainerJob(
            config=ctx.config,
            files=files,
            collect=[OUTPUT_DIR],
            handler_id=self.handler_id,
        )
        outcome = await self.run_job(ctx, job)
        if isinstance(outcome, HandlerResult):
            return outcome
        return _container_run_result(ctx, outcome)

    async def run_job(
        self, ctx: HandlerContext, job: ContainerJob
    ) -> HandlerResult | ContainerJobResult:
        """Run ``job`` on the sandbox daemon and return its outcome.

        The machinery behind ``container.run`` and every tool handler built on
        :mod:`hegemony_steps_container.runner`: preflight cleanup, attachment
        and step-output staging, the image pull, ``docker create``, staging of
        ``job.files``, the attached run with live output, collection of
        ``job.collect``, artifact harvest, and cleanup. Returns a
        :class:`ContainerJobResult` once the container has run, whatever its
        exit code; a failure before or around the run is a failed
        :class:`HandlerResult`. ``job.config`` must already be validated.
        """
        config = job.config
        services = ctx.require_services()
        runtime = services.container_runtime()

        # Every docker call below runs on the sandbox daemon: DOCKER_HOST is
        # placed on each invocation (never process-wide — see _docker_env). A
        # runtime that names no sandbox daemon is refused here, before the
        # first docker call, rather than inheriting the worker's environment
        # and with it the worker's own Docker daemon.
        try:
            docker_host = require_docker_host(runtime.docker_host or "")
        except ValueError as e:
            return HandlerResult(
                success=False,
                error=str(e),
                summary="Container sandbox not configured",
            )

        docker_bin = runtime.docker_bin
        # The step's Docker configuration (the organization's registry logins)
        # rides on the same environment as the daemon selection, so every pull
        # path and every docker call sees the same login for the image's host.
        docker_env = _docker_env(docker_host, getattr(runtime, "docker_config_dir", "") or "")
        image = config.get("image", "")
        timeout = config.get("timeout_seconds", ctx.timeout_seconds)
        working_dir = config.get("working_dir", "/workspace")
        # Where flow attachments are copied inside the container. Defaults to
        # /attachments; steps may override to any absolute path. Trailing
        # slashes are normalized off so the docker cp target is well-formed.
        attachments_path = _normalize_container_root(config.get("attachments_path"), "/attachments")
        artifacts_path = _normalize_container_root(config.get("artifacts_path"), "/artifacts")
        new_artifacts_path = _resolve_new_artifacts_path(config, artifacts_path)
        step_outputs_path = _normalize_container_root(
            config.get("step_outputs_path"), "/step_outputs"
        )

        # Container name with short IDs for uniqueness
        run_short = ctx.run_id[:8]
        step_short = ctx.step_run_id[:8]
        container_name = f"hegemony-{run_short}-{step_short}-a{ctx.attempt}"

        start_time = time.monotonic()
        deadline = start_time + timeout
        # A step cancelled while its container runs gives the container
        # stop_grace seconds after SIGTERM before removing it (see `finally`).
        stop_grace = max(0, min(int(job.stop_grace_seconds or 0), MAX_STOP_GRACE_SECONDS))
        cancelled_while_running = False
        output_lines: list[str] = []
        exit_code = -1
        staging_dir: str | None = None
        artifact_staging_dir: str | None = None
        generated_artifacts_staging_dir: str | None = None
        step_outputs_staging_dir: str | None = None
        root_dirs_staging_parent: str | None = None
        root_dirs_staging_dir: str | None = None

        async def _safe_emit_progress(message: str, attrs: dict[str, object] | None = None) -> None:
            try:
                await ctx.emit_progress(message, attrs=attrs)
            except Exception as e:
                logger.debug(
                    "Progress emission failed",
                    extra={
                        "run_id": ctx.run_id,
                        "step_id": ctx.step_id,
                        "step_run_id": ctx.step_run_id,
                        "attrs": attrs or {},
                        "error": str(e),
                    },
                )

        try:
            # 1. Preflight cleanup
            await self._preflight_cleanup(docker_bin, ctx, docker_host=docker_host)

            # 2. Create a temp staging directory for files to copy into container
            staging_dir = tempfile.mkdtemp(prefix="hegemony-container-")

            # 3. Fetch and provision run attachment snapshots
            try:
                if not ctx.run_id:
                    raise ValueError("Missing run_id in handler context")

                attachments = await services.fetch_run_attachments(ctx.run_id)

                mounted = 0
                skipped = 0
                for att in attachments:
                    if ctx.mounted_files is not None and not _matches_mounted_files(
                        att["filename"], ctx.mounted_files
                    ):
                        skipped += 1
                        continue

                    # Staged at the attachments root (copied to attachments_path,
                    # default /attachments, e.g. /attachments/scripts/test.py).
                    root_path = os.path.normpath(os.path.join(staging_dir, att["filename"]))
                    if not root_path.startswith(staging_dir + os.sep) and root_path != staging_dir:
                        logger.warning(
                            f"Skipping attachment with path traversal: {att['filename']}"
                        )
                        continue
                    os.makedirs(os.path.dirname(root_path), exist_ok=True)
                    with open(root_path, "w", encoding="utf-8") as fh:
                        fh.write(att["content"])

                    mounted += 1

                sel_mode = (
                    "all"
                    if ctx.mounted_files is None
                    else "none"
                    if len(ctx.mounted_files) == 0
                    else f"custom({len(ctx.mounted_files)} selectors)"
                )
                logger.info(
                    "Attachment provisioning: fetched=%d mounted=%d skipped=%d mode=%s",
                    len(attachments),
                    mounted,
                    skipped,
                    sel_mode,
                    extra={
                        "run_id": ctx.run_id,
                        "flow_id": ctx.flow_id,
                        "step_id": ctx.step_id,
                        "step_run_id": ctx.step_run_id,
                    },
                )
            except Exception as e:
                logger.warning(
                    "Failed to fetch attachments",
                    extra={
                        "run_id": ctx.run_id,
                        "step_id": ctx.step_id,
                        "step_run_id": ctx.step_run_id,
                        "error": str(e),
                    },
                )
                return HandlerResult(
                    success=False,
                    error=f"Failed to provision attachments: {e}",
                    summary="Attachment provisioning failed",
                )

            # 4. Best-effort snapshot of completed step outputs for filesystem access.
            # This is additive context for container commands, so failures here should
            # not turn a previously-working container step into a hard failure.
            raw_mounted_step_outputs = config.get("mounted_step_outputs")
            selected_step_output_steps = (
                None
                if raw_mounted_step_outputs is None
                else {
                    step_id.strip()
                    for step_id in raw_mounted_step_outputs
                    if isinstance(step_id, str) and step_id.strip()
                }
            )
            try:
                # An explicit empty selection mounts nothing; skip the fetch.
                fetched_step_outputs = (
                    {}
                    if selected_step_output_steps is not None and not selected_step_output_steps
                    else await services.fetch_run_step_outputs(ctx.run_id)
                )
                step_outputs = (
                    fetched_step_outputs
                    if selected_step_output_steps is None
                    else {
                        step_id: summary
                        for step_id, summary in fetched_step_outputs.items()
                        if step_id in selected_step_output_steps
                    }
                )
                if step_outputs:
                    step_outputs_staging_dir = tempfile.mkdtemp(prefix="hegemony-step-outputs-")
                    staged_step_output_files = _stage_step_output_snapshots(
                        step_outputs_staging_dir, step_outputs
                    )
                    logger.info(
                        "Step outputs provisioning complete",
                        extra={
                            "run_id": ctx.run_id,
                            "step_id": ctx.step_id,
                            "step_run_id": ctx.step_run_id,
                            "step_outputs_path": step_outputs_path,
                            "selected_steps": None
                            if selected_step_output_steps is None
                            else sorted(selected_step_output_steps),
                            "fetched_step_output_steps": len(fetched_step_outputs),
                            "step_output_steps": len(step_outputs),
                            "count": staged_step_output_files,
                        },
                    )
            except Exception as e:
                logger.warning(
                    "Failed to provision step outputs",
                    extra={
                        "run_id": ctx.run_id,
                        "step_id": ctx.step_id,
                        "step_run_id": ctx.step_run_id,
                        "error": str(e),
                    },
                )

            # 5. Provision upstream step artifacts. New flows use
            # mounted_artifacts + artifacts_path; legacy flows may still carry
            # mount_step_artifacts objects with per-entry relative paths.
            raw_mounted_artifacts = config.get("mounted_artifacts")
            selected_artifact_steps = (
                None
                if raw_mounted_artifacts is None
                else {
                    step_id.strip()
                    for step_id in raw_mounted_artifacts
                    if isinstance(step_id, str) and step_id.strip()
                }
            )
            legacy_mount_step_artifacts: list[dict[str, Any]] = []
            if raw_mounted_artifacts is None:
                raw_legacy_mounts = config.get("mount_step_artifacts") or []
                if isinstance(raw_legacy_mounts, list):
                    legacy_mount_step_artifacts = [
                        entry for entry in raw_legacy_mounts if isinstance(entry, dict)
                    ]

            should_mount_artifacts = bool(legacy_mount_step_artifacts) or bool(
                selected_artifact_steps
            )

            if should_mount_artifacts:
                try:
                    # Step artifacts are staged separately from attachments so
                    # they can be copied under artifacts_path (or legacy custom
                    # paths) while attachments are copied under attachments_path.
                    artifact_staging_dir = tempfile.mkdtemp(prefix="hegemony-artifacts-")

                    all_artifacts = await services.fetch_run_artifacts(ctx.run_id)
                    by_step: dict[str, list[dict]] = {}
                    for art in all_artifacts:
                        by_step.setdefault(art.get("step_id") or "", []).append(art)

                    total_written = 0
                    used_names_by_dir: dict[str, dict[str, int]] = {}
                    if legacy_mount_step_artifacts:
                        for entry in legacy_mount_step_artifacts:
                            step_id = entry["step"]
                            subdir = entry.get("as") or f"artifacts/{step_id}/"
                            if not subdir.endswith("/"):
                                subdir = subdir + "/"
                            kind_filter = entry.get("kind")

                            target_dir = os.path.normpath(
                                os.path.join(artifact_staging_dir, subdir)
                            )
                            if (
                                not target_dir.startswith(artifact_staging_dir + os.sep)
                                and target_dir != artifact_staging_dir
                            ):
                                return HandlerResult(
                                    success=False,
                                    error=f"Invalid mount_step_artifacts.as for step={step_id}: {subdir!r}",
                                    summary="Invalid artifact mount path",
                                )
                            os.makedirs(target_dir, exist_ok=True)

                            written_for_step = 0
                            used_names = used_names_by_dir.setdefault(target_dir, {})
                            for art in by_step.get(step_id, []):
                                if kind_filter and art.get("kind") != kind_filter:
                                    continue

                                base = _sanitize_artifact_filename(
                                    art.get("name") or art.get("id", "")
                                )
                                count = used_names.get(base, 0)
                                used_names[base] = count + 1
                                filename = base if count == 0 else f"{base}_{count}"

                                content = art.get("content_text")
                                if content is None:
                                    cj = art.get("content_json")
                                    content = json.dumps(cj, indent=2) if cj is not None else ""

                                with open(
                                    os.path.join(target_dir, filename), "w", encoding="utf-8"
                                ) as fh:
                                    fh.write(content)
                                written_for_step += 1

                            total_written += written_for_step
                            logger.info(
                                "Mounted step artifacts (legacy paths)",
                                extra={
                                    "run_id": ctx.run_id,
                                    "step_id": ctx.step_id,
                                    "upstream_step_id": step_id,
                                    "as": subdir,
                                    "kind_filter": kind_filter,
                                    "count": written_for_step,
                                },
                            )
                    else:
                        step_ids_to_mount = (
                            sorted(selected_artifact_steps)
                            if selected_artifact_steps is not None
                            else sorted(step_id for step_id in by_step if step_id)
                        )
                        for upstream_step_id in step_ids_to_mount:
                            target_dir = os.path.normpath(
                                os.path.join(artifact_staging_dir, upstream_step_id)
                            )
                            if (
                                not target_dir.startswith(artifact_staging_dir + os.sep)
                                and target_dir != artifact_staging_dir
                            ):
                                return HandlerResult(
                                    success=False,
                                    error=(
                                        f"Invalid mounted_artifacts entry: {upstream_step_id!r}"
                                    ),
                                    summary="Invalid artifact mount path",
                                )
                            os.makedirs(target_dir, exist_ok=True)

                            written_for_step = 0
                            used_names = used_names_by_dir.setdefault(target_dir, {})
                            for art in by_step.get(upstream_step_id, []):
                                base = _sanitize_artifact_filename(
                                    art.get("name") or art.get("id", "")
                                )
                                count = used_names.get(base, 0)
                                used_names[base] = count + 1
                                filename = base if count == 0 else f"{base}_{count}"

                                content = art.get("content_text")
                                if content is None:
                                    cj = art.get("content_json")
                                    content = json.dumps(cj, indent=2) if cj is not None else ""

                                with open(
                                    os.path.join(target_dir, filename), "w", encoding="utf-8"
                                ) as fh:
                                    fh.write(content)
                                written_for_step += 1

                            total_written += written_for_step
                            logger.info(
                                "Mounted step artifacts",
                                extra={
                                    "run_id": ctx.run_id,
                                    "step_id": ctx.step_id,
                                    "upstream_step_id": upstream_step_id,
                                    "artifacts_path": artifacts_path,
                                    "count": written_for_step,
                                },
                            )

                    logger.info(
                        "Artifact provisioning complete",
                        extra={
                            "run_id": ctx.run_id,
                            "step_id": ctx.step_id,
                            "step_run_id": ctx.step_run_id,
                            "artifacts_path": artifacts_path,
                            "selected_steps": None
                            if selected_artifact_steps is None
                            else sorted(selected_artifact_steps),
                            "legacy_mounts": len(legacy_mount_step_artifacts),
                            "count": total_written,
                        },
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to provision step artifacts",
                        extra={
                            "run_id": ctx.run_id,
                            "step_id": ctx.step_id,
                            "step_run_id": ctx.step_run_id,
                            "error": str(e),
                        },
                    )
                    return HandlerResult(
                        success=False,
                        error=f"Failed to provision step artifacts: {e}",
                        summary="Step artifact provisioning failed",
                    )

            # 6. Pull image: through the platform registry's cache when the host
            # serves one and the step keeps "Cache image" on, else straight from
            # the image's registry (Engine-API streaming progress, CLI fallback).
            acquired = await self._acquire_image(
                job=job,
                image=image,
                cache=getattr(runtime, "image_cache", None),
                docker_bin=docker_bin,
                docker_env=docker_env,
                docker_host=docker_host,
                deadline=deadline,
                emit=_safe_emit_progress,
            )
            if isinstance(acquired, HandlerResult):
                return acquired
            served = acquired.served
            if served != image:
                # The daemon knows the image by the reference it pulled.
                config = {**config, "image": served}
            image_digest = ""
            if job.pin_image:
                image_digest = await self._image_repo_digest(
                    docker_bin=docker_bin, image=served, docker_env=docker_env, deadline=deadline
                )
                if image_digest:
                    # The tag can move (another step pulls it) before `docker create`.
                    config = {**config, "image": image_digest}
            elif "@sha256:" in image:
                # A digest-qualified reference already names exact content; record
                # it as the digest without the inspect a pinned job pays for.
                image_digest = image

            # 7. Build docker create command (container is created but not started)
            shared_workspace_path: str | None = None
            shared_workspace_volume: str | None = None
            if ctx.shared_workspace and runtime.shared_workspaces_enabled:
                workspace_dir = os.path.join(runtime.shared_workspace_root, ctx.run_id)
                # Create the run's subdirectory inside the worker's mounted
                # shared-workspace volume, the directory the sandbox daemon's
                # shared-workspace volume is backed by, so the step container's
                # volume-subpath (or bind) mount resolves to existing content.
                os.makedirs(workspace_dir, exist_ok=True)
                volume_name = runtime.shared_workspace_volume.strip()
                if volume_name:
                    shared_workspace_volume = volume_name
                else:
                    shared_workspace_path = workspace_dir
            docker_args = self.build_docker_args(
                config=config,
                container_name=container_name,
                run_id=ctx.run_id,
                step_run_id=ctx.step_run_id,
                shared_workspace_path=shared_workspace_path,
                shared_workspace_volume=shared_workspace_volume,
                docker_network=runtime.docker_network,
                docker_mac=runtime.docker_mac,
                handler_id=job.handler_id,
                extra_hosts=job.extra_hosts,
                stop_grace_seconds=stop_grace,
            )
            # 8. Create the container
            create_proc = await self._run_docker(
                docker_bin,
                docker_args,
                env=docker_env,
                timeout=max(deadline - time.monotonic(), 1),
            )
            if create_proc.returncode != 0:
                return HandlerResult(
                    success=False,
                    error=f"Docker create failed: {create_proc.stderr[:500]}",
                    summary="Failed to create container",
                )

            # 9. Materialize the container-visible roots even when there are no
            # files to copy yet. This keeps /attachments, /artifacts, the
            # dedicated new-artifacts upload subfolder, /step_outputs, and the
            # working directory visible/usable from inside the container.
            # The tree holds job files such as secrets at their container mode
            # (0644), so it lives under a private (0700) parent no other user of
            # the worker can enter. The tree's own directories keep 0755: they
            # become directories of the container, the root included.
            root_dirs_staging_parent = tempfile.mkdtemp(prefix="hegemony-container-roots-")
            root_dirs_staging_dir = os.path.join(root_dirs_staging_parent, "root")
            os.mkdir(root_dirs_staging_dir)
            os.chmod(root_dirs_staging_dir, 0o755)
            for container_root in {
                attachments_path,
                artifacts_path,
                new_artifacts_path,
                step_outputs_path,
                working_dir,
            }:
                _stage_container_root_dir(root_dirs_staging_dir, container_root)
            # The job's own files (step I/O contract, tool inventories and
            # scripts) ride in the same copy as the roots: one docker cp, and
            # their parent directories are created on the way.
            for staged_file in job.files:
                _write_job_file(root_dirs_staging_dir, staged_file)
            for collect_root in job.collect:
                _stage_container_root_dir(root_dirs_staging_dir, collect_root)
                # Writable by whatever user the image runs as: docker cp
                # creates it root-owned, and results are written by the step.
                os.chmod(
                    os.path.join(root_dirs_staging_dir, collect_root.strip().lstrip("/")),
                    0o777,
                )

            if any(os.scandir(root_dirs_staging_dir)):
                cp_proc = await self._run_docker(
                    docker_bin,
                    ["cp", f"{root_dirs_staging_dir}/.", f"{container_name}:/"],
                    env=docker_env,
                    timeout=max(deadline - time.monotonic(), 1),
                )
                if cp_proc.returncode != 0:
                    return HandlerResult(
                        success=False,
                        error=(
                            f"Failed to materialize container directories: {cp_proc.stderr[:500]}"
                        ),
                        summary="Container filesystem setup failed",
                    )

            # 10. Copy provisioned files into the container.
            # Attachments are copied under attachments_path (default
            # /attachments); upstream step artifacts are copied under the new
            # artifacts_path root (default /artifacts), with legacy flows still
            # using their saved custom paths under the working directory.
            if staging_dir and any(os.scandir(staging_dir)):
                cp_proc = await self._run_docker(
                    docker_bin,
                    ["cp", f"{staging_dir}/.", f"{container_name}:{attachments_path}/"],
                    env=docker_env,
                    timeout=max(deadline - time.monotonic(), 1),
                )
                if cp_proc.returncode != 0:
                    return HandlerResult(
                        success=False,
                        error=f"Failed to copy attachments into container: {cp_proc.stderr[:500]}",
                        summary="Attachment provisioning failed",
                    )

            if step_outputs_staging_dir and any(os.scandir(step_outputs_staging_dir)):
                cp_proc = await self._run_docker(
                    docker_bin,
                    [
                        "cp",
                        f"{step_outputs_staging_dir}/.",
                        f"{container_name}:{step_outputs_path}/",
                    ],
                    env=docker_env,
                    timeout=max(deadline - time.monotonic(), 1),
                )
                if cp_proc.returncode != 0:
                    logger.warning(
                        "Failed to copy step outputs into container",
                        extra={
                            "run_id": ctx.run_id,
                            "step_id": ctx.step_id,
                            "step_run_id": ctx.step_run_id,
                            "step_outputs_path": step_outputs_path,
                            "stderr": cp_proc.stderr[:500],
                        },
                    )

            if artifact_staging_dir and any(os.scandir(artifact_staging_dir)):
                cp_proc = await self._run_docker(
                    docker_bin,
                    [
                        "cp",
                        f"{artifact_staging_dir}/.",
                        (
                            f"{container_name}:{working_dir}/"
                            if legacy_mount_step_artifacts
                            else f"{container_name}:{artifacts_path}/"
                        ),
                    ],
                    env=docker_env,
                    timeout=max(deadline - time.monotonic(), 1),
                )
                if cp_proc.returncode != 0:
                    return HandlerResult(
                        success=False,
                        error=f"Failed to copy step artifacts into container: {cp_proc.stderr[:500]}",
                        summary="Step artifact provisioning failed",
                    )

            # 11. Start container in attached mode (streams stdout/stderr through pipe)
            # Using -a allows future upgrade to real-time line-by-line streaming
            await _safe_emit_progress(
                "Container started",
                attrs={"milestone": "container_started", "container_id": container_name},
            )

            proc = await asyncio.create_subprocess_exec(
                docker_bin,
                "start",
                "-a",
                container_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=docker_env,
            )
            if proc.stdout is None or proc.stderr is None:
                raise RuntimeError("subprocess pipes not available")

            max_bytes = self._MAX_OUTPUT_BYTES
            stream_budget = max_bytes // 2

            async def _stream_and_capture(
                proc: asyncio.subprocess.Process,
                ctx: HandlerContext,
                deadline: float,
                stream_budget: int,
            ) -> tuple[str, bool, str, bool]:
                """Stream stdout/stderr line-by-line, emit batched progress events, and
                capture full output (capped per-stream).

                Returns: (stdout_text, stdout_truncated, stderr_text, stderr_truncated)
                """

                lock = asyncio.Lock()

                stdout_bytes = bytearray()
                stderr_bytes = bytearray()
                stdout_trunc = False
                stderr_trunc = False

                # Event buffers store decoded text fragments to emit via ctx.emit_progress
                stdout_event_buf: list[str] = []
                stderr_event_buf: list[str] = []
                stdout_event_size = 0
                stderr_event_size = 0

                stdout_done = False
                stderr_done = False

                async def _flush_event_buffer(stream_label: str, buf: list[str]):
                    if not buf:
                        return
                    data = "".join(buf)
                    try:
                        await ctx.emit_progress(
                            data, attrs={"milestone": "output", "stream": stream_label}
                        )
                    except Exception as e:
                        logger.debug("emit_progress failed for %s: %s", stream_label, e)

                async def _take(line: bytes, artifact_bytes: bytearray, event_buf_label: str):
                    nonlocal stdout_trunc, stderr_trunc, stdout_event_size, stderr_event_size
                    # Decode using replace to avoid errors
                    text = line.decode("utf-8", errors="replace")

                    # Append to event buffer and possibly flush if size >= 1KB
                    to_flush: str | None = None
                    async with lock:
                        if event_buf_label == "stdout":
                            stdout_event_buf.append(text)
                            stdout_event_size += len(text.encode("utf-8"))
                            should_flush = stdout_event_size >= 1024
                            if should_flush:
                                to_flush = "".join(stdout_event_buf)
                                stdout_event_buf.clear()
                                stdout_event_size = 0
                        else:
                            stderr_event_buf.append(text)
                            stderr_event_size += len(text.encode("utf-8"))
                            should_flush = stderr_event_size >= 1024
                            if should_flush:
                                to_flush = "".join(stderr_event_buf)
                                stderr_event_buf.clear()
                                stderr_event_size = 0

                    if to_flush is not None:
                        # Flush outside the lock
                        await _flush_event_buffer(event_buf_label, [to_flush])

                    # Capture artifact bytes up to budget
                    if len(artifact_bytes) < stream_budget:
                        remaining = stream_budget - len(artifact_bytes)
                        if len(line) > remaining:
                            artifact_bytes.extend(line[:remaining])
                            if event_buf_label == "stdout":
                                stdout_trunc = True
                            else:
                                stderr_trunc = True
                        else:
                            artifact_bytes.extend(line)

                async def _reader(
                    stream: asyncio.StreamReader,
                    artifact_bytes: bytearray,
                    event_buf_label: str,
                ):
                    nonlocal stdout_done, stderr_done
                    # Read to the end whatever happens to a line: a pipe nobody
                    # reads fills up and blocks the container, and its client
                    # then never exits.
                    try:
                        async for line in read_lines(stream):
                            try:
                                await _take(line, artifact_bytes, event_buf_label)
                            except Exception as e:
                                logger.debug("Output line dropped on %s: %s", event_buf_label, e)
                    except Exception as e:
                        # The pipe itself failed, and asyncio has closed it:
                        # there is nothing left to read, and nothing to block on.
                        logger.warning("Reading container %s failed: %s", event_buf_label, e)

                    # Mark done
                    if event_buf_label == "stdout":
                        stdout_done = True
                    else:
                        stderr_done = True

                async def _flusher():
                    nonlocal stdout_event_size, stderr_event_size
                    # Periodically flush any buffered events every 500ms until both readers done.
                    try:
                        while not (stdout_done and stderr_done):
                            await asyncio.sleep(0.15)
                            async with lock:
                                sbuf = stdout_event_buf.copy()
                                stdout_event_buf.clear()
                                stdout_event_size = 0
                                ebuf = stderr_event_buf.copy()
                                stderr_event_buf.clear()
                                stderr_event_size = 0
                            if sbuf:
                                await _flush_event_buffer("stdout", sbuf)
                            if ebuf:
                                await _flush_event_buffer("stderr", ebuf)
                        # Final flush after readers are done
                        async with lock:
                            sbuf = stdout_event_buf.copy()
                            stdout_event_buf.clear()
                            ebuf = stderr_event_buf.copy()
                            stderr_event_buf.clear()
                        if sbuf:
                            await _flush_event_buffer("stdout", sbuf)
                        if ebuf:
                            await _flush_event_buffer("stderr", ebuf)
                    except asyncio.CancelledError:
                        return

                # Start readers and flusher
                assert proc.stdout is not None
                assert proc.stderr is not None
                reader_tasks = [
                    asyncio.create_task(_reader(proc.stdout, stdout_bytes, "stdout")),
                    asyncio.create_task(_reader(proc.stderr, stderr_bytes, "stderr")),
                ]
                flusher_task = asyncio.create_task(_flusher())

                # Wait until readers finish or deadline is reached
                try:
                    remaining = max(deadline - time.monotonic(), 1)
                    await asyncio.wait_for(asyncio.gather(*reader_tasks), timeout=remaining)
                except TimeoutError:
                    # Let caller handle killing the process
                    for t in reader_tasks:
                        t.cancel()
                    flusher_task.cancel()
                    with contextlib.suppress(Exception):
                        await flusher_task
                    raise
                except asyncio.CancelledError:
                    # Outer cancellation. gather() has already cancelled the
                    # readers, so they never reach their mark-done lines — and
                    # the flusher's loop waits on exactly those flags, so
                    # nothing else would ever stop it: one immortal task per
                    # cancelled step. Cancel it (no await — same cancelled-task
                    # rule as the caller's kill path) and let the cancellation
                    # propagate.
                    for t in reader_tasks:
                        t.cancel()
                    flusher_task.cancel()
                    raise

                # Readers done — let flusher complete its final flush
                try:
                    await asyncio.wait_for(flusher_task, timeout=5.0)
                except (TimeoutError, Exception):
                    flusher_task.cancel()
                    with contextlib.suppress(Exception):
                        await flusher_task

                # Return decoded artifacts and truncation flags
                return (
                    stdout_bytes.decode("utf-8", errors="replace"),
                    stdout_trunc,
                    stderr_bytes.decode("utf-8", errors="replace"),
                    stderr_trunc,
                )

            try:
                remaining = max(deadline - time.monotonic(), 1)
                stdout_out, stdout_trunc, stderr_out, stderr_trunc = await asyncio.wait_for(
                    _stream_and_capture(proc, ctx, deadline, stream_budget),
                    timeout=remaining,
                )
                exit_code = await asyncio.wait_for(
                    proc.wait(), timeout=max(deadline - time.monotonic(), 1)
                )
            except TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                # Bounded: the readers are stopped by now, and a pipe they left
                # full never closes, which asyncio's wait() also waits for.
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(proc.wait(), timeout=KILL_WAIT_SECONDS)
                return HandlerResult(
                    success=False,
                    error=f"Container execution timed out after {timeout}s",
                    summary="Container timed out",
                )
            except asyncio.CancelledError:
                # Cancellation (workflow cancelled, heartbeat timeout) is a
                # BaseException, so it bypasses the `except Exception` clause
                # below: without this branch, `finally` would be the only thing
                # that runs. `finally` force-removes the container, which is
                # what normally ends this attached client -- but it is an
                # unshielded `await` in a cancelled task, so it cannot be the
                # last line of defence. Kill the client here so `docker start
                # -a` can never outlive the step it belongs to.
                #
                # Deliberately no `await proc.wait()`: awaiting inside an
                # already-cancelling task is not guaranteed to make progress,
                # and the event loop's child watcher reaps the killed process
                # whether or not anyone waits on it.
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                cancelled_while_running = True
                raise

            raw_stdout = stdout_out
            raw_stderr = stderr_out
            output = raw_stdout + raw_stderr
            truncated = stdout_trunc or stderr_trunc
            if truncated:
                output += f"\n[TRUNCATED after {max_bytes} bytes]"

            output_lines.append(output)

            await _safe_emit_progress(
                f"Container exited with code {exit_code}",
                attrs={"milestone": "container_exited", "exit_code": exit_code},
            )

            duration = time.monotonic() - start_time

            # Structured results the step wrote (step I/O contract). Collected
            # before the artifact harvest and never fatal here: what could not
            # be collected is reported in collect_errors for the handler.
            collected, collect_errors = await self._collect_job_paths(
                docker_bin,
                container_name,
                job.collect,
                docker_env=docker_env,
                deadline=deadline,
                ctx=ctx,
            )

            generated_text_artifacts: list[dict[str, Any]] = []
            skipped_generated_artifacts: list[dict[str, Any]] = []
            generated_artifacts_cap: int | None = None
            try:
                generated_artifacts_staging_dir = tempfile.mkdtemp(
                    prefix="hegemony-generated-artifacts-"
                )
                generated_artifacts_cp = await self._run_docker(
                    docker_bin,
                    [
                        "cp",
                        f"{container_name}:{new_artifacts_path}/.",
                        generated_artifacts_staging_dir,
                    ],
                    env=docker_env,
                    timeout=max(deadline - time.monotonic(), 1),
                )
                if generated_artifacts_cp.returncode != 0:
                    logger.warning(
                        "Failed to collect generated container artifacts",
                        extra={
                            "run_id": ctx.run_id,
                            "step_id": ctx.step_id,
                            "step_run_id": ctx.step_run_id,
                            "new_artifacts_path": new_artifacts_path,
                            "stderr": generated_artifacts_cp.stderr[:500],
                        },
                    )
                else:
                    generated_artifacts_cap = runtime.artifact_max_file_size_bytes
                    (
                        generated_text_artifacts,
                        generated_binary_files,
                        skipped_generated_artifacts,
                    ) = _collect_generated_text_artifacts(
                        generated_artifacts_staging_dir, generated_artifacts_cap
                    )
                    uploaded_binary = await _upload_generated_binary_artifacts(
                        ctx, generated_binary_files
                    )
                    logger.info(
                        "Collected generated container artifacts",
                        extra={
                            "run_id": ctx.run_id,
                            "step_id": ctx.step_id,
                            "step_run_id": ctx.step_run_id,
                            "new_artifacts_path": new_artifacts_path,
                            "count": len(generated_text_artifacts),
                            "uploaded_binary": uploaded_binary,
                            "skipped": len(skipped_generated_artifacts),
                            "skipped_detail": skipped_generated_artifacts[
                                :_MAX_LOGGED_SKIP_RECORDS
                            ],
                            "max_file_size_bytes": generated_artifacts_cap,
                        },
                    )

            except Exception as e:
                logger.warning(
                    "Generated container artifact harvesting failed",
                    extra={
                        "run_id": ctx.run_id,
                        "step_id": ctx.step_id,
                        "step_run_id": ctx.step_run_id,
                        "new_artifacts_path": new_artifacts_path,
                        "error": str(e),
                    },
                )

            # 8. Store full output as artifact
            # Split stdout/stderr for UI rendering; keep combined in content_text for fallback
            evidence = [
                {
                    "kind": "container_output",
                    "name": f"container_output_{ctx.step_id}",
                    "content_text": output,
                    "content_json": {
                        "exit_code": exit_code,
                        "image": image,
                        "image_digest": image_digest,
                        "image_served": served,
                        "image_source": acquired.source,
                        "image_cached": acquired.cached,
                        "duration_seconds": round(duration, 2),
                        "truncated": truncated,
                        "container_name": container_name,
                        "stdout": stdout_out,
                        "stderr": stderr_out,
                    },
                }
            ]
            evidence.extend(generated_text_artifacts)
            if skipped_generated_artifacts:
                evidence.append(
                    _describe_skipped_artifacts(
                        skipped_generated_artifacts,
                        step_id=ctx.step_id,
                        new_artifacts_path=new_artifacts_path,
                        max_binary_size=generated_artifacts_cap,
                    )
                )

            return ContainerJobResult(
                exit_code=exit_code,
                stdout=stdout_out,
                stderr=stderr_out,
                truncated=truncated,
                duration_seconds=round(duration, 2),
                image=image,
                evidence=evidence,
                skipped_artifacts=len(skipped_generated_artifacts),
                collected=collected,
                collect_errors=collect_errors,
                image_digest=image_digest,
                image_served=served,
                image_source=acquired.source,
                image_cached=acquired.cached,
            )

        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start_time
            # Kill the container on timeout
            await self._force_remove_container(docker_bin, container_name, docker_host=docker_host)
            return HandlerResult(
                success=False,
                error=f"Container timed out after {timeout}s (image: {image})",
                summary=f"Timeout after {timeout}s",
                # Zero, not absent: a timeout kills the container before the
                # harvest runs, and consumers of the metric should not have to
                # special-case the shape of a timed-out step.
                metrics={
                    "duration_seconds": round(duration, 2),
                    "image": image,
                    "skipped_artifacts": 0,
                },
            )
        except FileNotFoundError:
            return HandlerResult(
                success=False,
                error=f"Docker binary not found at '{docker_bin}'",
                summary="Docker not available",
            )
        except Exception as e:
            logger.exception(f"Container execution failed: {e}")
            return HandlerResult(
                success=False,
                error=str(e),
                summary=f"Container execution error: {type(e).__name__}",
            )
        finally:
            # A cancelled step's container may be mid-change (a tf apply): with a
            # stop grace it gets SIGTERM and that long to finish in-flight work,
            # save its state and release its locks before it is removed. A second
            # cancellation (the worker shutting down) does not cut the wait short:
            # removing the container then would kill the tool mid-save. The wait
            # is bounded by docker stop's own timeout (the grace plus 30 s).
            if cancelled_while_running and stop_grace:
                stop = asyncio.ensure_future(
                    self._stop_container(
                        docker_bin, container_name, stop_grace, docker_host=docker_host
                    )
                )
                try:
                    while not stop.done():
                        with contextlib.suppress(asyncio.CancelledError):
                            await asyncio.shield(stop)
                    stop.result()
                except (Exception, asyncio.CancelledError) as e:
                    logger.warning(f"Cleanup: graceful stop of {container_name} failed: {e!r}")
            # Best-effort cleanup
            try:
                await self._force_remove_container(
                    docker_bin, container_name, docker_host=docker_host
                )
            except Exception as e:
                logger.warning(f"Cleanup: container removal failed: {e}")

            try:
                if staging_dir and os.path.exists(staging_dir):
                    shutil.rmtree(staging_dir, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Cleanup: workspace removal failed: {e}")

            try:
                if artifact_staging_dir and os.path.exists(artifact_staging_dir):
                    shutil.rmtree(artifact_staging_dir, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Cleanup: artifact staging removal failed: {e}")

            try:
                if generated_artifacts_staging_dir and os.path.exists(
                    generated_artifacts_staging_dir
                ):
                    shutil.rmtree(generated_artifacts_staging_dir, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Cleanup: generated artifact staging removal failed: {e}")

            try:
                if step_outputs_staging_dir and os.path.exists(step_outputs_staging_dir):
                    shutil.rmtree(step_outputs_staging_dir, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Cleanup: step outputs staging removal failed: {e}")

            try:
                if root_dirs_staging_parent and os.path.exists(root_dirs_staging_parent):
                    shutil.rmtree(root_dirs_staging_parent, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Cleanup: container root staging removal failed: {e}")

            await _safe_emit_progress(
                "Cleanup complete",
                attrs={"milestone": "cleanup_complete"},
            )

    async def _collect_job_paths(
        self,
        docker_bin: str,
        container_name: str,
        paths: list[str],
        *,
        docker_env: dict[str, str],
        deadline: float,
        ctx: HandlerContext,
    ) -> tuple[dict[str, bytes], dict[str, str]]:
        """Copy ``paths`` (container directories) out of the exited container.

        Returns file contents keyed by absolute container path, and what could
        not be collected (path -> reason). Bounded by
        :data:`MAX_COLLECTED_BYTES`; symlinks and anything that resolves
        outside the copy are skipped for the same reason the artifact harvest
        skips them (``docker cp`` preserves links, and the worker must never
        follow one onto its own filesystem). The copy gets at least
        :data:`COLLECT_GRACE_SECONDS`, whatever is left of the step's deadline.
        """
        collected: dict[str, bytes] = {}
        errors: dict[str, str] = {}
        budget = MAX_COLLECTED_BYTES
        for container_path in paths:
            root = container_path.rstrip("/") or "/"
            local_dir = tempfile.mkdtemp(prefix="hegemony-collect-")
            try:
                proc = await self._run_docker(
                    docker_bin,
                    ["cp", f"{container_name}:{root}/.", local_dir],
                    env=docker_env,
                    timeout=max(deadline - time.monotonic(), COLLECT_GRACE_SECONDS),
                )
                if proc.returncode != 0:
                    # The runner staged every collect root, so this is not "the
                    # step wrote nothing": the copy itself failed.
                    stderr = proc.stderr.strip()[:500]
                    errors[root] = f"docker cp failed: {stderr or f'exit code {proc.returncode}'}"
                    logger.warning(
                        "Collecting container results failed",
                        extra={
                            "run_id": ctx.run_id,
                            "step_run_id": ctx.step_run_id,
                            "path": root,
                            "stderr": stderr,
                        },
                    )
                    continue
                resolved_root = os.path.realpath(local_dir)
                for walk_root, dirs, files in os.walk(local_dir):
                    dirs.sort()
                    files.sort()
                    for file_name in files:
                        file_path = os.path.join(walk_root, file_name)
                        if (
                            os.path.islink(file_path)
                            or not os.path.isfile(file_path)
                            or not _is_within_directory(resolved_root, os.path.realpath(file_path))
                        ):
                            continue
                        size = os.path.getsize(file_path)
                        relative = os.path.relpath(file_path, local_dir).replace(os.sep, "/")
                        if size > budget:
                            errors[f"{root.rstrip('/')}/{relative}"] = (
                                f"{size} bytes, over the {MAX_COLLECTED_BYTES}-byte "
                                "collection budget"
                            )
                            logger.warning(
                                "Collected file skipped: over the collection budget",
                                extra={
                                    "run_id": ctx.run_id,
                                    "step_run_id": ctx.step_run_id,
                                    "path": file_path,
                                    "size": size,
                                },
                            )
                            continue
                        with open(file_path, "rb") as fh:
                            data = fh.read()
                        budget -= len(data)
                        collected[f"{root.rstrip('/')}/{relative}"] = data
            except Exception as e:  # noqa: BLE001 - reported, never fatal
                errors[root] = f"{type(e).__name__}: {e}"[:500]
                logger.warning(
                    "Collecting container results failed",
                    extra={
                        "run_id": ctx.run_id,
                        "step_run_id": ctx.step_run_id,
                        "path": root,
                        "error": str(e),
                    },
                )
            finally:
                shutil.rmtree(local_dir, ignore_errors=True)
        return collected, errors

    async def _pull_image(
        self,
        *,
        docker_bin: str,
        image: str,
        docker_env: dict[str, str],
        docker_host: str,
        deadline: float,
        emit: Callable[..., Awaitable[None]],
    ) -> HandlerResult | None:
        """Pull ``image``, streaming byte progress; returns a failure result or None.

        The Engine API path (:func:`stream_pull`) provides throttled
        ``pull_progress`` events; any :class:`EnginePullError` falls back to
        the plain ``docker pull`` CLI — the authoritative pull mechanism —
        after announcing the downgrade with a single ``pull_fallback`` event.
        Daemon selection matches the CLI calls byte-for-byte: the API path
        derives its endpoint from the same ``docker_host`` value that
        ``_docker_env`` would place as ``DOCKER_HOST``.

        Deadline exhaustion mid-pull raises ``subprocess.TimeoutExpired`` so
        the existing timeout handling in ``execute`` produces the identical
        "Container timed out" result — there is no time left for a CLI retry.
        """
        await emit(
            f"Pulling image {image}...",
            attrs={"milestone": "pull_start", "image": image},
        )
        pull_start = time.monotonic()
        pull_method = "api"
        outcome: PullOutcome | None = None
        # No floor: a second granted to a step that has already run out is a
        # second it does not have, and a pull that succeeds inside it leaves
        # the step running past its own deadline. Out of time is a timeout.
        remaining = deadline - pull_start
        if remaining <= 0:
            raise subprocess.TimeoutExpired([docker_bin, "pull", image], 0)
        try:
            outcome = await asyncio.wait_for(
                stream_pull(
                    image=image,
                    docker_host=docker_host,
                    env=docker_env,
                    emit=emit,
                ),
                timeout=remaining,
            )
        except TimeoutError:
            raise subprocess.TimeoutExpired([docker_bin, "pull", image], remaining) from None
        except EnginePullError as e:
            reason = str(e)[:200] or type(e).__name__
            logger.info(
                "Engine-API pull unavailable, falling back to docker pull",
                extra={"image": image, "reason": reason},
            )
            await emit(
                f"Streaming pull unavailable ({reason}); falling back to docker pull",
                attrs={"milestone": "pull_fallback", "image": image, "reason": reason},
            )
            pull_method = "cli"
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired([docker_bin, "pull", image], 0) from None
            pull_proc = await self._run_docker(
                docker_bin, ["pull", image], env=docker_env, timeout=remaining
            )
            if pull_proc.returncode != 0:
                return HandlerResult(
                    success=False,
                    error=f"Docker pull failed: {pull_proc.stderr[:500]}",
                    summary=f"Failed to pull image {image}",
                )
            # The CLI prints the same closing sentence the API stream carries,
            # so a cached image reads the same on both paths. Bytes moved are
            # not recoverable here — a piped `docker pull` prints no progress.
            outcome = PullOutcome(
                up_to_date="image is up to date" in pull_proc.stdout.lower(),
                bytes_downloaded=BYTES_UNKNOWN,
            )
        pull_duration = time.monotonic() - pull_start
        image_size = await self._image_size_bytes(
            docker_bin=docker_bin, image=image, docker_env=docker_env, deadline=deadline
        )

        # Steps reuse images constantly — the same image across a whole flow is
        # the normal case — and a pull that fetched nothing looked identical to
        # one that fetched a gigabyte. Say which happened, and how big the
        # thing is either way.
        size_note = f" ({format_size(image_size)})" if image_size is not None else ""
        if outcome is not None and outcome.up_to_date:
            message = f"Image already present{size_note}, checked in {pull_duration:.1f}s"
        else:
            message = f"Image pulled in {pull_duration:.1f}s{size_note}"

        attrs: dict[str, Any] = {
            "milestone": "pull_complete",
            "image_pull_duration_seconds": round(pull_duration, 1),
            "image": image,
            "pull_method": pull_method,
        }
        if image_size is not None:
            attrs["image_size_bytes"] = image_size
        if outcome is not None:
            attrs["image_up_to_date"] = outcome.up_to_date
            if outcome.bytes_downloaded != BYTES_UNKNOWN:
                attrs["bytes_downloaded"] = outcome.bytes_downloaded
        await emit(message, attrs=attrs)
        return None

    async def _lookup(
        self,
        client: RegistryClient,
        repo: str,
        reference: str,
        *,
        docker_bin: str,
        image: str,
        deadline: float,
    ) -> str | None:
        """:meth:`RegistryClient.manifest_digest`, bounded by the step's deadline.

        A registry that answers slowly must not carry the step past its own
        timeout before the pull has even started: out of time here is the same
        timeout the pull reports, so ``execute`` ends the step the same way.
        """
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired([docker_bin, "pull", image], 0)
        try:
            return await asyncio.wait_for(
                client.manifest_digest(repo, reference), timeout=remaining
            )
        except TimeoutError:
            raise subprocess.TimeoutExpired([docker_bin, "pull", image], remaining) from None

    async def _acquire_image(
        self,
        *,
        job: ContainerJob,
        image: str,
        cache: ImageCache | None,
        docker_bin: str,
        docker_env: dict[str, str],
        docker_host: str,
        deadline: float,
        emit: Callable[..., Awaitable[None]],
    ) -> HandlerResult | AcquiredImage:
        """Put ``image`` on the daemon, through the platform registry's cache when it applies.

        Without a cache (no platform registry, ``cache_image`` off, or an image
        that already lives in the platform registry) this is the plain pull.
        Otherwise: ask the image's registry which digest the reference names
        today (one ``HEAD``; a digest-qualified reference already says), look
        for a copy of that digest under the step's own namespace and then the
        read-only ones, and pull the copy when there is one. A missing copy
        means pulling that digest from upstream and saving a copy of it
        (:meth:`_store_copy`). An unreachable upstream falls back to the last
        copy by tag, with a warning; an upstream that refuses the check gets
        the plain pull, with no copy served or saved, since a refusal may mean
        access was withdrawn; an unreachable platform registry means a plain
        upstream pull, with a note. Every registry lookup is bounded by what
        is left of the step's deadline. Nothing here fails the step except the
        pull itself, or running out of time.
        """
        wants_cache = bool(job.config.get("cache_image", True))
        plan = plan_cache(image, cache) if (wants_cache and cache is not None) else None
        if plan is None:
            failure = await self._pull_image(
                docker_bin=docker_bin,
                image=image,
                docker_env=docker_env,
                docker_host=docker_host,
                deadline=deadline,
                emit=emit,
            )
            if failure is not None:
                return failure
            in_platform = cache is not None and parse_reference(image).host == cache.registry
            return AcquiredImage(
                served=image, source="platform" if in_platform else "upstream", cached=False
            )

        assert cache is not None  # plan_cache returned a plan
        reference = plan.reference
        registry = RegistryClient(
            cache.api_url,
            login_for(cache.registry, docker_env),
            trust_env=False,
            transport=_registry_transport(cache.api_url),
        )
        upstream_url = upstream_api_url(reference.host)
        upstream = RegistryClient(
            upstream_url,
            login_for(reference.host, docker_env),
            trust_env=True,
            transport=_registry_transport(upstream_url),
        )

        # 1. The digest upstream serves today: the key a copy is filed under,
        # and what the pull below asks for.
        upstream_digest: str | None = reference.digest
        upstream_problem: str | None = None
        if upstream_digest is None:
            try:
                upstream_digest = await self._lookup(
                    upstream,
                    reference.repo,
                    reference.manifest_reference,
                    docker_bin=docker_bin,
                    image=image,
                    deadline=deadline,
                )
            except RegistryUnavailable as exc:
                upstream_problem = str(exc)
            except RegistryDenied as exc:
                # A refusal is an answer, not an outage. The login this client
                # could offer was not accepted, so no copy stands in for the
                # image (access may have been withdrawn) and none is made (the
                # digest is unknown). The pull is the authority: docker may
                # hold a login this client cannot use, or fail the step.
                await emit(
                    f"{reference.host} refused the manifest check for {image} ({exc}); "
                    "pulling it from its registry without the cache",
                    attrs={"milestone": "image_cache_skip", "image": image, "reason": str(exc)},
                )
                failure = await self._pull_image(
                    docker_bin=docker_bin,
                    image=image,
                    docker_env=docker_env,
                    docker_host=docker_host,
                    deadline=deadline,
                    emit=emit,
                )
                if failure is not None:
                    return failure
                return AcquiredImage(served=image, source="upstream", cached=False)
            # None: the tag does not exist upstream; the pull below says so.
        key_tag = cache_key_tag(upstream_digest) if upstream_digest else None

        # 2. A copy of that digest, or, with upstream unreachable, the last copy
        # under the tag.
        lookup_tag = key_tag or (reference.tag if upstream_problem else None)
        cache_problem: str | None = None
        copy: str | None = None
        if lookup_tag:
            for repo in plan.read_repos:
                try:
                    found = await self._lookup(
                        registry,
                        repo,
                        lookup_tag,
                        docker_bin=docker_bin,
                        image=image,
                        deadline=deadline,
                    )
                except (RegistryUnavailable, RegistryDenied) as exc:
                    cache_problem = str(exc)
                    break
                if found is not None:
                    copy = plan.copy_reference(repo, lookup_tag)
                    break
        if copy is not None:
            if upstream_problem:
                await emit(
                    f"{reference.host} is unreachable ({upstream_problem}); using the cached "
                    f"copy of {image} from the platform registry",
                    attrs={
                        "milestone": "image_cache_stale",
                        "image": image,
                        "copy": copy,
                        "reason": upstream_problem,
                    },
                )
            else:
                await emit(
                    f"Using the cached copy of {image} from the platform registry",
                    attrs={"milestone": "image_cache_hit", "image": image, "copy": copy},
                )
            failure = await self._pull_image(
                docker_bin=docker_bin,
                image=copy,
                docker_env=docker_env,
                docker_host=docker_host,
                deadline=deadline,
                emit=emit,
            )
            if failure is None:
                return AcquiredImage(served=copy, source="cache", cached=False)
            # The copy was there a moment ago and cannot be pulled now: the
            # image's own registry is the fallback, and saving a copy afterwards
            # would ask the same registry again.
            cache_problem = failure.error or "the copy could not be pulled"
            await emit(
                f"Could not pull the cached copy ({cache_problem}); pulling {image} from "
                "its registry",
                attrs={"milestone": "image_cache_miss", "image": image, "reason": cache_problem},
            )
        elif cache_problem:
            await emit(
                f"Platform registry unavailable ({cache_problem}); pulling {image} from its "
                "registry without caching it",
                attrs={"milestone": "image_cache_skip", "image": image, "reason": cache_problem},
            )

        # 3. The image's own registry, by the digest the check named when it
        # named one: the tag may move between the check and the pull, and a
        # copy filed under a digest must hold that digest's content.
        target = image
        if upstream_digest and not reference.digest:
            target = pin_reference(image, upstream_digest)
        failure = await self._pull_image(
            docker_bin=docker_bin,
            image=target,
            docker_env=docker_env,
            docker_host=docker_host,
            deadline=deadline,
            emit=emit,
        )
        if failure is not None:
            return failure
        cached = False
        if key_tag and cache_problem is None:
            tags = [key_tag, *([reference.tag] if reference.tag else [])]
            cached = await self._store_copy(
                image=target,
                plan=plan,
                tags=tags,
                docker_bin=docker_bin,
                docker_env=docker_env,
                deadline=deadline,
                emit=emit,
            )
        return AcquiredImage(served=target, source="upstream", cached=cached)

    async def _store_copy(
        self,
        *,
        image: str,
        plan: CachePlan,
        tags: list[str],
        docker_bin: str,
        docker_env: dict[str, str],
        deadline: float,
        emit: Callable[..., Awaitable[None]],
    ) -> bool:
        """Push the pulled ``image`` into the platform registry under ``tags``.

        The digest key goes first, so a later run finds the copy even if the
        human-readable tag never lands; a copy that made it under the key
        alone counts as saved, with a note about the missing tag. Bounded by
        what is left of the step's deadline minus a reserve for the step
        itself, and by an absolute cap, the tagging included; out of time, a
        refused push or a daemon error leave a note in the step's events and
        the step carries on with the image it already has. The local tags stay
        on the daemon: the next pull of the copy then finds it present.
        """
        remaining = deadline - time.monotonic()
        budget = min(remaining - _COPY_RESERVE_SECONDS, _COPY_MAX_SECONDS)
        if budget < _COPY_MIN_SECONDS:
            await emit(
                f"Not enough time left to save a copy of {image} to the platform registry",
                attrs={"milestone": "image_cache_store_skipped", "image": image},
            )
            return False
        started = time.monotonic()
        problem = ""
        published: list[str] = []
        copy = ""
        for tag in tags:
            copy = plan.copy_reference(plan.write_repo, tag)
            try:
                left = budget - (time.monotonic() - started)
                if left <= 0:
                    problem = "ran out of time"
                    break
                tagged = await self._run_docker(
                    docker_bin,
                    ["tag", image, copy],
                    env=docker_env,
                    timeout=min(left, _TAG_TIMEOUT_SECONDS),
                )
                if tagged.returncode != 0:
                    problem = (tagged.stderr or "docker tag failed")[:300]
                    break
                left = budget - (time.monotonic() - started)
                if left <= 0:
                    problem = "ran out of time"
                    break
                pushed = await self._run_docker(
                    docker_bin, ["push", copy], env=docker_env, timeout=left
                )
                if pushed.returncode != 0:
                    problem = (pushed.stderr or "docker push failed")[:300]
                    break
                published.append(copy)
            except subprocess.TimeoutExpired:
                problem = "ran out of time"
                break
            except (subprocess.SubprocessError, OSError) as exc:
                problem = str(exc)[:300] or type(exc).__name__
                break
        duration = time.monotonic() - started
        if problem and not published:
            await emit(
                f"Could not save a copy of {image} to the platform registry: {problem}",
                attrs={"milestone": "image_cache_store_failed", "image": image, "reason": problem},
            )
            return False
        if problem:
            # The key is in place, so later runs find the copy; only the
            # human-readable tag is missing. The copy counts as saved.
            await emit(
                f"Saved a copy of {image} to the platform registry as {published[-1]}, "
                f"but not as {copy}: {problem}",
                attrs={
                    "milestone": "image_cache_store_partial",
                    "image": image,
                    "copy": published[-1],
                    "missing": copy,
                    "reason": problem,
                    "duration_seconds": round(duration, 1),
                },
            )
            return True
        copy = plan.copy_reference(plan.write_repo, tags[-1])
        await emit(
            f"Saved a copy of {image} to the platform registry as {copy} in {duration:.1f}s",
            attrs={
                "milestone": "image_cache_store",
                "image": image,
                "copy": copy,
                "duration_seconds": round(duration, 1),
            },
        )
        return True

    async def _image_size_bytes(
        self,
        *,
        docker_bin: str,
        image: str,
        docker_env: dict[str, str],
        deadline: float,
    ) -> int | None:
        """On-disk size of ``image``, or None when the daemon will not say.

        The number ``docker images`` prints — the unpacked size — rather than
        the bytes that crossed the wire. It is the figure a reader can check
        against their own daemon, and the only one that still means something
        when the pull transferred nothing at all.

        Never fails the step, and never extends it: this is a caption on an
        event that has already succeeded, so a daemon that is slow or terse
        just loses the caption. A step already out of time skips the lookup
        rather than spending another second of a budget it has overrun.
        """
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            proc = await self._run_docker(
                docker_bin,
                ["image", "inspect", "--format", "{{.Size}}", image],
                env=docker_env,
                timeout=min(remaining, _IMAGE_INSPECT_TIMEOUT),
            )
        except (subprocess.SubprocessError, OSError):
            return None
        if proc.returncode != 0:
            return None
        try:
            return int(proc.stdout.strip())
        except ValueError:
            return None

    async def _image_repo_digest(
        self,
        *,
        docker_bin: str,
        image: str,
        docker_env: dict[str, str],
        deadline: float,
    ) -> str:
        """``repository@sha256:...`` of the pulled ``image``, or "" when unknown.

        Read from the image's RepoDigests, the digests the daemon pulled it by,
        for the repository ``image`` names (in ``image``'s own spelling). An
        image built on the daemon and never pushed has none; the step then
        runs, and reports, the tag. Never fails the step.
        """
        if "@" in image:
            return image
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return ""
        try:
            proc = await self._run_docker(
                docker_bin,
                ["image", "inspect", "--format", "{{json .RepoDigests}}", image],
                env=docker_env,
                timeout=min(remaining, _IMAGE_INSPECT_TIMEOUT),
            )
        except (subprocess.SubprocessError, OSError):
            return ""
        if proc.returncode != 0:
            return ""
        try:
            repo_digests = json.loads(proc.stdout.strip() or "null") or []
        except ValueError:
            return ""
        digest = repo_digest_for(image, [str(entry) for entry in repo_digests])
        if not digest:
            logger.info("No registry digest for image %s; running it by tag", image)
        return digest

    @staticmethod
    async def _run_docker(
        docker_bin: str,
        args: list[str],
        *,
        env: dict[str, str],
        timeout: float,
    ) -> subprocess.CompletedProcess[str]:
        """Run one docker CLI call with captured text output.

        The single choke point for daemon selection: every docker invocation
        receives its environment (and thus ``DOCKER_HOST``) here, so a future
        call site cannot forget ``env`` and silently target the wrong daemon.
        The attached ``docker start -a`` stream is the one deliberate
        exception (``asyncio.create_subprocess_exec`` for live pipes).
        """

        def _invoke() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [docker_bin, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )

        return await asyncio.to_thread(_invoke)

    async def _preflight_cleanup(
        self, docker_bin: str, ctx: HandlerContext, *, docker_host: str
    ) -> None:
        """Remove pre-existing containers with matching labels before new attempt.

        Sweeps the same sandbox daemon the run targets (``docker_host`` selects
        it), so a retry cleans up the previous attempt's container on the
        daemon it was actually created on.
        """
        docker_env = _docker_env(docker_host)
        try:
            result = await self._run_docker(
                docker_bin,
                [
                    "ps",
                    "-a",
                    "--filter",
                    f"label=hegemony.run_id={ctx.run_id}",
                    "--filter",
                    f"label=hegemony.step_run_id={ctx.step_run_id}",
                    "--format",
                    "{{.Names}}",
                ],
                env=docker_env,
                timeout=10,
            )
            stdout = str(result.stdout or "")
            for name in stdout.strip().splitlines():
                if name:
                    await self._force_remove_container(
                        docker_bin, name.strip(), docker_host=docker_host
                    )
        except Exception as e:
            logger.warning(f"Preflight cleanup failed: {e}")

    @classmethod
    async def _stop_container(
        cls, docker_bin: str, container_name: str, grace_seconds: int, *, docker_host: str
    ) -> None:
        """``docker stop``: SIGTERM, then SIGKILL after ``grace_seconds`` if it still runs."""
        logger.info(f"Stopping container {container_name}: SIGTERM, up to {grace_seconds}s to exit")
        start = time.monotonic()
        result = await cls._run_docker(
            docker_bin,
            ["stop", "-t", str(grace_seconds), container_name],
            env=_docker_env(docker_host),
            timeout=grace_seconds + 30,
        )
        if result.returncode != 0:
            raise RuntimeError(str(result.stderr or "").strip()[:200] or "docker stop failed")
        logger.info(f"Container {container_name} stopped after {time.monotonic() - start:.0f}s")

    @classmethod
    async def _force_remove_container(
        cls, docker_bin: str, container_name: str, *, docker_host: str
    ) -> None:
        """Force remove a container, ignoring errors if already gone.

        ``docker_host`` selects the sandbox daemon so removal hits the same
        daemon that created the container.
        """
        docker_env = _docker_env(docker_host)
        with contextlib.suppress(Exception):
            await cls._run_docker(
                docker_bin, ["rm", "-f", container_name], env=docker_env, timeout=10
            )
