# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""RunContainerHandler: run commands inside Docker containers with provisioning."""

import asyncio
import contextlib
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

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    MAX_CHAIN_OUTPUT_CHARS,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)

from .pull_progress import (
    BYTES_UNKNOWN,
    EnginePullError,
    PullOutcome,
    format_size,
    stream_pull,
)

logger = logging.getLogger(__name__)

# The image-size lookup is a caption, not a step operation: bounded well below
# any step deadline so a wedged daemon costs a missing number, not the step.
_IMAGE_INSPECT_TIMEOUT = 15.0


def _docker_env(docker_host: str) -> dict[str, str] | None:
    """Environment for a docker subprocess, optionally selecting the daemon.

    When ``docker_host`` is set (the worker's ``container_docker_host`` setting,
    surfaced as :attr:`ContainerRuntime.docker_host`), every docker invocation
    the handler spawns gets ``DOCKER_HOST`` pointing at the sandbox daemon on top
    of the inherited process environment. When empty, ``None`` is returned so the
    subprocess inherits the plain environment unchanged — byte-for-byte today's
    host-socket behavior. Daemon selection is environment, never argv, so the
    ``docker create`` args are identical on either daemon.

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
    if not docker_host:
        return None
    env = {key: value for key, value in os.environ.items() if key != "DOCKER_CONTEXT"}
    env["DOCKER_HOST"] = docker_host
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
            "share another container's namespace. Disabled when network access is "
            "disabled; leave empty for default Docker networking."
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
        title="Attach host Docker socket",
        description=(
            "Mounts /var/run/docker.sock into the container, granting full control of the "
            "host Docker daemon. Required for DinD tools like containerlab. Off by default."
        ),
        json_schema_extra={"x_advanced": True, "x_admin_only": True, "x_col_span": 2},
    )
    privileged: bool = Field(
        default=False,
        title="Run as privileged",
        description=(
            "Runs the container with --privileged, granting all host capabilities and "
            "access to /proc/sys (needed by containerlab to adjust rp_filter, etc.). "
            "Off by default."
        ),
        json_schema_extra={"x_advanced": True, "x_admin_only": True, "x_col_span": 2},
    )
    pid_mode: str = Field(
        default="",
        title="PID namespace",
        description=(
            "Optional. Share the host PID namespace (host) or another container's "
            "(container:<name>). Required by containerlab-in-Docker so it can resolve "
            "sibling container PIDs. Leave empty for default isolation."
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
            "One per line, format <abs-src>:<abs-dst>[:opts]. Bypasses workspace "
            "isolation; use sparingly (e.g. containerlab needs /var/run/netns shared)."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "/var/run/netns:/var/run/netns:shared\n/host/data:/data:ro",
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
            "Absolute path inside the container where newly created UTF-8 text files are "
            "harvested as step artifacts after the container exits. Defaults to "
            "/artifacts/new, or <artifacts_path>/new when you change the artifacts root."
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


def _decode_generated_artifact_text(raw_bytes: bytes) -> str | None:
    """Return UTF-8 text for generated artifacts, or None for binary payloads."""
    if b"\0" in raw_bytes:
        return None
    try:
        return raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _collect_generated_text_artifacts(
    staging_root: str, max_binary_size: int | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Read files harvested from the container's new-artifacts subfolder.

    Returns a tuple of ``(text_artifacts, binary_files, skipped_files)``:
    - ``text_artifacts``: UTF-8 text files as inline ``step_result`` artifacts.
    - ``binary_files``: metadata for non-text files to upload for download,
      each ``{"name", "path", "size", "content_type"}``.
    - ``skipped_files``: count of files skipped (unreadable, traversal, or
      binary files exceeding ``max_binary_size``).
    """
    import mimetypes

    artifacts: list[dict[str, Any]] = []
    binary_files: list[dict[str, Any]] = []
    skipped_files = 0

    if not os.path.isdir(staging_root):
        return artifacts, binary_files, skipped_files

    for root, dirs, files in os.walk(staging_root):
        dirs.sort()
        files.sort()

        for file_name in files:
            file_path = os.path.join(root, file_name)
            if not os.path.isfile(file_path):
                continue

            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                skipped_files += 1
                continue

            try:
                with open(file_path, "rb") as fh:
                    raw_bytes = fh.read()
            except OSError:
                skipped_files += 1
                continue

            relative_name = os.path.relpath(file_path, staging_root).replace(os.sep, "/")
            if relative_name.startswith("../"):
                skipped_files += 1
                continue

            content_text = _decode_generated_artifact_text(raw_bytes)
            if content_text is not None:
                artifacts.append(
                    {
                        "kind": "step_result",
                        "name": relative_name[:255],
                        "content_text": content_text,
                    }
                )
                continue

            # Binary file: schedule for upload unless it exceeds the size cap.
            if max_binary_size is not None and len(raw_bytes) > max_binary_size:
                skipped_files += 1
                continue

            content_type, _ = mimetypes.guess_type(file_name)
            binary_files.append(
                {
                    "name": relative_name[:255],
                    "path": file_path,
                    "size": file_size,
                    "content_type": content_type or "application/octet-stream",
                }
            )

    return artifacts, binary_files, skipped_files


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
                phase=ctx.phase,
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


class RunContainerHandler(BaseHandler):
    """Handler for running commands inside Docker containers.

    Executes user-defined scripts/commands in arbitrary Docker images
    with file provisioning, environment variables, and output capture.
    """

    handler_id = "container.run"
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "Run Container"
    description = "Run a command inside a Docker container on the worker host."
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
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
    # clab-in-Docker to resolve sibling container PIDs from the host.
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
        docker_ip: str = "",
        docker_ip6: str = "",
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
          bind-mounted at ``/shared`` (legacy Docker-in-Docker mode requiring an
          identical host path).

        ``docker_ip``/``docker_ip6`` pin the container's addresses on the policy
        network. The platform reserves them before programming the firewall so
        that this step's packet counters can be scoped to this container; an
        address the daemon rejects as taken fails the start rather than
        launching under someone else's counters, and the platform allocates a
        different one on the retry. Both are empty for the ordinary step, which
        declares no egress policy.
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
            # Only meaningful on a policy network, and only when the platform
            # reserved an address: it is what lets the worker count this
            # container's egress separately from every other step running
            # under the same policy. `none` takes no address at all.
            if docker_network != "none":
                if docker_ip:
                    args.append(f"--ip={docker_ip}")
                if docker_ip6:
                    args.append(f"--ip6={docker_ip6}")
        elif network_disabled:
            args.append("--network=none")

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
                "hegemony.handler_id=container.run",
            ]
        )

        # Stack discriminator: several compose stacks (dev/prod/demo) can share
        # one host Docker daemon, and the id labels alone cannot tell their
        # flow containers apart. The worker sets HEGEMONY_STACK_NAME (its
        # compose project name) so stack-scoped cleanup — the platform's
        # startup janitor and demo reset — only ever touches its own stack's
        # containers.
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

        # Advanced: expose the host Docker socket (DinD, containerlab, etc.).
        # This grants the container full control of the host Docker daemon;
        # opt-in only.
        if attach_docker_socket:
            args.extend(["-v", "/var/run/docker.sock:/var/run/docker.sock"])

        # Advanced: run the container with full host privileges. Required for
        # tools that need to write to /proc/sys (e.g. containerlab adjusting
        # rp_filter) or manage devices. Opt-in only.
        if privileged:
            args.append("--privileged")

        # Advanced: share the host PID namespace so the container can resolve
        # sibling container PIDs (clab-in-Docker needs this to inspect netns
        # paths of containers it creates via the host Docker socket).
        if pid_mode:
            args.append(f"--pid={pid_mode}")

        # Advanced: arbitrary bind mounts (validated above). Used to share
        # paths like /var/run/netns:/var/run/netns:shared with the host.
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

        services = ctx.require_services()
        runtime = services.container_runtime()

        docker_bin = runtime.docker_bin
        # Daemon selection for every docker call below. None (setting unset) means
        # inherit the worker's environment / host socket; set means DOCKER_HOST is
        # placed on each invocation (never process-wide — see _docker_env).
        docker_host = runtime.docker_host
        docker_env = _docker_env(docker_host)
        image = ctx.config.get("image", "")
        timeout = ctx.config.get("timeout_seconds", ctx.timeout_seconds)
        working_dir = ctx.config.get("working_dir", "/workspace")
        # Where flow attachments are copied inside the container. Defaults to
        # /attachments; steps may override to any absolute path. Trailing
        # slashes are normalized off so the docker cp target is well-formed.
        attachments_path = _normalize_container_root(
            ctx.config.get("attachments_path"), "/attachments"
        )
        artifacts_path = _normalize_container_root(ctx.config.get("artifacts_path"), "/artifacts")
        new_artifacts_path = _resolve_new_artifacts_path(ctx.config, artifacts_path)
        step_outputs_path = _normalize_container_root(
            ctx.config.get("step_outputs_path"), "/step_outputs"
        )

        # Container name with short IDs for uniqueness
        run_short = ctx.run_id[:8]
        step_short = ctx.step_run_id[:8]
        container_name = f"hegemony-{run_short}-{step_short}-a{ctx.attempt}"

        start_time = time.monotonic()
        deadline = start_time + timeout
        output_lines: list[str] = []
        exit_code = -1
        staging_dir: str | None = None
        artifact_staging_dir: str | None = None
        generated_artifacts_staging_dir: str | None = None
        step_outputs_staging_dir: str | None = None
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
            await self._preflight_cleanup(docker_bin, ctx, docker_host)

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
            raw_mounted_step_outputs = ctx.config.get("mounted_step_outputs")
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
                fetched_step_outputs = await services.fetch_run_step_outputs(ctx.run_id)
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
            raw_mounted_artifacts = ctx.config.get("mounted_artifacts")
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
                raw_legacy_mounts = ctx.config.get("mount_step_artifacts") or []
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

            # 6. Pull image (Engine-API streaming progress, CLI fallback)
            pull_failure = await self._pull_image(
                docker_bin=docker_bin,
                image=image,
                docker_env=docker_env,
                docker_host=docker_host,
                deadline=deadline,
                emit=_safe_emit_progress,
            )
            if pull_failure is not None:
                return pull_failure

            # 7. Build docker create command (container is created but not started)
            shared_workspace_path: str | None = None
            shared_workspace_volume: str | None = None
            if ctx.shared_workspace and runtime.shared_workspaces_enabled:
                workspace_dir = os.path.join(runtime.shared_workspace_root, ctx.run_id)
                # Create the run's subdirectory inside the worker's mounted
                # shared-workspace volume so the sibling container's
                # volume-subpath (or bind) mount resolves to existing content.
                os.makedirs(workspace_dir, exist_ok=True)
                volume_name = runtime.shared_workspace_volume.strip()
                if volume_name:
                    shared_workspace_volume = volume_name
                else:
                    shared_workspace_path = workspace_dir
            docker_args = self.build_docker_args(
                config=ctx.config,
                container_name=container_name,
                run_id=ctx.run_id,
                step_run_id=ctx.step_run_id,
                shared_workspace_path=shared_workspace_path,
                shared_workspace_volume=shared_workspace_volume,
                docker_network=runtime.docker_network,
                docker_ip=runtime.docker_ip,
                docker_ip6=runtime.docker_ip6,
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
            root_dirs_staging_dir = f"{staging_dir}-roots"
            os.makedirs(root_dirs_staging_dir, exist_ok=True)
            for container_root in {
                attachments_path,
                artifacts_path,
                new_artifacts_path,
                step_outputs_path,
                working_dir,
            }:
                _stage_container_root_dir(root_dirs_staging_dir, container_root)

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

                async def _reader(
                    stream: asyncio.StreamReader,
                    artifact_bytes: bytearray,
                    event_buf_label: str,
                ):
                    nonlocal \
                        stdout_trunc, \
                        stderr_trunc, \
                        stdout_event_size, \
                        stderr_event_size, \
                        stdout_done, \
                        stderr_done
                    while True:
                        try:
                            line = await stream.readline()
                        except Exception:
                            # On any read error, stop the reader
                            break
                        if not line:
                            break
                        # Decode using replace to avoid errors
                        text = line.decode("utf-8", errors="replace")

                        # Append to event buffer and possibly flush if size >= 4KB
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
                            if event_buf_label == "stdout":
                                await _flush_event_buffer("stdout", [to_flush])
                            else:
                                await _flush_event_buffer("stderr", [to_flush])

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
                proc.kill()
                await proc.wait()
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

            generated_text_artifacts: list[dict[str, Any]] = []
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
                    max_binary_size = runtime.artifact_max_file_size_bytes
                    (
                        generated_text_artifacts,
                        generated_binary_files,
                        skipped_generated_artifacts,
                    ) = _collect_generated_text_artifacts(
                        generated_artifacts_staging_dir, max_binary_size
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
                            "skipped_non_text": skipped_generated_artifacts,
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
                        "duration_seconds": round(duration, 2),
                        "truncated": truncated,
                        "container_name": container_name,
                        "stdout": stdout_out,
                        "stderr": stderr_out,
                    },
                }
            ]
            evidence.extend(generated_text_artifacts)

            success = exit_code == 0
            return HandlerResult(
                success=success,
                summary=f"Container exited with code {exit_code}"
                if success
                else f"Container failed with exit code {exit_code}",
                error=None if success else f"Exit code {exit_code}",
                metrics={
                    "exit_code": exit_code,
                    "duration_seconds": round(duration, 2),
                    "image": image,
                },
                evidence=evidence,
                output={
                    "stdout": stdout_out[:MAX_CHAIN_OUTPUT_CHARS],
                    "stderr": stderr_out[:MAX_CHAIN_OUTPUT_CHARS],
                },
            )

        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start_time
            # Kill the container on timeout
            await self._force_remove_container(docker_bin, container_name, docker_host)
            return HandlerResult(
                success=False,
                error=f"Container timed out after {timeout}s (image: {image})",
                summary=f"Timeout after {timeout}s",
                metrics={"duration_seconds": round(duration, 2), "image": image},
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
            # Best-effort cleanup
            try:
                await self._force_remove_container(docker_bin, container_name, docker_host)
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
                if root_dirs_staging_dir and os.path.exists(root_dirs_staging_dir):
                    shutil.rmtree(root_dirs_staging_dir, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Cleanup: container root staging removal failed: {e}")

            await _safe_emit_progress(
                "Cleanup complete",
                attrs={"milestone": "cleanup_complete"},
            )

    async def _pull_image(
        self,
        *,
        docker_bin: str,
        image: str,
        docker_env: dict[str, str] | None,
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
                    env=docker_env if docker_env is not None else os.environ,
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

    async def _image_size_bytes(
        self,
        *,
        docker_bin: str,
        image: str,
        docker_env: dict[str, str] | None,
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

    @staticmethod
    async def _run_docker(
        docker_bin: str,
        args: list[str],
        *,
        env: dict[str, str] | None,
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
        self, docker_bin: str, ctx: HandlerContext, docker_host: str = ""
    ) -> None:
        """Remove pre-existing containers with matching labels before new attempt.

        Sweeps the same daemon the run targets (``docker_host`` selects it, empty
        = host socket), so a retry cleans up the previous attempt's container on
        the daemon it was actually created on.
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
                    await self._force_remove_container(docker_bin, name.strip(), docker_host)
        except Exception as e:
            logger.warning(f"Preflight cleanup failed: {e}")

    @classmethod
    async def _force_remove_container(
        cls, docker_bin: str, container_name: str, docker_host: str = ""
    ) -> None:
        """Force remove a container, ignoring errors if already gone.

        ``docker_host`` (empty = host socket) selects the daemon so removal hits
        the same daemon that created the container.
        """
        docker_env = _docker_env(docker_host)
        with contextlib.suppress(Exception):
            await cls._run_docker(
                docker_bin, ["rm", "-f", container_name], env=docker_env, timeout=10
            )
