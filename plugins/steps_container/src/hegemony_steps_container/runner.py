# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Public container runner for tool handlers built on ``container.run``.

``container.run`` owns the platform's container execution: the sandbox daemon,
egress policy networks, image pulls with progress, attachment staging, live
output streaming, artifact harvesting, and cleanup. Tool handlers (Ansible,
OpenTofu/Terraform, …) reuse all of it instead of copying it: they describe a
:class:`ContainerJob` — the container config, extra files to stage, and
container paths to collect after exit — and call :func:`run_container_job`.

A tool handler sets ``container_backed = True`` so the host gives its steps the
same egress enforcement and admission rules as ``container.run``, and depends on
this wheel, so a hardened deployment that omits container execution omits every
tool handler with it. The wheels release in lockstep, so this module is a
monorepo API rather than third-party ABI.

Step I/O contract shared by every container-backed step. :data:`IO_ROOT`
(``/hegemony``) is reserved for it in every step container, ``container.run``
included:

- :data:`CONTEXT_PATH` (read): run and step identity and the step's tags.
  Never flow inputs: a step gets those through its own templated config.
- :data:`OUTPUT_DIR` (write): collected after the container exits; for
  ``container.run`` an ``output.json`` object here becomes the step's
  ``output.data``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from hegemony_step_sdk import HandlerContext, HandlerResult

#: Root of the platform's step I/O files inside a container.
IO_ROOT = "/hegemony"
#: Read-only context file staged into every container-backed step.
CONTEXT_PATH = f"{IO_ROOT}/context.json"
#: Directory collected after exit; tools write structured results here.
OUTPUT_DIR = f"{IO_ROOT}/out"
#: Where ``container.run`` stages ``secret_files`` (Docker's secrets convention).
SECRET_FILES_DIR = "/run/secrets"

#: Upper bound on bytes collected from the container per job. Collected files
#: are structured results, not artifacts: anything bigger belongs in the
#: new-artifacts folder, which uploads to storage instead of worker memory.
MAX_COLLECTED_BYTES = 8 * 1024 * 1024
#: Least time given to copying ``ContainerJob.collect`` out of the exited
#: container, even when the step's own deadline is (nearly) used up: the
#: container has finished, and losing its results would misreport the run.
#: Kept well under the 30 s the host allows an activity past its step timeout,
#: so the harvest and the container's removal still fit and the activity is
#: not timed out (and retried) over a slow copy.
COLLECT_GRACE_SECONDS = 10

#: How long a tool run through ``bounded`` (:func:`deadline_shell_lines`) gets
#: by default to stop after SIGTERM at the step's deadline before SIGKILL (the
#: tf steps give a longer stop grace period in full). OpenTofu and
#: Terraform stop starting new changes on SIGTERM and save the state of those
#: done; this leaves them time to, and still ends the container well before
#: the platform frees a managed-state lock held by a step whose worker died
#: (the step timeout, then 600 s of grace).
KILL_AFTER_SECONDS = 300

#: The exit status ``bounded`` returns for a command it refused to start
#: because the container was asked to stop (128 + SIGTERM).
STOPPED_EXIT_STATUS = 143

#: Longest stop grace period a job may ask for (see ``ContainerJob``).
MAX_STOP_GRACE_SECONDS = 3600

#: A secret reference written bare (``vault://orgs/acme/secrets/db/password``)
#: rather than as a ``{{ secret('...') }}`` template.
_BARE_SECRET_REF_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s'\"{}\\]+$")

#: Template syntax, which the host renders (``{{ secret('…') }}``).
_TEMPLATE_RE = re.compile(r"\{\{|\{%")

#: Names usable as a staged secret file or a tool variable.
SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")


@dataclass(frozen=True, slots=True)
class StagedFile:
    """A file written into the container before it starts.

    ``path`` is absolute inside the container. Files are staged with
    ``docker cp`` and so are owned by root in the container; ``mode`` 0o644 keeps
    them readable by images that run as another user. Anything that must be
    private to that user (an SSH key) is copied to a private path by the
    step's own script.
    """

    path: str
    content: str | bytes
    mode: int = 0o644


@dataclass
class ContainerJob:
    """What a container-backed handler asks the runner to execute.

    ``config`` has the ``container.run`` config shape (``image``, ``command``,
    ``entrypoint``, ``env``, ``memory``, ``cpus``, ``working_dir``,
    ``timeout_seconds``, egress fields, mount paths). Tool handlers build it
    from their own config; they never expose the host-access options.
    """

    config: dict[str, Any]
    files: list[StagedFile] = field(default_factory=list)
    # Absolute container directories copied out after the container exits.
    collect: list[str] = field(default_factory=list)
    # Recorded in the container's ``hegemony.handler_id`` label.
    handler_id: str = "container.run"
    # Host name -> IP address entries for the container's /etc/hosts
    # (``--add-host``), e.g. the platform API from ``open_state_backend``.
    extra_hosts: dict[str, str] = field(default_factory=dict)
    # Seconds the container gets to stop after SIGTERM when the step is
    # cancelled or times out, before it is removed; 0 removes it at once. A
    # tool run through ``bounded`` (see :func:`deadline_shell_lines`) receives
    # the SIGTERM when the run script is the container's PID 1 (start it with
    # ``exec``), and can finish in-flight work, save state and release locks.
    stop_grace_seconds: int = 0
    # Run the pulled image by its registry digest and report it as
    # ``ContainerJobResult.image_digest``, for a tool that hands its image to a
    # later step (``tf.apply`` after ``tf.plan``): that step then gets exactly
    # these bytes, even if the tag moved in between.
    pin_image: bool = False


@dataclass
class ContainerJobResult:
    """A container that ran to completion (any exit code).

    Failures before or around the run — invalid config, pull or create
    failure, timeout — come back from :func:`run_container_job` as a failed
    ``HandlerResult`` instead, with the same messages ``container.run`` uses.
    """

    exit_code: int
    stdout: str
    stderr: str
    truncated: bool
    duration_seconds: float
    image: str
    # container_output + harvested new artifacts + the skipped-artifacts report.
    evidence: list[dict[str, Any]]
    skipped_artifacts: int
    # Files collected from ``ContainerJob.collect``, keyed by absolute container path.
    collected: dict[str, bytes] = field(default_factory=dict)
    # What could not be collected, keyed by absolute container path (a collect
    # root whose copy failed, or one file over the budget) -> the reason. A path
    # in neither map was simply not written by the step.
    collect_errors: dict[str, str] = field(default_factory=dict)
    # ``repository@sha256:...`` the container ran from, when the job asked for
    # ``pin_image`` and the daemon knows the image's registry digest (an image
    # built on the daemon and never pushed has none); otherwise empty.
    image_digest: str = ""


class ContainerExecutionConfig(BaseModel):
    """Container fields shared by tool handlers built on this runner.

    Tool handler configs subclass this and add their own fields. Deliberately
    no host-access options (network mode, privileged, docker socket, extra
    mounts): tool steps always run isolated, so they need no admin gate.
    """

    model_config = ConfigDict(extra="allow")

    timeout_seconds: int = Field(
        default=600,
        ge=1,
        title="Timeout (seconds)",
        description="Maximum run time of the container, including the image pull.",
        json_schema_extra={"x_advanced": True},
    )
    memory: str = Field(
        default="",
        title="Memory Limit",
        description="Container memory limit, e.g. 512m or 2g. Defaults to 1g.",
        json_schema_extra={"x_placeholder": "1g", "x_advanced": True},
    )
    cpus: str = Field(
        default="",
        title="CPU Limit",
        description="Container CPU limit, e.g. 0.5 or 2.0. Defaults to 1.0.",
        json_schema_extra={"x_placeholder": "1.0", "x_advanced": True},
    )
    env: dict[str, str] = Field(
        default_factory=dict,
        title="Environment Variables",
        description=(
            "KEY=VALUE format, one per line. Keys starting with HEGEMONY_ are reserved "
            "and ignored. Prefer Secrets for sensitive values: environment variables "
            "are visible in the sandbox's container metadata."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "MY_VAR=value",
            "x_rows": 3,
            "x_col_span": 2,
            "x_advanced": True,
        },
    )
    egress_mode: str = Field(
        default="",
        title="Egress policy mode",
        description=(
            "Outbound firewall for this step's container: 'open' allows everything "
            "except Deny rules, 'allow-listed' allows only Allow rules (minus Deny), "
            "'deny-all' blocks all network access. Leave empty to inherit the flow's "
            "network policy."
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
            "CIDR[:port[-port]][/tcp|udp] or service:port."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "172.20.30.0/24:22/tcp\n0.0.0.0/0:443/tcp",
            "x_rows": 3,
            "x_advanced": True,
            "x_col_span": 2,
        },
    )
    egress_deny: list[str] = Field(
        default_factory=list,
        title="Egress deny rules",
        description="One rule per line, same format as Allow rules. Deny always wins.",
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "169.254.169.254/32",
            "x_rows": 3,
            "x_advanced": True,
            "x_col_span": 2,
        },
    )
    # Stored as step-level data (node.mounted_files → ctx.mounted_files), not in
    # params; declared so the schema-driven editor offers the attachment picker.
    mounted_files: list[str] | None = Field(
        default=None,
        title="Attachments",
        description=(
            "Which flow attachments are copied into the container under /attachments. "
            "Leave at All to copy every attachment; a selector ending in / includes "
            "that folder recursively."
        ),
        json_schema_extra={"x_widget": "mounted-files", "x_advanced": True, "x_col_span": 2},
    )


#: Container fields a tool handler forwards from its own config into the job.
CONTAINER_PASSTHROUGH_FIELDS = (
    "timeout_seconds",
    "memory",
    "cpus",
    "egress_mode",
    "egress_allow",
    "egress_deny",
)


def container_config_from(
    config: dict[str, Any],
    *,
    image: str,
    command: list[str],
    env: dict[str, str] | None = None,
    working_dir: str = "/workspace",
    entrypoint: str | list[str] | None = None,
    default_memory: str = "1g",
) -> dict[str, Any]:
    """Build a ``container.run``-shaped job config from a tool handler's config.

    Copies the shared container fields, applies the tool's defaults, and adds
    the tool-built image, command, entrypoint, and environment. The tool's own
    variables are applied after the step's ``env``, so a step cannot silently
    undo the tool's wiring. Host-access options never pass through.
    """
    job_config: dict[str, Any] = {
        key: config[key] for key in CONTAINER_PASSTHROUGH_FIELDS if key in config
    }
    if not (isinstance(job_config.get("memory"), str) and job_config["memory"].strip()):
        job_config["memory"] = default_memory
    merged_env: dict[str, str] = {}
    user_env = config.get("env")
    if isinstance(user_env, dict):
        merged_env.update({str(k): str(v) for k, v in user_env.items()})
    if env:
        merged_env.update(env)
    job_config.update(
        {
            "image": image,
            "command": command,
            "working_dir": working_dir,
            "env": merged_env,
            # Tool steps work from the files they stage: no upstream step
            # outputs or artifacts (an explicit empty selection skips the fetch).
            "mounted_step_outputs": [],
            "mounted_artifacts": [],
        }
    )
    if entrypoint is not None:
        job_config["entrypoint"] = entrypoint
    return job_config


def is_bare_secret_ref(value: str) -> bool:
    """Whether ``value`` is a bare secret reference like ``vault://path/key``."""
    return bool(_BARE_SECRET_REF_RE.match(value.strip()))


async def resolve_secret_values(
    ctx: HandlerContext, secrets: dict[str, Any] | None, *, source: str
) -> dict[str, str]:
    """Resolve a ``name -> secret`` map into plain values.

    Handlers list their secret fields in ``raw_config_keys``, so each value
    arrives as the step author wrote it, and is one of:

    - a bare reference (``vault://orgs/acme/secrets/db/password``), resolved
      through the host as ``{{ secret('<reference>') }}``;
    - a template (``{{ secret('vault://…') }}``), rendered through the host;
    - anything else, used as written.

    The written text decides, never the resolved value: a secret whose value
    looks like a reference (``postgres://user:pw@db/app``) is not resolved a
    second time. Any ``scheme://…`` text is read as a reference, since only
    the host knows its backends' schemes, so a literal URL cannot be written
    directly. The host registers every value it resolves for redaction; a
    literal is not registered (the SDK has no way to), so it is not redacted.

    Raises ``ValueError`` for an invalid name, a non-string value, or a
    reference that resolves to nothing.
    """
    resolved: dict[str, str] = {}
    if not secrets:
        return resolved
    services = ctx.require_services()
    for name, raw in secrets.items():
        if not isinstance(name, str) or not SECRET_NAME_RE.match(name):
            raise ValueError(f"invalid secret name {name!r}")
        if not isinstance(raw, str):
            raise ValueError(f"secret {name!r} must be a string")
        bare = is_bare_secret_ref(raw)
        if bare:
            template = "{{ secret('" + raw.strip() + "') }}"
        elif _TEMPLATE_RE.search(raw):
            template = raw
        else:
            resolved[name] = raw
            continue
        value = await services.resolve_secret_ref(template, source=source) or ""
        if not value and bare:
            scheme = raw.strip().split("://", 1)[0]
            raise ValueError(
                f"secret {name!r} resolved to an empty value: it is written as a secret "
                f"reference (scheme {scheme!r}), and no secret backend returned a value for "
                "it. Check the reference; a literal value shaped like a URL cannot be "
                "written directly, so store it in a secret backend and reference it"
            )
        if not value:
            raise ValueError(f"secret {name!r} resolved to an empty value")
        resolved[name] = value
    return resolved


def secret_map_errors(field_name: str, value: Any) -> list[str]:
    """Validation errors for a ``name -> secret`` map field (empty when valid)."""
    if value is None:
        return []
    if not isinstance(value, dict):
        return [f"'{field_name}' must be an object mapping names to secret references"]
    errors: list[str] = []
    for name, raw in value.items():
        if not isinstance(name, str) or not SECRET_NAME_RE.match(name):
            errors.append(
                f"'{field_name}' name {name!r} must start with a letter or underscore and "
                "use only letters, digits, '_', '.', '-' (max 128)"
            )
        elif not isinstance(raw, str) or not raw.strip():
            errors.append(f"'{field_name}.{name}' must be a non-empty string")
    return errors


async def run_container_job(
    ctx: HandlerContext, job: ContainerJob
) -> HandlerResult | ContainerJobResult:
    """Run ``job`` on the sandbox exactly as ``container.run`` runs its steps.

    Returns a :class:`ContainerJobResult` when the container ran (whatever its
    exit code), or a failed ``HandlerResult`` for a failure before or around
    the run. The job config is validated with ``container.run``'s own rules.
    """
    from hegemony_step_sdk import HandlerResult

    from .run import RunContainerHandler

    runner = RunContainerHandler()
    errors = runner.validate_config(job.config)
    if errors:
        return HandlerResult(
            success=False,
            error=f"Invalid container config: {'; '.join(errors)}",
            summary="Config validation failed",
        )
    return await runner.run_job(ctx, job)


def deadline_shell_lines(deadline: int, kill_after: int = KILL_AFTER_SECONDS) -> list[str]:
    """POSIX shell lines defining ``bounded CMD [ARG...]``: run CMD until ``deadline``.

    The worker stops a step's container at the step's timeout, but a worker
    that dies stops nothing, and the tool would run on in the sandbox past the
    access it was given (a managed-state token and lock). ``bounded`` sends the
    command SIGTERM at ``deadline`` (a Unix time) and SIGKILL ``kill_after``
    seconds later (:data:`KILL_AFTER_SECONDS` by default), through ``timeout``
    from BusyBox or coreutils. With a ``timeout`` that has no ``-k`` it sends
    only SIGTERM, and in an image without ``timeout`` the command runs
    unbounded, as before. The command's exit status is returned (BusyBox
    gives 143 when the deadline stopped it, coreutils 124).

    The lines also pass a stop request on: a shell waiting for a foreground
    command runs its traps only after the command ends, so ``bounded`` runs
    the command in the background and waits for it, and SIGTERM or SIGINT to
    the script (``docker stop`` signals PID 1) is sent on to the command as
    SIGTERM, once: a later request is not passed on, since OpenTofu and
    Terraform exit at once, without saving, on a second interrupt. After a
    stop request, ``bounded`` starts nothing new and returns
    :data:`STOPPED_EXIT_STATUS`, also when the request came while it was
    about to start the command. Works under ``set -eu``.
    """
    kill = f"-k {int(kill_after)}"
    stopped = f'if [ -n "$hegemony_stopping" ]; then return {STOPPED_EXIT_STATUS}; fi'
    return [
        f"hegemony_deadline={int(deadline)}",
        "hegemony_child=",
        "hegemony_stopping=",
        "hegemony_forwarded=",
        # Only the first request is passed on: OpenTofu and Terraform take a
        # second interrupt as "exit now", and two stoppers (the step's worker
        # and the platform's container sweep) can each send one.
        "hegemony_forward() {",
        '  if [ -n "$hegemony_child" ] && [ -z "$hegemony_forwarded" ]; then',
        "    hegemony_forwarded=yes",
        '    kill -TERM "$hegemony_child" 2>/dev/null || :',
        "  fi",
        "}",
        "hegemony_stop() {",
        '  if [ -n "$hegemony_stopping" ]; then return 0; fi',
        "  hegemony_stopping=yes",
        "  hegemony_forward",
        "}",
        "trap hegemony_stop TERM INT",
        "bounded() {",
        f"  {stopped}",
        "  left=$((hegemony_deadline - $(date +%s)))",
        '  if [ "$left" -lt 1 ]; then left=1; fi',
        "  if ! command -v timeout >/dev/null 2>&1; then",
        "    hegemony_how=none",
        f"  elif timeout -s TERM {kill} 5 true >/dev/null 2>&1; then",
        "    hegemony_how=kill",
        "  else",
        "    hegemony_how=term",
        "  fi",
        # A request that came while the lines above ran found nothing to stop.
        f"  {stopped}",
        '  case "$hegemony_how" in',
        '    none) "$@" & ;;',
        f'    kill) timeout -s TERM {kill} "$left" "$@" & ;;',
        '    *) timeout -s TERM "$left" "$@" & ;;',
        "  esac",
        "  hegemony_child=$!",
        # Nor did one that came between the launch and the line above.
        '  if [ -n "$hegemony_stopping" ]; then hegemony_forward; fi',
        # A trapped signal ends wait early (status > 128) while the command
        # still runs: wait again until it has exited and been reaped.
        "  hegemony_status=0",
        '  wait "$hegemony_child" || hegemony_status=$?',
        '  while kill -0 "$hegemony_child" 2>/dev/null; do',
        "    hegemony_status=0",
        '    wait "$hegemony_child" || hegemony_status=$?',
        "  done",
        "  hegemony_child=",
        '  return "$hegemony_status"',
        "}",
    ]


__all__ = [
    "COLLECT_GRACE_SECONDS",
    "CONTAINER_PASSTHROUGH_FIELDS",
    "CONTEXT_PATH",
    "IO_ROOT",
    "KILL_AFTER_SECONDS",
    "MAX_COLLECTED_BYTES",
    "MAX_STOP_GRACE_SECONDS",
    "OUTPUT_DIR",
    "SECRET_FILES_DIR",
    "SECRET_NAME_RE",
    "STOPPED_EXIT_STATUS",
    "ContainerExecutionConfig",
    "ContainerJob",
    "ContainerJobResult",
    "StagedFile",
    "container_config_from",
    "deadline_shell_lines",
    "is_bare_secret_ref",
    "resolve_secret_values",
    "run_container_job",
    "secret_map_errors",
]
