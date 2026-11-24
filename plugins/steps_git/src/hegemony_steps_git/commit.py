# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``git.commit``: commit an earlier step's evidence to a Git repository.

The step takes the text evidence one earlier step recorded (the output of
``netcli.collect_evidence``, say: a running configuration per device), writes
each artifact to a file in a fresh clone of the repository's branch, and
commits and pushes only when a file changed. The repository's history is then
the history of what the step read.

It runs git in a container on the sandbox through ``container.run``'s runner,
like the other tool steps, so the flow's egress policy decides which Git
server it may reach. The login reaches git through ``GIT_ASKPASS`` from staged
files, never through the URL, an argument or an environment variable.
"""

from __future__ import annotations

import re
import shlex
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
)
from hegemony_step_sdk.trust import combined_ca_pem, org_trusted_ca_pem
from hegemony_steps_container.runner import (
    KILL_AFTER_SECONDS,
    OUTPUT_DIR,
    ContainerExecutionConfig,
    ContainerJob,
    ContainerJobResult,
    StagedFile,
    container_config_from,
    deadline_shell_lines,
    is_bare_secret_ref,
    report_timeout_cut,
    resolve_secret_values,
    run_container_job,
    step_container_timeout,
)

HANDLER_ID = "git.commit"

#: The step's default image: Alpine with git and the CA bundle, built from
#: images/git-runner and published by the Images workflow for every release.
DEFAULT_IMAGE = "ghcr.io/hegemony-sh/git-runner:0.55"

#: Where the step's own files live in the container.
GIT_ROOT = "/hegemony/git"
RUN_SCRIPT = f"{GIT_ROOT}/run.sh"
ASKPASS_SCRIPT = f"{GIT_ROOT}/askpass.sh"
USERNAME_FILE = f"{GIT_ROOT}/username"
PASSWORD_FILE = f"{GIT_ROOT}/password"
MESSAGE_FILE = f"{GIT_ROOT}/message"
MANIFEST_FILE = f"{GIT_ROOT}/manifest"
CA_FILE = f"{GIT_ROOT}/ca-bundle.pem"
FILES_DIR = f"{GIT_ROOT}/files"

#: What the script reports, collected after the container exits.
CHANGED_OUT = f"{OUTPUT_DIR}/changed"
COMMIT_OUT = f"{OUTPUT_DIR}/commit"
CHANGED_FILES_OUT = f"{OUTPUT_DIR}/changed-files"

#: The script's own exit codes, for failures it can name.
EXIT_NO_BRANCH = 3
EXIT_UNSAFE_PATH = 4
EXIT_PUSH_REJECTED = 5

#: Times the script clones, commits and pushes again when the push is refused
#: (another run pushed to the branch in between).
PUSH_ATTEMPTS = 3

#: Largest file, and all files together, the step writes.
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
#: Most files one step writes.
MAX_FILES = 5000
#: Paths listed in the output; the evidence keeps them all.
MAX_OUTPUT_PATHS = 500

DEFAULT_PATH_TEMPLATE = "{device}/{command}.txt"
PLACEHOLDERS = ("device", "command", "name", "step")

_PLACEHOLDER_RE = re.compile(r"\{([^{}]*)\}")
_UNSAFE_CHAR_RE = re.compile(r"[^A-Za-z0-9._-]+")
#: A branch name git accepts, kept to a safe subset (git check-ref-format).
_BRANCH_RE = re.compile(r"^(?!/)(?!.*//)(?!.*\.\.)(?!.*@\{)[A-Za-z0-9._/-]+(?<![/.])$")
_TEMPLATE_RE = re.compile(r"\{\{|\{%")


def _is_secret_ref(value: str) -> bool:
    text = value.strip()
    return is_bare_secret_ref(text) or bool(_TEMPLATE_RE.search(text))


def url_error(value: str) -> str | None:
    """Why ``value`` cannot be the repository URL, or None."""
    text = value.strip()
    if not text:
        return "'repository_url' is required"
    try:
        parts = urlsplit(text)
    except ValueError:
        return "'repository_url' is not a valid URL"
    if parts.scheme != "https":
        return "'repository_url' must be an https:// URL"
    if not parts.hostname:
        return "'repository_url' has no host"
    if parts.username is not None or parts.password is not None:
        return (
            "'repository_url' must not carry a login; set Username and Password, which "
            "reach git without appearing in the URL"
        )
    if parts.query or parts.fragment:
        return "'repository_url' must not have a query or a fragment"
    if any(char.isspace() or ord(char) < 32 for char in text):
        return "'repository_url' must not contain spaces or control characters"
    return None


def branch_error(value: str) -> str | None:
    """Why ``value`` cannot be the branch, or None."""
    text = value.strip()
    if text.startswith("refs/"):
        return "'branch' is a branch name such as main, not a ref"
    if (
        not _BRANCH_RE.match(text)
        or text.startswith("-")
        or text.endswith(".lock")
        or any(part.startswith(".") for part in text.split("/"))
    ):
        return f"'branch' {text!r} is not a valid branch name"
    return None


def path_template_error(value: str) -> str | None:
    """Why ``value`` cannot be the Path template, or None."""
    text = value.strip()
    if not text:
        return "'path_template' is required"
    for name in _PLACEHOLDER_RE.findall(text):
        if name not in PLACEHOLDERS:
            return f"'path_template' has an unknown placeholder {{{name}}}; use " + ", ".join(
                f"{{{item}}}" for item in PLACEHOLDERS
            )
    stripped = _PLACEHOLDER_RE.sub("x", text)
    if "{" in stripped or "}" in stripped:
        return "'path_template' has an unmatched { or }"
    return _relative_path_error(stripped, "'path_template'")


def _relative_path_error(path: str, what: str) -> str | None:
    """Why ``path`` is not a safe path inside the repository, or None."""
    if path.startswith("/") or "\\" in path:
        return f"{what} must be a relative path with / between folders"
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        return f"{what} must not contain control characters"
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return f"{what} must not have empty, . or .. segments"
    if any(part.lower() == ".git" for part in parts):
        return f"{what} must not reach into .git"
    if path != path.strip():
        return f"{what} must not start or end with spaces"
    return None


def safe_segment(value: str) -> str:
    """``value`` as one file-name segment: letters, digits, '.', '_' and '-' only."""
    # No leading dot: no hidden files, and never "." or "..".
    text = _UNSAFE_CHAR_RE.sub("_", value.strip()).lstrip("._").rstrip("_")
    return text[:120] or "_"


class GitCommitConfig(ContainerExecutionConfig):
    """Config for ``git.commit``."""

    repository_url: str = Field(
        default="",
        title="Repository URL",
        description=(
            "The repository's https:// clone URL, without a login. The flow's network "
            "policy must allow the step to reach it."
        ),
        json_schema_extra={
            "x_placeholder": "https://git.example.com/netops/backups.git",
            "x_col_span": 2,
        },
    )
    branch: str = Field(
        default="main",
        title="Branch",
        description="The branch to commit to. Defaults to main.",
        json_schema_extra={"x_placeholder": "main"},
    )
    create_branch: bool = Field(
        default=False,
        title="Create the branch",
        description=(
            "Start the branch when it does not exist yet (needed for the first commit to "
            "an empty repository). It starts empty, holding only this step's files. Off: "
            "a missing branch fails the step."
        ),
    )
    username: str = Field(
        default="",
        title="Username",
        description=(
            "The Git login's user name: text, a secret reference or a "
            "{{ secret('...') }} template. With a token, any name the server accepts "
            "(GitHub takes x-access-token)."
        ),
        json_schema_extra={"x_placeholder": "backup-bot"},
    )
    password: str = Field(
        default="",
        title="Password or Token",
        description=(
            "The Git login's password or access token: a secret reference such as "
            "vault://orgs/acme/secrets/git/token, or a {{ secret('...') }} template. A "
            "value written in clear is refused. Empty: no login."
        ),
        json_schema_extra={
            "x_placeholder": "vault://orgs/acme/secrets/git/token",
            "x_col_span": 2,
        },
    )
    source_step: str = Field(
        default="",
        title="Evidence Step",
        description=(
            "The earlier step whose evidence is committed, such as a "
            "netcli.collect_evidence step. Its newest artifact per device and command is "
            "written; failed captures are skipped."
        ),
        json_schema_extra={"x_widget": "step-select", "x_placeholder": "Select a step..."},
    )
    path_template: str = Field(
        default=DEFAULT_PATH_TEMPLATE,
        title="Path",
        description=(
            "Where each artifact is written in the repository. {device} is the device "
            "name, {command} the command, {name} the artifact's name and {step} the "
            "evidence step's id, each made safe for a file name. Defaults to "
            "{device}/{command}.txt."
        ),
        json_schema_extra={"x_placeholder": "configs/{device}.cfg", "x_col_span": 2},
    )
    commit_message: str = Field(
        default="",
        title="Commit Message",
        description=(
            "The commit's message. Empty: 'Hegemony: <flow> run <run id>'. Templates "
            "such as {{ run_id }} are filled in."
        ),
        json_schema_extra={"x_widget": "textarea", "x_rows": 3, "x_col_span": 2},
    )
    author_name: str = Field(
        default="Hegemony",
        title="Author Name",
        description="The commit's author and committer name. Defaults to Hegemony.",
        json_schema_extra={"x_advanced": True},
    )
    author_email: str = Field(
        default="hegemony@localhost",
        title="Author Email",
        description="The commit's author and committer email. Defaults to hegemony@localhost.",
        json_schema_extra={"x_advanced": True},
    )
    trusted_cas: bool = Field(
        default=False,
        title="Trust the organization's CAs",
        description=(
            "Let git trust the organization's trusted CAs (Settings, Trusted CAs) as well "
            "as the public ones, for a Git server whose certificate a private CA signed."
        ),
        json_schema_extra={"x_advanced": True},
    )
    image: str = Field(
        default=DEFAULT_IMAGE,
        min_length=1,
        title="Execution image",
        description=(
            "Container image with git and /bin/sh. Change it only to pull the default "
            "image from a mirror."
        ),
        json_schema_extra={"x_advanced": True, "x_col_span": 2},
    )
    cache_image: bool = Field(
        default=True,
        title="Cache image",
        description=(
            "Keep a copy of the pulled image in the platform registry, under this "
            "organization, and use it on later runs. No effect when the platform runs no "
            "registry."
        ),
        json_schema_extra={"x_advanced": True},
    )

    @field_validator("author_name", "author_email")
    @classmethod
    def _one_line(cls, value: str) -> str:
        if any(ord(char) < 32 or char in "<>" for char in value):
            raise ValueError("must be one line without < or >")
        return value


def config_errors(config: GitCommitConfig) -> list[str]:
    """Checks across fields that the model's own validators cannot make."""
    errors = [
        error
        for error in (
            url_error(config.repository_url),
            branch_error(config.branch),
            path_template_error(config.path_template),
        )
        if error
    ]
    if not config.source_step.strip():
        errors.append("'source_step' is required: choose the step whose evidence is committed")
    if config.password.strip() and not _is_secret_ref(config.password):
        errors.append(
            "'password' must be a secret reference or a {{ secret('...') }} template; a "
            "value written in clear would be stored in the flow and not redacted"
        )
    if config.password.strip() and not config.username.strip():
        errors.append("'username' is required with a password or token")
    if not config.author_name.strip() or not config.author_email.strip():
        errors.append("'author_name' and 'author_email' must not be empty")
    return errors


# --- Choosing the files ------------------------------------------------------


@dataclass
class Selection:
    """The files to write, and what was left out and why."""

    files: dict[str, str] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _created_at(artifact: dict[str, Any]) -> datetime | None:
    value = artifact.get("created_at")
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _metadata(artifact: dict[str, Any]) -> dict[str, Any]:
    meta = artifact.get("content_json")
    return meta if isinstance(meta, dict) else {}


def _capture_key(artifact: dict[str, Any]) -> tuple[str, ...]:
    """One capture: the device and full command a netcli step records, else the name."""
    meta = _metadata(artifact)
    if isinstance(meta.get("command"), str):
        return (
            "command",
            str(meta.get("device_id")),
            str(meta.get("device_name")),
            meta["command"].strip(),
        )
    return ("name", str(artifact.get("name") or ""))


def newest_captures(artifacts: list[dict[str, Any]], step_id: str) -> list[dict[str, Any]]:
    """The newest artifact of ``step_id`` per capture, in the order they were first seen.

    A step that runs more than once (loop iterations, retries) adds artifacts
    with the same device and command each time; the newest wins. Artifacts
    without a usable ``created_at`` sort below dated ones, and among
    themselves the last one listed wins (the API lists oldest first).
    """
    best: dict[tuple[str, ...], dict[str, Any]] = {}
    for artifact in artifacts:
        if artifact.get("step_id") != step_id:
            continue
        key = _capture_key(artifact)
        if key == ("name", ""):
            continue
        current = best.get(key)
        if current is None:
            best[key] = artifact
            continue
        new_at, old_at = _created_at(artifact), _created_at(current)
        if new_at is None and old_at is not None:
            continue
        if new_at is None or old_at is None or new_at >= old_at:
            best[key] = artifact
    return list(best.values())


def _device_key(meta: dict[str, Any]) -> str | None:
    """The device an artifact's record names: its id, else its name."""
    for field_name in ("device_id", "device_name"):
        value = meta.get(field_name)
        if isinstance(value, str) and value:
            return f"{field_name}:{value}"
    return None


_UNDATED = datetime.min.replace(tzinfo=UTC)


def _order(artifact: dict[str, Any], position: int) -> tuple[int, datetime, int]:
    """Sort key for "newer": dated after undated, then by date, then by list position."""
    created = _created_at(artifact)
    return (0, _UNDATED, position) if created is None else (1, created, position)


def newest_device_failures(
    artifacts: list[dict[str, Any]], step_id: str
) -> dict[str, tuple[tuple[int, datetime, int], str]]:
    """Each device's newest device-wide failure (an error with no command), with its order key.

    ``netcli.collect_evidence`` records a device it could not reach as one
    ``error`` artifact without a command, so it never shares a capture key
    with the device's command outputs.
    """
    failures: dict[str, tuple[tuple[int, datetime, int], str]] = {}
    for position, artifact in enumerate(artifacts):
        meta = _metadata(artifact)
        if artifact.get("step_id") != step_id or artifact.get("kind") != "error":
            continue
        if isinstance(meta.get("command"), str):
            continue
        device = _device_key(meta)
        if device is None:
            continue
        key = _order(artifact, position)
        if device not in failures or key >= failures[device][0]:
            failures[device] = (key, str(meta.get("error") or "the capture failed"))
    return failures


def _label(artifact: dict[str, Any]) -> str:
    meta = _metadata(artifact)
    if isinstance(meta.get("command"), str):
        return f"{meta.get('device_name') or '?'}:{meta['command'].strip().splitlines()[0][:80]}"
    return str(artifact.get("name") or artifact.get("id") or "?")


def _failure(artifact: dict[str, Any]) -> str | None:
    """Why the capture holds no usable output, or None."""
    meta = _metadata(artifact)
    if artifact.get("kind") == "error":
        return str(meta.get("error") or "the capture failed")
    if meta.get("success") is False:
        return str(meta.get("error") or f"the command failed (exit code {meta.get('exit_code')})")
    if not isinstance(artifact.get("content_text"), str):
        return "it has no text content"
    return None


def render_path(template: str, artifact: dict[str, Any], step_id: str) -> str:
    """The repository path ``template`` gives ``artifact``.

    Raises ``ValueError`` when the template needs a device the artifact has
    none for.
    """
    meta = _metadata(artifact)
    command = meta.get("command") if isinstance(meta.get("command"), str) else None
    device = meta.get("device_name") or artifact.get("device_name")
    name = str(artifact.get("name") or artifact.get("id") or "")
    if "{device}" in template and not device:
        raise ValueError("it has no device; use {name} in Path instead of {device}")
    values = {
        "device": safe_segment(str(device or "")),
        "command": safe_segment(command if command is not None else name),
        "name": safe_segment(name),
        "step": safe_segment(step_id),
    }
    return _PLACEHOLDER_RE.sub(lambda match: values[match.group(1)], template.strip())


def select_files(artifacts: list[dict[str, Any]], step_id: str, template: str) -> Selection:
    """The files to write from ``step_id``'s artifacts, keyed by repository path."""
    selection = Selection()
    total = 0
    owners: dict[str, str] = {}
    positions = {id(artifact): position for position, artifact in enumerate(artifacts)}
    device_failures = newest_device_failures(artifacts, step_id)
    for artifact in newest_captures(artifacts, step_id):
        label = _label(artifact)
        failure = _failure(artifact)
        meta = _metadata(artifact)
        device = _device_key(meta)
        if failure is None and isinstance(meta.get("command"), str) and device in device_failures:
            # The device failed after this capture was read (a later loop
            # iteration or retry): keep the repository's file as it is.
            failed_at, reason = device_failures[device]
            if failed_at > _order(artifact, positions[id(artifact)]):
                failure = f"a later attempt failed: {reason}"
        if failure:
            selection.skipped.append(f"{label}: {failure}")
            continue
        try:
            path = render_path(template, artifact, step_id)
        except ValueError as exc:
            selection.errors.append(f"{label}: {exc}")
            continue
        error = _relative_path_error(path, f"the path {path!r}")
        if error:
            selection.errors.append(f"{label}: {error}")
            continue
        if path in owners:
            selection.errors.append(
                f"{owners[path]} and {label} would both be written to {path}; put "
                "{device} and {command} in Path"
            )
            continue
        content = artifact["content_text"]
        size = len(content.encode("utf-8"))
        if size > MAX_FILE_BYTES:
            selection.errors.append(f"{label}: larger than {MAX_FILE_BYTES // (1024 * 1024)} MiB")
            continue
        total += size
        owners[path] = label
        selection.files[path] = content
    if total > MAX_TOTAL_BYTES:
        selection.errors.append(
            f"the files add up to more than {MAX_TOTAL_BYTES // (1024 * 1024)} MiB"
        )
    if len(selection.files) > MAX_FILES:
        selection.errors.append(f"more than {MAX_FILES} files")
    return selection


# --- The script --------------------------------------------------------------


def _config_env_lines(settings: dict[str, str]) -> list[str]:
    """Shell lines that give every git call ``settings`` (GIT_CONFIG_COUNT, git 2.31+)."""
    lines = [f"export GIT_CONFIG_COUNT={len(settings)}"]
    for index, (key, value) in enumerate(settings.items()):
        lines.append(
            f"export GIT_CONFIG_KEY_{index}={shlex.quote(key)} "
            f"GIT_CONFIG_VALUE_{index}={shlex.quote(value)}"
        )
    return lines


def build_script(
    *,
    url: str,
    branch: str,
    create_branch: bool,
    deadline: int,
    login: bool,
    ca_bundle: bool,
    kill_after: int = KILL_AFTER_SECONDS,
    root: str = GIT_ROOT,
    out: str = OUTPUT_DIR,
    allow_file_protocol: bool = False,
) -> str:
    """The POSIX shell script the container runs.

    ``root`` and ``out`` are the container paths of the step's files and of
    its report. Tests run the script outside a container, with other paths
    and a ``file://`` repository (``allow_file_protocol``); the step itself
    allows git only https.
    """
    q = shlex.quote
    lines = [
        "#!/bin/sh",
        "# Generated by the git.commit step.",
        "set -eu",
        "umask 022",
        f"out={q(out)}",
        f"root={q(root)}",
        'mkdir -p "$out"',
        *deadline_shell_lines(deadline, kill_after),
        f"url={q(url)}",
        f"branch={q(branch)}",
        f"create_branch={'yes' if create_branch else 'no'}",
        'work="$(mktemp -d)"',
        'export HOME="$work/home"',
        'mkdir -p "$HOME"',
        # No prompt, no system or global config, no hooks, no credential store.
        # The step's own Environment Variables reach this shell too: drop every
        # GIT_* variable but the commit identity, so none can undo what follows
        # (GIT_CONFIG_PARAMETERS, GIT_SSL_NO_VERIFY, GIT_ALLOW_PROTOCOL, ...).
        'for name in $(env | sed -n "s/^\\(GIT_[A-Za-z0-9_]*\\)=.*/\\1/p"); do',
        '  case "$name" in',
        "    GIT_AUTHOR_NAME|GIT_AUTHOR_EMAIL|GIT_COMMITTER_NAME|GIT_COMMITTER_EMAIL) ;;",
        '    *) unset "$name" ;;',
        "  esac",
        "done",
        "unset SSH_ASKPASS",
        "export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null",
        # Paths are file names, never patterns (:(glob), *, ...).
        "export GIT_LITERAL_PATHSPECS=1",
        "export GIT_PROTOCOL_FROM_USER=0",
        # Settings every git call gets, also under `timeout`, which cannot run
        # a shell function: no hooks, no fsmonitor, HTTPS only, no stored
        # credentials, redirects only on the first request.
        *_config_env_lines(
            {
                "core.hooksPath": "/dev/null",
                "core.fsmonitor": "false",
                "protocol.allow": "never",
                "protocol.https.allow": "always",
                "protocol.file.allow": "always" if allow_file_protocol else "never",
                "credential.helper": "",
                "http.followRedirects": "initial",
            }
        ),
    ]
    if login:
        lines.append('export GIT_ASKPASS="$root/askpass.sh"')
    if ca_bundle:
        lines.append('export GIT_SSL_CAINFO="$root/ca-bundle.pem"')
    lines += [
        'repo="$work/repo"',
        "attempt=1",
        "while :; do",
        '  rm -rf "$repo"',
        "  status=0",
        '  bounded git ls-remote --exit-code --heads -- "$url" "refs/heads/$branch" '
        + ">/dev/null || status=$?",
        '  case "$status" in',
        "    0)",
        "      bounded git clone --quiet --depth 1 --single-branch --no-tags "
        + '--branch "$branch" -- "$url" "$repo"',
        "      ;;",
        "    2)",
        '      if [ "$create_branch" != yes ]; then',
        '        echo "branch $branch does not exist in the repository" >&2',
        f"        exit {EXIT_NO_BRANCH}",
        "      fi",
        '      git init --quiet "$repo"',
        '      git -C "$repo" remote add origin "$url"',
        '      git -C "$repo" checkout --quiet --orphan "$branch"',
        "      ;;",
        '    *) exit "$status" ;;',
        "  esac",
        # Every path the step writes, checked against symbolic links in the
        # clone: a link would carry the write out of the working tree.
        "  while IFS= read -r line; do",
        '    index="${line%% *}"',
        '    path="${line#* }"',
        '    probe="$repo"',
        '    rest="$path"',
        "    while :; do",
        '      part="${rest%%/*}"',
        '      probe="$probe/$part"',
        '      if [ -L "$probe" ]; then',
        '        echo "the repository has a symbolic link at ${probe#"$repo"/}; not writing $path" >&2',
        f"        exit {EXIT_UNSAFE_PATH}",
        "      fi",
        '      [ "$rest" = "$part" ] && break',
        '      rest="${rest#*/}"',
        "    done",
        '    if [ -e "$repo/$path" ] && [ ! -f "$repo/$path" ]; then',
        '      echo "$path exists in the repository and is not a file" >&2',
        f"      exit {EXIT_UNSAFE_PATH}",
        "    fi",
        '    mkdir -p "$(dirname "$repo/$path")"',
        '    cat "$root/files/$index" > "$repo/$path"',
        '    git -C "$repo" add --force -- "$path"',
        '  done < "$root/manifest"',
        '  if git -C "$repo" diff --cached --quiet; then',
        '    echo no > "$out/changed"',
        '    git -C "$repo" rev-parse --verify --quiet HEAD > "$out/commit" || : > "$out/commit"',
        "    exit 0",
        "  fi",
        '  git -C "$repo" diff --cached --name-only -z > "$out/changed-files"',
        '  git -C "$repo" commit --quiet --no-verify --no-gpg-sign -F "$root/message"',
        "  push=0",
        '  bounded git -C "$repo" push --porcelain origin "HEAD:refs/heads/$branch" '
        + '> "$work/push" 2>&1 || push=$?',
        '  if [ "$push" = 0 ]; then',
        '    echo yes > "$out/changed"',
        '    git -C "$repo" rev-parse HEAD > "$out/commit"',
        "    exit 0",
        "  fi",
        '  cat "$work/push" >&2',
        # A refusal of an update that is not a fast-forward: another run
        # pushed in between. Start over from the new branch head.
        '  if grep -Eq "^!.*\\[rejected\\]" "$work/push" '
        + f'&& [ "$attempt" -lt {PUSH_ATTEMPTS} ]; then',
        "    attempt=$((attempt + 1))",
        '    echo "the branch moved while committing; trying again ($attempt)" >&2',
        "    continue",
        "  fi",
        '  if grep -q "^!" "$work/push"; then',
        f"    exit {EXIT_PUSH_REJECTED}",
        "  fi",
        '  exit "$push"',
        "done",
    ]
    return "\n".join(lines) + "\n"


ASKPASS = """#!/bin/sh
# git asks for the user name and then the password; answer from the staged files.
case "$1" in
  Username*) cat "{username}" ;;
  *) cat "{password}" ;;
esac
"""


def _message(config: GitCommitConfig, ctx: HandlerContext) -> str:
    text = config.commit_message.strip()
    if text:
        return text + "\n"
    flow = ctx.flow_name or ctx.flow_id
    return f"Hegemony: {flow} run {ctx.run_id}\n"


def _decode(outcome: ContainerJobResult, path: str) -> str:
    return (outcome.collected.get(path) or b"").decode("utf-8", "replace")


def failure_message(outcome: ContainerJobResult, branch: str) -> str:
    """The step error for a script that exited non-zero."""
    if outcome.exit_code == EXIT_NO_BRANCH:
        return (
            f"the branch {branch!r} does not exist in the repository; turn on Create the "
            "branch to start it"
        )
    if outcome.exit_code == EXIT_UNSAFE_PATH:
        return (
            "the repository holds a symbolic link or a folder where the step writes a file; "
            "see the container output"
        )
    if outcome.exit_code == EXIT_PUSH_REJECTED:
        return "the server refused the push; see the container output"
    text = f"{outcome.stdout}\n{outcome.stderr}"
    if "Authentication failed" in text or "could not read Username" in text:
        return "git could not log in to the repository: check Username and Password or Token"
    if "SSL certificate problem" in text or "server certificate verification failed" in text:
        return (
            "git does not trust the server's certificate: turn on Trust the organization's "
            "CAs if a private CA signed it"
        )
    if "Could not resolve host" in text or "Failed to connect" in text:
        return "git could not reach the repository; check the URL and the flow's network policy"
    return f"git exited with code {outcome.exit_code}; see the container output"


def _capped(paths: list[str]) -> list[str]:
    return paths[:MAX_OUTPUT_PATHS]


class GitCommitHandler(BaseHandler):
    """Commit an earlier step's evidence to a Git repository, only when it changed."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "Git Commit"
    description = "Commit an earlier step's evidence to a Git repository when it changed."
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    container_backed = True
    # The login reaches the handler as written, so it resolves it itself and
    # can refuse a password written in clear.
    raw_config_keys = frozenset({"username", "password"})
    config_model = GitCommitConfig
    default_config = {"branch": "main", "path_template": DEFAULT_PATH_TEMPLATE}
    run_timeout_field = "timeout_seconds"
    output_fields = (
        OutputField("changed", "Whether a commit was pushed (false when nothing changed)", "bool"),
        OutputField(
            "commit", "The branch head after the step: the new commit, or the old head", "string"
        ),
        OutputField("branch", "The branch committed to", "string"),
        OutputField("files", "Repository paths the step wrote", "list"),
        OutputField("changed_files", "Paths the commit changed", "list"),
        OutputField("skipped", "Captures left out, with the reason", "list"),
    )

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        errors = super().validate_config(config)
        if errors:
            return errors
        return config_errors(GitCommitConfig.model_validate(config))

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        try:
            config = self.parse_config(ctx.config, GitCommitConfig)
        except InvalidConfigError as exc:
            return exc.result()
        services = ctx.require_services()
        source = config.source_step.strip()
        artifacts = await services.fetch_run_artifacts(ctx.run_id)
        selection = select_files(artifacts, source, config.path_template)
        if selection.errors:
            return _refuse("; ".join(selection.errors))
        if not selection.files:
            reason = f" ({'; '.join(selection.skipped)})" if selection.skipped else ""
            return _refuse(f"step {source!r} has no text evidence in this run to commit{reason}")

        try:
            login = await resolve_secret_values(
                ctx,
                {
                    key: value
                    for key, value in (("username", config.username), ("password", config.password))
                    if value.strip()
                },
                source=HANDLER_ID,
            )
        except ValueError as exc:
            return _refuse(str(exc))

        files: list[StagedFile] = [StagedFile(MESSAGE_FILE, _message(config, ctx))]
        manifest = []
        for index, (path, content) in enumerate(sorted(selection.files.items())):
            files.append(StagedFile(f"{FILES_DIR}/{index}", content))
            manifest.append(f"{index} {path}")
        files.append(StagedFile(MANIFEST_FILE, "\n".join(manifest) + "\n"))
        if login:
            files += [
                StagedFile(USERNAME_FILE, login.get("username", "")),
                StagedFile(PASSWORD_FILE, login.get("password", "")),
                StagedFile(
                    ASKPASS_SCRIPT,
                    ASKPASS.format(username=USERNAME_FILE, password=PASSWORD_FILE),
                    mode=0o755,
                ),
            ]
        if config.trusted_cas:
            org_pem = await org_trusted_ca_pem(services)
            if org_pem:
                files.append(StagedFile(CA_FILE, combined_ca_pem(org_pem)))

        timeout = step_container_timeout(ctx, config.timeout_seconds)
        await report_timeout_cut(ctx, config.timeout_seconds, timeout)
        script = build_script(
            url=config.repository_url.strip(),
            branch=config.branch.strip(),
            create_branch=config.create_branch,
            # The script stops git itself at the step's end, even if the worker is gone.
            deadline=int(time.time()) + int(timeout),
            login=bool(login),
            ca_bundle=any(item.path == CA_FILE for item in files),
        )
        files.append(StagedFile(RUN_SCRIPT, script, mode=0o755))
        identity = {
            "GIT_AUTHOR_NAME": config.author_name.strip(),
            "GIT_AUTHOR_EMAIL": config.author_email.strip(),
            "GIT_COMMITTER_NAME": config.author_name.strip(),
            "GIT_COMMITTER_EMAIL": config.author_email.strip(),
        }
        job = ContainerJob(
            config={
                **container_config_from(
                    {**ctx.config, "timeout_seconds": timeout},
                    image=config.image.strip(),
                    command=[f"exec sh {RUN_SCRIPT}"],
                    entrypoint="/bin/sh",
                    env=identity,
                    default_memory="512m",
                ),
                "cache_image": config.cache_image,
            },
            files=files,
            collect=[OUTPUT_DIR],
            handler_id=self.handler_id,
        )
        outcome = await run_container_job(ctx, job)
        if isinstance(outcome, HandlerResult):
            return outcome
        return self._result(config, selection, outcome)

    def _result(
        self, config: GitCommitConfig, selection: Selection, outcome: ContainerJobResult
    ) -> HandlerResult:
        branch = config.branch.strip()
        written = sorted(selection.files)
        metrics = {
            "exit_code": outcome.exit_code,
            "duration_seconds": outcome.duration_seconds,
            "files_written": len(written),
            "image": outcome.image,
            "image_digest": outcome.image_digest,
        }
        evidence = list(outcome.evidence)
        if outcome.exit_code != 0:
            return HandlerResult(
                success=False,
                summary="git commit failed",
                error=failure_message(outcome, branch),
                metrics=metrics,
                evidence=evidence,
            )
        changed_flag = _decode(outcome, CHANGED_OUT).strip()
        if changed_flag not in ("yes", "no"):
            # Never guess: the push may or may not have happened.
            return HandlerResult(
                success=False,
                summary="git commit result unknown",
                error="the step's result could not be read from the container",
                metrics=metrics,
                evidence=evidence,
            )
        changed = changed_flag == "yes"
        commit = _decode(outcome, COMMIT_OUT).strip()
        changed_files = (
            [path for path in _decode(outcome, CHANGED_FILES_OUT).split("\0") if path]
            if changed
            else []
        )
        if changed and (not commit or not changed_files):
            # A push happened, but its report is incomplete: never guess.
            return HandlerResult(
                success=False,
                summary="git commit result unknown",
                error=(
                    "the push succeeded but the commit or the changed files could not be read "
                    "from the container"
                ),
                metrics=metrics,
                evidence=evidence,
            )
        metrics["files_changed"] = len(changed_files)
        evidence.append(
            {
                "kind": "transport_meta",
                "name": "git_commit",
                "content_json": {
                    "repository_url": config.repository_url.strip(),
                    "branch": branch,
                    "changed": changed,
                    "commit": commit,
                    "files": written,
                    "changed_files": changed_files,
                    "skipped": selection.skipped,
                },
            }
        )
        short = commit[:12] if commit else "none"
        if changed:
            summary = f"Committed {len(changed_files)} changed file(s) to {branch} ({short})"
        else:
            summary = f"No changes: {len(written)} file(s) match {branch} ({short})"
        if selection.skipped:
            summary += f"; {len(selection.skipped)} capture(s) skipped"
        return HandlerResult(
            success=True,
            summary=summary,
            metrics=metrics,
            evidence=evidence,
            output={
                "changed": changed,
                "commit": commit,
                "branch": branch,
                "files": _capped(written),
                "changed_files": _capped(changed_files),
                "skipped": selection.skipped[:MAX_OUTPUT_PATHS],
            },
        )


def _refuse(message: str) -> HandlerResult:
    return HandlerResult(success=False, error=message, summary="Cannot commit")
