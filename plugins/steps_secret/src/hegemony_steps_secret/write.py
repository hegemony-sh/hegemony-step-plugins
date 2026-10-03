# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""WriteSecretHandler: store, swap or delete a secret in the organization's secret store.

The handler runs on the worker and never talks to a secret backend itself: it
hands a path relative to the run organization's secret root to the host's
``read_secret`` / ``write_secret`` / ``delete_secret`` services, which build
the backend path, enforce what the organization allows, register the values
for redaction and audit the call. Values come from files a previous step left
in the run's shared workspace, or from references and literals in the step's
own ``values`` map. Nothing the handler returns (output, evidence, summary,
error) carries a value or a file's content.
"""

from __future__ import annotations

import asyncio
import base64
import os
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerServices,
    HandlerTargeting,
    StepKind,
)

from .paths import secret_path_error, templated, workspace_file_error
from .values import key_name_error, resolve_values, value_map_errors
from .workspace import SourceFile, WorkspaceError, read_source_files, scrub_source_files

SecretOperation = Literal["write", "swap", "delete"]
SecretEncoding = Literal["base64", "text"]

#: The host services this handler needs; hosts older than the SDK's secret
#: store services lack them.
SECRET_SERVICES = ("read_secret", "write_secret", "delete_secret")

#: ``source`` passed to the host's reference resolver for ``values``.
RESOLVE_SOURCE = "step.secret.write"

#: The host's documented error types: their messages name paths and keys only.
_HOST_ERRORS = (PermissionError, ValueError, RuntimeError)


def _shown_for(operation: str, **extra: Any) -> dict[str, Any]:
    """Editor hints for a field that only the given operation uses."""
    return {**extra, "x_show_when": {"field": "operation", "value": operation}}


class SecretWriteConfig(BaseModel):
    """Config for ``secret.write``."""

    model_config = ConfigDict(extra="allow")

    operation: SecretOperation = Field(
        default="write",
        title="Operation",
        description=(
            "write stores keys at Secret path; swap exchanges the keys of Secret path "
            "and Swap with; delete removes the secret at Secret path."
        ),
        json_schema_extra={
            "x_option_labels": {
                "write": "Write keys",
                "swap": "Swap two secrets",
                "delete": "Delete the secret",
            }
        },
    )
    path: str = Field(
        min_length=1,
        title="Secret path",
        description=(
            "Path of the secret under the organization's own secret root, e.g. certs/web: "
            "segments of letters, digits, '_', '.', '-' joined by '/', no leading '/', no "
            "segment starting with '.'. The platform decides the backend and refuses paths "
            "outside the prefixes the organization allows steps to write."
        ),
        json_schema_extra={"x_placeholder": "certs/web", "x_col_span": 2},
    )
    files: dict[str, str] = Field(
        default_factory=dict,
        title="Keys from files",
        description=(
            "KEY=file, one per line: the content of a file an earlier step wrote to the run's "
            "shared workspace becomes the key's value. Write the file as the step container "
            "saw it (/shared/out/cert.pem) or relative to the workspace (out/cert.pem). Needs "
            "shared (or explicit) execution affinity."
        ),
        json_schema_extra=_shown_for(
            "write",
            x_widget="env-vars",
            x_placeholder="cert=/shared/out/cert.pem",
            x_rows=3,
            x_col_span=2,
        ),
    )
    encoding: SecretEncoding = Field(
        default="base64",
        title="File encoding",
        description=(
            "How a file's bytes are stored: base64 (the default) keeps any file intact, "
            "multi-line text included, in stores that change line endings; text stores the "
            "file as it is and requires UTF-8."
        ),
        json_schema_extra=_shown_for("write"),
    )
    values: dict[str, str] = Field(
        default_factory=dict,
        title="Keys from values",
        description=(
            "KEY=value, one per line: a bare secret reference (vault://orgs/acme/secrets/"
            "db/password), a {{ secret('...') }} template, or a literal stored as written. A "
            "literal stays readable in the flow definition: use references for anything "
            "sensitive."
        ),
        json_schema_extra=_shown_for(
            "write",
            x_widget="env-vars",
            x_placeholder="username=svc-backup",
            x_rows=2,
            x_col_span=2,
        ),
    )
    merge: bool = Field(
        default=False,
        title="Keep other keys",
        description=(
            "Off (the default): the secret holds exactly the keys written now. On: keys the "
            "secret already holds and this step does not write are kept."
        ),
        json_schema_extra=_shown_for("write"),
    )
    keep_previous_at: str = Field(
        default="",
        title="Keep previous values at",
        description=(
            "Optional secret path that receives the secret's current keys before they are "
            "overwritten (replacing what that path held), e.g. certs/web-previous. Nothing "
            "is copied when Secret path holds no secret yet. Must differ from Secret path."
        ),
        json_schema_extra=_shown_for(
            "write", x_placeholder="certs/web-previous", x_col_span=2, x_advanced=True
        ),
    )
    delete_source_files: bool = Field(
        default=True,
        title="Delete source files",
        description=(
            "After a successful write, overwrite each source file with zeros and delete it "
            "from the shared workspace. Best effort, not a secure wipe."
        ),
        json_schema_extra=_shown_for("write", x_advanced=True),
    )
    swap_with: str = Field(
        default="",
        title="Swap with",
        description=(
            "Path of the other secret, under the organization's secret root. Both secrets "
            "must exist; each ends up holding the other's keys."
        ),
        json_schema_extra=_shown_for("swap", x_placeholder="certs/web-previous", x_col_span=2),
    )
    missing_ok: bool = Field(
        default=True,
        title="Succeed when absent",
        description=(
            "On (the default): deleting a secret that does not exist succeeds. Off: the step "
            "fails when there is nothing to delete."
        ),
        json_schema_extra=_shown_for("delete"),
    )


def semantic_errors(config: dict[str, Any], *, allow_templates: bool) -> list[str]:
    """Checks the schema cannot express; templated paths are checked again once rendered."""
    errors: list[str] = []
    path = config.get("path")
    error = secret_path_error("path", path, allow_template=allow_templates)
    if error:
        errors.append(error)
    operation = config.get("operation") or "write"
    if operation == "write":
        files = config.get("files") or {}
        values = config.get("values") or {}
        if isinstance(files, dict):
            for key, written in files.items():
                error = key_name_error("files", key) or workspace_file_error(
                    f"files.{key}", written, allow_template=allow_templates
                )
                if error:
                    errors.append(error)
        else:
            errors.append("'files' must be an object mapping key names to files")
        errors.extend(value_map_errors("values", values))
        if isinstance(files, dict) and isinstance(values, dict):
            for key in sorted(set(files) & set(values), key=str):
                errors.append(f"key {key!r} is set in both 'files' and 'values'; give it once")
            if not files and not values:
                errors.append("a write needs at least one key: set 'files', 'values' or both")
        keep = config.get("keep_previous_at")
        if isinstance(keep, str) and keep.strip():
            error = secret_path_error("keep_previous_at", keep, allow_template=allow_templates)
            if error:
                errors.append(error)
            elif _same_path(keep, path):
                errors.append("'keep_previous_at' must differ from 'path'")
        elif keep not in (None, ""):
            errors.append("'keep_previous_at' must be a secret path")
    elif operation == "swap":
        other = config.get("swap_with")
        if not isinstance(other, str) or not other.strip():
            errors.append("a swap needs 'swap_with': the path of the other secret")
        else:
            error = secret_path_error("swap_with", other, allow_template=allow_templates)
            if error:
                errors.append(error)
            elif _same_path(other, path):
                errors.append("'swap_with' must differ from 'path'")
    return errors


def _same_path(one: object, other: object) -> bool:
    """Whether two rendered paths name the same secret (templated ones are not compared)."""
    if not isinstance(one, str) or not isinstance(other, str):
        return False
    if templated(one) or templated(other):
        return False
    return one.strip() == other.strip()


def _plural(count: int) -> str:
    return f"{count} key" if count == 1 else f"{count} keys"


def _describe(exc: BaseException) -> str:
    """A host error as text: the message of a documented error type, else only its type.

    The host's documented errors name paths and keys; anything else might
    carry a backend's request (and a value with it), so only its type is
    reported.
    """
    if isinstance(exc, _HOST_ERRORS):
        return str(exc).strip() or type(exc).__name__
    return f"unexpected {type(exc).__name__} from the platform's secret store"


def _host_summary(exc: BaseException) -> str:
    if isinstance(exc, PermissionError):
        return "Refused by the platform"
    if isinstance(exc, ValueError):
        return "Rejected by the platform"
    if isinstance(exc, RuntimeError):
        return "Secret store unavailable"
    return "Secret store failed"


def _failure(error: str, summary: str, *, output: dict[str, Any] | None = None) -> HandlerResult:
    return HandlerResult(success=False, error=error, summary=summary, output=output or {})


def _host_failure(
    action: str, exc: BaseException, *, output: dict[str, Any] | None = None
) -> HandlerResult:
    return _failure(f"Could not {action}: {_describe(exc)}", _host_summary(exc), output=output)


def _result_output(
    operation: str,
    path: str,
    *,
    reference: str | None = None,
    keys: list[str] | None = None,
    created: bool = False,
    previous_path: str | None = None,
    swapped_with: str | None = None,
    deleted: bool = False,
) -> dict[str, Any]:
    """The step's chainable output: names and references only, never values."""
    return {
        "operation": operation,
        "path": path,
        "reference": reference,
        "keys": list(keys or []),
        "created": created,
        "previous_path": previous_path,
        "swapped_with": swapped_with,
        "deleted": deleted,
    }


def _success(
    ctx: HandlerContext,
    output: dict[str, Any],
    summary: str,
    *,
    metrics: dict[str, Any],
    details: dict[str, Any] | None = None,
) -> HandlerResult:
    content = {**output, **(details or {})}
    lines = [summary]
    if output.get("reference"):
        lines.append(f"reference: {output['reference']}")
    if output.get("keys"):
        lines.append("keys: " + ", ".join(output["keys"]))
    return HandlerResult(
        success=True,
        summary=summary,
        metrics=metrics,
        output=output,
        evidence=[
            {
                "kind": "step_result",
                "name": f"secret_{output['operation']}_{ctx.step_id}",
                "content_text": "\n".join(lines) + "\n",
                "content_json": content,
            }
        ],
    )


def _stored(result: Any, fallback_keys: list[str]) -> tuple[str, list[str], bool]:
    """``(reference, keys, created)`` from a host's ``SecretWriteResult``."""
    reference = str(getattr(result, "reference", "") or "")
    keys = getattr(result, "keys", None)
    names = sorted(str(k) for k in keys) if keys else sorted(fallback_keys)
    return reference, names, bool(getattr(result, "created", False))


class _NoWorkspace(Exception):
    """The step cannot read the run's shared workspace; the message says why."""


def _workspace_dir(ctx: HandlerContext, services: HandlerServices) -> str:
    """The run's shared workspace on this worker, where step containers' ``/shared`` lives."""
    needs = (
        "Keys from files are read from the run's shared workspace, so this step must run "
        "with shared (or explicit) execution affinity, on the same worker as the step that "
        "wrote the files, on a worker with shared workspaces enabled"
    )
    if not ctx.shared_workspace:
        raise _NoWorkspace(f"{needs}; this step has no shared workspace")
    try:
        runtime = services.container_runtime()
    except Exception as exc:  # noqa: BLE001 - any failure means no workspace to read
        raise _NoWorkspace(
            f"{needs}; this worker does not describe one ({type(exc).__name__})"
        ) from None
    root = getattr(runtime, "shared_workspace_root", "") or ""
    if not getattr(runtime, "shared_workspaces_enabled", False) or not root:
        raise _NoWorkspace(f"{needs}; this worker has shared workspaces disabled")
    run_id = ctx.run_id
    if not run_id or run_id in (".", "..") or "/" in run_id or "\\" in run_id:
        raise _NoWorkspace(f"run id {run_id!r} cannot name a shared workspace")
    return os.path.join(root, run_id)


class WriteSecretHandler(BaseHandler):
    """Store keys in, swap, or delete a secret of the run's organization."""

    handler_id = "secret.write"
    supported_kinds = [StepKind.ACTION]
    display_name = "Write Secret"
    description = (
        "Store files from the run's shared workspace or values in the organization's secret "
        "store, swap two secrets, or delete one."
    )
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    writes_secrets = True
    # Values reach the handler as written (see values.resolve_values).
    raw_config_keys = frozenset({"values"})
    config_model = SecretWriteConfig
    default_config = {"operation": "write"}

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate the step's fields; templated paths are checked again once rendered."""
        errors = super().validate_config(config)
        if errors:
            return errors
        return semantic_errors(config, allow_templates=True)

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Run the configured operation through the host's secret store services."""
        errors = self.validate_config(ctx.config)
        if not errors:
            # Rendered now: a templated path must hold up as well.
            errors = semantic_errors(ctx.config, allow_templates=False)
        if errors:
            return _failure(
                f"Invalid secret step config: {'; '.join(errors)}", "Config validation failed"
            )
        config = SecretWriteConfig.model_validate(ctx.config)

        services = ctx.require_services()
        missing = [name for name in SECRET_SERVICES if not callable(getattr(services, name, None))]
        if missing:
            return _failure(
                "this platform does not provide secret writes to steps: its worker lacks "
                f"{', '.join(missing)}. Upgrade the platform to use this step",
                "Secret writes unavailable",
            )

        path = config.path.strip()
        if config.operation == "swap":
            return await self._swap(ctx, services, path, config.swap_with.strip())
        if config.operation == "delete":
            return await self._delete(ctx, services, path, missing_ok=config.missing_ok)
        return await self._write(ctx, services, path, config)

    async def _write(
        self,
        ctx: HandlerContext,
        services: HandlerServices,
        path: str,
        config: SecretWriteConfig,
    ) -> HandlerResult:
        workspace = ""
        sources: list[SourceFile] = []
        if config.files:
            try:
                workspace = _workspace_dir(ctx, services)
            except _NoWorkspace as exc:
                return _failure(str(exc), "Shared workspace unavailable")
            try:
                sources = await asyncio.to_thread(read_source_files, workspace, config.files)
            except WorkspaceError as exc:
                return _failure(f"Cannot use a source file: {exc}", "Source file refused")

        values: dict[str, str] = {}
        for source in sources:
            if config.encoding == "text":
                try:
                    values[source.key] = source.data.decode("utf-8")
                except UnicodeDecodeError:
                    return _failure(
                        f"file {source.path!r} (key {source.key!r}) is not UTF-8 text: set "
                        "File encoding to base64 to store it",
                        "Source file refused",
                    )
            else:
                values[source.key] = base64.b64encode(source.data).decode("ascii")
        try:
            values.update(await resolve_values(services, config.values, source=RESOLVE_SOURCE))
        except Exception as exc:  # noqa: BLE001 - reported without values, step fails
            return _failure(
                f"Could not resolve 'values': {_describe(exc)}", "Secret value not resolved"
            )
        written = sorted(values)

        previous_path: str | None = None
        keep = config.keep_previous_at.strip()
        nothing_to_keep = False
        if keep:
            try:
                current = await services.read_secret(path)
            except Exception as exc:  # noqa: BLE001 - mapped to a failed result
                return _host_failure(f"read the current keys of {path}", exc)
            if current:
                try:
                    await services.write_secret(keep, dict(current), merge=False)
                except Exception as exc:  # noqa: BLE001 - mapped to a failed result
                    return _host_failure(
                        f"keep the current keys of {path} at {keep}; {path} is unchanged", exc
                    )
                previous_path = keep
            else:
                nothing_to_keep = True

        try:
            result = await services.write_secret(path, values, merge=config.merge)
        except Exception as exc:  # noqa: BLE001 - mapped to a failed result
            action = f"write {_plural(len(written))} to {path}"
            if previous_path:
                action += f" (its previous keys were already copied to {previous_path})"
            return _host_failure(action, exc)
        reference, keys, created = _stored(result, written)

        not_removed: dict[str, str] = {}
        if sources and config.delete_source_files:
            not_removed = await asyncio.to_thread(scrub_source_files, workspace, sources)

        notes: list[str] = []
        if config.merge:
            notes.append(f"merged, {_plural(len(keys))} stored")
        if previous_path:
            notes.append(f"previous kept at {previous_path}")
        elif nothing_to_keep:
            notes.append(f"no previous secret to keep at {keep}")
        if not_removed:
            count = len(not_removed)
            notes.append(f"{count} source file{'s' if count != 1 else ''} not deleted")
        summary = f"wrote {_plural(len(written))} to {path}"
        if notes:
            summary += f" ({'; '.join(notes)})"

        output = _result_output(
            "write",
            path,
            reference=reference,
            keys=keys,
            created=created,
            previous_path=previous_path,
        )
        removed = (
            sorted({s.path for s in sources} - set(not_removed))
            if sources and config.delete_source_files
            else []
        )
        metrics: dict[str, Any] = {"keys": len(written)}
        if sources:
            metrics["source_files"] = len({s.path for s in sources})
            metrics["source_files_deleted"] = len(removed)
        return _success(
            ctx,
            output,
            summary,
            metrics=metrics,
            details={
                "keys_written": written,
                "merge": config.merge,
                "keys_from_files": sorted(s.key for s in sources),
                "keys_from_values": sorted(config.values),
                "encoding": config.encoding if sources else None,
                "source_files": sorted({s.path for s in sources}),
                "source_files_deleted": removed,
                "source_files_not_deleted": dict(sorted(not_removed.items())),
            },
        )

    async def _swap(
        self, ctx: HandlerContext, services: HandlerServices, path: str, other: str
    ) -> HandlerResult:
        try:
            first = await services.read_secret(path)
            second = await services.read_secret(other)
        except Exception as exc:  # noqa: BLE001 - mapped to a failed result
            return _host_failure(f"read {path} and {other} to swap them", exc)
        absent = [name for name, held in ((path, first), (other, second)) if not held]
        if absent or first is None or second is None:
            return _failure(
                f"Cannot swap {path} and {other}: no secret exists at {' or '.join(absent)}; "
                "nothing changed",
                "Secret not found",
            )

        try:
            written = await services.write_secret(path, dict(second), merge=False)
        except Exception as exc:  # noqa: BLE001 - mapped to a failed result
            return _host_failure(f"write {other}'s keys to {path}; nothing changed", exc)
        try:
            written_other = await services.write_secret(other, dict(first), merge=False)
        except Exception as exc:  # noqa: BLE001 - restore, then report
            reason = _describe(exc)
            try:
                await services.write_secret(path, dict(first), merge=False)
            except Exception as restore_exc:  # noqa: BLE001 - both failures reported
                return _failure(
                    f"Swap failed half-way: {path} now holds the keys {other} held, and "
                    f"{other} still holds its own. Writing {other} failed ({reason}), and "
                    f"restoring {path} failed too ({_describe(restore_exc)}): restore {path} "
                    "by hand",
                    "Swap failed half-way",
                    output=_result_output("swap", path, swapped_with=None),
                )
            return _failure(
                f"Swap failed: writing {other} failed ({reason}). {path} was restored, so "
                "both secrets hold their original keys",
                "Swap failed, restored",
                output=_result_output("swap", path, swapped_with=None),
            )

        reference, keys, _created = _stored(written, sorted(second))
        other_reference, other_keys, _ = _stored(written_other, sorted(first))
        output = _result_output("swap", path, reference=reference, keys=keys, swapped_with=other)
        return _success(
            ctx,
            output,
            f"swapped {path} and {other}",
            metrics={"keys": len(keys)},
            details={"swapped_with_reference": other_reference, "swapped_with_keys": other_keys},
        )

    async def _delete(
        self, ctx: HandlerContext, services: HandlerServices, path: str, *, missing_ok: bool
    ) -> HandlerResult:
        try:
            deleted = bool(await services.delete_secret(path))
        except Exception as exc:  # noqa: BLE001 - mapped to a failed result
            return _host_failure(f"delete {path}", exc)
        output = _result_output("delete", path, deleted=deleted)
        if not deleted and not missing_ok:
            return _failure(
                f"No secret exists at {path}, so nothing was deleted (turn on Succeed when "
                "absent to accept that)",
                "Secret not found",
                output=output,
            )
        summary = f"deleted {path}" if deleted else f"no secret at {path}; nothing deleted"
        return _success(ctx, output, summary, metrics={"keys": 0})
