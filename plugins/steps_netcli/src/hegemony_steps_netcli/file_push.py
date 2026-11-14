# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""FilePushHandler: the worker copies a file-repository file to each target.

The step asks the host for a short-lived download link to the file
(``services.open_file_download``), fetches the file onto the worker through
it once, checks its size and SHA-256 against the stored file's, and ends the
link. It then copies the file to every target through the device transport's
``scp_put``: SCP on a network device, SFTP on a server. The worker's copy is
removed when the step ends.

The target needs no route to the platform, only the SSH access the other
steps use. ``netcli.file_download`` is the other way round: the target fetches
the file by itself, and the file never passes through the worker.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Any

import httpx
from pydantic import ConfigDict, Field, field_validator

from hegemony_step_sdk import (
    MAX_CHAIN_OUTPUT_CHARS,
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
    for_each_target_device,
    max_parallel_from_config,
)
from hegemony_step_sdk.ssh import SshSecurityConfig, configure_ssh_security

from .file_download import (
    _LINK_PLACEHOLDER,
    _NO_DOWNLOAD_LINKS,
    _NOT_A_PLAIN_NAME,
    _QUESTION_MARK_REASON,
    _has_control_characters,
    _is_plain_file_name,
)

logger = logging.getLogger(__name__)

#: How long the worker has to start fetching the file once the link exists.
#: The fetch starts right away, and one under way is not cut off at its end.
_LINK_TTL_SECONDS = 600
_CHUNK_BYTES = 1024 * 1024
#: Free space the worker keeps beyond the file itself.
_FREE_SPACE_MARGIN_BYTES = 64 * 1024 * 1024
#: Connecting to the platform, and the longest pause between two chunks.
_FETCH_TIMEOUT = httpx.Timeout(60.0, connect=30.0)
#: The worker's copy has this name whatever the stored file is called, so a
#: stored name never becomes a path on the worker.
_LOCAL_NAME = "file"


class FilePushConfig(SshSecurityConfig):
    """Config for ``netcli.file_push``."""

    model_config = ConfigDict(extra="allow")

    # Named file_ids on purpose: the platform refuses to delete a stored file
    # that a flow lists under this key.
    file_ids: list[str] = Field(
        default_factory=list,
        title="File Repository File",
        description="The file copied to each target. Browse the file repositories and pick one.",
        json_schema_extra={
            "x_widget": "repository-file-select",
            "x_multiple": False,
            "x_file_type_filter": "file",
            "x_col_span": 2,
        },
    )
    dest_fs: str = Field(
        default="flash:",
        title="Destination",
        description=(
            "Where the file goes on the target: a device filesystem with its "
            "colon (flash:, bootflash:), or a directory on a server (/var/tmp). "
            'Defaults to "flash:".'
        ),
        json_schema_extra={"x_placeholder": "flash:"},
    )
    dest_filename: str = Field(
        default="",
        title="Destination Filename",
        description="File name on the target. Leave empty to keep the stored file's name.",
        json_schema_extra={"x_placeholder": "cat9k_iosxe.17.09.05.SPA.bin"},
    )
    overwrite: bool = Field(
        default=False,
        title="Overwrite",
        description=(
            "Replace a file of the same name on the target. Off: a target that "
            "already holds a different file of that name fails."
        ),
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Targets copied to concurrently (1 = sequential)",
    )

    @field_validator("file_ids", mode="before")
    @classmethod
    def _single_file_id(cls, value: Any) -> Any:
        # One id given as text, as a rendered template gives it, is a list of one.
        return [value] if isinstance(value, str) else value


class _FetchError(Exception):
    """The worker could not get a sound copy of the file; the message is for the user."""


@dataclass
class _DeviceOutcome:
    """One target's result, merged in device order after the fan-out."""

    evidence: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    success: bool = True
    transferred: bool = False
    already_present: bool = False


def _without_link(text: str, url: str) -> str:
    """``text`` with the download link taken out (an HTTP error names its URL)."""
    if not url:
        return text
    return text.replace(url, _LINK_PLACEHOLDER)


def _free_bytes(directory: str) -> int:
    return shutil.disk_usage(directory).free


async def _fetch(url: str, path: str, *, size_bytes: int, sha256: str) -> None:
    """Fetch ``url`` into ``path`` and check it against the stored file's size and SHA-256.

    No redirect is followed: a download link answers with the file itself.
    """
    digest = hashlib.sha256()
    received = 0
    try:
        async with (
            httpx.AsyncClient(timeout=_FETCH_TIMEOUT, follow_redirects=False) as client,
            client.stream("GET", url) as response,
        ):
            if response.status_code != 200:
                raise _FetchError(
                    f"the platform answered the download with HTTP {response.status_code}"
                )
            # Created for the owner only: the file may be anything a
            # repository holds.
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                async for chunk in response.aiter_bytes(_CHUNK_BYTES):
                    received += len(chunk)
                    if received > size_bytes:
                        raise _FetchError(
                            f"the platform sent more than the stored file's {size_bytes} bytes"
                        )
                    digest.update(chunk)
                    # A megabyte at a time, off the event loop's thread.
                    await asyncio.to_thread(target.write, chunk)
    except httpx.HTTPError as exc:
        detail = _without_link(str(exc) or type(exc).__name__, url)
        raise _FetchError(f"the worker could not fetch the file: {detail}") from exc
    if received != size_bytes:
        raise _FetchError(f"the worker received {received} bytes of the stored file's {size_bytes}")
    if digest.hexdigest() != sha256.lower():
        raise _FetchError("the file the worker received does not match the stored file's SHA-256")


class FilePushHandler(BaseHandler):
    """Handler that copies one file-repository file from the worker to each target."""

    handler_id = "netcli.file_push"
    supported_kinds = [StepKind.ACTION]
    display_name = "Push File to Device"
    description = (
        "Copy a file-repository file from the worker to each target over "
        "SCP/SFTP. The target needs no route to the platform."
    )
    category = "Actions"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = FilePushConfig
    # A software image over a slow link takes a while.
    default_timeout_seconds = 7200

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Fetch the configured file once and copy it to every target device."""
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )

        raw_ids = ctx.config.get("file_ids") or []
        if isinstance(raw_ids, str):
            raw_ids = [raw_ids]
        file_ids = [str(item).strip() for item in raw_ids if str(item).strip()]
        if len(file_ids) != 1:
            return HandlerResult(
                success=False,
                error=(
                    "Select exactly one file repository file"
                    if file_ids
                    else "No file repository file selected"
                ),
                summary="Missing file",
            )
        file_id = file_ids[0]

        services = ctx.require_services()
        open_file_download = getattr(services, "open_file_download", None)
        if open_file_download is None:
            return HandlerResult(
                success=False,
                error=_NO_DOWNLOAD_LINKS,
                summary="Download links not supported",
            )

        dest_fs = str(ctx.config.get("dest_fs") or "flash:").strip()
        dest_filename_config = str(ctx.config.get("dest_filename") or "").strip()
        overwrite = bool(ctx.config.get("overwrite", False))
        # The destination goes into commands a network device runs (the
        # checks before and after the copy), as it does for a download.
        for label, value in (
            ("Destination", dest_fs),
            ("Destination Filename", dest_filename_config),
        ):
            if _has_control_characters(value):
                return HandlerResult(
                    success=False,
                    error=f"{label} contains a line break or another control character",
                    summary="Invalid destination",
                )
            if "?" in value:
                return HandlerResult(
                    success=False,
                    error=f"{label} contains a question mark, {_QUESTION_MARK_REASON}",
                    summary="Invalid destination",
                )
        if dest_filename_config and not _is_plain_file_name(dest_filename_config):
            return HandlerResult(
                success=False,
                error=f"Destination Filename {_NOT_A_PLAIN_NAME}",
                summary="Invalid destination",
            )

        def _refused(message: str, summary: str) -> HandlerResult:
            return HandlerResult(success=False, error=message, summary=summary)

        staging_dir = tempfile.mkdtemp(prefix="hegemony-file-push-")
        local_path = os.path.join(staging_dir, _LOCAL_NAME)
        try:
            url = ""
            link_opened = False
            try:
                async with open_file_download(file_id, ttl_seconds=_LINK_TTL_SECONDS) as download:
                    link_opened = True
                    url = download.worker_url
                    file_info: dict[str, Any] = {
                        "file_id": download.file_id,
                        "filename": download.filename,
                        "size_bytes": download.size_bytes,
                        "sha256": download.sha256,
                        "md5": download.md5,
                    }
                    dest_filename = dest_filename_config or download.filename
                    if _has_control_characters(dest_filename):
                        return _refused(
                            "The stored file's name contains a line break or another "
                            "control character; set Destination Filename",
                            "Invalid destination",
                        )
                    if "?" in dest_filename:
                        return _refused(
                            "The stored file's name contains a question mark, "
                            f"{_QUESTION_MARK_REASON}; set Destination Filename",
                            "Invalid destination",
                        )
                    if not _is_plain_file_name(dest_filename):
                        return _refused(
                            "The stored file's name has a directory part; set Destination Filename",
                            "Invalid destination",
                        )
                    if not url:
                        return _refused(
                            "The platform gave no address the worker can fetch the file from",
                            "File not fetched",
                        )
                    needed = download.size_bytes + _FREE_SPACE_MARGIN_BYTES
                    free = await asyncio.to_thread(_free_bytes, staging_dir)
                    if free < needed:
                        return _refused(
                            f"The worker has {free} bytes free for temporary files and "
                            f"needs {needed} to hold the file ({download.size_bytes} bytes)",
                            "Not enough space on the worker",
                        )
                    await ctx.emit_output(
                        f"Fetching {download.filename} ({download.size_bytes} bytes) "
                        "onto the worker",
                        command="file push",
                    )
                    await _fetch(
                        url, local_path, size_bytes=download.size_bytes, sha256=download.sha256
                    )
            except NotImplementedError:
                if not link_opened:
                    return _refused(_NO_DOWNLOAD_LINKS, "Download links not supported")
                raise
            except _FetchError as exc:
                return _refused(str(exc)[:1].upper() + str(exc)[1:], "File not fetched")
            except (LookupError, ValueError, RuntimeError, OSError) as exc:
                if not link_opened:
                    # The host refused the link: no such file, a malformed id,
                    # or the platform could not be reached.
                    return _refused(str(exc) or type(exc).__name__, "File not fetched")
                detail = _without_link(str(exc) or type(exc).__name__, url)
                return _refused(
                    f"The worker could not store the file: {detail}", "File not fetched"
                )

            # The link is ended by now: the copies below need the worker's
            # file only.
            many = len(target_devices) > 1

            async def _process_device(device: dict) -> _DeviceOutcome:
                outcome = _DeviceOutcome()
                device_id = device.get("id", device.get("mgmt_host"))
                device_name = device.get("name", device_id)
                artifact_name = f"File push ({device_name})" if many else "File push"

                def _fail(message: str, **details: Any) -> _DeviceOutcome:
                    outcome.success = False
                    outcome.errors.append(f"{device_name}: {message}")
                    outcome.evidence.append(
                        {
                            "kind": "cli_output",
                            "name": f"Error ({device_name})",
                            "device_id": device_id,
                            "content_text": message,
                            "content_json": {
                                "device_id": device_id,
                                "device_name": device_name,
                                "file_id": file_id,
                                "error": message,
                                "success": False,
                                **details,
                            },
                        }
                    )
                    return outcome

                if not device.get("mgmt_host"):
                    return _fail("no mgmt_host configured")
                try:
                    # step_run_id registers the session, so cancelling the run
                    # closes it.
                    transport = services.connect(
                        device,
                        platform=device.get("platform"),
                        step_run_id=ctx.step_run_id,
                    )
                    configure_ssh_security(transport, ctx.config.get("allow_legacy_ssh", False))
                    result = await transport.scp_put(
                        local_path=local_path,
                        dest_fs=dest_fs,
                        dest_filename=dest_filename,
                        overwrite=overwrite,
                    )
                except NotImplementedError as exc:
                    return _fail(str(exc) or "its transport cannot copy a file to the device")
                except Exception as exc:  # noqa: BLE001 - one device's failure, reported
                    return _fail(str(exc) or type(exc).__name__)

                transferred = bool(result.get("transferred"))
                verified = bool(result.get("verified"))
                exists = bool(result.get("exists"))
                details = {
                    "dest_fs": dest_fs,
                    "dest_filename": dest_filename,
                    "transferred": transferred,
                    "verified": verified,
                    "elapsed_ms": result.get("elapsed_ms"),
                }
                if transferred and not verified:
                    return _fail(
                        "the file was copied, but the copy on the target does not match it",
                        **details,
                    )
                if not transferred and not (exists and verified):
                    if exists:
                        return _fail(
                            "a file of that name is already on the target; turn on "
                            "Overwrite to replace it",
                            **details,
                        )
                    return _fail("the target did not take the file", **details)

                outcome.transferred = transferred
                outcome.already_present = not transferred
                text = (
                    "File copied and verified"
                    if transferred
                    else "The target already holds this file; nothing copied"
                )
                await ctx.emit_output(text, device=device, command="file push")
                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": artifact_name,
                        "device_id": device_id,
                        "content_text": text,
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            **file_info,
                            **details,
                            "already_present": not transferred,
                            "success": True,
                        },
                    }
                )
                return outcome

            outcomes = await for_each_target_device(
                target_devices,
                _process_device,
                max_parallel=max_parallel_from_config(ctx.config),
            )
        finally:
            await asyncio.to_thread(shutil.rmtree, staging_dir, True)

        errors = [error for outcome in outcomes for error in outcome.errors]
        all_success = all(outcome.success for outcome in outcomes)
        transferred_count = sum(1 for outcome in outcomes if outcome.transferred)
        already_present_count = sum(1 for outcome in outcomes if outcome.already_present)
        filename = str(file_info.get("filename") or "")

        if all_success:
            summary = f"{filename or 'File'} copied to {transferred_count} device(s)"
            if already_present_count:
                summary += f", already on {already_present_count}"
        else:
            summary = f"File push failed on some devices: {'; '.join(errors)}"

        return HandlerResult(
            success=all_success,
            error="; ".join(errors)[:MAX_CHAIN_OUTPUT_CHARS] if errors else None,
            summary=summary[:MAX_CHAIN_OUTPUT_CHARS],
            metrics={
                "device_count": len(target_devices),
                "transferred_count": transferred_count,
                "already_present_count": already_present_count,
                "size_bytes": file_info.get("size_bytes"),
            },
            evidence=[item for outcome in outcomes for item in outcome.evidence],
            output={
                "file_id": file_id,
                "filename": filename,
                "dest_fs": dest_fs,
                "dest_filename": dest_filename,
                "size_bytes": file_info.get("size_bytes"),
                "sha256": file_info.get("sha256"),
                "md5": file_info.get("md5"),
                "transferred_count": transferred_count,
                "already_present_count": already_present_count,
            },
        )
