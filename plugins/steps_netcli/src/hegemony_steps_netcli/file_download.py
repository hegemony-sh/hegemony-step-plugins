# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""FileDownloadHandler: each target downloads a file-repository file by itself.

The step asks the host for a short-lived download link to the file
(``services.open_file_download``) and has the target fetch it over HTTP(S)
through the device transport's ``http_transfer``: a ``copy <url> <fs>`` on a
network device, a ``curl`` on a server. The link is asked for anew for each
target right before its transfer and ended right after it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

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

logger = logging.getLogger(__name__)

_DEFAULT_TRANSFER_TIMEOUT_SECONDS = 3600
#: How long a target has to start its download once the link exists. The link
#: is asked for right before the transfer, so this only has to cover the
#: connection to the target; a transfer under way is not cut off at its end.
_LINK_TTL_SECONDS = 600
#: What a link is replaced with wherever the step reports text a target echoed.
_LINK_PLACEHOLDER = "<download link>"


class FileDownloadConfig(SshSecurityConfig):
    """Config for ``netcli.file_download``."""

    model_config = ConfigDict(extra="allow")

    # Named file_ids on purpose: the platform refuses to delete a stored file
    # that a flow lists under this key.
    file_ids: list[str] = Field(
        default_factory=list,
        title="File Repository File",
        description="The file each target downloads. Browse the file repositories and pick one.",
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
    transfer_timeout_seconds: int = Field(
        _DEFAULT_TRANSFER_TIMEOUT_SECONDS,
        ge=60,
        le=86400,
        title="Transfer timeout (seconds)",
        description=(
            "How long one target's download may take before it fails. The step "
            "timeout must still cover every target. Defaults to one hour."
        ),
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Targets downloading concurrently (1 = sequential)",
    )

    @field_validator("file_ids", mode="before")
    @classmethod
    def _single_file_id(cls, value: Any) -> Any:
        # One id given as text, as a rendered template gives it, is a list of one.
        return [value] if isinstance(value, str) else value


@dataclass
class _DeviceOutcome:
    """One target's result, merged in device order after the fan-out."""

    evidence: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    success: bool = True
    transferred: bool = False
    file: dict[str, Any] | None = None


def _has_control_characters(value: str) -> bool:
    """Whether ``value`` holds a character a command line must not carry.

    The destination goes into the command a target runs (``copy <link>
    <fs><name>`` typed on a network device's CLI). A line break or another
    control character in it would end that command and start another, so a
    value from a run input or a stored file's name could run commands of its
    own on the device. Printable characters only: no CR, LF, ESC or other
    control character, and no Unicode line or paragraph separator.
    """
    return any(not character.isprintable() for character in value)


def _without_link(text: str, url: str) -> str:
    """``text`` with the download link taken out (a device echoes the copy command).

    The host redacts the link's token from everything a step reports; this
    keeps the rest of the address out too, and does not depend on the host.
    """
    if not url:
        return text
    return text.replace(url, _LINK_PLACEHOLDER)


class FileDownloadHandler(BaseHandler):
    """Handler that has each target download one file-repository file."""

    handler_id = "netcli.file_download"
    supported_kinds = [StepKind.ACTION]
    display_name = "Download File to Device"
    description = (
        "Have each target device or server download a file-repository file "
        "over HTTP(S), through a short-lived link."
    )
    category = "Actions"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = FileDownloadConfig
    # A software image over a slow link takes a while, and every target has
    # its own Transfer timeout within the step's.
    default_timeout_seconds = 7200

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Stage the configured file on every target device."""
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
                error=(
                    "This Hegemony version cannot issue download links for file "
                    "repository files; upgrade the platform to use this step"
                ),
                summary="Download links not supported",
            )

        dest_fs = str(ctx.config.get("dest_fs") or "flash:").strip()
        dest_filename_config = str(ctx.config.get("dest_filename") or "").strip()
        transfer_timeout = int(
            ctx.config.get("transfer_timeout_seconds") or _DEFAULT_TRANSFER_TIMEOUT_SECONDS
        )
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
        many = len(target_devices) > 1

        async def _process_device(device: dict) -> _DeviceOutcome:
            outcome = _DeviceOutcome()
            device_id = device.get("id", device.get("mgmt_host"))
            device_name = device.get("name", device_id)
            artifact_name = f"File download ({device_name})" if many else "File download"

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

            url = ""
            try:
                # A link of its own for each target, asked for right before its
                # transfer: a slow target earlier in the list cannot use up the
                # time a later one has to start.
                async with open_file_download(file_id, ttl_seconds=_LINK_TTL_SECONDS) as download:
                    url = download.url
                    outcome.file = {
                        "file_id": download.file_id,
                        "filename": download.filename,
                        "size_bytes": download.size_bytes,
                        "sha256": download.sha256,
                        "md5": download.md5,
                    }
                    if not url:
                        return _fail(
                            "the platform has no address targets can reach it at; an "
                            "administrator sets HEGEMONY_API_EXTERNAL_URL"
                        )
                    dest_filename = dest_filename_config or download.filename
                    if _has_control_characters(dest_filename):
                        # The stored file's own name, used as it is: refused
                        # before any connection, as the configured one is.
                        return _fail(
                            "the stored file's name contains a line break or another "
                            "control character; set Destination Filename"
                        )
                    # step_run_id registers the session, so cancelling the run
                    # closes it.
                    transport = services.connect(
                        device,
                        platform=device.get("platform"),
                        step_run_id=ctx.step_run_id,
                    )
                    configure_ssh_security(transport, ctx.config.get("allow_legacy_ssh", False))
                    result = await transport.http_transfer(
                        url=url,
                        dest_fs=dest_fs,
                        dest_filename=dest_filename,
                        timeout_seconds=transfer_timeout,
                    )
            except NotImplementedError as exc:
                detail = str(exc) or "its transport cannot have the device download a file"
                return _fail(_without_link(detail, url))
            except Exception as exc:  # noqa: BLE001 - one device's failure, reported
                return _fail(_without_link(str(exc) or type(exc).__name__, url))

            output = _without_link(str(result.get("output") or ""), url)
            transferred = bool(result.get("transferred"))
            if output:
                await ctx.emit_output(output, device=device, command="file download")
            outcome.transferred = transferred
            outcome.evidence.append(
                {
                    "kind": "cli_output",
                    "name": artifact_name,
                    "device_id": device_id,
                    "content_text": output or ("File transferred" if transferred else ""),
                    "content_json": {
                        "device_id": device_id,
                        "device_name": device_name,
                        **(outcome.file or {}),
                        "dest_fs": dest_fs,
                        "dest_filename": dest_filename,
                        "success": transferred,
                        "elapsed_ms": result.get("elapsed_ms"),
                    },
                }
            )
            if not transferred:
                outcome.success = False
                outcome.errors.append(f"{device_name}: the device did not complete the download")
            return outcome

        outcomes = await for_each_target_device(
            target_devices,
            _process_device,
            max_parallel=max_parallel_from_config(ctx.config),
        )

        errors = [error for outcome in outcomes for error in outcome.errors]
        all_success = all(outcome.success for outcome in outcomes)
        transferred_count = sum(1 for outcome in outcomes if outcome.transferred)
        file_info = next((outcome.file for outcome in outcomes if outcome.file), None) or {}
        filename = str(file_info.get("filename") or "")
        dest_name = dest_filename_config or filename

        if all_success:
            summary = f"{filename or 'File'} downloaded by {transferred_count} device(s)"
        else:
            summary = f"File download failed on some devices: {'; '.join(errors)}"

        return HandlerResult(
            success=all_success,
            error="; ".join(errors)[:MAX_CHAIN_OUTPUT_CHARS] if errors else None,
            summary=summary[:MAX_CHAIN_OUTPUT_CHARS],
            metrics={
                "device_count": len(target_devices),
                "transferred_count": transferred_count,
                "size_bytes": file_info.get("size_bytes"),
            },
            evidence=[item for outcome in outcomes for item in outcome.evidence],
            output={
                "file_id": file_id,
                "filename": filename,
                "dest_fs": dest_fs,
                "dest_filename": dest_name,
                "size_bytes": file_info.get("size_bytes"),
                "sha256": file_info.get("sha256"),
                "md5": file_info.get("md5"),
                "transferred_count": transferred_count,
            },
        )
