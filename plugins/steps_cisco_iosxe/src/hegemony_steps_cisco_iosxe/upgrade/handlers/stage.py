# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Upgrade Stage Handler.

Transfers upgrade file to device and verifies integrity.

This handler should run in PREPARE phase to pre-stage files
before the maintenance window.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    DEFAULT_DEVICE_PLATFORM,
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
    for_each_target_device,
    max_parallel_from_config,
)

from ..api_client import get_file_device_download_url
from ..driver import UpgradeMode, get_driver

logger = logging.getLogger(__name__)


class UpgradeStageConfig(BaseModel):
    """Config for ``cisco.iosxe.upgrade.stage``."""

    model_config = ConfigDict(extra="allow")

    upgrade_mode: Literal["install", "bundle"] = Field(
        default="install",
        title="Upgrade Mode",
        description=(
            "Which IOS-XE upgrade workflow the staged image is intended for: "
            "install mode (modern devices) or bundle mode (legacy devices). The "
            "transfer itself behaves the same in both modes; keep this "
            "consistent with the install step that follows. Defaults to install "
            "mode."
        ),
        json_schema_extra={
            "x_option_labels": {
                "install": "Install Mode (modern IOS-XE)",
                "bundle": "Bundle Mode (legacy ISR)",
            }
        },
    )
    transfer_method: Literal["auto", "http", "https", "scp"] = Field(
        default="auto",
        title="Transfer Method",
        description=(
            "How the image reaches the device. Auto (the default) prefers a "
            "device-side HTTPS/HTTP pull when the source is an HTTP(S) URL. "
            "Selecting SCP is not yet supported by this step and fails with an "
            "explanatory error."
        ),
        json_schema_extra={
            "x_option_labels": {
                "auto": "Auto (detect best method)",
                "http": "HTTP",
                "https": "HTTPS",
                "scp": "SCP",
            }
        },
    )
    file_ids: list[str] = Field(
        default_factory=list,
        title="File Repository File",
        description=(
            "Browse files in the file repository and select one. Use either this or "
            "Source URL (not both)."
        ),
        json_schema_extra={
            "x_widget": "repository-file-select",
            "x_multiple": False,
            "x_file_type_filter": "file",
            "x_col_span": 2,
            "x_disabled_when": {"field": "source_url", "is_not_empty": True},
        },
    )
    source_url: str = Field(
        default="",
        title="Source URL",
        description=("Manual URL fallback (http/https). Do not combine with File Repository File."),
        json_schema_extra={
            "x_placeholder": "https://repo.example.com/images/cat9k_iosxe.17.09.04a.SPA.bin",
            "x_col_span": 2,
            "x_disabled_when": {"field": "file_ids", "is_not_empty": True},
        },
    )
    dest_filename: str = Field(
        default="",
        title="Destination Filename",
        description=(
            "Optional when selecting File Repository File (defaults to selected filename)"
        ),
        json_schema_extra={"x_placeholder": "cat9k_iosxe.17.09.04a.SPA.bin"},
    )
    dest_fs: str = Field(
        default="flash:",
        title="Destination Filesystem",
        description=(
            'Device filesystem the image is copied to. Defaults to "flash:"; a '
            "trailing colon is added automatically if omitted."
        ),
        json_schema_extra={"x_placeholder": "flash:"},
    )
    expected_md5: str = Field(
        default="",
        title="MD5 Checksum (optional)",
        description=(
            "MD5 hash verified on the device with verify /md5 after a "
            "transfer - and before one: a file already staged under the "
            "destination name that passes this check is not transferred "
            "again."
        ),
        json_schema_extra={
            "x_placeholder": "d41d8cd98f00b204e9800998ecf8427e",
            "x_col_span": 2,
            "x_disabled_when": {"field": "file_ids", "is_not_empty": True},
        },
    )
    overwrite: bool = Field(
        default=False,
        title="Force re-transfer even if file exists",
        description=(
            "Transfer the image again even when a file with the same name is "
            "already on the device. When off (the default), an existing file "
            "whose size matches the expected size (and whose MD5 verifies, when "
            "one is given) is reused and the transfer is skipped."
        ),
        json_schema_extra={"x_col_span": 2},
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Devices staged concurrently (1 = sequential)",
    )


@dataclass
class _DeviceOutcome:
    """One device's results, merged in device order after the fan-out.

    Workers collect into these locals instead of shared collections so
    aggregation stays deterministic when devices run in parallel.
    """

    evidence: list[dict[str, Any]] = field(default_factory=list)
    ok: bool = False
    failed_device: str | None = None
    device_id: Any = None
    context: dict[str, Any] | None = None


class UpgradeStageHandler(BaseHandler):
    """Handler for staging upgrade files.

    Transfers file to device flash and verifies integrity.
    Skips transfer if file already exists and is verified.

    Required params:
        platform: Device platform (e.g., "ios-xe")
        Either:
            - source_url: URL to download file from (http/https)
            - file_ids: file repository file ID array (must contain exactly one ID for this handler)

    Optional params:
        dest_filename: Target filename on device (defaults from selected file repository file)
        upgrade_mode: "install" or "bundle" (default: "install")
        dest_fs: Destination filesystem (default: "flash:")
        transfer_method: "auto", "http", "https", "scp" (default: "auto")
        expected_md5: MD5 hash for verification
        expected_size: Expected file size in bytes
        overwrite: Force re-transfer even if file exists (default: false)

    Output context:
        stage.staged: Whether file is now on device
        stage.skipped: Whether transfer was skipped (already exists)
        stage.full_path: Full path to staged file
        stage.hash_verified: Whether hash was verified
    """

    handler_id = "cisco.iosxe.upgrade.stage"
    default_timeout_seconds = 7200
    supported_kinds = [StepKind.ACTION, StepKind.TRANSFER]
    display_name = "Upgrade: Stage"
    description = "Transfer the upgrade image to device flash and verify integrity."
    category = "Upgrade"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = UpgradeStageConfig
    default_config = {"upgrade_mode": "install", "transfer_method": "auto", "dest_fs": "flash:"}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Stage upgrade file on all target devices."""
        services = ctx.require_services()
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )

        # Get parameters
        platform = ctx.config.get("platform", DEFAULT_DEVICE_PLATFORM)
        mode_str = ctx.config.get("upgrade_mode", "install")
        upgrade_mode = UpgradeMode.BUNDLE if mode_str.lower() == "bundle" else UpgradeMode.INSTALL

        source_url = ctx.config.get("source_url")
        dest_filename = ctx.config.get("dest_filename")
        file_ids_raw = ctx.config.get("file_ids")

        file_ids: list[str] = []
        if isinstance(file_ids_raw, list):
            file_ids = [str(v).strip() for v in file_ids_raw if str(v).strip()]
        elif isinstance(file_ids_raw, str) and file_ids_raw.strip():
            file_ids = [file_ids_raw.strip()]

        if source_url and file_ids:
            return HandlerResult(
                success=False,
                error="Provide either source_url or file_ids, not both",
                summary="Invalid stage source configuration",
            )

        if file_ids:
            if len(file_ids) != 1:
                return HandlerResult(
                    success=False,
                    error="cisco.iosxe.upgrade.stage currently supports exactly one selected file repository file",
                    summary="Invalid file selection",
                )

            selected_file_id = file_ids[0]
            try:
                download_info = await get_file_device_download_url(services, selected_file_id)
            except ValueError as e:
                return HandlerResult(
                    success=False,
                    error=str(e),
                    summary="Failed to resolve file repository file URL",
                )

            source_url = download_info.url
            if not dest_filename:
                dest_filename = download_info.filename

        if not source_url or not dest_filename:
            return HandlerResult(
                success=False,
                error="source_url (or file_ids) and dest_filename are required",
                summary="Missing required parameters",
            )

        dest_fs = ctx.config.get("dest_fs", "flash:")
        transfer_method = ctx.config.get("transfer_method", "auto")
        expected_md5 = ctx.config.get("expected_md5")
        expected_size = ctx.config.get("expected_size")
        overwrite = ctx.config.get("overwrite", False)

        # Get driver for platform
        try:
            driver = get_driver(platform, upgrade_mode)
        except ValueError as e:
            return HandlerResult(
                success=False,
                error=str(e),
                summary=f"Unsupported platform: {platform}",
            )

        async def _process_device(device: dict[str, Any]) -> _DeviceOutcome:
            outcome = _DeviceOutcome()
            device_id = device.get("id", "unknown")
            device_name = device.get("name", device_id)
            outcome.device_id = device_id
            host = device.get("mgmt_host")
            if not host:
                logger.error(f"Stage skipped for {device_name}: missing mgmt_host")
                outcome.failed_device = device_name
                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Stage Error: {device_name}",
                        "device_id": device_id,
                        "content_text": "Error during stage:\nmissing mgmt_host",
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": "missing mgmt_host",
                            "success": False,
                        },
                    }
                )
                return outcome

            await ctx.emit_progress(f"Staging file on {device_name}", device_id)

            try:
                ssh = services.connect(device, platform=platform)
                result = await driver.stage(
                    ssh,
                    source_url=source_url,
                    dest_fs=dest_fs,
                    dest_filename=dest_filename,
                    transfer_method=transfer_method,
                    expected_md5=expected_md5,
                    expected_size=expected_size,
                    overwrite=overwrite,
                )

                if result.success:
                    outcome.ok = True

                    if result.skipped:
                        summary = f"File already staged at {result.full_path}"
                        await ctx.emit_progress(
                            summary,
                            device_id,
                            {"phase": "stage", "status": "skipped"},
                        )
                    else:
                        elapsed = result.transfer_elapsed_sec or 0.0
                        size_mb = (result.transferred_bytes or 0) / (1024 * 1024)
                        rate = size_mb / elapsed if elapsed > 0 else 0.0

                        summary = (
                            f"Transferred {size_mb:.1f} MB in {elapsed:.0f}s ({rate:.1f} MB/s)"
                        )
                        if result.hash_verified:
                            summary += f", {result.hash_type} verified"

                        await ctx.emit_progress(
                            summary,
                            device_id,
                            {"phase": "stage", "status": "success"},
                        )
                else:
                    outcome.failed_device = device_name
                    await ctx.emit_progress(
                        f"Staging failed: {result.error}",
                        device_id,
                        {"phase": "stage", "status": "failed"},
                    )

                # Store output context
                outcome.context = {
                    "staged": result.staged,
                    "skipped": result.skipped,
                    "full_path": result.full_path,
                    "hash_verified": result.hash_verified,
                    "transferred_bytes": result.transferred_bytes,
                }

                # Build evidence with proper structure for artifact saving
                content_lines = [
                    f"Device: {device_name}",
                    f"Platform: {platform}",
                    f"Success: {result.success}",
                ]
                if result.skipped:
                    content_lines.append(f"Skipped: File already exists at {result.full_path}")
                elif result.staged:
                    content_lines.append(f"Staged: {result.full_path}")
                    if result.transferred_bytes:
                        content_lines.append(f"Transferred: {result.transferred_bytes:,} bytes")
                    if result.transfer_method:
                        content_lines.append(f"Method: {result.transfer_method}")
                    if result.transfer_elapsed_sec:
                        content_lines.append(f"Duration: {result.transfer_elapsed_sec:.1f}s")
                    if result.hash_verified:
                        content_lines.append(f"Hash Verified: {result.hash_type}")
                if result.error:
                    content_lines.append(f"Error: {result.error}")
                if result.cli_output:
                    content_lines.append(f"\n--- CLI Output ---\n{result.cli_output}")

                if result.cli_output and not getattr(ssh, "streams_timing_output", False):
                    # Live view: the staging transcript (copy dialog, verify)
                    # reaches the Logs tab — unless the transport already
                    # streamed it live (Phase B sinks set streams_timing_output).
                    await ctx.emit_output(result.cli_output, device=device, command="stage")

                evidence_item = {
                    "kind": "cli_output",
                    "name": f"Stage: {device_name}",
                    "device_id": device_id,
                    "content_text": "\n".join(content_lines),
                    "content_json": {
                        "device_id": device_id,
                        "device_name": device_name,
                        "platform": platform,
                        "success": result.success,
                        "staged": result.staged,
                        "skipped": result.skipped,
                        "full_path": result.full_path,
                        "transferred_bytes": result.transferred_bytes,
                        "transfer_method": result.transfer_method,
                        "transfer_elapsed_sec": result.transfer_elapsed_sec,
                        "hash_verified": result.hash_verified,
                        "hash_type": result.hash_type,
                        "error": result.error,
                    },
                }
                outcome.evidence.append(evidence_item)

            except Exception as e:
                logger.error(f"Stage failed for {device_name}: {e}")
                outcome.ok = False
                outcome.failed_device = device_name

                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Stage Error: {device_name}",
                        "device_id": device_id,
                        "content_text": f"Error during file staging:\n{str(e)}",
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": str(e),
                            "success": False,
                        },
                    }
                )

            return outcome

        outcomes = await for_each_target_device(
            target_devices,
            _process_device,
            max_parallel=max_parallel_from_config(ctx.config),
        )

        # Merge per-device results in device order — deterministic regardless
        # of completion order when devices run in parallel.
        all_evidence = [item for outcome in outcomes for item in outcome.evidence]
        success_count = sum(1 for outcome in outcomes if outcome.ok)
        failure_count = sum(1 for outcome in outcomes if not outcome.ok)
        failed_devices = [
            outcome.failed_device for outcome in outcomes if outcome.failed_device is not None
        ]
        output_context = {
            outcome.device_id: outcome.context
            for outcome in outcomes
            if outcome.context is not None
        }

        # Determine overall success
        overall_success = failure_count == 0

        if overall_success:
            # Count skipped from content_json where the skipped field is stored
            skipped = sum(1 for e in all_evidence if e.get("content_json", {}).get("skipped"))
            summary = f"Staged on {success_count} device(s)"
            if skipped:
                summary += f" ({skipped} already staged)"
        else:
            summary = f"Staging failed on {failure_count} device(s): {', '.join(failed_devices)}"

        return HandlerResult(
            success=overall_success,
            summary=summary,
            evidence=all_evidence,
            metrics={
                "success_count": success_count,
                "failure_count": failure_count,
                "output_context": output_context,
            },
            error=summary if not overall_success else None,
        )
