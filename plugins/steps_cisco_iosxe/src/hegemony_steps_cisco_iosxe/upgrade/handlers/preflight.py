# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Upgrade Preflight Handler.

Runs pre-upgrade checks:
- Current running version
- Available disk space
- Image already exists
- Install mode supported (IOS-XE)
- Target version already installed

This handler should run in PREPARE phase to validate upgrade readiness.
"""

import logging
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

from ..driver import UpgradeMode, get_driver

logger = logging.getLogger(__name__)


class UpgradePreflightConfig(BaseModel):
    """Config for ``cisco.iosxe.upgrade.preflight``."""

    model_config = ConfigDict(extra="allow")

    upgrade_mode: Literal["install", "bundle"] = Field(
        default="install",
        title="Upgrade Mode",
        json_schema_extra={
            "x_option_labels": {
                "install": "Install Mode (modern IOS-XE)",
                "bundle": "Bundle Mode (legacy ISR)",
            }
        },
    )
    image_name: str = Field(
        default="",
        title="Image Filename (optional)",
        description="Check if image is already staged",
        json_schema_extra={"x_placeholder": "cat9k_iosxe.17.09.04a.SPA.bin"},
    )
    target_version: str = Field(
        default="",
        title="Target Version (optional)",
        description="Expected version after upgrade",
        json_schema_extra={"x_placeholder": "17.09.04a"},
    )
    dest_fs: str = Field(
        default="flash:",
        title="Destination Filesystem",
        json_schema_extra={"x_placeholder": "flash:"},
    )
    min_free_bytes: int = Field(
        default=1073741824,
        ge=100000000,
        title="Min Free Space (bytes)",
        description="Minimum free disk space required (default: 1GB)",
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Devices checked concurrently (1 = sequential)",
    )


class UpgradePreflightHandler(BaseHandler):
    """Handler for upgrade preflight checks.

    Validates that devices are ready for upgrade before proceeding.

    Required params:
        platform: Device platform (e.g., "ios-xe")

    Optional params:
        upgrade_mode: "install" or "bundle" (default: "install")
        image_name: Expected image filename to check if already staged
        target_version: Expected version after upgrade
        dest_fs: Destination filesystem (default: "flash:")
        min_free_bytes: Minimum required free space

    Output context (stored in step_outputs for later steps):
        preflight.current_version: Running version before upgrade
        preflight.free_bytes: Available disk space
        preflight.image_exists: Whether image is already on device
        preflight.install_mode_supported: Whether install mode works
    """

    handler_id = "cisco.iosxe.upgrade.preflight"
    default_timeout_seconds = 7200
    supported_kinds = [StepKind.CHECK]
    display_name = "Upgrade: Preflight"
    description = "Validate devices are ready for upgrade (space, image, install mode)."
    category = "Upgrade"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = UpgradePreflightConfig
    default_config = {"upgrade_mode": "install", "dest_fs": "flash:", "min_free_bytes": 1073741824}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Execute preflight checks on all target devices."""
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

        image_name = ctx.config.get("image_name")
        target_version = ctx.config.get("target_version")
        dest_fs = ctx.config.get("dest_fs", "flash:")
        min_free_bytes = ctx.config.get("min_free_bytes")

        # Get driver for platform
        try:
            driver = get_driver(platform, upgrade_mode)
        except ValueError as e:
            return HandlerResult(
                success=False,
                error=str(e),
                summary=f"Unsupported platform: {platform}",
            )

        all_evidence = []
        success_count = 0
        failure_count = 0
        failed_devices = []
        output_context = {}

        services = ctx.require_services()

        async def _process_device(device: dict[str, Any]) -> None:
            nonlocal success_count, failure_count
            device_id = device.get("id", "unknown")
            device_name = device.get("name", device_id)
            host = device.get("mgmt_host")
            if not host:
                logger.error(f"Preflight skipped for {device_name}: missing mgmt_host")
                failure_count += 1
                failed_devices.append(device_name)
                all_evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Preflight Error: {device_name}",
                        "device_id": device_id,
                        "content_text": "Error during preflight:\nmissing mgmt_host",
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": "missing mgmt_host",
                            "success": False,
                        },
                    }
                )
                return

            await ctx.emit_progress(f"Running preflight checks on {device_name}", device_id)

            try:
                ssh = services.connect(device, platform=platform)
                result = await driver.preflight(
                    ssh,
                    image_name=image_name,
                    dest_fs=dest_fs,
                    min_free_bytes=min_free_bytes,
                    target_version=target_version,
                )

                if result.success:
                    success_count += 1
                    # Always include version in summary
                    summary_parts = [f"Version: {result.current_version or 'unknown'}"]
                    if result.free_bytes:
                        summary_parts.append(f"Free: {result.free_bytes:,} bytes")
                    if result.image_exists:
                        summary_parts.append("Image already staged")
                    if result.target_version_installed:
                        summary_parts.append("Target version already installed")
                    summary = ", ".join(summary_parts)

                    await ctx.emit_progress(
                        f"Preflight passed: {summary}",
                        device_id,
                        {"phase": "preflight", "status": "success"},
                    )
                else:
                    failure_count += 1
                    failed_devices.append(device_name)
                    await ctx.emit_progress(
                        f"Preflight failed: {result.error}",
                        device_id,
                        {"phase": "preflight", "status": "failed"},
                    )

                # Store output context for this device
                device_context = {
                    "current_version": result.current_version,
                    "free_bytes": result.free_bytes,
                    "image_exists": result.image_exists,
                    "install_mode_supported": result.install_mode_supported,
                    "target_version_installed": result.target_version_installed,
                }
                output_context[device_id] = device_context

                # Build evidence with proper structure for artifact saving
                # Build human-readable summary
                content_lines = [
                    f"Device: {device_name}",
                    f"Platform: {platform} ({mode_str} mode)",
                    f"Current Version: {result.current_version or 'unknown'}",
                    f"Free Space: {result.free_bytes:,} bytes"
                    if result.free_bytes
                    else "Free Space: unknown",
                    f"Image Exists: {result.image_exists}",
                    f"Install Mode Supported: {result.install_mode_supported}",
                    f"Target Version Installed: {result.target_version_installed}",
                ]
                if result.error:
                    content_lines.append(f"Error: {result.error}")
                if result.warnings:
                    content_lines.append(f"Warnings: {', '.join(result.warnings)}")
                if result.cli_outputs:
                    content_lines.append("\n--- CLI Outputs ---")
                    for cmd, output in result.cli_outputs.items():
                        content_lines.append(f"\n> {cmd}\n{output}")
                        if output:
                            # Live view: preflight command outputs reach the
                            # Logs tab (show commands — never streamed by the
                            # transport, so no dedup guard needed).
                            await ctx.emit_output(output, device=device, command=cmd)

                evidence_item = {
                    "kind": "cli_output",
                    "name": f"Preflight: {device_name}",
                    "device_id": device_id,
                    "content_text": "\n".join(content_lines),
                    "content_json": {
                        "device_id": device_id,
                        "device_name": device_name,
                        "platform": platform,
                        "upgrade_mode": mode_str,
                        "success": result.success,
                        "current_version": result.current_version,
                        "free_bytes": result.free_bytes,
                        "image_exists": result.image_exists,
                        "install_mode_supported": result.install_mode_supported,
                        "target_version_installed": result.target_version_installed,
                        "error": result.error,
                        "warnings": result.warnings,
                    },
                }
                all_evidence.append(evidence_item)

            except Exception as e:
                logger.error(f"Preflight failed for {device_name}: {e}")
                failure_count += 1
                failed_devices.append(device_name)

                all_evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Preflight Error: {device_name}",
                        "device_id": device_id,
                        "content_text": f"Error during preflight check:\n{str(e)}",
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": str(e),
                            "success": False,
                        },
                    }
                )

        await for_each_target_device(
            target_devices,
            _process_device,
            max_parallel=max_parallel_from_config(ctx.config),
        )

        # Determine overall success
        overall_success = failure_count == 0

        if overall_success:
            summary = f"Preflight passed on {success_count} device(s)"
        else:
            summary = f"Preflight failed on {failure_count} device(s): {', '.join(failed_devices)}"

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
