# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Upgrade Install Handler.

Executes the upgrade installation and triggers device reload.

This handler should run in IMPLEMENTATION phase during the
maintenance window. It will cause device reboot.
"""

import logging
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    DEFAULT_DEVICE_PLATFORM,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)

from ..driver import UpgradeMode, get_driver

logger = logging.getLogger(__name__)


class UpgradeInstallConfig(BaseModel):
    """Config for ``cisco.iosxe.upgrade.install``."""

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
        min_length=1,
        title="Image Filename",
        description="Image filename on device flash",
        json_schema_extra={"x_placeholder": "cat9k_iosxe.17.09.04a.SPA.bin"},
    )
    dest_fs: str = Field(
        default="flash:",
        title="Destination Filesystem",
        json_schema_extra={"x_placeholder": "flash:"},
    )
    activate: bool = Field(
        default=True,
        title="Activate (trigger reload immediately)",
        description="If unchecked, upgrade is staged but not activated",
    )
    commit: bool = Field(
        default=True,
        title="Commit (prevent rollback)",
        description="For install mode: commit to prevent automatic rollback",
        json_schema_extra={"x_show_when": {"field": "upgrade_mode", "value": "install"}},
    )


class UpgradeInstallHandler(BaseHandler):
    """Handler for executing upgrade installation.

    Triggers the device upgrade which causes a reboot.

    For install-mode (IOS-XE):
        Runs 'install add file <image> activate commit'

    For bundle-mode:
        Configures boot system and triggers reload

    Required params:
        platform: Device platform (e.g., "ios-xe")
        image_name: Image filename on device flash

    Optional params:
        upgrade_mode: "install" or "bundle" (default: "install")
        dest_fs: Filesystem where image is staged (default: "flash:")
        activate: Trigger reload immediately (default: true)
        commit: Commit change to prevent rollback (default: true)

    Output context:
        install.reboot_triggered: Whether device is rebooting
        install.activated: Whether upgrade was activated
        install.committed: Whether change was committed

    Note: After this handler completes, the device will be rebooting.
    Use cisco.iosxe.upgrade.verify in a subsequent step after device comes back up.
    """

    handler_id = "cisco.iosxe.upgrade.install"
    default_timeout_seconds = 7200
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "Upgrade: Install"
    description = "Install and activate the staged image (may reload the device)."
    category = "Upgrade"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = UpgradeInstallConfig
    default_config = {
        "upgrade_mode": "install",
        "dest_fs": "flash:",
        "activate": True,
        "commit": True,
    }

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Execute upgrade installation on all target devices."""
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
        if not image_name:
            return HandlerResult(
                success=False,
                error="image_name is required",
                summary="Missing required parameter",
            )

        dest_fs = ctx.config.get("dest_fs", "flash:")
        activate = ctx.config.get("activate", True)
        commit = ctx.config.get("commit", True)

        # Get driver for platform
        try:
            driver = get_driver(platform, upgrade_mode)
        except ValueError as e:
            return HandlerResult(
                success=False,
                error=str(e),
                summary=f"Unsupported platform: {platform}",
            )

        all_evidence: list[dict[str, Any]] = []
        success_count = 0
        failure_count = 0
        failed_devices = []
        output_context = {}

        services = ctx.require_services()
        for device in target_devices:
            device_id = device.get("id", "unknown")
            device_name = device.get("name", device_id)
            host = device.get("mgmt_host")
            if not host:
                logger.error(f"Install skipped for {device_name}: missing mgmt_host")
                failure_count += 1
                failed_devices.append(device_name)
                all_evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Install Error: {device_name}",
                        "device_id": device_id,
                        "content_text": "Error during install:\nmissing mgmt_host",
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": "missing mgmt_host",
                            "success": False,
                        },
                    }
                )
                continue

            await ctx.emit_progress(
                f"Starting upgrade on {device_name}",
                device_id,
                {"phase": "install", "status": "starting"},
            )

            try:
                ssh = services.connect(device, platform=platform)
                await ctx.emit_progress(
                    f"Executing install command on {device_name}",
                    device_id,
                )

                result = await driver.install(
                    ssh,
                    image_name=image_name,
                    dest_fs=dest_fs,
                    activate=activate,
                    commit=commit,
                )

                if result.cli_output:
                    # Live view: surface the install session transcript in the
                    # Logs tab once the (long) timing command returns. True
                    # mid-command streaming needs transport-level support.
                    await ctx.emit_output(result.cli_output, device=device, command="install")

                if result.success:
                    success_count += 1

                    if result.reboot_triggered:
                        summary = "Install completed, device rebooting"
                        await ctx.emit_progress(
                            summary,
                            device_id,
                            {"phase": "install", "status": "rebooting"},
                        )
                    else:
                        summary = "Install configured (reload pending)"
                        await ctx.emit_progress(
                            summary,
                            device_id,
                            {"phase": "install", "status": "configured"},
                        )
                else:
                    failure_count += 1
                    failed_devices.append(device_name)
                    await ctx.emit_progress(
                        f"Install failed: {result.error}",
                        device_id,
                        {"phase": "install", "status": "failed"},
                    )

                # Store output context
                device_context = {
                    "reboot_triggered": result.reboot_triggered,
                    "activated": result.activated,
                    "committed": result.committed,
                }
                output_context[device_id] = device_context

                # Build evidence with proper structure for artifact saving
                content_lines = [
                    f"Device: {device_name}",
                    f"Platform: {platform} ({mode_str} mode)",
                    f"Success: {result.success}",
                    f"Reboot Triggered: {result.reboot_triggered}",
                    f"Activated: {result.activated}",
                    f"Committed: {result.committed}",
                ]
                if result.note:
                    content_lines.append(f"Note: {result.note}")
                if result.error:
                    content_lines.append(f"Error: {result.error}")
                if result.cli_output:
                    content_lines.append(f"\n--- CLI Output ---\n{result.cli_output}")

                evidence_item = {
                    "kind": "cli_output",
                    "name": f"Install: {device_name}",
                    "device_id": device_id,
                    "content_text": "\n".join(content_lines),
                    "content_json": {
                        "device_id": device_id,
                        "device_name": device_name,
                        "platform": platform,
                        "upgrade_mode": mode_str,
                        "success": result.success,
                        "reboot_triggered": result.reboot_triggered,
                        "activated": result.activated,
                        "committed": result.committed,
                        "note": result.note,
                        "error": result.error,
                    },
                }
                all_evidence.append(evidence_item)

            except Exception as e:
                error_str = str(e).lower()
                # Connection loss is expected during reboot
                if "connection" in error_str or "timeout" in error_str or "ssh" in error_str:
                    logger.info(f"Connection lost for {device_name} - expected during reboot")
                    success_count += 1

                    output_context[device_id] = {
                        "reboot_triggered": True,
                        "activated": True,
                    }

                    all_evidence.append(
                        {
                            "kind": "cli_output",
                            "name": f"Install: {device_name}",
                            "device_id": device_id,
                            "content_text": f"Device: {device_name}\nSuccess: True\nReboot Triggered: True\nNote: Connection lost (expected during reboot)",
                            "content_json": {
                                "device_id": device_id,
                                "device_name": device_name,
                                "success": True,
                                "reboot_triggered": True,
                                "note": "Connection lost (expected during reboot)",
                            },
                        }
                    )

                    await ctx.emit_progress(
                        f"Device {device_name} rebooting (connection closed)",
                        device_id,
                        {"phase": "install", "status": "rebooting"},
                    )
                else:
                    logger.error(f"Install failed for {device_name}: {e}")
                    failure_count += 1
                    failed_devices.append(device_name)

                    all_evidence.append(
                        {
                            "kind": "cli_output",
                            "name": f"Install Error: {device_name}",
                            "device_id": device_id,
                            "content_text": f"Error during install:\n{str(e)}",
                            "content_json": {
                                "device_id": device_id,
                                "device_name": device_name,
                                "error": str(e),
                                "success": False,
                            },
                        }
                    )

        # Determine overall success
        overall_success = failure_count == 0

        if overall_success:
            # Count rebooting from content_json where the field is stored
            rebooting = sum(
                1 for e in all_evidence if e.get("content_json", {}).get("reboot_triggered")
            )
            summary = f"Install initiated on {success_count} device(s)"
            if rebooting:
                summary += f" ({rebooting} rebooting)"
        else:
            summary = f"Install failed on {failure_count} device(s): {', '.join(failed_devices)}"

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
