# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Upgrade Cleanup Handler.

Removes inactive packages/old images after successful upgrade.

This handler should run in CLEANUP phase after verification.
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
    InvalidConfigError,
    StepKind,
    for_each_target_device,
)

from ..driver import UpgradeMode, get_driver

logger = logging.getLogger(__name__)


class UpgradeCleanupConfig(BaseModel):
    """Config for ``cisco.iosxe.upgrade.cleanup``."""

    model_config = ConfigDict(extra="allow")

    upgrade_mode: Literal["install", "bundle"] = Field(
        default="install",
        title="Upgrade Mode",
        description=(
            'Which cleanup workflow to run: install mode uses "install remove '
            'inactive", while bundle mode deletes old .bin images from flash '
            "that the boot configuration no longer references. Defaults to "
            "install mode."
        ),
        json_schema_extra={
            "x_option_labels": {
                "install": "Install Mode (modern IOS-XE)",
                "bundle": "Bundle Mode (legacy ISR)",
            }
        },
    )
    remove_inactive: bool = Field(
        default=True,
        title="Remove inactive packages/old images",
        description='For install mode: runs "install remove inactive"',
    )
    keep_versions: int = Field(
        default=1,
        ge=0,
        le=5,
        title="Versions to Keep",
        description="Number of old versions to keep (for bundle mode)",
        json_schema_extra={"x_show_when": {"field": "upgrade_mode", "value": "bundle"}},
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Devices cleaned concurrently (1 = sequential)",
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
    removed: list[str] = field(default_factory=list)


class UpgradeCleanupHandler(BaseHandler):
    """Handler for post-upgrade cleanup.

    For install-mode:
        Runs 'install remove inactive' to remove old packages

    For bundle-mode:
        Deletes old .bin images from flash

    Required params:
        platform: Device platform (e.g., "ios-xe")

    Optional params:
        upgrade_mode: "install" or "bundle" (default: "install")
        remove_inactive: Whether to remove old packages (default: true)
        keep_versions: Number of old versions to keep (default: 1)

    Output context:
        cleanup.removed_packages: List of removed packages/files
    """

    handler_id = "cisco.iosxe.upgrade.cleanup"
    default_timeout_seconds = 7200
    supported_kinds = [StepKind.ACTION]
    display_name = "Upgrade: Cleanup"
    description = "Remove inactive packages/old images after a successful upgrade."
    category = "Upgrade"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = UpgradeCleanupConfig
    default_config = {"upgrade_mode": "install", "remove_inactive": True, "keep_versions": 1}

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Run cleanup on all target devices."""
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )

        try:
            config = self.parse_config(ctx.config, UpgradeCleanupConfig)
        except InvalidConfigError as exc:
            return exc.result()
        # Not a setting: only the IOS-XE drivers exist. Kept for steps that name it.
        platform = ctx.config.get("platform", DEFAULT_DEVICE_PLATFORM)
        mode_str = config.upgrade_mode
        upgrade_mode = UpgradeMode.BUNDLE if mode_str == "bundle" else UpgradeMode.INSTALL

        remove_inactive = config.remove_inactive
        keep_versions = config.keep_versions

        if not remove_inactive:
            return HandlerResult(
                success=True,
                summary="Cleanup skipped (remove_inactive=false)",
                evidence=[],
            )

        # Get driver for platform
        try:
            driver = get_driver(platform, upgrade_mode)
        except ValueError as e:
            return HandlerResult(
                success=False,
                error=str(e),
                summary=f"Unsupported platform: {platform}",
            )

        services = ctx.require_services()

        async def _process_device(device: dict[str, Any]) -> _DeviceOutcome:
            outcome = _DeviceOutcome()
            device_id = device.get("id", "unknown")
            device_name = device.get("name", device_id)
            outcome.device_id = device_id
            host = device.get("mgmt_host")
            if not host:
                logger.error(f"Cleanup skipped for {device_name}: missing mgmt_host")
                outcome.failed_device = device_name
                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Cleanup Error: {device_name}",
                        "device_id": device_id,
                        "content_text": "Error during cleanup:\nmissing mgmt_host",
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": "missing mgmt_host",
                            "success": False,
                        },
                    }
                )
                return outcome

            await ctx.emit_progress(
                f"Running cleanup on {device_name}",
                device_id,
                {"phase": "cleanup", "status": "running"},
            )

            try:
                ssh = services.connect(device, platform=platform, step_run_id=ctx.step_run_id)
                result = await driver.cleanup(
                    ssh,
                    remove_inactive=remove_inactive,
                    keep_versions=keep_versions,
                )

                if result.success:
                    outcome.ok = True

                    removed = result.removed_packages or []
                    if removed:
                        summary = f"Removed {len(removed)} package(s)/file(s)"
                        outcome.removed = list(removed)
                    else:
                        summary = "No inactive packages to remove"

                    await ctx.emit_progress(
                        summary,
                        device_id,
                        {"phase": "cleanup", "status": "success"},
                    )
                else:
                    outcome.failed_device = device_name
                    await ctx.emit_progress(
                        f"Cleanup failed: {result.error}",
                        device_id,
                        {"phase": "cleanup", "status": "failed"},
                    )

                # Store output context
                outcome.context = {
                    "removed_packages": result.removed_packages or [],
                }

                # Build evidence with proper structure for artifact saving
                removed = result.removed_packages or []
                content_lines = [
                    f"Device: {device_name}",
                    f"Platform: {platform} ({mode_str} mode)",
                    f"Success: {result.success}",
                    f"Packages Removed: {len(removed)}",
                ]
                if removed:
                    content_lines.append("\nRemoved items:")
                    for pkg in removed:
                        content_lines.append(f"  - {pkg}")
                if result.error:
                    content_lines.append(f"Error: {result.error}")
                if result.cli_output:
                    content_lines.append(f"\n--- CLI Output ---\n{result.cli_output}")

                if result.cli_output and not getattr(ssh, "streams_timing_output", False):
                    # Live view: the cleanup transcript ("install remove
                    # inactive") reaches the Logs tab — unless the transport
                    # already streamed it live (Phase B sinks set
                    # streams_timing_output).
                    await ctx.emit_output(result.cli_output, device=device, command="cleanup")

                evidence_item = {
                    "kind": "cli_output",
                    "name": f"Cleanup: {device_name}",
                    "device_id": device_id,
                    "content_text": "\n".join(content_lines),
                    "content_json": {
                        "device_id": device_id,
                        "device_name": device_name,
                        "platform": platform,
                        "upgrade_mode": mode_str,
                        "success": result.success,
                        "removed_packages": result.removed_packages,
                        "error": result.error,
                    },
                }
                outcome.evidence.append(evidence_item)

            except Exception as e:
                logger.error(f"Cleanup failed for {device_name}: {e}")
                outcome.ok = False
                outcome.failed_device = device_name

                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Cleanup Error: {device_name}",
                        "device_id": device_id,
                        "content_text": f"Error during cleanup:\n{str(e)}",
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
            max_parallel=config.max_parallel_devices,
        )

        # Merge per-device results in device order — deterministic regardless
        # of completion order when devices run in parallel.
        all_evidence = [item for outcome in outcomes for item in outcome.evidence]
        success_count = sum(1 for outcome in outcomes if outcome.ok)
        failure_count = sum(1 for outcome in outcomes if not outcome.ok)
        failed_devices = [
            outcome.failed_device for outcome in outcomes if outcome.failed_device is not None
        ]
        total_removed = [item for outcome in outcomes for item in outcome.removed]
        output_context = {
            outcome.device_id: outcome.context
            for outcome in outcomes
            if outcome.context is not None
        }

        # Determine overall success
        overall_success = failure_count == 0

        if overall_success:
            if total_removed:
                summary = f"Cleanup completed on {success_count} device(s), removed {len(total_removed)} item(s)"
            else:
                summary = f"Cleanup completed on {success_count} device(s)"
        else:
            summary = f"Cleanup failed on {failure_count} device(s): {', '.join(failed_devices)}"

        return HandlerResult(
            success=overall_success,
            summary=summary,
            evidence=all_evidence,
            metrics={
                "success_count": success_count,
                "failure_count": failure_count,
                "total_removed": len(total_removed),
                "output_context": output_context,
            },
            error=summary if not overall_success else None,
        )
