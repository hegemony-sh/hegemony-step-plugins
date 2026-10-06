# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Upgrade Install Handler.

Executes the upgrade installation and triggers device reload.

This handler should run in IMPLEMENTATION phase during the
maintenance window. It will cause device reboot.
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


class UpgradeInstallConfig(BaseModel):
    """Config for ``cisco.iosxe.upgrade.install``."""

    model_config = ConfigDict(extra="allow")

    upgrade_mode: Literal["install", "bundle"] = Field(
        default="install",
        title="Upgrade Mode",
        description=(
            'Which activation workflow to run: install mode uses the "install '
            'add file ... activate commit" command, while bundle mode points '
            "the boot system at the .bin image, saves the configuration, and "
            "reloads. Defaults to install mode; it must match how the device "
            "boots."
        ),
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
        description=(
            "Device filesystem holding the staged image; combined with the "
            'image filename to build the full image path. Defaults to "flash:"; '
            "a trailing colon is added automatically if omitted."
        ),
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
    fix_boot_config: bool = Field(
        default=False,
        title="Fix Boot Setting",
        description=(
            "For install mode: when the boot variable does not point at "
            "packages.conf on the destination filesystem, set it there and "
            'save the configuration with "write memory" before installing. '
            "Saving also stores any other unsaved change. When off (the "
            "default), the device fails instead and nothing is changed."
        ),
        json_schema_extra={"x_show_when": {"field": "upgrade_mode", "value": "install"}},
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Devices upgraded concurrently (1 = sequential)",
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
        fix_boot_config: Install mode: set the boot variable to packages.conf
            and save it instead of failing (default: false)

    Output context:
        install.reboot_triggered: Whether device is rebooting
        install.activated: Whether upgrade was activated
        install.committed: Whether change was committed
        install.boot_config_changed: Whether the step changed the running boot
            setting (not whether it was saved)
        install.previous_boot: Boot entries before the step

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
        "fix_boot_config": False,
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

        # The model requires a non-empty Image Filename.
        try:
            config = self.parse_config(ctx.config, UpgradeInstallConfig)
        except InvalidConfigError as exc:
            return exc.result()
        # Not a setting: only the IOS-XE drivers exist. Kept for steps that name it.
        platform = ctx.config.get("platform", DEFAULT_DEVICE_PLATFORM)
        mode_str = config.upgrade_mode
        upgrade_mode = UpgradeMode.BUNDLE if mode_str == "bundle" else UpgradeMode.INSTALL

        image_name = config.image_name
        dest_fs = config.dest_fs
        activate = config.activate
        commit = config.commit
        fix_boot_config = config.fix_boot_config

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
                logger.error(f"Install skipped for {device_name}: missing mgmt_host")
                outcome.failed_device = device_name
                outcome.evidence.append(
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
                return outcome

            await ctx.emit_progress(
                f"Starting upgrade on {device_name}",
                device_id,
                {"phase": "install", "status": "starting"},
            )

            try:
                ssh = services.connect(device, platform=platform, step_run_id=ctx.step_run_id)
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
                    fix_boot_config=fix_boot_config,
                )

                if result.cli_output and not getattr(ssh, "streams_timing_output", False):
                    # Live view: surface the install session transcript in the
                    # Logs tab once the (long) timing command returns — but only
                    # when the transport didn't already stream it live (Phase B
                    # sinks set streams_timing_output; emitting again would
                    # duplicate the whole transcript).
                    await ctx.emit_output(result.cli_output, device=device, command="install")

                if result.success:
                    outcome.ok = True

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
                    outcome.failed_device = device_name
                    await ctx.emit_progress(
                        f"Install failed: {result.error}",
                        device_id,
                        {"phase": "install", "status": "failed"},
                    )

                # Store output context
                outcome.context = {
                    "reboot_triggered": result.reboot_triggered,
                    "activated": result.activated,
                    "committed": result.committed,
                    "boot_config_changed": result.boot_config_changed,
                    "previous_boot": result.previous_boot,
                }

                # Build evidence with proper structure for artifact saving
                content_lines = [
                    f"Device: {device_name}",
                    f"Platform: {platform} ({mode_str} mode)",
                    f"Success: {result.success}",
                    f"Reboot Triggered: {result.reboot_triggered}",
                    f"Activated: {result.activated}",
                    f"Committed: {result.committed}",
                    f"Boot Config Changed: {result.boot_config_changed}",
                    f"Previous Boot: {';'.join(result.previous_boot) or 'unknown'}",
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
                        "boot_config_changed": result.boot_config_changed,
                        "previous_boot": result.previous_boot,
                        "note": result.note,
                        "error": result.error,
                    },
                }
                outcome.evidence.append(evidence_item)

            except Exception as e:
                # connect() does not dial, and the transports report a dropped
                # session in the command result, so an exception here is a
                # configuration, credentials or driver error - never the reload.
                logger.error(f"Install failed for {device_name}: {e}")
                outcome.ok = False
                outcome.failed_device = device_name

                outcome.evidence.append(
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
        output_context = {
            outcome.device_id: outcome.context
            for outcome in outcomes
            if outcome.context is not None
        }

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
