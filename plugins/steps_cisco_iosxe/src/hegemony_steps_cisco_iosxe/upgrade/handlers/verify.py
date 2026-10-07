# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Upgrade Verify Handler.

Verifies upgrade was successful after device reboot.

This handler should run in VERIFY phase after the device
has rebooted and is accessible again.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

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


class UpgradeVerifyConfig(BaseModel):
    """Config for ``cisco.iosxe.upgrade.verify``."""

    model_config = ConfigDict(extra="allow")

    upgrade_mode: Literal["install", "bundle"] = Field(
        default="install",
        title="Upgrade Mode",
        description=(
            "Which verification workflow to run: install mode additionally "
            'checks commit status with "show install summary" and can '
            "auto-commit, while bundle mode checks the running version and boot "
            "configuration only. Defaults to install mode."
        ),
        json_schema_extra={
            "x_option_labels": {
                "install": "Install Mode (modern IOS-XE)",
                "bundle": "Bundle Mode (legacy ISR)",
            }
        },
    )
    target_version: str = Field(
        default="",
        title="Target Version",
        description=(
            "Expected version after upgrade, compared as a release: 17.9.4a "
            "matches 17.09.04a, but 17.09.04 does not"
        ),
        json_schema_extra={"x_placeholder": "17.09.04a"},
    )
    preflight_version: str = Field(
        default="",
        title="Pre-upgrade Version (optional)",
        description=(
            "Version the devices ran before the upgrade, for example from the "
            "preflight step's output. A device still running it fails: the "
            "upgrade did not change its version. Empty skips this check."
        ),
        json_schema_extra={"x_placeholder": "17.06.05"},
    )
    max_wait_seconds: int = Field(
        default=600,
        ge=60,
        title="Max Wait (sec)",
        description="Max time to wait for device to come back online",
    )
    poll_interval_seconds: int = Field(
        default=30,
        ge=5,
        # Steps saved before the rename carry retry_interval.
        validation_alias=AliasChoices("poll_interval_seconds", "retry_interval"),
        title="Poll Interval (sec)",
        description="Seconds between reconnect attempts",
        json_schema_extra={"x_legacy_keys": ["retry_interval"]},
    )
    auto_commit: bool = Field(
        default=True,
        title="Auto-commit if not committed",
        description='For install mode: run "install commit" if needed',
        json_schema_extra={
            "x_show_when": {"field": "upgrade_mode", "value": "install"},
            "x_col_span": 2,
        },
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Devices verified concurrently (1 = sequential)",
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


class UpgradeVerifyHandler(BaseHandler):
    """Handler for post-upgrade verification.

    Verifies that:
    - Device is accessible after reboot
    - Version matches expected target
    - Version changed from pre-upgrade
    - Software is committed (install mode)

    Required params:
        platform: Device platform (e.g., "ios-xe")

    Optional params:
        upgrade_mode: "install" or "bundle" (default: "install")
        target_version: Expected version after upgrade
        preflight_version: Version from preflight (to confirm change)
        auto_commit: Run 'install commit' if not committed (default: true)
        max_wait_seconds: Max time to wait for device (default: 600)
        poll_interval_seconds: Seconds between reconnect attempts (default: 30)

    Output context:
        verify.current_version: Running version after upgrade
        verify.version_match: Whether version matches target
        verify.committed: Whether upgrade is committed
    """

    handler_id = "cisco.iosxe.upgrade.verify"
    default_timeout_seconds = 7200
    supported_kinds = [StepKind.CHECK]
    display_name = "Upgrade: Verify"
    description = "Wait for the device to return and verify the running version."
    category = "Upgrade"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = UpgradeVerifyConfig
    default_config = {
        "upgrade_mode": "install",
        "max_wait_seconds": 600,
        "poll_interval_seconds": 30,
    }
    # No run_timeout_field: Max Wait applies to each device in turn, and each
    # then still runs its checks and may commit, so it bounds no whole step.

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Verify upgrade on all target devices."""
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )

        try:
            config = self.parse_config(ctx.config, UpgradeVerifyConfig)
        except InvalidConfigError as exc:
            return exc.result()
        # Not a setting: only the IOS-XE drivers exist. Kept for steps that name it.
        platform = ctx.config.get("platform", DEFAULT_DEVICE_PLATFORM)
        upgrade_mode = (
            UpgradeMode.BUNDLE if config.upgrade_mode == "bundle" else UpgradeMode.INSTALL
        )

        target_version = config.target_version or None
        preflight_version = config.preflight_version or None
        auto_commit = config.auto_commit
        max_wait_seconds = config.max_wait_seconds
        retry_interval = config.poll_interval_seconds

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
                logger.error(f"Verify skipped for {device_name}: missing mgmt_host")
                outcome.failed_device = device_name
                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Verify Error: {device_name}",
                        "device_id": device_id,
                        "content_text": "Error during verify:\nmissing mgmt_host",
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
                f"Waiting for {device_name} to come back online",
                device_id,
                {"phase": "verify", "status": "waiting"},
            )

            try:
                # Wait for device to come back online by attempting a simple command
                start_time = asyncio.get_event_loop().time()
                last_error = None
                attempts = 0

                while True:
                    elapsed = asyncio.get_event_loop().time() - start_time
                    if elapsed > max_wait_seconds:
                        raise TimeoutError(
                            f"Device did not come back online within {max_wait_seconds}s. "
                            f"Last error: {last_error}"
                        )

                    attempts += 1
                    try:
                        # Create transport and test with a simple command
                        ssh = services.connect(
                            device, platform=platform, step_run_id=ctx.step_run_id
                        )
                        # Test connectivity with a simple command
                        test_result = await ssh.execute_command("show clock")
                        if test_result.exit_code == 0:
                            await ctx.emit_progress(
                                f"Connected to {device_name} after {elapsed:.0f}s ({attempts} attempts)",
                                device_id,
                            )
                            break
                        else:
                            raise Exception(f"Command failed: {test_result.error}")

                    except Exception as e:
                        last_error = str(e)
                        logger.debug(f"Reconnect attempt {attempts} failed for {device_name}: {e}")
                        await asyncio.sleep(retry_interval)

                # Run verification (create fresh transport for verification commands)
                ssh = services.connect(device, platform=platform, step_run_id=ctx.step_run_id)
                result = await driver.verify(
                    ssh,
                    target_version=target_version,
                    preflight_version=preflight_version,
                    auto_commit=auto_commit,
                )

                if result.success:
                    outcome.ok = True

                    summary = f"Version: {result.current_version}"
                    if result.version_match:
                        summary += " (matches target)"
                    if result.committed:
                        summary += ", committed"

                    await ctx.emit_progress(
                        f"Verification passed: {summary}",
                        device_id,
                        {"phase": "verify", "status": "success"},
                    )
                else:
                    outcome.failed_device = device_name
                    await ctx.emit_progress(
                        f"Verification failed: {result.error}",
                        device_id,
                        {"phase": "verify", "status": "failed"},
                    )

                # Store output context
                outcome.context = {
                    "current_version": result.current_version,
                    "version_match": result.version_match,
                    "version_changed": result.version_changed,
                    "committed": result.committed,
                }

                # Build evidence with proper structure for artifact saving
                content_lines = [
                    f"Device: {device_name}",
                    f"Platform: {platform} ({config.upgrade_mode} mode)",
                    f"Success: {result.success}",
                    f"Current Version: {result.current_version}",
                    f"Version Match: {result.version_match}",
                    f"Version Changed: {result.version_changed}",
                    f"Committed: {result.committed}",
                    f"Reconnect Attempts: {attempts}",
                    f"Reconnect Time: {elapsed:.1f}s",
                ]
                if result.error:
                    content_lines.append(f"Error: {result.error}")
                if result.cli_outputs:
                    content_lines.append("\n--- CLI Outputs ---")
                    for cmd, output in result.cli_outputs.items():
                        content_lines.append(f"\n> {cmd}\n{output}")
                        if output:
                            # Live view: verification command outputs reach the
                            # Logs tab (show commands — never streamed by the
                            # transport, so no dedup guard needed).
                            await ctx.emit_output(output, device=device, command=cmd)

                evidence_item = {
                    "kind": "cli_output",
                    "name": f"Verify: {device_name}",
                    "device_id": device_id,
                    "content_text": "\n".join(content_lines),
                    "content_json": {
                        "device_id": device_id,
                        "device_name": device_name,
                        "platform": platform,
                        "upgrade_mode": config.upgrade_mode,
                        "success": result.success,
                        "current_version": result.current_version,
                        "version_match": result.version_match,
                        "version_changed": result.version_changed,
                        "committed": result.committed,
                        "reconnect_attempts": attempts,
                        "reconnect_elapsed_sec": elapsed,
                        "error": result.error,
                    },
                }
                outcome.evidence.append(evidence_item)

            except TimeoutError as e:
                logger.error(f"Verification timeout for {device_name}: {e}")
                outcome.ok = False
                outcome.failed_device = device_name

                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Verify Timeout: {device_name}",
                        "device_id": device_id,
                        "content_text": f"Device: {device_name}\nError: Timeout waiting for device\nMax Wait: {max_wait_seconds}s\n\n{str(e)}",
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "error": str(e),
                            "max_wait_seconds": max_wait_seconds,
                            "success": False,
                        },
                    }
                )

                await ctx.emit_progress(
                    "Verification timeout: device did not come back online",
                    device_id,
                    {"phase": "verify", "status": "timeout"},
                )

            except Exception as e:
                logger.error(f"Verification failed for {device_name}: {e}")
                outcome.ok = False
                outcome.failed_device = device_name

                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Verify Error: {device_name}",
                        "device_id": device_id,
                        "content_text": f"Error during verification:\n{str(e)}",
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
            summary = f"Upgrade verified on {success_count} device(s)"
        else:
            summary = (
                f"Verification failed on {failure_count} device(s): {', '.join(failed_devices)}"
            )

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
