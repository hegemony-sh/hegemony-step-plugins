# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Cisco IOS-XE Install-Mode upgrade driver.

This driver supports modern IOS-XE devices that use install mode:
- Catalyst 3K/9K switches
- ISR 4K routers (16.x and later)
- ASR 1K routers

Install mode uses the 'install add file ... activate commit' command
which handles package extraction, activation, and commit in one step.
The device boots from packages.conf which references individual packages.

Key characteristics:
- Uses 'install add file <fs><image> activate commit'
- Boot system must point to packages.conf
- Supports 'install remove inactive' for cleanup
- Auto-rollback if not committed within timer (usually 6 hours)
"""

import asyncio
import logging
import re

from hegemony_step_sdk import Transport

from ..driver import (
    CleanupResult,
    InstallResult,
    PreflightResult,
    StageResult,
    TransferCapabilities,
    UpgradeDriver,
    UpgradeMode,
    VerifyResult,
    register_driver,
)
from .iosxe_common import (
    check_file_exists_in_dir,
    normalize_filesystem,
    parse_free_bytes,
    parse_version_from_show_version,
    stage_image,
)

logger = logging.getLogger(__name__)


@register_driver("ios-xe", UpgradeMode.INSTALL)
class IOSXEInstallDriver(UpgradeDriver):
    """IOS-XE install-mode upgrade driver.

    Uses the modern install command workflow:
    1. Preflight: Check version, disk space, install mode support
    2. Stage: Transfer image via HTTP or SCP, verify with MD5
    3. Install: 'install add file ... activate commit' (triggers reboot)
    4. Verify: Check version, commit status after reboot
    5. Cleanup: 'install remove inactive' to reclaim space
    """

    platform = "ios-xe"
    display_name = "Cisco IOS-XE (Install Mode)"
    default_fs = "flash:"
    upgrade_mode = UpgradeMode.INSTALL
    transfer_capabilities = TransferCapabilities(
        http=True,
        https=True,
        scp=True,
        # No TFTP implementation exists anywhere in the stage path.
        tftp=False,
    )

    async def preflight(
        self,
        ssh: Transport,
        *,
        image_name: str | None = None,
        dest_fs: str | None = None,
        min_free_bytes: int | None = None,
        target_version: str | None = None,
    ) -> PreflightResult:
        """Run preflight checks for IOS-XE install-mode upgrade.

        Checks:
        - Current running version
        - Disk space availability
        - Image already exists
        - Install mode supported (show install summary works)
        - Target version already installed
        """
        dest_fs = normalize_filesystem(dest_fs or self.default_fs)
        cli_outputs: dict[str, str] = {}
        errors: list[str] = []
        warnings: list[str] = []

        try:
            # Get current version
            version_result = await ssh.execute_commands(["show version"])
            version_output = version_result[0].output if version_result else ""
            cli_outputs["show version"] = version_output
            current_version = parse_version_from_show_version(version_output)

            # Small delay between commands
            await asyncio.sleep(0.1)

            # Check disk space
            dir_result = await ssh.execute_commands([f"dir {dest_fs}"])
            dir_output = dir_result[0].output if dir_result else ""
            cli_outputs[f"dir {dest_fs}"] = dir_output
            free_bytes = parse_free_bytes(dir_output)

            await asyncio.sleep(0.1)

            # Check if image exists
            image_exists = None
            if image_name:
                image_exists = check_file_exists_in_dir(dir_output, image_name)
                logger.info("Preflight: image_name=%s, image_exists=%s", image_name, image_exists)

            # Verify disk space (only if image doesn't already exist)
            if (
                min_free_bytes
                and free_bytes is not None
                and free_bytes < min_free_bytes
                and not image_exists
            ):
                errors.append(
                    f"Insufficient disk space: {free_bytes:,} bytes free, "
                    f"need {min_free_bytes:,} bytes"
                )
            elif (
                min_free_bytes
                and free_bytes is not None
                and free_bytes < min_free_bytes
                and image_exists
            ):
                # Image exists, so we don't need additional space - just warn
                warnings.append(
                    f"Low disk space ({free_bytes:,} bytes free) but image already staged"
                )

            # Check install mode support via "show install summary"
            install_mode_supported = False
            target_version_installed = False

            try:
                install_result = await ssh.execute_commands(["show install summary"])
                if install_result:
                    result = install_result[0]
                    cli_outputs["show install summary"] = result.output

                    if result.exit_code == 0 and result.error is None:
                        install_mode_supported = True

                        # Check if target version is already committed
                        if target_version:
                            committed_pattern = rf"\bC\s+{re.escape(target_version)}"
                            if re.search(committed_pattern, result.output):
                                target_version_installed = True
                                logger.info("Target version %s already committed", target_version)
                    else:
                        logger.warning(
                            "Install mode not supported: %s",
                            result.error or "unknown error",
                        )
            except Exception as e:
                logger.warning("Failed to check install mode: %s", e)

            if not install_mode_supported:
                errors.append(
                    "Device does not support install mode (show install summary failed). "
                    "Consider using bundle-mode upgrade instead."
                )

            # Check if running config is saved
            config_saved = True  # Assume saved, could add check if needed

            success = len(errors) == 0

            return PreflightResult(
                success=success,
                current_version=current_version,
                free_bytes=free_bytes,
                filesystem=dest_fs,
                image_exists=image_exists,
                target_version_installed=target_version_installed,
                install_mode_supported=install_mode_supported,
                config_saved=config_saved,
                error="; ".join(errors) if errors else None,
                warnings=warnings,
                cli_outputs=cli_outputs,
            )

        except Exception as e:
            logger.exception("IOS-XE preflight failed")
            return PreflightResult(
                success=False,
                error=str(e),
                cli_outputs=cli_outputs,
            )

    async def stage(
        self,
        ssh: Transport,
        *,
        source_url: str,
        dest_fs: str,
        dest_filename: str,
        transfer_method: str = "auto",
        expected_md5: str | None = None,
        expected_size: int | None = None,
        overwrite: bool = False,
    ) -> StageResult:
        """Stage image to IOS-XE device.

        Transfers the image and verifies integrity.
        Skips transfer if image already exists and is verified.
        """
        return await stage_image(
            ssh,
            source_url=source_url,
            dest_fs=dest_fs,
            dest_filename=dest_filename,
            transfer_method=transfer_method,
            expected_md5=expected_md5,
            expected_size=expected_size,
            overwrite=overwrite,
            select_transfer_method_fn=self.select_transfer_method,
        )

    async def install(
        self,
        ssh: Transport,
        *,
        image_name: str,
        dest_fs: str,
        activate: bool = True,
        commit: bool = True,
    ) -> InstallResult:
        """Execute IOS-XE install command.

        Uses: install add file <fs><image> activate commit
        This triggers an automatic reboot.
        """
        dest_fs = normalize_filesystem(dest_fs)

        # Ensure boot system is set to packages.conf
        try:
            boot_result = await ssh.execute_commands(["show boot"])
            boot_output = boot_result[0].output if boot_result else ""

            if "packages.conf" not in boot_output.lower():
                logger.warning("Reconfiguring boot system to packages.conf")
                config_commands = [
                    "configure terminal",
                    "no boot system",
                    "boot system flash:packages.conf",
                    "end",
                    "write memory",
                ]
                await ssh.execute_commands(config_commands)
                logger.info("Boot system configured")
        except Exception as e:
            logger.warning("Failed to verify/set boot system: %s", e)

        # Build install command
        install_cmd = f"install add file {dest_fs}{image_name}"
        if activate:
            install_cmd += " activate"
        if commit:
            install_cmd += " commit"

        prompts = {
            "Please confirm you have changed boot config to flash:packages.conf": "y",
            "This operation requires a reload": "y",
            "This operation may require a reload": "y",
            "Do you want to proceed": "y",
            "Proceed with install": "y",
            "[y/n]": "y",
            "[yes/no]": "yes",
        }

        completion_patterns = [
            "install_add_activate_commit: SUCCESS",
            "install_add_activate_commit: FAILED",
            "SUCCESS: install_",
            "FAILED: install_",
            "Install will reload the system now",
            "INSTALL-5-INSTALL_COMPLETED_INFO",
            "Reload requested",
            "% Invalid input",
            "%Error",
        ]

        try:
            logger.info("Executing: %s", install_cmd)

            result = await ssh.execute_command_timing(
                install_cmd,
                read_timeout=1800,  # 30 minutes
                delay_factor=2,
                answers=prompts,
                wait_for_patterns=completion_patterns,
            )

            output = result.output

            # Check for reboot
            reboot_patterns = [
                "reload",
                "reboot",
                "restarting",
                "disconnecting",
                "connection closed",
                "SUCCESS: install_activate",
            ]
            reboot_triggered = any(p.lower() in output.lower() for p in reboot_patterns)

            # Check for "already at target version" scenario
            # When device already has the target image active, install command returns
            # "Same Image File-No Change" and then FAILED because there's nothing to activate
            already_at_target = (
                "Same Image File-No Change" in output
                or "Nothing to activate" in output
                or "No package is added or removed" in output
            )

            if already_at_target:
                logger.info("Device already at target version - install not needed")
                return InstallResult(
                    success=True,
                    reboot_triggered=False,
                    activated=False,
                    committed=True,  # Already committed since it's the active version
                    cli_output=output,
                    note="Already at target version - no action needed",
                )

            # Check for errors
            error_patterns = [
                r"FAILED:\s*install_",
                r"FAILED:\s*\[",
                r"\bInstall failed\b",
                r"\bCannot activate\b",
                r"\bCannot install\b",
                r"\bAborted\b",
                r"Failed to expand",
            ]
            has_error = any(re.search(p, output, re.IGNORECASE) for p in error_patterns)

            if has_error:
                return InstallResult(
                    success=False,
                    reboot_triggered=reboot_triggered,
                    error="Install command indicated failure",
                    cli_output=output,
                )

            return InstallResult(
                success=True,
                reboot_triggered=reboot_triggered,
                activated=activate,
                committed=commit,
                cli_output=output,
            )

        except Exception as e:
            error_str = str(e).lower()
            if "connection" in error_str or "timeout" in error_str or "ssh" in error_str:
                logger.info("Connection lost after install - likely rebooting")
                return InstallResult(
                    success=True,
                    reboot_triggered=True,
                    activated=activate,
                    cli_output=f"Connection lost (expected during reboot): {e}",
                )

            logger.exception("IOS-XE install failed")
            return InstallResult(
                success=False,
                error=str(e),
            )

    async def verify(
        self,
        ssh: Transport,
        *,
        target_version: str | None = None,
        preflight_version: str | None = None,
        auto_commit: bool = True,
    ) -> VerifyResult:
        """Verify IOS-XE upgrade was successful.

        Checks:
        - Running version changed from preflight
        - Running version matches target (if specified)
        - Software is committed (won't auto-rollback)
        """
        cli_outputs: dict[str, str] = {}

        try:
            # Get current version
            version_result = await ssh.execute_commands(["show version"])
            version_output = version_result[0].output if version_result else ""
            cli_outputs["show version"] = version_output
            current_version = parse_version_from_show_version(version_output)

            # Check version match
            version_match = False
            if target_version:
                version_match = target_version.lower() in current_version.lower()

            # Check version changed
            version_changed = True
            if preflight_version and preflight_version.lower() in current_version.lower():
                logger.error(
                    "Upgrade FAILED: version unchanged (before: '%s', after: '%s')",
                    preflight_version,
                    current_version,
                )
                return VerifyResult(
                    success=False,
                    current_version=current_version,
                    version_match=False,
                    version_changed=False,
                    committed=False,
                    error=f"Version unchanged: still running {current_version}",
                    cli_outputs=cli_outputs,
                )

            # Check commit status
            committed = False
            try:
                summary_result = await ssh.execute_commands(["show install summary"])
                if summary_result and summary_result[0].exit_code == 0:
                    summary_output = summary_result[0].output
                    cli_outputs["show install summary"] = summary_output

                    if re.search(r"\bC\s+\d+\.\d+", summary_output):
                        committed = True
                        logger.info("New version is committed")
                    elif auto_commit:
                        logger.warning("Version not committed, running 'install commit'")
                        commit_result = await ssh.execute_command_timing(
                            "install commit",
                            read_timeout=120,
                            answers={"[y/n]": "y", "Do you want to proceed": "y"},
                        )
                        cli_outputs["install commit"] = commit_result.output

                        await asyncio.sleep(5)
                        summary_result2 = await ssh.execute_commands(["show install summary"])
                        if summary_result2 and summary_result2[0].exit_code == 0:
                            cli_outputs["show install summary (after commit)"] = summary_result2[
                                0
                            ].output
                            if re.search(r"\bC\s+\d+\.\d+", summary_result2[0].output):
                                committed = True
                                logger.info("Successfully committed")
            except Exception as e:
                logger.warning("Failed to check/run commit: %s", e)

            success = version_changed and (not target_version or version_match) and committed

            return VerifyResult(
                success=success,
                current_version=current_version,
                version_match=version_match,
                version_changed=version_changed,
                committed=committed,
                cli_outputs=cli_outputs,
            )

        except Exception as e:
            logger.exception("IOS-XE verify failed")
            return VerifyResult(
                success=False,
                error=str(e),
                cli_outputs=cli_outputs,
            )

    async def cleanup(
        self,
        ssh: Transport,
        *,
        remove_inactive: bool = True,
        keep_versions: int = 1,
    ) -> CleanupResult:
        """Remove inactive IOS-XE packages.

        Uses: install remove inactive
        """
        if not remove_inactive:
            return CleanupResult(success=True)

        try:
            prompts = {
                "Do you want to remove": "y",
                "Proceed": "y",
                "[y/n]": "y",
            }

            result = await ssh.execute_command_timing(
                "install remove inactive",
                read_timeout=300,
                answers=prompts,
            )

            output = result.output

            removed = []
            for line in output.split("\n"):
                if "Removing" in line or "removed" in line.lower():
                    removed.append(line.strip())

            success = "ERROR" not in output.upper() and "FAILED" not in output.upper()

            return CleanupResult(
                success=success,
                removed_packages=removed,
                cli_output=output,
            )

        except Exception as e:
            logger.exception("IOS-XE cleanup failed")
            return CleanupResult(
                success=False,
                error=str(e),
            )
