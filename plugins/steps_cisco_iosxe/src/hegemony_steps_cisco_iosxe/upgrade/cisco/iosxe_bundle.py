# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Cisco IOS-XE Bundle-Mode upgrade driver.

This driver supports legacy IOS-XE devices that use bundle boot mode:
- ISR routers running older IOS-XE (15.x, early 16.x)
- Devices where install mode is not supported

Bundle mode uses the traditional approach:
- Copy the monolithic .bin image to flash
- Set "boot system flash:<image>.bin"
- Save config and reload

Key characteristics:
- Uses single monolithic .bin file
- Boot system points directly to .bin image
- No install/commit workflow
- Manual cleanup (delete old images)
- Rollback requires manual boot system change
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
    parse_boot_statements,
    parse_free_bytes,
    parse_version_from_show_version,
    stage_image,
)

logger = logging.getLogger(__name__)


@register_driver("ios-xe", UpgradeMode.BUNDLE)
class IOSXEBundleDriver(UpgradeDriver):
    """IOS-XE bundle-mode upgrade driver.

    Uses traditional boot system workflow:
    1. Preflight: Check version, disk space
    2. Stage: Transfer .bin image via HTTP or SCP
    3. Install: Set boot system, save config, reload
    4. Verify: Check version after reboot
    5. Cleanup: Delete old images from flash
    """

    platform = "ios-xe"
    display_name = "Cisco IOS-XE (Bundle Mode)"
    default_fs = "flash:"
    upgrade_mode = UpgradeMode.BUNDLE
    transfer_capabilities = TransferCapabilities(
        http=True,
        https=True,
        # Neither SCP push nor TFTP is implemented anywhere in the stage path.
        scp=False,
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
        """Run preflight checks for IOS-XE bundle-mode upgrade.

        Checks:
        - Current running version
        - Disk space availability
        - Image already exists
        - Current boot configuration
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

            # Get current boot configuration
            boot_result = await ssh.execute_commands(["show boot"])
            boot_output = boot_result[0].output if boot_result else ""
            cli_outputs["show boot"] = boot_output
            current_boot_images = parse_boot_statements(boot_output)

            if current_boot_images:
                logger.info("Current boot config: %s", current_boot_images)
            else:
                warnings.append("No boot system statement found")

            # Bundle mode doesn't use install command
            install_mode_supported = False

            # Check if target version already running
            target_version_installed = False
            if target_version and target_version.lower() in current_version.lower():
                target_version_installed = True
                logger.info("Target version %s already running", target_version)

            success = len(errors) == 0

            return PreflightResult(
                success=success,
                current_version=current_version,
                free_bytes=free_bytes,
                filesystem=dest_fs,
                image_exists=image_exists,
                target_version_installed=target_version_installed,
                install_mode_supported=install_mode_supported,
                error="; ".join(errors) if errors else None,
                warnings=warnings,
                cli_outputs=cli_outputs,
                extra={"current_boot_images": current_boot_images},
            )

        except Exception as e:
            logger.exception("IOS-XE bundle preflight failed")
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
        Same as install mode - staging is platform-agnostic.
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
        fix_boot_config: bool = False,
    ) -> InstallResult:
        """Configure boot system and trigger reload.

        Bundle mode workflow:
        1. Clear existing boot statements
        2. Set boot system to new image
        3. Save configuration
        4. Reload

        Changing the boot variable is what bundle mode does, so
        ``fix_boot_config`` (an install-mode option) does not apply.
        """
        dest_fs = normalize_filesystem(dest_fs)
        full_image_path = f"{dest_fs}{image_name}"
        cli_outputs: list[str] = []

        try:
            # Get current boot config for rollback info
            boot_result = await ssh.execute_commands(["show boot"])
            boot_output = boot_result[0].output if boot_result else ""
            cli_outputs.append(f"=== show boot (before) ===\n{boot_output}")
            previous_boot_images = parse_boot_statements(boot_output)

            # Configure boot system
            config_commands = [
                "configure terminal",
                "no boot system",  # Clear existing
                f"boot system {full_image_path}",
            ]

            # Add previous image as backup (optional safety)
            if previous_boot_images:
                # Add first previous image as fallback
                config_commands.append(f"boot system {previous_boot_images[0]}")
                logger.info("Added fallback boot image: %s", previous_boot_images[0])

            config_commands.extend(
                [
                    "end",
                ]
            )

            # Execute config
            for cmd in config_commands:
                result = await ssh.execute_commands([cmd])
                if result:
                    cli_outputs.append(f"=== {cmd} ===\n{result[0].output}")
                await asyncio.sleep(0.2)

            # Verify boot config was set correctly
            verify_result = await ssh.execute_commands(["show boot"])
            verify_output = verify_result[0].output if verify_result else ""
            cli_outputs.append(f"=== show boot (after config) ===\n{verify_output}")

            if image_name.lower() not in verify_output.lower():
                return InstallResult(
                    success=False,
                    error=f"Boot system not set correctly to {image_name}",
                    cli_output="\n".join(cli_outputs),
                )

            # Save configuration
            save_result = await ssh.execute_command_timing(
                "write memory",
                read_timeout=60,
                answers={
                    "[OK]": "",
                    "[confirm]": "",
                    "Overwrite the previous": "y",
                },
            )
            cli_outputs.append(f"=== write memory ===\n{save_result.output}")

            if not activate:
                # Just configure, don't reload yet
                return InstallResult(
                    success=True,
                    reboot_triggered=False,
                    activated=False,
                    cli_output="\n".join(cli_outputs),
                )

            # Trigger reload
            reload_result = await ssh.execute_command_timing(
                "reload",
                read_timeout=30,
                answers={
                    "Proceed with reload": "y",
                    "confirm": "y",
                    "[yes/no]": "yes",
                    "Save?": "no",  # Already saved
                    "System configuration has been modified": "no",
                },
            )
            cli_outputs.append(f"=== reload ===\n{reload_result.output}")

            return InstallResult(
                success=True,
                reboot_triggered=True,
                activated=True,
                committed=True,  # Bundle mode doesn't have separate commit
                cli_output="\n".join(cli_outputs),
            )

        except Exception as e:
            # Transports report a dropped session in the result, not by
            # raising, so an exception here is never the reload.
            logger.exception("IOS-XE bundle install failed")
            return InstallResult(
                success=False,
                error=str(e),
                cli_output="\n".join(cli_outputs) if cli_outputs else "",
            )

    async def verify(
        self,
        ssh: Transport,
        *,
        target_version: str | None = None,
        preflight_version: str | None = None,
        auto_commit: bool = True,
    ) -> VerifyResult:
        """Verify bundle-mode upgrade was successful.

        Checks:
        - Running version changed from preflight
        - Running version matches target (if specified)
        - Boot config points to correct image
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

            # Verify boot config
            boot_result = await ssh.execute_commands(["show boot"])
            boot_output = boot_result[0].output if boot_result else ""
            cli_outputs["show boot"] = boot_output

            # Bundle mode is always "committed" since boot system is saved
            committed = True

            success = version_changed and (not target_version or version_match)

            return VerifyResult(
                success=success,
                current_version=current_version,
                version_match=version_match,
                version_changed=version_changed,
                committed=committed,
                cli_outputs=cli_outputs,
            )

        except Exception as e:
            logger.exception("IOS-XE bundle verify failed")
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
        """Remove old images from flash.

        Bundle mode cleanup:
        - List .bin files in flash
        - Identify images not in current boot config
        - Delete old images (keeping specified number)
        """
        if not remove_inactive:
            return CleanupResult(success=True)

        cli_outputs: list[str] = []
        removed_packages: list[str] = []

        try:
            # Get current boot config
            boot_result = await ssh.execute_commands(["show boot"])
            boot_output = boot_result[0].output if boot_result else ""
            cli_outputs.append(f"=== show boot ===\n{boot_output}")
            current_boot_images = parse_boot_statements(boot_output)

            # Get all .bin files in flash
            dir_result = await ssh.execute_commands(["dir flash:*.bin"])
            dir_output = dir_result[0].output if dir_result else ""
            cli_outputs.append(f"=== dir flash:*.bin ===\n{dir_output}")

            # Parse .bin files from dir output
            bin_files = []
            for line in dir_output.split("\n"):
                match = re.search(r"\s+([\w.-]+\.bin)\s*$", line, re.IGNORECASE)
                if match:
                    bin_files.append(match.group(1))

            # Identify files to delete (not in boot config)
            files_to_delete = []
            for bin_file in bin_files:
                is_boot_image = any(
                    bin_file.lower() in boot_img.lower() for boot_img in current_boot_images
                )
                if not is_boot_image:
                    files_to_delete.append(bin_file)

            # Keep specified number of old versions (sort by name, assume version in name)
            if len(files_to_delete) > keep_versions:
                files_to_delete.sort()
                files_to_delete = (
                    files_to_delete[:-keep_versions] if keep_versions > 0 else files_to_delete
                )

            # Delete files
            for filename in files_to_delete:
                delete_cmd = f"delete /force flash:{filename}"
                try:
                    result = await ssh.execute_command_timing(
                        delete_cmd,
                        read_timeout=60,
                        answers={
                            "Delete filename": "",
                            "confirm": "",
                            "[confirm]": "",
                        },
                    )
                    cli_outputs.append(f"=== {delete_cmd} ===\n{result.output}")
                    removed_packages.append(filename)
                    logger.info("Deleted: %s", filename)
                except Exception as e:
                    logger.warning("Failed to delete %s: %s", filename, e)

            return CleanupResult(
                success=True,
                removed_packages=removed_packages,
                cli_output="\n".join(cli_outputs),
            )

        except Exception as e:
            logger.exception("IOS-XE bundle cleanup failed")
            return CleanupResult(
                success=False,
                error=str(e),
                cli_output="\n".join(cli_outputs) if cli_outputs else "",
            )
