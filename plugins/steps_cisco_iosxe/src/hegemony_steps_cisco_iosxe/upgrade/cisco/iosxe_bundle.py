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
    CommandError,
    all_boot_images,
    boot_change_failure,
    check_file_exists_in_dir,
    checked,
    cli_error_line,
    has_boot_variable,
    normalize_filesystem,
    parse_boot_statements,
    parse_free_bytes,
    parse_version_from_show_version,
    run_checked,
    run_config,
    same_file_path,
    same_version,
    save_config,
    stage_image,
    undo_boot_change,
)

logger = logging.getLogger(__name__)

# The reload started: the device asked to confirm it, or said it is reloading.
_RELOAD_STARTED_RE = re.compile(
    r"Proceed with reload|%SYS-5-RELOAD|Reload requested|reloading, reason", re.IGNORECASE
)


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
            version_output = await run_checked(ssh, "show version")
            cli_outputs["show version"] = version_output
            current_version = parse_version_from_show_version(version_output)

            await asyncio.sleep(0.1)

            # Check disk space
            dir_output = await run_checked(ssh, f"dir {dest_fs}")
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
            boot_output = await run_checked(ssh, "show boot")
            cli_outputs["show boot"] = boot_output
            current_boot_images = parse_boot_statements(boot_output)

            if current_boot_images:
                logger.info("Current boot config: %s", current_boot_images)
            else:
                warnings.append("No boot system statement found")
            # A device booting packages.conf runs in install mode; bundle mode
            # would point it back at a single .bin image.
            if current_boot_images and current_boot_images[0].lower().endswith("packages.conf"):
                errors.append(
                    f"The device boots {current_boot_images[0]} (install mode); "
                    "use install mode for this device"
                )

            # Bundle mode doesn't use install command
            install_mode_supported = False

            # Check if target version already running
            target_version_installed = False
            if target_version and same_version(current_version, target_version):
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

        except CommandError as e:
            logger.warning("IOS-XE bundle preflight failed: %s", e)
            return PreflightResult(
                success=False,
                error=str(e),
                cli_outputs=cli_outputs,
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
        previous_boot: list[str] = []
        boot_config_changed = False

        def _failed(error: str) -> InstallResult:
            return InstallResult(
                success=False,
                error=error,
                cli_output="\n".join(cli_outputs),
                boot_config_changed=boot_config_changed,
                previous_boot=previous_boot,
            )

        try:
            # Get current boot config for rollback info
            boot_output = await run_checked(ssh, "show boot")
            cli_outputs.append(f"=== show boot (before) ===\n{boot_output}")
            if not has_boot_variable(boot_output):
                return _failed("Could not read the boot variable from show boot")
            previous_boot = parse_boot_statements(boot_output)

            # Keep the first other image as a fallback boot entry
            fallback = next(
                (image for image in previous_boot if not same_file_path(image, full_image_path)),
                None,
            )

            # One configuration session: the transports send a list as config
            # only when it starts with "configure terminal"; sent line by line,
            # each line would run in exec mode and be rejected.
            config_lines = [
                "configure terminal",
                "no boot system",
                f"boot system {full_image_path}",
            ]
            if fallback:
                config_lines.append(f"boot system {fallback}")
                logger.info("Added fallback boot image: %s", fallback)
            config_lines.append("end")
            try:
                transcript = await run_config(ssh, config_lines)
            except CommandError as e:
                cli_outputs.append(f"=== boot configuration (failed) ===\n{e.transcript}")
                restored = await undo_boot_change(ssh, previous_boot, cli_outputs)
                boot_config_changed = not restored
                return _failed(boot_change_failure(e, restored=restored))
            boot_config_changed = True
            cli_outputs.append(f"=== boot configuration ===\n{transcript}")

            # A failed save or read-back leaves the change in the running
            # configuration, so it is undone there as well.
            try:
                saved = await save_config(ssh)
                cli_outputs.append(f"=== write memory ===\n{saved}")

                # The boot variable follows the saved configuration, so it is
                # read back after the save. The new image must come first.
                verify_output = await run_checked(ssh, "show boot")
                cli_outputs.append(f"=== show boot (after) ===\n{verify_output}")
                new_boot = parse_boot_statements(verify_output)
                if not (new_boot and same_file_path(new_boot[0], full_image_path)):
                    raise CommandError(
                        f"Boot variable is {';'.join(new_boot) or 'not set'} after the change, "
                        f"expected {full_image_path} first"
                    )
            except CommandError as e:
                restored = await undo_boot_change(ssh, previous_boot, cli_outputs)
                boot_config_changed = not restored
                return _failed(boot_change_failure(e, restored=restored, after_save=True))

            if not activate:
                # Just configure, don't reload yet
                return InstallResult(
                    success=True,
                    reboot_triggered=False,
                    activated=False,
                    cli_output="\n".join(cli_outputs),
                    boot_config_changed=boot_config_changed,
                    previous_boot=previous_boot,
                )

            # Trigger reload. One key per prompt, so each is answered once and
            # in the order the device asks: "Save? [yes/no]" (already saved),
            # then "Proceed with reload? [confirm]".
            reload_result = await ssh.execute_command_timing(
                "reload",
                read_timeout=60,
                answers={
                    "Save?": "no",
                    "Proceed with reload": "y",
                },
            )
            reload_output = reload_result.output or ""
            cli_outputs.append(f"=== reload ===\n{reload_output}")
            if reload_result.error:
                cli_outputs.append(f"[reload session: {reload_result.error}]")

            # The session drops when the device reloads, so exit code -1 is
            # expected once the reload was confirmed - and a failure before.
            error_line = cli_error_line(reload_output)
            if error_line or not _RELOAD_STARTED_RE.search(reload_output):
                reason = error_line or reload_result.error or reload_output.strip() or "no output"
                return _failed(f"Reload did not start: {reason}")
            if reload_result.exit_code > 0:
                return _failed(f"Reload did not start: {reload_result.error or 'CLI error'}")

            return InstallResult(
                success=True,
                reboot_triggered=True,
                activated=True,
                committed=True,  # Bundle mode doesn't have separate commit
                cli_output="\n".join(cli_outputs),
                boot_config_changed=boot_config_changed,
                previous_boot=previous_boot,
            )

        except CommandError as e:
            logger.warning("IOS-XE bundle install failed: %s", e)
            return _failed(str(e))
        except Exception as e:
            # Transports report a dropped session in the result, not by
            # raising, so an exception here is never the reload.
            logger.exception("IOS-XE bundle install failed")
            return _failed(str(e))

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
            version_output = await run_checked(ssh, "show version")
            cli_outputs["show version"] = version_output
            current_version = parse_version_from_show_version(version_output)

            # Check version match
            version_match = False
            if target_version:
                version_match = same_version(current_version, target_version)

            # Check version changed
            version_changed = True
            if preflight_version and same_version(current_version, preflight_version):
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
            cli_outputs["show boot"] = await run_checked(ssh, "show boot")

            # Bundle mode is always "committed" since boot system is saved
            committed = True

            success = version_changed and (not target_version or version_match)

            return VerifyResult(
                success=success,
                current_version=current_version,
                version_match=version_match,
                version_changed=version_changed,
                committed=committed,
                error=(
                    None
                    if success
                    else f"Running version {current_version or 'unknown'} is not {target_version}"
                ),
                cli_outputs=cli_outputs,
            )

        except CommandError as e:
            logger.warning("IOS-XE bundle verify failed: %s", e)
            return VerifyResult(
                success=False,
                error=str(e),
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
        failed_deletes: list[str] = []

        try:
            # Get current boot config
            boot_output = await run_checked(ssh, "show boot")
            cli_outputs.append(f"=== show boot ===\n{boot_output}")
            # Both the current and the next-reload boot images stay.
            current_boot_images = all_boot_images(boot_output)

            # With no image in the boot variable the device boots the first
            # file it finds, so no image is known to be unused.
            if not current_boot_images:
                return CleanupResult(
                    success=False,
                    error="The boot variable names no image, so nothing was deleted",
                    cli_output="\n".join(cli_outputs),
                )

            # Get all .bin files in flash. A wildcard that matches nothing
            # answers "No such file", which is an empty listing.
            dir_results = await ssh.execute_commands(["dir flash:*.bin"])
            dir_result = dir_results[0] if dir_results else None
            if dir_result and dir_result.exit_code >= 0 and "No such file" in dir_result.output:
                dir_output = ""
            else:
                dir_output = checked(dir_result, "dir flash:*.bin")
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

            # Keep the newest old images (sorted by name, assume version in name)
            files_to_delete.sort()
            if keep_versions > 0:
                files_to_delete = files_to_delete[:-keep_versions]

            # Delete files
            for filename in files_to_delete:
                delete_cmd = f"delete /force flash:{filename}"
                result = await ssh.execute_command_timing(
                    delete_cmd,
                    read_timeout=60,
                    answers={"Delete filename": "", "[confirm]": ""},
                )
                cli_outputs.append(f"=== {delete_cmd} ===\n{result.output}")
                try:
                    checked(result, delete_cmd)
                except CommandError as e:
                    logger.warning("Failed to delete %s: %s", filename, e)
                    failed_deletes.append(str(e))
                    continue
                removed_packages.append(filename)
                logger.info("Deleted: %s", filename)

            return CleanupResult(
                success=not failed_deletes,
                removed_packages=removed_packages,
                error="; ".join(failed_deletes) or None,
                cli_output="\n".join(cli_outputs),
            )

        except CommandError as e:
            logger.warning("IOS-XE bundle cleanup failed: %s", e)
            return CleanupResult(
                success=False,
                removed_packages=removed_packages,
                error=str(e),
                cli_output="\n".join(cli_outputs),
            )
        except Exception as e:
            logger.exception("IOS-XE bundle cleanup failed")
            return CleanupResult(
                success=False,
                removed_packages=removed_packages,
                error=str(e),
                cli_output="\n".join(cli_outputs) if cli_outputs else "",
            )
