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
    CommandError,
    check_file_exists_in_dir,
    has_boot_variable,
    normalize_filesystem,
    parse_boot_statements,
    parse_free_bytes,
    parse_version_from_show_version,
    run_checked,
    run_config,
    same_boot_path,
    save_config,
    stage_image,
)

logger = logging.getLogger(__name__)

# Output that means the install failed: the device rejected the command, or
# the install itself reported a failure.
_INSTALL_FAILURE_RES = [
    re.compile(r"^\s*%\s*Invalid input", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*%\s*Error", re.MULTILINE | re.IGNORECASE),
    re.compile(r"% Incomplete command", re.IGNORECASE),
    re.compile(r"% Ambiguous command", re.IGNORECASE),
    re.compile(r"FAILED:\s*install_", re.IGNORECASE),
    re.compile(r"install_\w+:\s*FAILED", re.IGNORECASE),
    re.compile(r"FAILED:\s*\[", re.IGNORECASE),
    re.compile(r"\bInstall failed\b", re.IGNORECASE),
    re.compile(r"\bCannot activate\b", re.IGNORECASE),
    re.compile(r"\bCannot install\b", re.IGNORECASE),
    re.compile(r"\bAborted\b", re.IGNORECASE),
    re.compile(r"Failed to expand", re.IGNORECASE),
]
# The device starting to reload. Not the "... may require a reload ... [y/n]"
# confirmation prompt, which appears before anything happens.
_RELOAD_RE = re.compile(
    r"Install will reload the system now|%SYS-5-RELOAD|Reload requested|reloading, reason",
    re.IGNORECASE,
)
# Positive proof that the install command finished.
_INSTALL_DONE_RE = re.compile(
    r"SUCCESS:\s*install_|install_\w+:\s*SUCCESS|INSTALL_COMPLETED_INFO", re.IGNORECASE
)
# Activation finished: a session that drops after this is the reload.
_ACTIVATED_RE = re.compile(r"Activate: Passed|Finished Activate", re.IGNORECASE)
# The device already runs this image, so nothing was activated. Some releases
# follow these with a FAILED line; errors are read first, so that install fails.
_NO_CHANGE_RE = re.compile(
    r"Same Image File-No Change|Nothing to activate|No package is added or removed",
    re.IGNORECASE,
)


def _install_failure(output: str) -> str | None:
    """The first line of ``output`` that reports a failed install, if any."""
    for pattern in _INSTALL_FAILURE_RES:
        match = pattern.search(output)
        if match:
            start = output.rfind("\n", 0, match.start()) + 1
            end = output.find("\n", match.end())
            return output[start : end if end >= 0 else len(output)].strip()
    return None


def _classify_install(
    output: str, *, exit_code: int, error: str | None, activate: bool, commit: bool
) -> InstallResult:
    """Decide what an "install add file ..." session did, failing closed.

    Errors are checked first. Success needs proof: a SUCCESS line, the
    install's completion message, or the device starting to reload. A session
    that dropped counts as the reload only when activation had finished or the
    reload had started; otherwise it is a failure, as is a session that never
    produced any output.
    """
    reloading = bool(_RELOAD_RE.search(output))

    failure = _install_failure(output)
    if failure:
        return InstallResult(
            success=False,
            reboot_triggered=reloading,
            error=f"Install failed: {failure}",
            cli_output=output,
        )

    if exit_code < 0:
        if activate and (reloading or _ACTIVATED_RE.search(output)):
            return InstallResult(
                success=True,
                reboot_triggered=True,
                activated=True,
                committed=commit,
                cli_output=output,
                note="Session closed after activation - the device is reloading",
            )
        return InstallResult(
            success=False,
            error=f"Install session failed: {error or 'no output'}",
            cli_output=output,
        )

    if exit_code != 0 or error:
        return InstallResult(
            success=False,
            reboot_triggered=reloading,
            error=f"Install failed: {error or f'exit code {exit_code}'}",
            cli_output=output,
        )

    if not (reloading or _INSTALL_DONE_RE.search(output)):
        return InstallResult(
            success=False,
            error="Install did not report completion",
            cli_output=output,
        )

    if _NO_CHANGE_RE.search(output) and not reloading:
        return InstallResult(
            success=True,
            reboot_triggered=False,
            activated=False,
            committed=True,  # Already committed since it's the active version
            cli_output=output,
            note="Already at target version - no action needed",
        )

    return InstallResult(
        success=True,
        reboot_triggered=reloading,
        activated=activate,
        committed=activate and commit,
        cli_output=output,
    )


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
        fix_boot_config: bool = False,
    ) -> InstallResult:
        """Execute IOS-XE install command.

        Uses: install add file <fs><image> activate commit
        This triggers an automatic reboot.

        Activation boots <fs>packages.conf, so the boot variable must point
        there first. When it does not, the install fails before it starts,
        unless ``fix_boot_config`` allows setting and saving it.
        """
        dest_fs = normalize_filesystem(dest_fs)
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

        # "install add" alone neither boots nor reloads, so only activation
        # needs the boot variable.
        if activate:
            expected_boot = f"{dest_fs}packages.conf"
            try:
                before = await run_checked(ssh, "show boot")
                cli_outputs.append(f"=== show boot ===\n{before}")
                if not has_boot_variable(before):
                    return _failed("Could not read the boot variable from show boot")
                previous_boot = parse_boot_statements(before)

                if not (previous_boot and same_boot_path(previous_boot[0], expected_boot)):
                    current = ";".join(previous_boot) or "not set"
                    if not fix_boot_config:
                        return _failed(
                            f"Boot variable is {current}, expected {expected_boot} "
                            "(turn on fix_boot_config to set it)"
                        )
                    logger.warning("Setting boot variable %s (was %s)", expected_boot, current)
                    transcript = await run_config(
                        ssh,
                        [
                            "configure terminal",
                            "no boot system",
                            f"boot system {expected_boot}",
                            "end",
                        ],
                    )
                    boot_config_changed = True
                    cli_outputs.append(f"=== boot configuration ===\n{transcript}")
                    saved = await save_config(ssh)
                    cli_outputs.append(f"=== write memory ===\n{saved}")
                    # The boot variable follows the saved configuration, so
                    # it is read back after the save.
                    after = await run_checked(ssh, "show boot")
                    cli_outputs.append(f"=== show boot (after) ===\n{after}")
                    new_boot = parse_boot_statements(after)
                    if not (new_boot and same_boot_path(new_boot[0], expected_boot)):
                        return _failed(
                            f"Boot variable is {';'.join(new_boot) or 'not set'} after the "
                            f"change, expected {expected_boot}"
                        )
            except CommandError as e:
                return _failed(str(e))
            except Exception as e:
                logger.exception("IOS-XE boot variable check failed")
                return _failed(str(e))

        # Build install command. "commit" is a keyword of "activate", so it
        # is only sent with it.
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

        # Stop waiting at the first sign that the install finished or failed.
        completion_patterns = [
            "SUCCESS: install_",
            "FAILED: install_",
            "install_add_activate_commit: SUCCESS",
            "install_add_activate_commit: FAILED",
            "Install will reload the system now",
            "INSTALL-5-INSTALL_COMPLETED_INFO",
            "Reload requested",
            "% Invalid input",
            "% Incomplete command",
            "% Ambiguous command",
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
            outcome = _classify_install(
                result.output or "",
                exit_code=result.exit_code,
                error=result.error,
                activate=activate,
                commit=commit,
            )
            cli_outputs.append(f"=== {install_cmd} ===\n{outcome.cli_output}")
            outcome.cli_output = "\n".join(cli_outputs)
            outcome.boot_config_changed = boot_config_changed
            outcome.previous_boot = previous_boot
            if outcome.success:
                logger.info("Install finished: %s", outcome.note or "ok")
            else:
                logger.warning("Install failed: %s", outcome.error)
            return outcome

        except Exception as e:
            logger.exception("IOS-XE install failed")
            return _failed(str(e))

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
