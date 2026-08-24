# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared IOS-XE parsing helpers and utilities.

These utilities are used by both install-mode and bundle-mode drivers.
"""

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hegemony_step_sdk import Transport

from ..driver import StageResult

logger = logging.getLogger(__name__)


# ==============================================================================
# Parsing helpers
# ==============================================================================


def parse_free_bytes(dir_output: str) -> int | None:
    """Parse free bytes from 'dir <fs>:' output.

    Handles various Cisco output formats:
    - "xxxxxx bytes total (xxxxxx bytes free)"
    - "xxxxxx bytes free"
    """
    # Try "(xxxxxx bytes free)" pattern first (most common)
    match = re.search(r"\((\d+)\s+bytes\s+free\)", dir_output, re.IGNORECASE)
    if match:
        return int(match.group(1))

    # Try "xxxxxx bytes free" without parentheses
    match = re.search(r"(\d+)\s+bytes\s+free", dir_output, re.IGNORECASE)
    if match:
        return int(match.group(1))

    return None


def parse_version_from_show_version(output: str) -> str:
    """Extract version string from 'show version' output.

    Handles various formats:
    - "Version 17.9.1"
    - "IOS Software, Version 17.9.1"
    - "Cisco IOS XE Software, Version 17.09.01"
    """
    match = re.search(r"Version\s+([\d.()a-zA-Z]+)", output)
    if match:
        return match.group(1)

    match = re.search(r"version\s+([\d.()a-zA-Z]+)", output, re.IGNORECASE)
    if match:
        return match.group(1)

    return ""


def normalize_filesystem(fs: str) -> str:
    """Normalize filesystem name to include trailing colon."""
    if not fs.endswith(":"):
        return fs + ":"
    return fs


def check_file_exists_in_dir(dir_output: str, filename: str) -> bool:
    """Check if a file exists in 'dir' command output.

    Uses precise matching to avoid substring false positives.
    """
    escaped = re.escape(filename)
    pattern = rf"(?:^|\s){escaped}(?:\s|$)"
    return bool(re.search(pattern, dir_output, re.IGNORECASE | re.MULTILINE))


def parse_file_size_from_dir(dir_output: str, filename: str) -> int | None:
    """Parse file size from dir output.

    IOS-XE dir format:
    "  3   482707791 Jan 25 2026 12:19:36.0000000000 +00:00 filename.bin"
    """
    size_match = re.search(
        rf"^\s*\d+\s+(\d+)\s+.*{re.escape(filename)}\s*$",
        dir_output,
        re.MULTILINE,
    )
    if size_match:
        return int(size_match.group(1))
    return None


def parse_boot_statements(show_boot: str) -> list[str]:
    """Parse boot system statements from show boot output.

    Returns list of boot images in order.
    """
    images = []
    # Common patterns:
    # "BOOT variable = flash:image.bin"
    # "BOOT path-list      : flash:image.bin"
    boot_match = re.search(
        r"(?:BOOT\s+(?:variable|path-list)\s*[=:]\s*)(.+)",
        show_boot,
        re.IGNORECASE,
    )
    if boot_match:
        # Could be semicolon or comma separated
        boot_str = boot_match.group(1).strip()
        for item in re.split(r"[;,]", boot_str):
            item = item.strip()
            if item and item.lower() != "not set":
                images.append(item)
    return images


# ==============================================================================
# Shared driver methods
# ==============================================================================


async def verify_md5(
    ssh: "Transport",
    file_path: str,
    expected_md5: str,
) -> tuple[bool, str]:
    """Verify file MD5 hash on IOS-XE device.

    Args:
        ssh: SSH transport connection
        file_path: Full path to file (e.g., "flash:image.bin")
        expected_md5: Expected MD5 hash

    Returns:
        Tuple of (verified: bool, cli_output: str)
    """
    md5_cmd = f"verify /md5 {file_path} {expected_md5}"
    logger.info("Running MD5 verification: %s", md5_cmd)

    result = await ssh.execute_command_timing(
        md5_cmd,
        read_timeout=600,  # 10 minutes for large images
        delay_factor=4,
        wait_for_patterns=[
            "Verified",
            "verified",
            "does not match",
            "mismatch",
            "Error",
            "%Error",
        ],
    )

    output = f"=== {md5_cmd} ===\n{result.output}"

    if "Verified" in result.output or "verified" in result.output.lower():
        return True, output
    elif "does not match" in result.output.lower() or "mismatch" in result.output.lower():
        return False, output
    else:
        # Uncertain - treat as success if no error
        return result.exit_code == 0, output


async def stage_image(
    ssh: "Transport",
    *,
    source_url: str,
    dest_fs: str,
    dest_filename: str,
    transfer_method: str,
    expected_md5: str | None,
    expected_size: int | None,
    overwrite: bool,
    select_transfer_method_fn,
) -> StageResult:
    """Stage image to IOS-XE device (shared implementation).

    Transfers the image and verifies integrity.
    Skips transfer if image already exists and is verified.

    This is the shared implementation used by both install and bundle modes.
    """
    import time

    dest_fs = normalize_filesystem(dest_fs)
    full_path = f"{dest_fs}{dest_filename}"
    cli_outputs: list[str] = []

    try:
        # Check if image already exists
        dir_result = await ssh.execute_commands([f"dir {full_path}"])
        dir_output = dir_result[0].output if dir_result else ""
        cli_outputs.append(f"=== dir {full_path} ===\n{dir_output}")

        file_exists = "No such file" not in dir_output and "%Error" not in dir_output
        actual_size = parse_file_size_from_dir(dir_output, dest_filename) if file_exists else None

        # A file already on the device is reused only when we can prove it is
        # the right one: the MD5 checksum, when configured, is verified on the
        # device; otherwise a supplied expected size must match. With neither,
        # the transfer runs again - re-transferring is safer than trusting a
        # name collision or a partial earlier transfer.
        if file_exists and not overwrite:
            if expected_md5:
                hash_verified, hash_output = await verify_md5(ssh, full_path, expected_md5)
                cli_outputs.append(hash_output)

                if hash_verified:
                    logger.info("Image already staged and verified: %s", full_path)
                    return StageResult(
                        success=True,
                        staged=True,
                        skipped=True,
                        transferred_bytes=actual_size or 0,
                        hash_verified=True,
                        verified_hash=expected_md5,
                        hash_type="md5",
                        filesystem=dest_fs,
                        full_path=full_path,
                        cli_output="\n".join(cli_outputs),
                    )
                logger.info("Existing image failed MD5 check, re-staging: %s", full_path)
            elif expected_size and actual_size and actual_size == expected_size:
                # No hash to verify, size matches = assume good
                logger.info("Image already exists with correct size: %s", full_path)
                return StageResult(
                    success=True,
                    staged=True,
                    skipped=True,
                    transferred_bytes=actual_size,
                    hash_verified=False,
                    filesystem=dest_fs,
                    full_path=full_path,
                    cli_output="\n".join(cli_outputs),
                )

        # Need to transfer. Only the device-side HTTP(S) pull exists, so an
        # unusable source URL must fail here - not surface later as a garbled
        # copy command or an unimplemented-method error after auto-selection.
        if not source_url.startswith(("http://", "https://")):
            return StageResult(
                success=False,
                error=(
                    f"Source URL {source_url!r} is not an HTTP(S) URL - the "
                    "device-side HTTP(S) pull is the only implemented transfer"
                ),
                cli_output="\n".join(cli_outputs),
            )
        transfer_method = select_transfer_method_fn(
            preferred=transfer_method,
            http_url_available=source_url.startswith(("http://", "https://")),
        )

        transfer_start = time.time()

        if transfer_method in ("http", "https"):
            transfer_result = await ssh.http_transfer(
                url=source_url,
                dest_fs=dest_fs,
                dest_filename=dest_filename,
                timeout_seconds=3600,  # 1 hour max
            )
            cli_outputs.append(f"=== HTTP transfer ===\n{transfer_result.get('output', '')}")

            if not transfer_result.get("transferred"):
                return StageResult(
                    success=False,
                    error=f"HTTP transfer failed: {transfer_result.get('output', 'unknown error')}",
                    cli_output="\n".join(cli_outputs),
                )

        else:
            # No implementation may ever fall through: before this branch an
            # explicit "tftp" skipped the transfer entirely and could report
            # success with no file on the device. "scp" (a worker-side push,
            # planned but never implemented) fails here the same way.
            return StageResult(
                success=False,
                error=(
                    f"Transfer method {transfer_method!r} is not implemented "
                    "(use auto, http, or https)"
                ),
                cli_output="\n".join(cli_outputs),
            )

        transfer_elapsed = time.time() - transfer_start

        # Verify transferred file
        dir_result = await ssh.execute_commands([f"dir {full_path}"])
        dir_output = dir_result[0].output if dir_result else ""
        cli_outputs.append(f"=== dir {full_path} (after transfer) ===\n{dir_output}")

        actual_size = parse_file_size_from_dir(dir_output, dest_filename)

        # Size verification
        if expected_size and actual_size and actual_size != expected_size:
            return StageResult(
                success=False,
                transferred_bytes=actual_size,
                transfer_method=transfer_method,
                transfer_elapsed_sec=transfer_elapsed,
                error=f"Size mismatch: expected {expected_size:,}, got {actual_size:,}",
                cli_output="\n".join(cli_outputs),
            )

        # Hash verification
        hash_verified = False
        verified_hash = None
        hash_type = ""

        if expected_md5:
            hash_verified, hash_output = await verify_md5(ssh, full_path, expected_md5)
            cli_outputs.append(hash_output)
            if hash_verified:
                verified_hash = expected_md5
                hash_type = "md5"
            else:
                return StageResult(
                    success=False,
                    transferred_bytes=actual_size,
                    transfer_method=transfer_method,
                    transfer_elapsed_sec=transfer_elapsed,
                    error="MD5 verification failed",
                    cli_output="\n".join(cli_outputs),
                )

        return StageResult(
            success=True,
            staged=True,
            skipped=False,
            transferred_bytes=actual_size,
            transfer_method=transfer_method,
            transfer_elapsed_sec=transfer_elapsed,
            hash_verified=hash_verified,
            verified_hash=verified_hash,
            hash_type=hash_type,
            filesystem=dest_fs,
            full_path=full_path,
            cli_output="\n".join(cli_outputs),
        )

    except Exception as e:
        logger.exception("IOS-XE stage failed")
        return StageResult(
            success=False,
            error=str(e),
            cli_output="\n".join(cli_outputs) if cli_outputs else "",
        )
