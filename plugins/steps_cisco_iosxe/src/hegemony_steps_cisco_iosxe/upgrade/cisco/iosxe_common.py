# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared IOS-XE parsing helpers and utilities.

These utilities are used by both install-mode and bundle-mode drivers.
"""

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hegemony_step_sdk import CommandResult, Transport

from ..driver import StageResult

logger = logging.getLogger(__name__)

# IOS error lines: "%Error ...", "% Invalid input ...", "% Incomplete command."
_CLI_ERROR_RE = re.compile(
    r"^\s*%\s*(?:Error|Invalid input|Incomplete command|Ambiguous command|Unknown command)",
    re.MULTILINE | re.IGNORECASE,
)
_BOOT_LINE_RE = re.compile(r"BOOT\s+(?:variable|path-list)\s*[=:]", re.IGNORECASE)
# The value stays on its line: an empty BOOT variable must not take the next
# line ("CONFIG_FILE variable = ...") as its value.
_BOOT_VALUE_RE = re.compile(r"BOOT\s+(?:variable|path-list)[ \t]*[=:][ \t]*(.*)", re.IGNORECASE)


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


def _boot_entries(value: str) -> list[str]:
    """Split a BOOT variable value into images.

    Entries end with ";" and may carry a boot attempt count after a comma
    ("bootflash:image.bin,12;"); the count is not an image.
    """
    entries = []
    for item in re.split(r"[;,]", value):
        item = item.strip()
        if item and item.lower() != "not set" and not item.isdigit():
            entries.append(item)
    return entries


def parse_boot_statements(show_boot: str) -> list[str]:
    """Parse the boot images from 'show boot' output, in boot order.

    Some platforms list the current boot variables and then those for the
    next reload; the next reload's are the ones the device will use.
    """
    # Common patterns:
    # "BOOT variable = flash:image.bin;"
    # "BOOT path-list      : flash:image.bin"
    next_reload = re.search(r"next reload", show_boot, re.IGNORECASE)
    boot_match = None
    if next_reload:
        boot_match = _BOOT_VALUE_RE.search(show_boot, next_reload.end())
    boot_match = boot_match or _BOOT_VALUE_RE.search(show_boot)
    return _boot_entries(boot_match.group(1)) if boot_match else []


def all_boot_images(show_boot: str) -> list[str]:
    """Every image any BOOT line of 'show boot' names, current and next reload."""
    return [
        entry
        for match in _BOOT_VALUE_RE.finditer(show_boot)
        for entry in _boot_entries(match.group(1))
    ]


def has_boot_variable(show_boot: str) -> bool:
    """Whether 'show boot' output shows a BOOT variable line at all."""
    return bool(_BOOT_LINE_RE.search(show_boot))


def same_file_path(first: str, second: str) -> bool:
    """Whether two device paths name the same file.

    flash: and bootflash: are one filesystem, and "flash:/x" is "flash:x".
    """

    def _norm(value: str) -> str:
        filesystem, colon, name = value.strip().lower().partition(":")
        if not colon:
            return filesystem
        if filesystem == "bootflash":
            filesystem = "flash"
        return f"{filesystem}:{name.lstrip('/')}"

    return _norm(first) == _norm(second)


# ==============================================================================
# Command helpers
# ==============================================================================


class CommandError(RuntimeError):
    """A device command failed, could not run, or gave an unusable answer.

    ``transcript`` holds what a configuration session printed before it
    failed, since some of its lines may already be applied.
    """

    def __init__(self, message: str, *, transcript: str = "") -> None:
        super().__init__(message)
        self.transcript = transcript


def cli_error_line(output: str) -> str | None:
    """The first IOS error line in ``output`` ("%Error ...", "% Invalid input ..."), if any."""
    match = _CLI_ERROR_RE.search(output)
    if not match:
        return None
    line_end = output.find("\n", match.start())
    return output[match.start() : line_end if line_end >= 0 else len(output)].strip()


def checked(result: "CommandResult | None", command: str) -> str:
    """Return a command's output, or raise when the command did not succeed.

    The transports never raise for a failed command: they return exit code -1
    with an error for a session that failed, and exit code 1 for a CLI error.
    Some errors ("%Error opening ...") even come back with exit code 0, so the
    output is read too.
    """
    if result is None:
        raise CommandError(f"{command}: no result")
    if result.exit_code != 0 or result.error:
        raise CommandError(f"{command} failed: {result.error or f'exit code {result.exit_code}'}")
    output = result.output or ""
    error_line = cli_error_line(output)
    if error_line:
        raise CommandError(f"{command} failed: {error_line}")
    return output


async def run_checked(ssh: "Transport", command: str) -> str:
    """Run one exec command and return its output; raise if it did not succeed."""
    results = await ssh.execute_commands([command])
    return checked(results[0] if results else None, command)


async def run_config(ssh: "Transport", lines: list[str]) -> str:
    """Send config lines in one session and return its transcript.

    ``lines`` starts with "configure terminal" and ends with "end", which is
    what makes the transports send them as one config session; sent one by
    one, each line would run in exec mode in a new session. Raises when any
    line fails or the session did not run; the lines before a failed one may
    be applied, so the error carries the whole transcript.
    """
    results = await ssh.execute_commands(lines)
    if not results:
        raise CommandError("configuration session returned no result")
    transcript: list[str] = []
    failure: CommandError | None = None
    for result in results:
        command = result.command or "configuration"
        output = (result.output or "").rstrip("\n")
        transcript.append(f"{command}\n{output}" if output else command)
        try:
            checked(result, command)
        except CommandError as e:
            transcript.append(f"! {e}")
            failure = failure or e
    if failure:
        raise CommandError(str(failure), transcript="\n".join(transcript))
    return "\n".join(transcript)


async def undo_boot_change(ssh: "Transport", previous: list[str], cli_outputs: list[str]) -> bool:
    """Put the boot entries back to ``previous`` after a boot change failed.

    A failed configuration session can still have applied its first lines,
    such as "no boot system", so the running boot setting is rewritten from
    the entries "show boot" listed before. Returns whether that worked; the
    transcript goes to ``cli_outputs``.
    """
    lines = ["configure terminal", "no boot system"]
    lines += [f"boot system {image}" for image in previous]
    lines.append("end")
    try:
        transcript = await run_config(ssh, lines)
    except CommandError as e:
        cli_outputs.append(f"=== restore previous boot entries (failed) ===\n{e.transcript or e}")
        return False
    cli_outputs.append(f"=== restore previous boot entries ===\n{transcript}")
    return True


def boot_change_failure(error: CommandError, *, restored: bool) -> str:
    """The error for a boot change session that failed, after the undo."""
    if restored:
        return f"{error}; the previous boot entries were restored"
    return (
        f"{error}; restoring the previous boot entries failed too, so check the "
        "device's boot setting"
    )


async def save_config(ssh: "Transport") -> str:
    """Run "write memory" and return its output; raise unless the save is confirmed."""
    result = await ssh.execute_command_timing(
        "write memory",
        read_timeout=120,
        answers={"[confirm]": ""},
        wait_for_patterns=["[OK]", "%Error", "% Invalid input", "% Incomplete command"],
    )
    output = checked(result, "write memory")
    if "[OK]" not in output:
        raise CommandError(
            f"write memory did not confirm the save: {output.strip() or 'no output'}"
        )
    return output


# ==============================================================================
# Shared driver methods
# ==============================================================================


# A matching "verify /md5 <file> <hash>" prints this line with the hash the
# device computed. A mismatch prints "%Error verifying <file>" followed by
# "Computed signature" and "Submitted signature" lines instead.
_MD5_VERIFIED_RE = re.compile(r"^\s*Verified \((.+)\) = ([0-9a-fA-F]{32})", re.MULTILINE)
_MD5_COMPUTED_RE = re.compile(r"Computed signature\s*[=:]?\s*([0-9a-fA-F]{32})", re.IGNORECASE)
_MD5_RE = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True)
class Md5Check:
    """Outcome of one on-device MD5 check."""

    verified: bool
    computed: str | None  # Hash the device reported (lowercase), if it printed one
    cli_output: str


async def verify_md5(
    ssh: "Transport",
    file_path: str,
    expected_md5: str,
) -> Md5Check:
    """Verify a file's MD5 hash on an IOS-XE device.

    Fails closed: the file counts as verified only when the device prints its
    "Verified (<file>) = <hash>" line for this file with the expected hash
    and the command reported no error. Anything else, including output this function does not
    recognise, is a failed check.

    Args:
        ssh: SSH transport connection
        file_path: Full path to file (e.g., "flash:image.bin")
        expected_md5: Expected MD5 hash (32 hex digits, any case)

    Raises:
        ValueError: If ``expected_md5`` is not 32 hex digits
    """
    expected = expected_md5.strip().lower()
    if not _MD5_RE.fullmatch(expected):
        raise ValueError("Expected MD5 must be 32 hexadecimal digits")

    md5_cmd = f"verify /md5 {file_path} {expected}"
    logger.info("Running MD5 verification: %s", md5_cmd)

    # The transports stop reading at the first of these they see, so each
    # must mark an answer that is complete: the match line once it holds the
    # whole hash, the last line of a mismatch report (the computed hash comes
    # before it), and errors that are the whole answer. "%Error verifying"
    # starts a mismatch report and is not one of them.
    result = await ssh.execute_command_timing(
        md5_cmd,
        read_timeout=600,  # 10 minutes for large images
        delay_factor=4,
        wait_for_patterns=[
            f") = {expected}",
            "Submitted signature",
            "%Error opening",
            "%Error reading",
            "% Invalid input",
            "% Incomplete command",
            "% Ambiguous command",
        ],
    )

    output = result.output or ""
    cli_output = f"=== {md5_cmd} ===\n{output}"
    if result.error:
        cli_output += f"\n[command error: {result.error}]"

    verified_match = _MD5_VERIFIED_RE.search(output)
    computed_match = _MD5_COMPUTED_RE.search(output)
    if verified_match:
        computed: str | None = verified_match.group(2).lower()
    elif computed_match:
        computed = computed_match.group(1).lower()
    else:
        computed = None

    verified = (
        result.exit_code == 0
        and not result.error
        and verified_match is not None
        and same_file_path(verified_match.group(1), file_path)
        and computed == expected
        and not _CLI_ERROR_RE.search(output)
        and "computed signature" not in output.lower()
    )
    return Md5Check(verified=verified, computed=computed, cli_output=cli_output)


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
        dir_results = await ssh.execute_commands([f"dir {full_path}"])
        dir_result = dir_results[0] if dir_results else None
        dir_output = dir_result.output if dir_result else ""
        cli_outputs.append(f"=== dir {full_path} ===\n{dir_output}")

        # A dir that did not run (no session, a dropped connection) or that
        # the device rejected says nothing about the file - it is an error,
        # not "the file exists". "No such file" is the one expected answer.
        if dir_result is None or dir_result.exit_code < 0:
            reason = dir_result.error if dir_result else "no result"
            return StageResult(
                success=False,
                error=f"Could not list {full_path}: {reason}",
                cli_output="\n".join(cli_outputs),
            )
        if "No such file" in dir_output:
            file_exists = False
        else:
            try:
                checked(dir_result, f"dir {full_path}")
            except CommandError as e:
                return StageResult(
                    success=False,
                    error=f"Could not list {full_path}: {e}",
                    cli_output="\n".join(cli_outputs),
                )
            file_exists = check_file_exists_in_dir(dir_output, dest_filename)
        actual_size = parse_file_size_from_dir(dir_output, dest_filename) if file_exists else None
        computed_hash: str | None = None

        # A file already on the device is reused only when we can prove it is
        # the right one: the MD5 checksum, when configured, is verified on the
        # device; otherwise a supplied expected size must match. With neither,
        # the transfer runs again - re-transferring is safer than trusting a
        # name collision or a partial earlier transfer.
        if file_exists and not overwrite:
            if expected_md5:
                check = await verify_md5(ssh, full_path, expected_md5)
                cli_outputs.append(check.cli_output)

                if check.verified:
                    logger.info("Image already staged and verified: %s", full_path)
                    return StageResult(
                        success=True,
                        staged=True,
                        skipped=True,
                        transferred_bytes=actual_size or 0,
                        hash_verified=True,
                        verified_hash=check.computed,
                        computed_hash=check.computed,
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
        dir_output = await run_checked(ssh, f"dir {full_path}")
        cli_outputs.append(f"=== dir {full_path} (after transfer) ===\n{dir_output}")
        if not check_file_exists_in_dir(dir_output, dest_filename):
            return StageResult(
                success=False,
                transfer_method=transfer_method,
                transfer_elapsed_sec=transfer_elapsed,
                error=f"{full_path} is not on the device after the transfer",
                cli_output="\n".join(cli_outputs),
            )

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
            check = await verify_md5(ssh, full_path, expected_md5)
            cli_outputs.append(check.cli_output)
            computed_hash = check.computed
            if check.verified:
                hash_verified = True
                verified_hash = check.computed
                hash_type = "md5"
            else:
                if check.computed:
                    error = (
                        f"MD5 mismatch: the device computed {check.computed}, "
                        f"expected {expected_md5.strip().lower()}"
                    )
                else:
                    error = "MD5 verification failed: the device did not confirm the checksum"
                return StageResult(
                    success=False,
                    transferred_bytes=actual_size,
                    transfer_method=transfer_method,
                    transfer_elapsed_sec=transfer_elapsed,
                    computed_hash=computed_hash,
                    error=error,
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
            computed_hash=computed_hash,
            hash_type=hash_type,
            filesystem=dest_fs,
            full_path=full_path,
            cli_output="\n".join(cli_outputs),
        )

    except CommandError as e:
        logger.warning("IOS-XE stage failed: %s", e)
        return StageResult(
            success=False,
            error=str(e),
            cli_output="\n".join(cli_outputs),
        )
    except Exception as e:
        logger.exception("IOS-XE stage failed")
        return StageResult(
            success=False,
            error=str(e),
            cli_output="\n".join(cli_outputs) if cli_outputs else "",
        )
