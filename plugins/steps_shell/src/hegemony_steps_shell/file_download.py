# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ShellFileDownloadHandler: each host downloads a file-repository file with curl.

The Linux/Unix counterpart of ``netcli.file_download``. The step asks the
platform for a short-lived download link (``services.open_file_download``),
has the host fetch it with ``curl`` over the device's shell transport, and
checks the SHA-256 on the host before the file takes its place. The file never
passes through the worker. Each host gets a link of its own, issued right
before its download and ended right after it.
"""

from __future__ import annotations

import logging
import secrets
import shlex
from dataclasses import dataclass, field
from typing import Any

from pydantic import ConfigDict, Field, field_validator

from hegemony_step_sdk import (
    MAX_CHAIN_OUTPUT_CHARS,
    MAX_PARALLEL_DEVICES_LIMIT,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    StepKind,
    for_each_target_device,
)
from hegemony_step_sdk.ssh import SshSecurityConfig

from .execute import _open_shell

logger = logging.getLogger(__name__)

_DEFAULT_TRANSFER_TIMEOUT_SECONDS = 3600
#: How long a host has to start its download once the link exists. The link is
#: asked for after the connection is open, so this only has to cover the start
#: of the transfer; a transfer under way is not cut off at its end.
_LINK_TTL_SECONDS = 600
#: Time the checksum and the final move get on the host.
_FINISH_TIMEOUT_SECONDS = 600
#: Time the transport gets beyond curl's own limit to return curl's answer.
_RUN_MARGIN_SECONDS = 15
#: What a link is replaced with wherever the step reports text a host printed.
_LINK_PLACEHOLDER = "<download link>"
#: Suffix of the file while it downloads (after a few random characters, so
#: every transfer has a staging file of its own). It becomes the destination
#: file only once it is complete (and verified), so a broken download never
#: looks done.
_PARTIAL_SUFFIX = ".part"

_NO_DOWNLOAD_LINKS = (
    "This Hegemony version cannot issue download links for file "
    "repository files; upgrade the platform to use this step"
)


class ShellFileDownloadConfig(SshSecurityConfig):
    """Config for ``shell.file_download``."""

    model_config = ConfigDict(extra="allow")

    # Named file_ids on purpose: the platform refuses to delete a stored file
    # that a flow lists under this key.
    file_ids: list[str] = Field(
        default_factory=list,
        title="File Repository File",
        description="The file each host downloads. Browse the file repositories and pick one.",
        json_schema_extra={
            "x_widget": "repository-file-select",
            "x_multiple": False,
            "x_file_type_filter": "file",
            "x_col_span": 2,
        },
    )
    dest_dir: str = Field(
        default="/var/tmp",
        title="Destination Directory",
        description=(
            "Directory on the host the file goes into, as an absolute path. It must "
            'exist and the login account must be able to write to it. Defaults to "/var/tmp".'
        ),
        json_schema_extra={"x_placeholder": "/var/tmp"},
    )
    dest_filename: str = Field(
        default="",
        title="Destination Filename",
        description="File name on the host. Leave empty to keep the stored file's name.",
        json_schema_extra={"x_placeholder": "app-release-1.4.2.tar.gz"},
    )
    verify_checksum: bool = Field(
        default=True,
        title="Verify checksum",
        description=(
            "Compare the downloaded file's SHA-256 with the stored file's before it "
            "takes its place (needs sha256sum on the host). On by default."
        ),
    )
    transfer_timeout_seconds: int = Field(
        _DEFAULT_TRANSFER_TIMEOUT_SECONDS,
        ge=60,
        le=86400,
        title="Transfer timeout (seconds)",
        description=(
            "How long one host's download may take before it fails. The step "
            "timeout must still cover every host. Defaults to one hour."
        ),
    )
    max_parallel_devices: int = Field(
        default=1,
        ge=1,
        le=MAX_PARALLEL_DEVICES_LIMIT,
        title="Max Parallel Devices",
        description="Hosts downloading concurrently (1 = sequential)",
    )

    @field_validator("file_ids", mode="before")
    @classmethod
    def _single_file_id(cls, value: Any) -> Any:
        # One id given as text, as a rendered template gives it, is a list of one.
        return [value] if isinstance(value, str) else value


@dataclass
class _DeviceOutcome:
    """One host's result, merged in device order after the fan-out."""

    evidence: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    success: bool = True
    transferred: bool = False
    verified: bool = False
    file: dict[str, Any] | None = None


def _has_control_characters(value: str) -> bool:
    """Whether ``value`` holds a line break or another non-printable character.

    Every value is quoted into the command the host runs, so none can become
    shell syntax; a control character in a path is refused all the same,
    because no real directory or file name needs one and a terminal or a log
    that shows it can be misled by it.
    """
    return any(not character.isprintable() for character in value)


def _is_plain_file_name(value: str) -> bool:
    """Whether ``value`` names a file and nothing else: no directory part."""
    return bool(value) and "/" not in value and value not in (".", "..")


def _without_link(text: str, url: str) -> str:
    """``text`` with the download link taken out.

    The host redacts the link's token from everything a step reports; this
    keeps the rest of the address out too, and does not depend on the host.
    """
    if not url:
        return text
    return text.replace(url, _LINK_PLACEHOLDER)


def download_command(url: str, partial_path: str, timeout_seconds: int) -> str:
    """The curl line that fetches ``url`` into ``partial_path``.

    ``-f`` makes an HTTP error a failure instead of a saved error page;
    ``-sS`` drops the progress meter and keeps error messages. No ``-L``: a
    download link answers with the file, so a redirect is not followed.
    """
    return (
        f"curl -fsS --max-time {int(timeout_seconds)} "
        f"-o {shlex.quote(partial_path)} {shlex.quote(url)}"
    )


def _first_line(text: str) -> str:
    lines = text.strip().splitlines()
    return lines[0] if lines else ""


class ShellFileDownloadHandler(BaseHandler):
    """Handler that has each Linux/Unix host download one file-repository file."""

    handler_id = "shell.file_download"
    supported_kinds = [StepKind.ACTION]
    display_name = "Download File to Host"
    description = (
        "Have each Linux/Unix host download a file-repository file with curl, "
        "through a short-lived link, and verify its checksum."
    )
    category = "Actions"
    targeting = HandlerTargeting(roles=True, ips=False)
    config_model = ShellFileDownloadConfig
    default_config = {"dest_dir": "/var/tmp", "verify_checksum": True}
    # A large file over a slow link takes a while, and every host has its own
    # Transfer timeout within the step's.
    default_timeout_seconds = 7200

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Stage the configured file on every target host."""
        target_devices = ctx.get_target_devices()
        if not target_devices:
            return HandlerResult(
                success=False,
                error="No target devices configured",
                summary="Missing target device",
            )
        try:
            config = self.parse_config(ctx.config, ShellFileDownloadConfig)
        except InvalidConfigError as exc:
            return exc.result()

        file_ids = [item.strip() for item in config.file_ids if item.strip()]
        if len(file_ids) != 1:
            return HandlerResult(
                success=False,
                error=(
                    "Select exactly one file repository file"
                    if file_ids
                    else "No file repository file selected"
                ),
                summary="Missing file",
            )
        file_id = file_ids[0]

        services = ctx.require_services()
        open_file_download = getattr(services, "open_file_download", None)
        if open_file_download is None:
            return HandlerResult(
                success=False,
                error=_NO_DOWNLOAD_LINKS,
                summary="Download links not supported",
            )

        dest_dir = config.dest_dir.strip()
        dest_filename_config = config.dest_filename.strip()
        for label, value in (
            ("Destination Directory", dest_dir),
            ("Destination Filename", dest_filename_config),
        ):
            if _has_control_characters(value):
                return HandlerResult(
                    success=False,
                    error=f"{label} contains a line break or another control character",
                    summary="Invalid destination",
                )
        if not dest_dir.startswith("/"):
            return HandlerResult(
                success=False,
                error="Destination Directory must be an absolute path (starting with /)",
                summary="Invalid destination",
            )
        if dest_filename_config and not _is_plain_file_name(dest_filename_config):
            return HandlerResult(
                success=False,
                error=(
                    "Destination Filename must be a file name without a directory part "
                    "(no slash); put the directory in Destination Directory"
                ),
                summary="Invalid destination",
            )
        directory = dest_dir.rstrip("/")
        many = len(target_devices) > 1

        async def _process_device(device: dict) -> _DeviceOutcome:
            outcome = _DeviceOutcome()
            device_id = device.get("id", device.get("mgmt_host"))
            device_name = device.get("name", device_id)
            artifact_name = f"File download ({device_name})" if many else "File download"

            def _fail(message: str, **details: Any) -> _DeviceOutcome:
                outcome.success = False
                outcome.errors.append(f"{device_name}: {message}")
                outcome.evidence.append(
                    {
                        "kind": "cli_output",
                        "name": f"Error ({device_name})",
                        "device_id": device_id,
                        "content_text": message,
                        "content_json": {
                            "device_id": device_id,
                            "device_name": device_name,
                            "file_id": file_id,
                            "error": message,
                            "success": False,
                            **details,
                        },
                    }
                )
                return outcome

            if not device.get("mgmt_host"):
                return _fail("no mgmt_host configured")

            # The connection first, the link second: the link's time is then
            # not spent waiting for a host that is slow to answer.
            try:
                transport = await _open_shell(services, device, config.allow_legacy_ssh)
            except Exception as exc:  # noqa: BLE001 - one host's failure, reported
                return _fail(str(exc) or type(exc).__name__)

            url = ""
            link_opened = False
            dest_path = ""
            #: The staging file, quoted for the command line, once curl may have made it.
            staged: str | None = None

            async def _discard() -> None:
                """Remove the staging file; never hides the failure that led here."""
                if staged is None:
                    return
                try:
                    await transport.run(f"rm -f {staged}", timeout=_FINISH_TIMEOUT_SECONDS)
                except Exception:  # noqa: BLE001 - cleanup is best-effort
                    logger.debug("staging file cleanup failed", exc_info=True)

            try:
                async with open_file_download(file_id, ttl_seconds=_LINK_TTL_SECONDS) as download:
                    link_opened = True
                    url = download.url
                    outcome.file = {
                        "file_id": download.file_id,
                        "filename": download.filename,
                        "size_bytes": download.size_bytes,
                        "sha256": download.sha256,
                        "md5": download.md5,
                    }
                    if not url:
                        return _fail(
                            "the platform has no address hosts can reach it at; an "
                            "administrator sets HEGEMONY_API_EXTERNAL_URL"
                        )
                    dest_filename = dest_filename_config or download.filename
                    if _has_control_characters(dest_filename):
                        return _fail(
                            "the stored file's name contains a line break or another "
                            "control character; set Destination Filename"
                        )
                    if not _is_plain_file_name(dest_filename):
                        return _fail(
                            "the stored file's name has a directory part; set Destination Filename"
                        )
                    dest_path = f"{directory}/{dest_filename}"
                    # mv would put the file inside a directory of that name and
                    # still succeed, so the step would report a file that is
                    # not there. Asked before anything is downloaded.
                    is_directory = await transport.run(
                        f"test -d {shlex.quote(dest_path)}", timeout=_FINISH_TIMEOUT_SECONDS
                    )
                    if is_directory.exit_code == 0:
                        return _fail(
                            f"{dest_path} is a directory on the host; set Destination "
                            "Filename, or name the directory in Destination Directory"
                        )
                    # A name of its own for every transfer: two runs staging the
                    # same file on one host then never write to, verify or
                    # remove each other's download.
                    staging_path = f"{dest_path}.{secrets.token_hex(4)}{_PARTIAL_SUFFIX}"
                    staged = shlex.quote(staging_path)
                    fetched = await transport.run(
                        download_command(url, staging_path, config.transfer_timeout_seconds),
                        timeout=config.transfer_timeout_seconds + _RUN_MARGIN_SECONDS,
                    )
                # The link is ended here: what follows needs the host only.
                if fetched.exit_code != 0:
                    await _discard()
                    detail = _without_link(_first_line(fetched.stderr or fetched.stdout), url)
                    return _fail(
                        f"curl exited {fetched.exit_code}" + (f" ({detail})" if detail else ""),
                        exit_code=fetched.exit_code,
                    )
                if config.verify_checksum:
                    # Read from standard input: given a file name with a
                    # backslash, sha256sum escapes the name and marks the line
                    # with a leading backslash, which is not part of the digest.
                    summed = await transport.run(
                        f"sha256sum < {staged}", timeout=_FINISH_TIMEOUT_SECONDS
                    )
                    words = summed.stdout.split()
                    actual = words[0].lower() if summed.exit_code == 0 and words else ""
                    expected = str(download.sha256 or "").lower()
                    if not actual or actual != expected:
                        await _discard()
                        if not actual:
                            reason = _first_line(summed.stderr or summed.stdout)
                            return _fail(
                                "the checksum could not be computed on the host"
                                + (f" ({reason})" if reason else "")
                                + "; install sha256sum or turn Verify checksum off"
                            )
                        return _fail(
                            "the downloaded file's SHA-256 does not match the stored file's",
                            expected_sha256=expected,
                            actual_sha256=actual,
                        )
                    outcome.verified = True
                moved = await transport.run(
                    f"mv -f {staged} {shlex.quote(dest_path)}", timeout=_FINISH_TIMEOUT_SECONDS
                )
                if moved.exit_code != 0:
                    await _discard()
                    reason = _first_line(moved.stderr or moved.stdout)
                    return _fail(
                        "the downloaded file could not be moved into place"
                        + (f" ({reason})" if reason else "")
                    )
                # A directory that appeared under the name since the check above
                # takes the file inside it, and mv still succeeds. Asked again,
                # so that case is reported as the failure it is.
                in_place = await transport.run(
                    f"test -f {shlex.quote(dest_path)}", timeout=_FINISH_TIMEOUT_SECONDS
                )
                if in_place.exit_code != 0:
                    return _fail(
                        f"{dest_path} is not a regular file after the move; a directory "
                        "of that name may have appeared during the download"
                    )
            except NotImplementedError as exc:
                await _discard()
                if not link_opened:
                    # The host platform has the service but does not implement
                    # it (the SDK's default).
                    return _fail(_NO_DOWNLOAD_LINKS)
                return _fail(_without_link(str(exc) or type(exc).__name__, url))
            except Exception as exc:  # noqa: BLE001 - one host's failure, reported
                # A command that raised (a timeout, a dropped session) may have
                # left the staging file: it is removed if the host still answers.
                await _discard()
                return _fail(_without_link(str(exc) or type(exc).__name__, url))
            finally:
                try:
                    await transport.close()
                except Exception:  # noqa: BLE001 - closing is best-effort
                    logger.debug("shell transport close failed", exc_info=True)

            outcome.transferred = True
            text = f"Downloaded to {dest_path}" + (", SHA-256 verified" if outcome.verified else "")
            if not getattr(transport, "streams_exec_output", False):
                await ctx.emit_output(text + "\n", device=device, command="file download")
            outcome.evidence.append(
                {
                    "kind": "cli_output",
                    "name": artifact_name,
                    "device_id": device_id,
                    "content_text": text,
                    "content_json": {
                        "device_id": device_id,
                        "device_name": device_name,
                        **(outcome.file or {}),
                        "dest_dir": dest_dir,
                        "dest_filename": dest_filename,
                        "dest_path": dest_path,
                        "verified": outcome.verified,
                        "success": True,
                    },
                }
            )
            return outcome

        outcomes = await for_each_target_device(
            target_devices,
            _process_device,
            max_parallel=config.max_parallel_devices,
        )

        errors = [error for outcome in outcomes for error in outcome.errors]
        all_success = all(outcome.success for outcome in outcomes)
        transferred_count = sum(1 for outcome in outcomes if outcome.transferred)
        file_info = next((outcome.file for outcome in outcomes if outcome.file), None) or {}
        filename = str(file_info.get("filename") or "")
        dest_name = dest_filename_config or filename

        if all_success:
            summary = f"{filename or 'File'} downloaded by {transferred_count} host(s)"
        else:
            summary = f"File download failed on some hosts: {'; '.join(errors)}"

        return HandlerResult(
            success=all_success,
            error="; ".join(errors)[:MAX_CHAIN_OUTPUT_CHARS] if errors else None,
            summary=summary[:MAX_CHAIN_OUTPUT_CHARS],
            metrics={
                "device_count": len(target_devices),
                "transferred_count": transferred_count,
                "size_bytes": file_info.get("size_bytes"),
            },
            evidence=[item for outcome in outcomes for item in outcome.evidence],
            output={
                "file_id": file_id,
                "filename": filename,
                "dest_dir": dest_dir,
                "dest_filename": dest_name,
                "dest_path": f"{directory}/{dest_name}" if dest_name else "",
                "size_bytes": file_info.get("size_bytes"),
                "sha256": file_info.get("sha256"),
                "md5": file_info.get("md5"),
                "verified": config.verify_checksum and all_success,
                "transferred_count": transferred_count,
            },
        )
