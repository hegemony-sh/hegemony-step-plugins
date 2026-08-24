# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The stage step's skip-if-already-staged path, made reachable.

Historically the skip required an expected file size that no configuration
field supplies, so every rerun re-transferred the image. The gate is now the
MD5 checksum: an existing file that verifies on the device is skipped, one
that fails the check (or has no checksum to prove it) is transferred again.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_common import stage_image


@dataclass
class _Result:
    output: str
    exit_code: int = 0


class _FakeTransport:
    """Scripted SSH transport: dir listing, verify /md5 (in order), HTTP transfer."""

    def __init__(self, *, dir_output: str, md5_outputs: list[str] | None = None) -> None:
        self._dir_output = dir_output
        self._md5_outputs = list(md5_outputs or [])
        self.transfers: list[str] = []
        self.commands: list[str] = []

    async def execute_commands(self, commands):
        self.commands.extend(commands)
        return [_Result(self._dir_output)]

    async def execute_command_timing(self, command, **kwargs):
        self.commands.append(command)
        return _Result(self._md5_outputs.pop(0))

    async def http_transfer(self, *, url, dest_fs, dest_filename, timeout_seconds):
        self.transfers.append(f"{dest_fs}{dest_filename}")
        return {"transferred": True, "output": "Copied file"}


_EXISTS = "-rw-  987654321  Jan 1 2026  img.bin"
_MISSING = "%Error opening flash:img.bin (No such file or directory)"


def _select(preferred, http_url_available):
    return "https"


async def _stage(ssh, **overrides: Any):
    kwargs: dict[str, Any] = dict(
        source_url="https://repo.example/img.bin",
        dest_fs="flash:",
        dest_filename="img.bin",
        transfer_method="auto",
        expected_md5=None,
        expected_size=None,
        overwrite=False,
        select_transfer_method_fn=_select,
    )
    kwargs.update(overrides)
    return await stage_image(ssh, **kwargs)


@pytest.mark.asyncio
async def test_existing_file_with_verified_md5_is_skipped():
    ssh = _FakeTransport(dir_output=_EXISTS, md5_outputs=["Verified (flash:img.bin)"])
    result = await _stage(ssh, expected_md5="abc123")
    assert result.success and result.skipped and result.hash_verified
    assert ssh.transfers == []


@pytest.mark.asyncio
async def test_existing_file_failing_md5_is_retransferred():
    ssh = _FakeTransport(
        dir_output=_EXISTS,
        md5_outputs=["%Error: hash does not match", "Verified (flash:img.bin)"],
    )
    result = await _stage(ssh, expected_md5="abc123")
    assert result.success and not result.skipped
    assert ssh.transfers == ["flash:img.bin"]


@pytest.mark.asyncio
async def test_existing_file_without_checksum_is_retransferred():
    """No proof the file is right - re-transferring beats trusting the name."""
    ssh = _FakeTransport(dir_output=_EXISTS)
    result = await _stage(ssh)
    assert result.success and not result.skipped
    assert ssh.transfers == ["flash:img.bin"]


@pytest.mark.asyncio
async def test_overwrite_forces_transfer_despite_verified_md5():
    ssh = _FakeTransport(dir_output=_EXISTS, md5_outputs=["Verified (flash:img.bin)"])
    result = await _stage(ssh, expected_md5="abc123", overwrite=True)
    assert result.success and not result.skipped
    assert ssh.transfers == ["flash:img.bin"]
    # Overwrite skips the pre-check entirely; verification still runs after.
    assert sum("verify /md5" in c for c in ssh.commands) == 1


@pytest.mark.asyncio
async def test_missing_file_is_transferred():
    ssh = _FakeTransport(dir_output=_MISSING, md5_outputs=["Verified (flash:img.bin)"])
    result = await _stage(ssh, expected_md5="abc123")
    assert result.success and not result.skipped
    assert ssh.transfers == ["flash:img.bin"]
