# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The stage step's skip-if-already-staged path, made reachable.

Historically the skip required an expected file size that no configuration
field supplies, so every rerun re-transferred the image. The gate is now the
MD5 checksum: an existing file that verifies on the device is skipped, one
that fails the check (or has no checksum to prove it) is transferred again.
A raw-definition ``expected_size`` is the no-checksum fallback.
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
    error: str | None = None


class _FakeTransport:
    """Scripted SSH transport: dir listing, verify /md5 (in order), HTTP transfer.

    After a transfer, a dir that answered "No such file" lists the file.
    """

    def __init__(self, *, dir_output: str, md5_outputs: list[str] | None = None) -> None:
        self._dir_output = dir_output
        self._md5_outputs = list(md5_outputs or [])
        self.transfers: list[str] = []
        self.commands: list[str] = []

    async def execute_commands(self, commands):
        self.commands.extend(commands)
        if self.transfers and "No such file" in self._dir_output:
            return [_Result(_EXISTS)]
        return [_Result(self._dir_output)]

    async def execute_command_timing(self, command, **kwargs):
        self.commands.append(command)
        return _Result(self._md5_outputs.pop(0))

    async def http_transfer(self, *, url, dest_fs, dest_filename, timeout_seconds):
        self.transfers.append(f"{dest_fs}{dest_filename}")
        return {"transferred": True, "output": "Copied file"}


_MD5 = "0123456789abcdef0123456789abcdef"
# What IOS-XE prints for "verify /md5 <file> <hash>": a match, and a mismatch.
_VERIFIED = f"..........Done!\nVerified (flash:img.bin) = {_MD5}\n"
_MISMATCH = (
    "..........Done!\n"
    "%Error verifying flash:img.bin\n"
    "Computed signature d41d8cd98f00b204e9800998ecf8427e\n"
    f"Submitted signature {_MD5}\n"
)
_EXISTS = "-rw-  987654321  Jan 1 2026  img.bin"
_MISSING = "%Error opening flash:img.bin (No such file or directory)"
# The IOS-XE dir format the size parser understands: index, size, date, name.
_EXISTS_SIZED = "  3   987654321 Jan 25 2026 12:19:36.0000000000 +00:00 img.bin"


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
    ssh = _FakeTransport(dir_output=_EXISTS, md5_outputs=[_VERIFIED])
    result = await _stage(ssh, expected_md5=_MD5)
    assert result.success and result.skipped and result.hash_verified
    assert ssh.transfers == []


@pytest.mark.asyncio
async def test_existing_file_failing_md5_is_retransferred():
    ssh = _FakeTransport(
        dir_output=_EXISTS,
        md5_outputs=[_MISMATCH, _VERIFIED],
    )
    result = await _stage(ssh, expected_md5=_MD5)
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
    ssh = _FakeTransport(dir_output=_EXISTS, md5_outputs=[_VERIFIED])
    result = await _stage(ssh, expected_md5=_MD5, overwrite=True)
    assert result.success and not result.skipped
    assert ssh.transfers == ["flash:img.bin"]
    # Overwrite skips the pre-check entirely; verification still runs after.
    assert sum("verify /md5" in c for c in ssh.commands) == 1


@pytest.mark.asyncio
async def test_missing_file_is_transferred():
    ssh = _FakeTransport(dir_output=_MISSING, md5_outputs=[_VERIFIED])
    result = await _stage(ssh, expected_md5=_MD5)
    assert result.success and not result.skipped
    assert ssh.transfers == ["flash:img.bin"]


@pytest.mark.asyncio
async def test_unimplemented_transfer_method_is_an_error_not_a_false_success():
    """An explicit tftp used to skip the transfer and report success anyway."""
    ssh = _FakeTransport(dir_output=_MISSING)
    result = await _stage(ssh, transfer_method="tftp", select_transfer_method_fn=lambda **_: "tftp")
    assert result.success is False
    assert "not implemented" in (result.error or "")
    assert ssh.transfers == []


@pytest.mark.asyncio
async def test_existing_file_matching_expected_size_is_skipped_without_md5():
    """The no-checksum fallback: a raw-definition expected_size reuses the file."""
    ssh = _FakeTransport(dir_output=_EXISTS_SIZED)
    result = await _stage(ssh, expected_size=987654321)
    assert result.success and result.skipped and not result.hash_verified
    assert ssh.transfers == []


@pytest.mark.asyncio
async def test_existing_file_with_wrong_expected_size_is_retransferred():
    ssh = _FakeTransport(dir_output=_EXISTS_SIZED)
    result = await _stage(ssh, expected_size=1234)
    assert ssh.transfers == ["flash:img.bin"]
    # The fake still reports the old size after the transfer, so the
    # post-transfer size verification fails - also worth pinning.
    assert result.success is False
    assert "Size mismatch" in (result.error or "")


@pytest.mark.asyncio
async def test_scp_transfer_method_is_an_error_not_a_false_success():
    """SCP was never implemented; a legacy stored value fails explicitly."""
    ssh = _FakeTransport(dir_output=_MISSING)
    result = await _stage(ssh, transfer_method="scp", select_transfer_method_fn=lambda **_: "scp")
    assert result.success is False
    assert "not implemented" in (result.error or "")
    assert ssh.transfers == []


@pytest.mark.asyncio
async def test_non_http_source_url_is_rejected_before_transfer():
    ssh = _FakeTransport(dir_output=_MISSING)
    result = await _stage(ssh, source_url="ftp://repo.example/img.bin")
    assert result.success is False
    assert "not an HTTP(S) URL" in (result.error or "")
    assert ssh.transfers == []


@pytest.mark.asyncio
async def test_legacy_expected_sha256_config_is_rejected_not_ignored():
    """extra="allow" accepts the removed field; the handler must fail it loudly."""
    from types import SimpleNamespace

    from hegemony_steps_cisco_iosxe.upgrade.handlers.stage import UpgradeStageHandler

    handler = UpgradeStageHandler.__new__(UpgradeStageHandler)
    ctx: Any = SimpleNamespace(config={"expected_sha256": "deadbeef"})
    result = await UpgradeStageHandler.execute(handler, ctx)
    assert result.success is False
    assert "expected_sha256" in (result.error or "")
