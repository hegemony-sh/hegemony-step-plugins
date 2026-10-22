# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The on-device MD5 check fails closed.

``verify /md5 <file> <hash>`` reports a mismatch with ``%Error verifying``
and exit code 0, so only the device's own ``Verified (<file>) = <hash>``
line with the expected hash may pass. Everything else fails: errors, an
unreachable device, output nobody recognises.
"""

from __future__ import annotations

from typing import Any

import pytest

from hegemony_steps_cisco_iosxe.upgrade.cisco.iosxe_common import stage_image, verify_md5
from hegemony_steps_cisco_iosxe.upgrade.handlers.stage import (
    UpgradeStageConfig,
    UpgradeStageHandler,
)
from tests.iosxe_fakes import UNREACHABLE, FakeServices, Result, ScriptedTransport, make_ctx

EXPECTED = "0123456789abcdef0123456789abcdef"
OTHER = "d41d8cd98f00b204e9800998ecf8427e"
MATCH = f"....................Done!\nVerified (flash:img.bin) = {EXPECTED}\n"
MISMATCH = (
    "....................Done!\n"
    "%Error verifying flash:img.bin\n"
    f"Computed signature {OTHER}\n"
    f"Submitted signature {EXPECTED}\n"
)
MISSING = "%Error opening flash:img.bin (No such file or directory)"
LISTED = "  3   987654321 Jan 25 2026 12:19:36.0000000000 +00:00 img.bin"
# The dir before the transfer, then the one after it.
DIRS = [Result(MISSING), Result(LISTED)]


async def _verify(result: Result, expected: str = EXPECTED):
    ssh = ScriptedTransport({"verify /md5": result})
    return await verify_md5(ssh, "flash:img.bin", expected), ssh


async def test_matching_hash_is_verified():
    check, _ = await _verify(Result(MATCH))
    assert check.verified is True
    assert check.computed == EXPECTED


async def test_real_ios_mismatch_is_not_verified():
    check, _ = await _verify(Result(MISMATCH))
    assert check.verified is False
    assert check.computed == OTHER


async def test_not_verified_wording_is_not_verified():
    check, _ = await _verify(Result("%Error: signature not verified\n"))
    assert check.verified is False


async def test_empty_output_is_not_verified():
    check, _ = await _verify(Result(""))
    assert check.verified is False
    assert check.computed is None


async def test_unreachable_device_is_not_verified():
    check, _ = await _verify(UNREACHABLE)
    assert check.verified is False
    assert "Connection timeout" in check.cli_output


async def test_verified_line_with_another_hash_is_not_verified():
    check, _ = await _verify(Result(f"Verified (flash:img.bin) = {OTHER}\n"))
    assert check.verified is False
    assert check.computed == OTHER


async def test_verified_line_with_a_cli_error_code_is_not_verified():
    check, _ = await _verify(Result(MATCH, exit_code=1, error="% Invalid input detected"))
    assert check.verified is False


async def test_uppercase_expected_hash_matches():
    check, ssh = await _verify(Result(MATCH), expected=f"  {EXPECTED.upper()} ")
    assert check.verified is True
    assert ssh.commands == [f"verify /md5 flash:img.bin {EXPECTED}"]


async def test_malformed_expected_hash_is_refused_before_the_device():
    ssh = ScriptedTransport()
    with pytest.raises(ValueError, match="32 hexadecimal"):
        await verify_md5(ssh, "flash:img.bin", "abc123; reload")
    assert ssh.commands == []


async def _stage(ssh: ScriptedTransport, **overrides: Any):
    kwargs: dict[str, Any] = dict(
        source_url="https://repo.example/img.bin",
        dest_fs="flash:",
        dest_filename="img.bin",
        transfer_method="auto",
        expected_md5=EXPECTED,
        expected_size=None,
        overwrite=False,
        select_transfer_method_fn=lambda **_: "https",
    )
    kwargs.update(overrides)
    return await stage_image(ssh, **kwargs)


async def test_stage_fails_on_a_real_mismatch_and_records_the_computed_hash():
    ssh = ScriptedTransport({"dir": DIRS, "verify /md5": Result(MISMATCH)})
    result = await _stage(ssh)
    assert result.success is False
    assert result.hash_verified is False
    assert result.computed_hash == OTHER
    assert OTHER in (result.error or "")
    assert ssh.transfers == ["flash:img.bin"]


async def test_stage_records_the_hash_the_device_confirmed():
    ssh = ScriptedTransport({"dir": DIRS, "verify /md5": Result(MATCH)})
    result = await _stage(ssh, expected_md5=EXPECTED.upper())
    assert result.success is True
    assert result.verified_hash == EXPECTED
    assert result.computed_hash == EXPECTED


async def test_stage_dir_that_did_not_run_is_an_error_not_an_existing_file():
    ssh = ScriptedTransport({"dir": UNREACHABLE, "verify /md5": Result(MATCH)})
    result = await _stage(ssh)
    assert result.success is False
    assert "Could not list flash:img.bin" in (result.error or "")
    assert ssh.transfers == []
    assert not any(c.startswith("verify") for c in ssh.commands)


def test_config_model_accepts_a_templated_md5():
    # Flow validation runs the model on the unrendered value, so a hash taken
    # from a run input must pass it; execute() checks the rendered value.
    handler = UpgradeStageHandler()
    base = {"source_url": "https://repo.example/img.bin", "dest_filename": "img.bin"}
    assert handler.validate_config({**base, "expected_md5": ""}) == []
    assert handler.validate_config({**base, "expected_md5": EXPECTED.upper()}) == []
    assert handler.validate_config({**base, "expected_md5": "{{ inputs.image_md5 }}"}) == []
    assert UpgradeStageConfig.model_fields["expected_md5"].description


async def test_handler_refuses_a_malformed_md5_before_connecting():
    services = FakeServices(ScriptedTransport)
    ctx = make_ctx(
        {
            "source_url": "https://repo.example/img.bin",
            "dest_filename": "img.bin",
            "expected_md5": "not-a-hash",
        },
        services,
    )
    result = await UpgradeStageHandler().execute(ctx)
    assert result.success is False
    assert "32 hexadecimal" in (result.error or "")
    assert services.connect_calls == []


async def test_handler_evidence_carries_the_computed_hash():
    ssh = ScriptedTransport({"dir": DIRS, "verify /md5": Result(MISMATCH)})
    ctx = make_ctx(
        {
            "source_url": "https://repo.example/img.bin",
            "dest_filename": "img.bin",
            "expected_md5": EXPECTED,
        },
        FakeServices(lambda: ssh),
    )
    result = await UpgradeStageHandler().execute(ctx)
    assert result.success is False
    content = result.evidence[0]["content_json"]
    assert content["computed_hash"] == OTHER
    assert content["hash_verified"] is False


class _ChunkedTransport(ScriptedTransport):
    """Answers a timing command in chunks and stops reading at the first
    chunk that holds a wait pattern, as the netmiko and scrapli transports do."""

    def __init__(self, chunks: list[str]) -> None:
        super().__init__()
        self.chunks = chunks

    async def execute_command_timing(self, command, *, wait_for_patterns=None, **kwargs):
        self.calls.append([command])
        output = ""
        for chunk in self.chunks:
            output += chunk
            if any(p.lower() in output.lower() for p in wait_for_patterns or []):
                break
        return Result(output, command=command)


async def test_mismatch_split_over_reads_still_records_the_computed_hash():
    """ "%Error verifying" comes before the hashes; reading must not stop there."""
    ssh = _ChunkedTransport(
        [
            "....................Done!\n%Error verifying flash:img.bin\n",
            f"Computed signature {OTHER}\n",
            f"Submitted signature {EXPECTED}\n",
        ]
    )
    check = await verify_md5(ssh, "flash:img.bin", EXPECTED)
    assert check.verified is False
    assert check.computed == OTHER


async def test_verified_line_split_over_reads_is_read_to_the_end():
    ssh = _ChunkedTransport(
        [
            f"....................Done!\nVerified (flash:img.bin) = {EXPECTED[:16]}",
            f"{EXPECTED[16:]}\n",
        ]
    )
    check = await verify_md5(ssh, "flash:img.bin", EXPECTED)
    assert check.verified is True
    assert check.computed == EXPECTED


async def test_verified_line_for_another_file_is_not_verified():
    check, _ = await _verify(Result(f"Verified (flash:other.bin) = {EXPECTED}\n"))
    assert check.verified is False


async def test_verified_line_may_name_the_file_on_bootflash():
    """flash: and bootflash: are one filesystem, and "fs:/name" is "fs:name"."""
    check, _ = await _verify(Result(f"Verified (bootflash:/img.bin) = {EXPECTED}\n"))
    assert check.verified is True
