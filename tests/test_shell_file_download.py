# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``shell.file_download``: each host downloads a file-repository file with curl.

The host's ``open_file_download`` and ``open_shell`` services are fakes that
record what they were asked for: a link per host, opened after the connection
and closed before the checksum, and the commands the host was told to run.
"""

from __future__ import annotations

import shlex
from contextlib import asynccontextmanager
from typing import Any, cast

import pytest

from hegemony_step_sdk import (
    FileDownload,
    HandlerContext,
    HandlerResult,
    HandlerServices,
    ShellResult,
)
from hegemony_step_sdk.docs import check_page, load_docs_bundle
from hegemony_steps_shell import file_download
from hegemony_steps_shell.file_download import (
    ShellFileDownloadConfig,
    ShellFileDownloadHandler,
    download_command,
)

FILE_ID = "0c7f1ee3-d824-4dea-9c07-bd44e5fe188b"
FILENAME = "app-release-1.4.2.tar.gz"
BASE = "https://hegemony.example.com/api"
SHA256 = "ab" * 32


class FakeShell:
    def __init__(self, services: FakeServices, device: dict[str, Any]) -> None:
        self.services = services
        self.device = device
        self.closed = False

    async def run(self, command: str, *, timeout: float | None = None) -> ShellResult:
        name = self.device["name"]
        program = command.split()[0]
        self.services.events.append(f"{program}:{name}")
        self.services.commands.append({"device": name, "command": command, "timeout": timeout})
        answer = self.services.answers.get((name, program))
        if isinstance(answer, Exception):
            raise answer
        if answer is not None:
            return ShellResult(command, *answer)
        if program == "sha256sum":
            return ShellResult(command, 0, f"{SHA256}  -\n", "")
        if program == "test":
            # ``test -d``: the destination is not a directory.
            return ShellResult(command, 1, "", "")
        return ShellResult(command, 0, "", "")

    async def close(self) -> None:
        self.closed = True
        self.services.events.append(f"close-shell:{self.device['name']}")


class FakeServices:
    """A host that issues a numbered link per request and records the commands."""

    def __init__(self, *, url_base: str = BASE, filename: str = FILENAME) -> None:
        self.filename = filename
        self.url_base = url_base
        self.events: list[str] = []
        self.opened: list[dict[str, Any]] = []
        self.commands: list[dict[str, Any]] = []
        self.shells: list[dict[str, Any]] = []
        #: (device name, program) -> (exit code, stdout, stderr) or an exception.
        self.answers: dict[tuple[str, str], Any] = {}
        self.open_error: Exception | None = None
        self.shell_error: Exception | None = None

    @asynccontextmanager
    async def open_file_download(self, file_id: str, *, ttl_seconds: int = 600):
        if self.open_error is not None:
            raise self.open_error
        number = len(self.opened) + 1
        self.opened.append({"file_id": file_id, "ttl_seconds": ttl_seconds})
        self.events.append(f"open:{number}")
        path = f"/dl/hgm_run_token{number}/{FILENAME}"
        try:
            yield FileDownload(
                file_id=file_id,
                filename=self.filename,
                size_bytes=1024,
                sha256=SHA256,
                md5="cd" * 16,
                url=f"{self.url_base}{path}" if self.url_base else "",
                worker_url=f"http://api:8000{path}",
                expires_at="2026-11-12T12:00:00+00:00",
            )
        finally:
            self.events.append(f"close:{number}")

    async def open_shell(self, device: dict[str, Any], **kwargs: Any) -> FakeShell:
        if self.shell_error is not None:
            raise self.shell_error
        self.shells.append({"device": device["name"], **kwargs})
        self.events.append(f"shell:{device['name']}")
        return FakeShell(self, device)


@pytest.fixture(autouse=True)
def _fixed_staging_name(monkeypatch):
    """Staging files get the same "random" part in every test."""
    monkeypatch.setattr(file_download.secrets, "token_hex", lambda size: "0a1b2c3d")


def _device(name: str, host: str | None = "192.0.2.1") -> dict:
    device: dict[str, Any] = {"id": f"id-{name}", "name": name, "platform": "linux"}
    if host:
        device["mgmt_host"] = host
    return device


async def _run(
    services: Any, config: dict[str, Any], devices: list[dict] | None = None
) -> tuple[HandlerResult, list[dict[str, Any]]]:
    emitted: list[dict[str, Any]] = []

    async def emit(message: str, device_id: Any, attrs: dict[str, Any]) -> bool:
        emitted.append({"message": message, "device_id": device_id, "attrs": attrs})
        return True

    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="stage",
        config=config,
        target_roles=["primary"],
        target_devices_by_role={"primary": devices if devices is not None else [_device("srv1")]},
        services=cast(HandlerServices, services),
        _emit_progress=emit,
    )
    return await ShellFileDownloadHandler().execute(ctx), emitted


def _commands(services: FakeServices, device: str = "srv1") -> list[str]:
    return [entry["command"] for entry in services.commands if entry["device"] == device]


@pytest.mark.asyncio
async def test_the_host_downloads_verifies_and_moves_the_file_into_place():
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is True, result.error
    link = f"{BASE}/dl/hgm_run_token1/{FILENAME}"
    part = f"/var/tmp/{FILENAME}.0a1b2c3d.part"
    assert _commands(services) == [
        f"test -d /var/tmp/{FILENAME}",
        f"curl -fsS --max-time 3600 -o {part} {link}",
        f"sha256sum < {part}",
        f"mv -f {part} /var/tmp/{FILENAME}",
    ]
    assert services.commands[1]["timeout"] == 3615
    assert result.output == {
        "file_id": FILE_ID,
        "filename": FILENAME,
        "dest_dir": "/var/tmp",
        "dest_filename": FILENAME,
        "dest_path": f"/var/tmp/{FILENAME}",
        "size_bytes": 1024,
        "sha256": SHA256,
        "md5": "cd" * 16,
        "verified": True,
        "transferred_count": 1,
    }
    assert result.metrics == {"device_count": 1, "transferred_count": 1, "size_bytes": 1024}
    assert result.summary == f"{FILENAME} downloaded by 1 host(s)"
    [artifact] = result.evidence
    assert artifact["name"] == "File download"
    assert artifact["content_json"]["dest_path"] == f"/var/tmp/{FILENAME}"
    assert artifact["content_json"]["verified"] is True


@pytest.mark.asyncio
async def test_the_link_is_opened_after_the_connection_and_closed_before_the_checksum():
    services = FakeServices()

    await _run(services, {"file_ids": [FILE_ID]}, [_device("a"), _device("b")])

    assert services.events == [
        "shell:a",
        "open:1",
        "test:a",
        "curl:a",
        "close:1",
        "sha256sum:a",
        "mv:a",
        "close-shell:a",
        "shell:b",
        "open:2",
        "test:b",
        "curl:b",
        "close:2",
        "sha256sum:b",
        "mv:b",
        "close-shell:b",
    ]
    assert [entry["ttl_seconds"] for entry in services.opened] == [600, 600]


@pytest.mark.asyncio
async def test_the_link_never_reaches_evidence_output_or_the_live_log():
    services = FakeServices()
    link = f"{BASE}/dl/hgm_run_token1/{FILENAME}"
    services.answers[("srv1", "curl")] = (22, "", f"curl: (22) error fetching {link}\n")

    result, emitted = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    reported = f"{result.error} {result.summary} {result.evidence} {result.output} {emitted}"
    assert "hgm_run_token" not in reported
    assert "<download link>" in (result.error or "")


@pytest.mark.asyncio
async def test_destination_name_and_timeout_come_from_the_config():
    services = FakeServices()

    result, _ = await _run(
        services,
        {
            "file_ids": FILE_ID,
            "dest_dir": "/opt/releases/",
            "dest_filename": "current.tar.gz",
            "transfer_timeout_seconds": 120,
        },
    )

    assert result.success is True, result.error
    assert _commands(services)[1].startswith(
        "curl -fsS --max-time 120 -o /opt/releases/current.tar.gz.0a1b2c3d.part "
    )
    assert _commands(services)[-1] == (
        "mv -f /opt/releases/current.tar.gz.0a1b2c3d.part /opt/releases/current.tar.gz"
    )
    assert result.output["dest_path"] == "/opt/releases/current.tar.gz"
    assert result.output["dest_dir"] == "/opt/releases/"


@pytest.mark.asyncio
async def test_names_with_spaces_and_shell_characters_are_quoted_as_single_words():
    services = FakeServices()

    result, _ = await _run(
        services,
        {"file_ids": [FILE_ID], "dest_dir": "/srv/my files", "dest_filename": "a b;$(id).bin"},
    )

    assert result.success is True, result.error
    for command in _commands(services):
        words = shlex.split(command)
        assert any(word.startswith("/srv/my files/a b;$(id).bin") for word in words)
        assert "$(id).bin" not in command.replace("'/srv/my files/a b;$(id).bin", "")


@pytest.mark.asyncio
async def test_without_the_check_the_file_is_moved_right_after_the_download():
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID], "verify_checksum": False})

    assert result.success is True, result.error
    assert [command.split()[0] for command in _commands(services)] == ["test", "curl", "mv"]
    assert result.output["verified"] is False


@pytest.mark.asyncio
async def test_a_failed_download_is_removed_and_reported_with_curls_message():
    services = FakeServices()
    services.answers[("srv1", "curl")] = (23, "", "curl: (23) Failure writing output\n")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "curl exited 23 (curl: (23) Failure writing output)" in (result.error or "")
    assert [command.split()[0] for command in _commands(services)] == ["test", "curl", "rm"]
    assert _commands(services)[2] == f"rm -f /var/tmp/{FILENAME}.0a1b2c3d.part"
    assert result.output["transferred_count"] == 0
    assert result.output["verified"] is False


@pytest.mark.asyncio
async def test_a_checksum_that_does_not_match_removes_the_file_and_fails_the_host():
    services = FakeServices()
    services.answers[("srv1", "sha256sum")] = (0, f"{'00' * 32}  x\n", "")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "does not match" in (result.error or "")
    assert [command.split()[0] for command in _commands(services)] == [
        "test",
        "curl",
        "sha256sum",
        "rm",
    ]
    [artifact] = result.evidence
    assert artifact["content_json"]["expected_sha256"] == SHA256
    assert artifact["content_json"]["actual_sha256"] == "00" * 32


@pytest.mark.asyncio
async def test_a_host_without_sha256sum_says_how_to_go_on():
    services = FakeServices()
    services.answers[("srv1", "sha256sum")] = (127, "", "sh: sha256sum: not found\n")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "could not be computed" in (result.error or "")
    assert "turn Verify checksum off" in (result.error or "")
    assert _commands(services)[-1].startswith("rm -f ")


@pytest.mark.asyncio
async def test_a_file_that_cannot_be_moved_into_place_fails_the_host():
    services = FakeServices()
    services.answers[("srv1", "mv")] = (1, "", "mv: cannot move: Permission denied\n")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "could not be moved into place (mv: cannot move: Permission denied)" in (
        result.error or ""
    )


@pytest.mark.asyncio
async def test_one_failing_host_fails_the_step_and_the_others_still_download():
    services = FakeServices()
    services.answers[("b", "curl")] = (7, "", "curl: (7) Failed to connect\n")

    result, _ = await _run(
        services, {"file_ids": [FILE_ID]}, [_device("a"), _device("b"), _device("c")]
    )

    assert result.success is False
    assert result.output["transferred_count"] == 2
    assert "b: curl exited 7" in (result.error or "")
    names = [item["name"] for item in result.evidence]
    assert names == ["File download (a)", "Error (b)", "File download (c)"]


@pytest.mark.asyncio
async def test_a_connection_that_fails_asks_for_no_link():
    services = FakeServices()
    services.shell_error = ConnectionError("connection refused")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "connection refused" in (result.error or "")
    assert services.opened == []


@pytest.mark.asyncio
async def test_a_command_error_is_reported_without_the_link_and_the_session_is_closed():
    services = FakeServices()
    link = f"{BASE}/dl/hgm_run_token1/{FILENAME}"
    services.answers[("srv1", "curl")] = TimeoutError(f"timed out running curl {link}")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "hgm_run_token" not in (result.error or "")
    # The download that may have started is removed before the session closes.
    assert services.events[-3:] == ["close:1", "rm:srv1", "close-shell:srv1"]


@pytest.mark.asyncio
async def test_a_cleanup_that_fails_does_not_hide_why_the_download_failed():
    services = FakeServices()
    services.answers[("srv1", "curl")] = TimeoutError("timed out")
    services.answers[("srv1", "rm")] = ConnectionError("session lost")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "timed out" in (result.error or "")
    assert "session lost" not in (result.error or "")


@pytest.mark.asyncio
async def test_a_checksum_command_that_raises_removes_the_download():
    services = FakeServices()
    services.answers[("srv1", "sha256sum")] = TimeoutError("timed out")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert _commands(services)[-1] == f"rm -f /var/tmp/{FILENAME}.0a1b2c3d.part"


@pytest.mark.asyncio
async def test_a_destination_that_is_a_directory_is_refused_before_the_download():
    services = FakeServices()
    services.answers[("srv1", "test")] = (0, "", "")

    result, _ = await _run(services, {"file_ids": [FILE_ID], "dest_filename": "releases"})

    assert result.success is False
    assert "/var/tmp/releases is a directory on the host" in (result.error or "")
    assert _commands(services) == ["test -d /var/tmp/releases"]


@pytest.mark.asyncio
async def test_each_transfer_stages_under_a_name_of_its_own(monkeypatch):
    names = iter(["aaaa1111", "bbbb2222"])
    monkeypatch.setattr(file_download.secrets, "token_hex", lambda size: next(names))
    services = FakeServices()

    await _run(services, {"file_ids": [FILE_ID]})
    await _run(services, {"file_ids": [FILE_ID]})

    staged = [c.split(" -o ")[1].split()[0] for c in _commands(services) if c.startswith("curl")]
    assert staged == [
        f"/var/tmp/{FILENAME}.aaaa1111.part",
        f"/var/tmp/{FILENAME}.bbbb2222.part",
    ]


@pytest.mark.asyncio
async def test_the_checksum_is_read_from_standard_input_so_a_backslash_changes_nothing():
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID], "dest_filename": "a\\b.bin"})

    assert result.success is True, result.error
    [checksum] = [c for c in _commands(services) if c.startswith("sha256sum")]
    assert checksum.startswith("sha256sum < ")


@pytest.mark.asyncio
async def test_without_an_address_hosts_can_reach_nothing_is_run():
    services = FakeServices(url_base="")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "HEGEMONY_API_EXTERNAL_URL" in (result.error or "")
    assert services.commands == []


@pytest.mark.asyncio
async def test_a_file_the_organization_does_not_have_fails_the_host():
    services = FakeServices()
    services.open_error = LookupError("No file in the run's organization's file repositories")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "No file" in (result.error or "")
    assert services.commands == []


@pytest.mark.asyncio
async def test_a_host_platform_that_does_not_implement_links_says_so():
    services = FakeServices()
    services.open_error = NotImplementedError()

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "upgrade the platform" in (result.error or "")


@pytest.mark.asyncio
async def test_a_platform_without_download_links_is_reported_clearly():
    class OldServices:
        pass

    result, _ = await _run(OldServices(), {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "upgrade the platform" in (result.error or "")


@pytest.mark.asyncio
async def test_a_device_without_a_management_host_is_not_contacted():
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]}, [_device("srv1", host=None)])

    assert result.success is False
    assert "no mgmt_host configured" in (result.error or "")
    assert services.shells == [] and services.opened == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("file_ids", "message"),
    [([], "No file repository file selected"), ([FILE_ID, FILE_ID], "exactly one")],
)
async def test_exactly_one_file_must_be_selected(file_ids, message):
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": file_ids})

    assert result.success is False
    assert message in (result.error or "")
    assert services.shells == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("config", "message"),
    [
        ({"dest_dir": "releases"}, "must be an absolute path"),
        ({"dest_dir": "/tmp\nrm -rf /"}, "Destination Directory contains a line break"),
        ({"dest_filename": "a\rb"}, "Destination Filename contains a line break"),
        ({"dest_filename": "../x"}, "without a directory part"),
        ({"dest_filename": "sub/x"}, "without a directory part"),
        ({"dest_filename": ".."}, "without a directory part"),
    ],
)
async def test_a_bad_destination_is_refused_before_any_host_is_contacted(config, message):
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID], **config})

    assert result.success is False
    assert message in (result.error or "")
    assert services.shells == []


@pytest.mark.asyncio
@pytest.mark.parametrize("filename", ["evil\nname.bin", "dir/name.bin", ".."])
async def test_a_stored_file_name_that_is_not_a_plain_name_needs_a_destination_name(filename):
    services = FakeServices(filename=filename)

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "set Destination Filename" in (result.error or "")
    assert services.commands == []


@pytest.mark.asyncio
async def test_legacy_ssh_is_passed_to_the_shell_only_when_asked_for():
    services = FakeServices()

    await _run(services, {"file_ids": [FILE_ID]})
    await _run(services, {"file_ids": [FILE_ID], "allow_legacy_ssh": True})

    assert services.shells == [
        {"device": "srv1"},
        {"device": "srv1", "allow_legacy_ssh": True},
    ]


@pytest.mark.asyncio
async def test_no_target_devices_fails_before_anything_is_asked():
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]}, [])

    assert result.success is False
    assert result.error == "No target devices configured"
    assert services.shells == []


def test_the_download_command_follows_no_redirect_and_fails_on_an_http_error():
    command = download_command("http://a/dl/t/f", "/tmp/f.part", 90)

    assert command == "curl -fsS --max-time 90 -o /tmp/f.part http://a/dl/t/f"
    assert "-L" not in command.split()


def test_the_config_takes_one_id_as_text_and_marks_the_field_for_the_file_picker():
    config = ShellFileDownloadConfig.model_validate({"file_ids": FILE_ID})
    assert config.file_ids == [FILE_ID]
    assert config.dest_dir == "/var/tmp"
    assert config.verify_checksum is True
    assert config.transfer_timeout_seconds == 3600

    field = ShellFileDownloadConfig.model_json_schema()["properties"]["file_ids"]
    assert field["x_widget"] == "repository-file-select"
    assert field["x_multiple"] is False


def test_the_handler_declares_what_the_editor_and_engine_read():
    handler = ShellFileDownloadHandler
    assert handler.handler_id == "shell.file_download"
    assert handler.targeting.roles is True and handler.targeting.ips is False
    assert handler.default_timeout_seconds == 7200
    assert handler.run_timeout_field is None


def test_the_docs_page_satisfies_the_contract():
    bundle = load_docs_bundle("hegemony_steps_shell")
    text = bundle["shell.file_download"]
    assert check_page("shell.file_download", text) == []
