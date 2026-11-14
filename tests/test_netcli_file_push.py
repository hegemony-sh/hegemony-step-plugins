# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``netcli.file_push``: the worker fetches a file once and copies it to each target.

The host's ``open_file_download`` service, the platform's download route and
the device transport are fakes. They record the order of things: the link is
opened, the file fetched and checked, the link closed, and only then is the
file copied to the targets and the worker's copy removed.
"""

from __future__ import annotations

import hashlib
import os
from contextlib import asynccontextmanager
from typing import Any, cast

import httpx
import pytest

from hegemony_step_sdk import FileDownload, HandlerContext, HandlerResult, HandlerServices
from hegemony_step_sdk.docs import check_page, load_docs_bundle
from hegemony_steps_netcli import file_push
from hegemony_steps_netcli.file_push import FilePushConfig, FilePushHandler

FILE_ID = "0c7f1ee3-d824-4dea-9c07-bd44e5fe188b"
FILENAME = "cat9k_iosxe.17.09.05.SPA.bin"
CONTENT = b"software image " * 200
SHA256 = hashlib.sha256(CONTENT).hexdigest()
WORKER_URL = f"http://api:8000/dl/hgm_run_token1/{FILENAME}"


class FakeTransport:
    def __init__(self, services: FakeServices, device: dict[str, Any]) -> None:
        self.services = services
        self.device = device

    def configure_ssh_security(self, *, allow_legacy: bool) -> None:
        self.services.legacy.append(allow_legacy)

    async def scp_put(
        self, *, local_path: str, dest_fs: str, dest_filename: str, overwrite: bool = False
    ) -> dict:
        name = self.device["name"]
        self.services.events.append(f"put:{name}")
        with open(local_path, "rb") as source:
            sent = source.read()
        self.services.puts.append(
            {
                "device": name,
                "local_path": local_path,
                "mode": os.stat(local_path).st_mode & 0o777,
                "content": sent,
                "dest_fs": dest_fs,
                "dest_filename": dest_filename,
                "overwrite": overwrite,
            }
        )
        answer = self.services.answers.get(name)
        if isinstance(answer, Exception):
            raise answer
        return answer or {"transferred": True, "verified": True, "exists": True, "elapsed_ms": 3.0}


class FakeServices:
    """A host that issues one link and records what the targets were sent."""

    def __init__(
        self,
        *,
        filename: str = FILENAME,
        size_bytes: int = len(CONTENT),
        sha256: str = SHA256,
        worker_url: str = WORKER_URL,
    ) -> None:
        self.filename = filename
        self.size_bytes = size_bytes
        self.sha256 = sha256
        self.worker_url = worker_url
        self.events: list[str] = []
        self.opened: list[dict[str, Any]] = []
        self.puts: list[dict[str, Any]] = []
        self.connects: list[dict[str, Any]] = []
        self.legacy: list[bool] = []
        self.answers: dict[str, Any] = {}
        self.open_error: Exception | None = None

    @asynccontextmanager
    async def open_file_download(self, file_id: str, *, ttl_seconds: int = 600):
        if self.open_error is not None:
            raise self.open_error
        self.opened.append({"file_id": file_id, "ttl_seconds": ttl_seconds})
        self.events.append("open")
        try:
            yield FileDownload(
                file_id=file_id,
                filename=self.filename,
                size_bytes=self.size_bytes,
                sha256=self.sha256,
                md5="cd" * 16,
                url="",
                worker_url=self.worker_url,
                expires_at="2026-11-12T12:00:00+00:00",
            )
        finally:
            self.events.append("close")

    def connect(self, device: dict[str, Any], *, platform: str | None = None, **kwargs: Any):
        self.connects.append({"device": device["name"], "platform": platform, **kwargs})
        return FakeTransport(self, device)


class Platform:
    """The platform's download route: answers the link with the file."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.body = CONTENT
        self.error: Exception | None = None
        self.client_options: dict[str, Any] = {}
        real_client = httpx.AsyncClient

        def client(**kwargs: Any) -> httpx.AsyncClient:
            self.client_options = kwargs
            return real_client(transport=httpx.MockTransport(self._answer), **kwargs)

        monkeypatch.setattr(file_push.httpx, "AsyncClient", client)

    def _answer(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return httpx.Response(self.status, content=self.body)


@pytest.fixture
def platform(monkeypatch: pytest.MonkeyPatch) -> Platform:
    return Platform(monkeypatch)


@pytest.fixture
def staging(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The worker directories the step made, to check they are gone afterwards."""
    made: list[str] = []
    real_mkdtemp = file_push.tempfile.mkdtemp

    def mkdtemp(**kwargs: Any) -> str:
        made.append(real_mkdtemp(**kwargs))
        return made[-1]

    monkeypatch.setattr(file_push.tempfile, "mkdtemp", mkdtemp)
    return made


def _device(name: str, host: str | None = "192.0.2.1", platform: str = "ios-xe") -> dict:
    device: dict[str, Any] = {"id": f"id-{name}", "name": name, "platform": platform}
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
        target_devices_by_role={"primary": devices if devices is not None else [_device("sw1")]},
        services=cast(HandlerServices, services),
        _emit_progress=emit,
    )
    return await FilePushHandler().execute(ctx), emitted


async def test_the_worker_fetches_the_file_and_copies_it_to_the_device(platform, staging):
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is True, result.error
    assert services.opened == [{"file_id": FILE_ID, "ttl_seconds": 600}]
    assert [str(request.url) for request in platform.requests] == [WORKER_URL]
    assert platform.client_options["follow_redirects"] is False
    [put] = services.puts
    assert put["content"] == CONTENT
    assert put["mode"] == 0o600
    assert (put["dest_fs"], put["dest_filename"], put["overwrite"]) == ("flash:", FILENAME, False)
    assert services.connects == [{"device": "sw1", "platform": "ios-xe", "step_run_id": "sr"}]
    assert result.output == {
        "file_id": FILE_ID,
        "filename": FILENAME,
        "dest_fs": "flash:",
        "dest_filename": FILENAME,
        "size_bytes": len(CONTENT),
        "sha256": SHA256,
        "md5": "cd" * 16,
        "transferred_count": 1,
        "already_present_count": 0,
    }
    assert result.metrics == {
        "device_count": 1,
        "transferred_count": 1,
        "already_present_count": 0,
        "size_bytes": len(CONTENT),
    }
    assert result.summary == f"{FILENAME} copied to 1 device(s)"
    [artifact] = result.evidence
    assert artifact["name"] == "File push"
    assert artifact["content_json"]["verified"] is True


async def test_the_file_is_fetched_once_and_the_link_is_closed_before_any_copy(platform, staging):
    services = FakeServices()

    result, _ = await _run(
        services, {"file_ids": [FILE_ID]}, [_device("sw1"), _device("sw2", "192.0.2.2")]
    )

    assert result.success is True
    assert services.events == ["open", "close", "put:sw1", "put:sw2"]
    assert len(platform.requests) == 1
    assert result.output["transferred_count"] == 2
    assert [item["name"] for item in result.evidence] == ["File push (sw1)", "File push (sw2)"]


async def test_the_workers_copy_is_removed_when_the_step_ends(platform, staging):
    services = FakeServices()
    services.answers["sw1"] = RuntimeError("connection refused")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    [directory] = staging
    assert not os.path.exists(directory)
    # The stored file's name is never a path on the worker.
    assert os.path.basename(services.puts[0]["local_path"]) == "file"
    assert os.path.dirname(services.puts[0]["local_path"]) == directory


async def test_destination_name_and_overwrite_come_from_the_config(platform, staging):
    services = FakeServices()

    result, _ = await _run(
        services,
        {
            "file_ids": FILE_ID,
            "dest_fs": "bootflash:",
            "dest_filename": "new.bin",
            "overwrite": True,
            "allow_legacy_ssh": True,
        },
    )

    assert result.success is True
    [put] = services.puts
    assert (put["dest_fs"], put["dest_filename"], put["overwrite"]) == (
        "bootflash:",
        "new.bin",
        True,
    )
    assert services.legacy == [True]
    assert result.output["dest_filename"] == "new.bin"


async def test_a_device_that_already_holds_the_same_file_counts_as_done(platform, staging):
    services = FakeServices()
    services.answers["sw1"] = {"transferred": False, "verified": True, "exists": True}

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is True
    assert result.output["transferred_count"] == 0
    assert result.output["already_present_count"] == 1
    assert result.summary == f"{FILENAME} copied to 0 device(s), already on 1"
    assert result.evidence[0]["content_json"]["already_present"] is True


async def test_a_different_file_of_that_name_fails_the_device_unless_overwrite_is_on(
    platform, staging
):
    services = FakeServices()
    services.answers["sw1"] = {"transferred": False, "verified": False, "exists": True}

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "already on the target" in (result.error or "")
    assert "Overwrite" in (result.error or "")


async def test_a_copy_that_does_not_verify_fails_the_device(platform, staging):
    services = FakeServices()
    services.answers["sw1"] = {"transferred": True, "verified": False, "exists": True}

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "does not match" in (result.error or "")
    assert result.output["transferred_count"] == 0


async def test_one_failing_device_fails_the_step_and_the_others_still_get_the_file(
    platform, staging
):
    services = FakeServices()
    services.answers["sw1"] = RuntimeError("MD5 failure between source and destination files")

    result, _ = await _run(
        services, {"file_ids": [FILE_ID]}, [_device("sw1"), _device("sw2", "192.0.2.2")]
    )

    assert result.success is False
    assert result.error == "sw1: MD5 failure between source and destination files"
    assert result.output["transferred_count"] == 1
    assert [item["name"] for item in result.evidence] == ["Error (sw1)", "File push (sw2)"]


async def test_a_transport_that_cannot_copy_files_says_which_one_to_use(platform, staging):
    services = FakeServices()
    services.answers["sw1"] = NotImplementedError(
        "scp_put is not supported by the scrapli transport; use the netmiko transport"
    )

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "use the netmiko transport" in (result.error or "")


async def test_a_device_without_a_management_host_fails_alone(platform, staging):
    services = FakeServices()

    result, _ = await _run(
        services, {"file_ids": [FILE_ID]}, [_device("sw1", None), _device("sw2", "192.0.2.2")]
    )

    assert result.success is False
    assert result.error == "sw1: no mgmt_host configured"
    assert [put["device"] for put in services.puts] == ["sw2"]


async def test_a_file_that_does_not_match_its_checksum_reaches_no_device(platform, staging):
    services = FakeServices(sha256="ab" * 32)

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "SHA-256" in (result.error or "")
    assert result.summary == "File not fetched"
    assert services.puts == [] and services.connects == []
    assert services.events == ["open", "close"]
    assert not os.path.exists(staging[0])


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (CONTENT[:-10], "received 2990 bytes of the stored file's 3000"),
        (CONTENT + b"more", "sent more than the stored file's 3000 bytes"),
    ],
)
async def test_a_file_of_the_wrong_size_reaches_no_device(platform, staging, body, message):
    platform.body = body
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert message in (result.error or "")
    assert services.puts == []


async def test_a_refused_download_is_reported_without_the_link(platform, staging):
    platform.status = 404
    services = FakeServices()

    result, emitted = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert result.error == "The platform answered the download with HTTP 404"
    assert "hgm_run_token1" not in repr((result.error, result.summary, result.evidence, emitted))
    assert services.puts == []


async def test_a_failed_fetch_is_reported_without_the_link(platform, staging):
    platform.error = httpx.ConnectError(f"cannot connect to {WORKER_URL}")
    services = FakeServices()

    result, emitted = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert result.error == (
        "The worker could not fetch the file: cannot connect to <download link>"
    )
    assert "hgm_run_token1" not in repr((result.error, result.summary, result.evidence, emitted))
    assert services.events == ["open", "close"]


async def test_a_worker_without_room_for_the_file_fetches_nothing(
    platform, staging, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(file_push, "_free_bytes", lambda directory: 1000)
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert result.summary == "Not enough space on the worker"
    assert "1000 bytes free" in (result.error or "")
    assert platform.requests == []
    assert services.events == ["open", "close"]


async def test_a_file_the_organization_does_not_have_fails_the_step(platform, staging):
    services = FakeServices()
    services.open_error = LookupError("File not found")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert result.error == "File not found"
    assert services.connects == []
    assert not os.path.exists(staging[0])


async def test_a_host_that_does_not_implement_links_is_reported_clearly(platform, staging):
    services = FakeServices()
    services.open_error = NotImplementedError()

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert result.summary == "Download links not supported"
    assert "upgrade the platform" in (result.error or "")


async def test_a_platform_without_download_links_is_reported_clearly(platform, staging):
    class OldServices:
        pass

    result, _ = await _run(OldServices(), {"file_ids": [FILE_ID]})

    assert result.success is False
    assert result.summary == "Download links not supported"
    assert staging == []


async def test_a_link_the_worker_cannot_use_is_refused(platform, staging):
    services = FakeServices(worker_url="")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "no address the worker can fetch the file from" in (result.error or "")
    assert platform.requests == []


@pytest.mark.parametrize(
    ("file_ids", "message"),
    [
        ([], "No file repository file selected"),
        ([FILE_ID, FILE_ID], "Select exactly one file repository file"),
    ],
)
async def test_exactly_one_file_must_be_selected(platform, staging, file_ids, message):
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": file_ids})

    assert result.success is False
    assert result.error == message
    assert services.opened == [] and staging == []


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("dest_fs", "flash:\nreload", "Destination contains a line break"),
        ("dest_filename", "a.bin\rreload", "Destination Filename contains a line break"),
        ("dest_fs", "flash:?", "Destination contains a question mark"),
        ("dest_filename", "a?.bin", "Destination Filename contains a question mark"),
        ("dest_filename", "../a.bin", "Destination Filename must be a file name"),
    ],
)
async def test_a_destination_a_command_line_would_misread_is_refused(
    platform, staging, field, value, message
):
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID], field: value})

    assert result.success is False
    assert (result.error or "").startswith(message)
    assert services.opened == [] and staging == []


@pytest.mark.parametrize("name", ["evil\nreload.bin", "what?.bin", "images/a.bin"])
async def test_a_stored_file_name_a_command_line_would_misread_is_refused(platform, staging, name):
    services = FakeServices(filename=name)

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "set Destination Filename" in (result.error or "")
    assert platform.requests == [] and services.puts == []

    renamed, _ = await _run(
        FakeServices(filename=name), {"file_ids": [FILE_ID], "dest_filename": "a.bin"}
    )
    assert renamed.success is True, renamed.error


async def test_no_target_devices_fails_before_anything_is_asked(platform, staging):
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]}, [])

    assert result.success is False
    assert result.error == "No target devices configured"
    assert services.opened == [] and staging == []


def test_the_config_takes_one_id_as_text_and_marks_the_field_for_the_file_picker():
    config = FilePushConfig.model_validate({"file_ids": FILE_ID})
    assert config.file_ids == [FILE_ID]
    assert config.dest_fs == "flash:"
    assert config.overwrite is False

    field = FilePushConfig.model_json_schema()["properties"]["file_ids"]
    assert field["x_widget"] == "repository-file-select"
    assert field["x_multiple"] is False


def test_the_handler_declares_what_the_editor_and_engine_read():
    handler = FilePushHandler
    assert handler.handler_id == "netcli.file_push"
    assert handler.targeting.roles is True and handler.targeting.ips is False
    assert handler.default_timeout_seconds == 7200
    assert handler.run_timeout_field is None


def test_the_docs_page_satisfies_the_contract():
    bundle = load_docs_bundle("hegemony_steps_netcli")
    text = bundle["netcli.file_push"]
    assert check_page("netcli.file_push", text) == []
