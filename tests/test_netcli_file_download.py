# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``netcli.file_download``: each target downloads a file-repository file by itself.

The host's ``open_file_download`` service and the device transport are fakes
that record what they were asked for: a link per target, opened right before
its transfer and closed right after it, and the transfer the target was told
to make.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, cast

import pytest

from hegemony_step_sdk import FileDownload, HandlerContext, HandlerResult, HandlerServices
from hegemony_step_sdk.docs import check_page, load_docs_bundle
from hegemony_steps_netcli.file_download import FileDownloadConfig, FileDownloadHandler

FILE_ID = "0c7f1ee3-d824-4dea-9c07-bd44e5fe188b"
FILENAME = "cat9k_iosxe.17.09.05.SPA.bin"
BASE = "https://hegemony.example.com/api"


class FakeTransport:
    def __init__(self, services: FakeServices, device: dict[str, Any]) -> None:
        self.services = services
        self.device = device

    def configure_ssh_security(self, *, allow_legacy: bool) -> None:
        self.services.legacy.append(allow_legacy)

    async def http_transfer(
        self, *, url: str, dest_fs: str, dest_filename: str, timeout_seconds: int = 3600
    ) -> dict:
        self.services.events.append(f"transfer:{self.device['name']}")
        self.services.transfers.append(
            {
                "device": self.device["name"],
                "url": url,
                "dest_fs": dest_fs,
                "dest_filename": dest_filename,
                "timeout_seconds": timeout_seconds,
            }
        )
        failure = self.services.fail.get(self.device["name"])
        if isinstance(failure, Exception):
            raise failure
        if failure:
            return {
                "transferred": False,
                "output": f"copy {url} {dest_fs}\n%Error",
                "elapsed_ms": 5,
            }
        return {
            "transferred": True,
            "output": f"copy {url} {dest_fs}{dest_filename}\n1024 bytes copied in 2 secs",
            "elapsed_ms": 2000.0,
        }


class FakeServices:
    """A host that issues a numbered link per request and records the transfers."""

    def __init__(
        self, *, url_base: str = BASE, md5: str | None = "cd" * 16, filename: str = FILENAME
    ) -> None:
        self.filename = filename
        self.url_base = url_base
        self.md5 = md5
        self.events: list[str] = []
        self.opened: list[dict[str, Any]] = []
        self.transfers: list[dict[str, Any]] = []
        self.connects: list[dict[str, Any]] = []
        self.legacy: list[bool] = []
        self.fail: dict[str, Any] = {}
        self.open_error: Exception | None = None

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
                sha256="ab" * 32,
                md5=self.md5,
                url=f"{self.url_base}{path}" if self.url_base else "",
                worker_url=f"http://api:8000{path}",
                expires_at="2026-11-12T12:00:00+00:00",
            )
        finally:
            self.events.append(f"close:{number}")

    def connect(self, device: dict[str, Any], *, platform: str | None = None, **kwargs: Any):
        self.connects.append({"device": device["name"], "platform": platform, **kwargs})
        return FakeTransport(self, device)


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
    return await FileDownloadHandler().execute(ctx), emitted


async def test_the_device_downloads_the_file_through_a_link_and_the_step_reports_the_file():
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is True, result.error
    assert services.opened == [{"file_id": FILE_ID, "ttl_seconds": 600}]
    assert services.transfers == [
        {
            "device": "sw1",
            "url": f"{BASE}/dl/hgm_run_token1/{FILENAME}",
            "dest_fs": "flash:",
            "dest_filename": FILENAME,
            "timeout_seconds": 3600,
        }
    ]
    assert services.connects == [{"device": "sw1", "platform": "ios-xe", "step_run_id": "sr"}]
    assert result.output == {
        "file_id": FILE_ID,
        "filename": FILENAME,
        "dest_fs": "flash:",
        "dest_filename": FILENAME,
        "size_bytes": 1024,
        "sha256": "ab" * 32,
        "md5": "cd" * 16,
        "transferred_count": 1,
    }
    assert result.metrics == {"device_count": 1, "transferred_count": 1, "size_bytes": 1024}
    assert result.summary == f"{FILENAME} downloaded by 1 device(s)"


async def test_the_link_never_reaches_evidence_output_or_the_live_log():
    services = FakeServices()

    result, emitted = await _run(services, {"file_ids": [FILE_ID]})

    reported = repr((result.evidence, result.output, result.summary, result.error, emitted))
    assert "hgm_run_token1" not in reported
    assert BASE not in reported
    [artifact] = result.evidence
    assert artifact["name"] == "File download"
    assert artifact["content_text"].startswith("copy <download link> flash:")
    assert "bytes copied" in artifact["content_text"]
    assert artifact["content_json"]["success"] is True
    assert artifact["content_json"]["sha256"] == "ab" * 32


async def test_each_device_gets_its_own_link_opened_before_and_closed_after_its_transfer():
    services = FakeServices()

    result, _ = await _run(
        services, {"file_ids": [FILE_ID]}, [_device("sw1"), _device("sw2", "192.0.2.2")]
    )

    assert result.success is True
    assert services.events == [
        "open:1",
        "transfer:sw1",
        "close:1",
        "open:2",
        "transfer:sw2",
        "close:2",
    ]
    assert [t["url"] for t in services.transfers] == [
        f"{BASE}/dl/hgm_run_token1/{FILENAME}",
        f"{BASE}/dl/hgm_run_token2/{FILENAME}",
    ]
    assert [item["name"] for item in result.evidence] == [
        "File download (sw1)",
        "File download (sw2)",
    ]
    assert result.output["transferred_count"] == 2


async def test_destination_name_and_timeout_come_from_the_config():
    services = FakeServices()

    result, _ = await _run(
        services,
        {
            "file_ids": FILE_ID,
            "dest_fs": "/var/tmp",
            "dest_filename": "image.bin",
            "transfer_timeout_seconds": 120,
            "allow_legacy_ssh": True,
        },
        [_device("srv1", platform="linux")],
    )

    assert result.success is True
    [transfer] = services.transfers
    assert (transfer["dest_fs"], transfer["dest_filename"]) == ("/var/tmp", "image.bin")
    assert transfer["timeout_seconds"] == 120
    assert services.legacy == [True]
    assert result.output["dest_filename"] == "image.bin"


async def test_one_failing_device_fails_the_step_and_the_others_still_download():
    services = FakeServices()
    services.fail = {"sw1": True}

    result, _ = await _run(
        services, {"file_ids": [FILE_ID]}, [_device("sw1"), _device("sw2", "192.0.2.2")]
    )

    assert result.success is False
    assert result.error == "sw1: the device did not complete the download"
    assert result.output["transferred_count"] == 1
    assert [t["device"] for t in services.transfers] == ["sw1", "sw2"]
    assert "hgm_run_token" not in repr(result.evidence)
    assert services.events[-1] == "close:2"


async def test_a_transport_error_is_reported_without_the_link_and_the_link_is_closed():
    services = FakeServices()
    services.fail = {
        "sw1": RuntimeError(f"copy {BASE}/dl/hgm_run_token1/{FILENAME} failed: timed out")
    }

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert result.error == "sw1: copy <download link> failed: timed out"
    assert services.events == ["open:1", "transfer:sw1", "close:1"]
    [artifact] = result.evidence
    assert artifact["name"] == "Error (sw1)"


async def test_a_transport_that_cannot_transfer_says_which_one_to_use():
    services = FakeServices()
    services.fail = {
        "sw1": NotImplementedError(
            "http_transfer is not supported by the scrapli transport; use the netmiko transport"
        )
    }

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "use the netmiko transport" in (result.error or "")


async def test_without_an_address_targets_can_reach_no_device_is_contacted():
    services = FakeServices(url_base="")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "HEGEMONY_API_EXTERNAL_URL" in (result.error or "")
    assert services.connects == []
    assert services.events == ["open:1", "close:1"]


async def test_a_file_the_organization_does_not_have_fails_the_device():
    services = FakeServices()
    services.open_error = LookupError(f"No file {FILE_ID} in the run's organization")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert f"sw1: No file {FILE_ID}" in (result.error or "")
    assert services.connects == []


async def test_a_device_without_a_management_host_asks_for_no_link():
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]}, [_device("sw1", host=None)])

    assert result.success is False
    assert result.error == "sw1: no mgmt_host configured"
    assert services.opened == []


@pytest.mark.parametrize(
    ("file_ids", "message"),
    [
        ([], "No file repository file selected"),
        ("", "No file repository file selected"),
        ([FILE_ID, FILE_ID], "Select exactly one file repository file"),
    ],
)
async def test_exactly_one_file_must_be_selected(file_ids, message):
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": file_ids})

    assert result.success is False
    assert result.error == message
    assert services.opened == []


@pytest.mark.parametrize(
    ("field", "value", "label"),
    [
        ("dest_fs", "flash:\nreload", "Destination"),
        ("dest_fs", "flash:\rreload\r", "Destination"),
        ("dest_filename", "image.bin\nerase startup-config", "Destination Filename"),
        ("dest_filename", "image\x1b[2J.bin", "Destination Filename"),
        ("dest_filename", "image\u2028.bin", "Destination Filename"),
    ],
)
async def test_a_destination_that_could_start_another_command_is_refused(field, value, label):
    """The destination is typed into the device's command line."""
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID], field: value})

    assert result.success is False
    assert result.error == f"{label} contains a line break or another control character"
    assert services.opened == []
    assert services.connects == []


async def test_a_stored_file_name_that_could_start_another_command_is_refused():
    services = FakeServices(filename="image.bin\nreload")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "set Destination Filename" in (result.error or "")
    assert services.connects == []
    assert services.transfers == []
    # The link opened to learn the name is closed again.
    assert services.events == ["open:1", "close:1"]


async def test_a_destination_name_with_spaces_is_passed_on_as_it_is():
    services = FakeServices()

    result, _ = await _run(
        services, {"file_ids": [FILE_ID], "dest_fs": "/var/tmp", "dest_filename": "my image.bin"}
    )

    assert result.success is True
    assert services.transfers[0]["dest_filename"] == "my image.bin"


@pytest.mark.parametrize(
    "name", ["/etc/hosts", "../image.bin", "sub/image.bin", "sub\\image.bin", "..", "."]
)
async def test_a_destination_file_name_with_a_directory_part_is_refused(name):
    """On a server the transport joins Destination and the name as a path."""
    services = FakeServices()

    result, _ = await _run(
        services, {"file_ids": [FILE_ID], "dest_fs": "/var/tmp", "dest_filename": name}
    )

    assert result.success is False
    assert result.error == (
        "Destination Filename must be a file name without a directory part (no slash); "
        "put the directory in Destination"
    )
    assert services.opened == []
    assert services.connects == []


async def test_a_stored_file_name_with_a_directory_part_is_refused():
    services = FakeServices(filename="../../etc/cron.d/job")

    result, _ = await _run(services, {"file_ids": [FILE_ID], "dest_fs": "/var/tmp"})

    assert result.success is False
    assert "has a directory part; set Destination Filename" in (result.error or "")
    assert services.connects == []
    assert services.events == ["open:1", "close:1"]


async def test_a_directory_belongs_in_the_destination():
    services = FakeServices()

    result, _ = await _run(
        services, {"file_ids": [FILE_ID], "dest_fs": "flash:images/", "dest_filename": "new.bin"}
    )

    assert result.success is True
    assert services.transfers[0]["dest_fs"] == "flash:images/"


async def test_a_host_that_does_not_implement_links_is_not_blamed_on_the_transport():
    """The SDK's default raises NotImplementedError before any device is contacted."""

    class HostWithoutSupport(FakeServices):
        def open_file_download(self, file_id: str, *, ttl_seconds: int = 600):
            raise NotImplementedError

    services = HostWithoutSupport()

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "upgrade the platform" in (result.error or "")
    assert "transport" not in (result.error or "")
    assert services.connects == []


@pytest.mark.parametrize(
    ("field", "label"), [("dest_fs", "Destination"), ("dest_filename", "Destination Filename")]
)
async def test_a_question_mark_in_the_destination_is_refused(field, label):
    """On a network device's command line it opens the help instead of being typed."""
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID], field: "image?.bin"})

    assert result.success is False
    assert (result.error or "").startswith(f"{label} contains a question mark")
    assert services.opened == []


async def test_a_stored_file_name_with_a_question_mark_is_refused():
    services = FakeServices(filename="image?.bin")

    result, _ = await _run(services, {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "question mark" in (result.error or "")
    assert "set Destination Filename" in (result.error or "")
    assert services.connects == []


async def test_parallel_targets_get_links_that_outlast_a_wait_for_a_free_thread():
    """A transfer may queue behind others after its link was issued."""
    services = FakeServices()

    result, _ = await _run(
        services,
        {"file_ids": [FILE_ID], "max_parallel_devices": 2},
        [_device("sw1"), _device("sw2", "192.0.2.2")],
    )

    assert result.success is True
    assert {opened["ttl_seconds"] for opened in services.opened} == {3600}


async def test_no_target_devices_fails_before_anything_is_asked():
    services = FakeServices()

    result, _ = await _run(services, {"file_ids": [FILE_ID]}, [])

    assert result.success is False
    assert result.error == "No target devices configured"
    assert services.opened == []


async def test_a_platform_without_download_links_is_reported_clearly():
    class OldServices:
        def connect(self, device, **kwargs):  # pragma: no cover - never reached
            raise AssertionError("no device is contacted")

    result, _ = await _run(OldServices(), {"file_ids": [FILE_ID]})

    assert result.success is False
    assert "upgrade the platform" in (result.error or "")


def test_the_config_takes_one_id_as_text_and_marks_the_field_for_the_file_picker():
    config = FileDownloadConfig.model_validate({"file_ids": FILE_ID})
    assert config.file_ids == [FILE_ID]
    assert config.dest_fs == "flash:"
    assert config.transfer_timeout_seconds == 3600

    field = FileDownloadConfig.model_json_schema()["properties"]["file_ids"]
    assert field["x_widget"] == "repository-file-select"
    assert field["x_multiple"] is False


def test_the_handler_declares_what_the_editor_and_engine_read():
    handler = FileDownloadHandler
    assert handler.handler_id == "netcli.file_download"
    assert handler.targeting.roles is True and handler.targeting.ips is False
    assert handler.default_timeout_seconds == 7200
    assert handler.run_timeout_field is None


def test_the_docs_page_satisfies_the_contract():
    bundle = load_docs_bundle("hegemony_steps_netcli")
    text = bundle["netcli.file_download"]
    assert check_page("netcli.file_download", text) == []
