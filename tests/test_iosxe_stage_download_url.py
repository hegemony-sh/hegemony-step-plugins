# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Each device stages a repository file from a URL fetched just before.

The repository's device download URL is presigned and expires (after an
hour by default). The stage step fetched it once for all devices, so with
devices staged one at a time a later device whose transfer started after
the expiry failed. Each device now gets a fresh URL right before staging.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from hegemony_step_sdk import HandlerContext
from hegemony_steps_cisco_iosxe.upgrade.handlers.stage import UpgradeStageHandler
from tests.iosxe_fakes import FakeServices, Result, ScriptedTransport

DEVICES = [
    {"id": "d1", "name": "sw1", "mgmt_host": "192.0.2.10"},
    {"id": "d2", "name": "sw2", "mgmt_host": "192.0.2.11"},
]
MISSING = Result("%Error opening flash:img.bin (No such file or directory)")
LISTED = Result("  3   987654321 Jan 25 2026 12:19:36.0000000000 +00:00 img.bin")


class _Response:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict[str, Any]:
        return self._payload


class _Repository(FakeServices):
    """Issues a new presigned URL per request and records it with each transfer."""

    def __init__(self, *, fail_from: int | None = None) -> None:
        super().__init__(self._device)
        self.events: list[tuple[str, ...]] = []
        self.issued = 0
        self.fail_from = fail_from
        self._connecting: dict[str, Any] = {}

    def connect(self, device: dict[str, Any], *, platform: str | None = None, **kwargs: Any):
        self._connecting = device
        return super().connect(device, platform=platform, **kwargs)

    def _device(self) -> ScriptedTransport:
        events, name = self.events, self._connecting["name"]

        class _Transport(ScriptedTransport):
            async def http_transfer(self, *, url: str, **kwargs: Any) -> dict:
                events.append(("transfer", name, url))
                return await super().http_transfer(url=url, **kwargs)

        return _Transport({"dir": [MISSING, LISTED]})

    @asynccontextmanager
    async def open_api_client(self, *, timeout: float = 30):
        repository = self

        class _Client:
            async def post(self, path: str) -> _Response:
                repository.issued += 1
                if repository.fail_from and repository.issued >= repository.fail_from:
                    return _Response(404)
                url = f"https://s3.example/img.bin?signature={repository.issued}"
                repository.events.append(("issued", path, url))
                return _Response(
                    200, {"url": url, "expires_at": "2026-10-06T12:00:00Z", "filename": "img.bin"}
                )

        yield _Client()


def _ctx(config: dict[str, Any], services: Any) -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr-1",
        step_id="s",
        target_roles=["sw"],
        target_devices_by_role={"sw": DEVICES},
        config=config,
        services=services,
    )


async def test_each_device_gets_a_fresh_url_right_before_its_transfer():
    repository = _Repository()
    result = await UpgradeStageHandler().execute(_ctx({"file_ids": ["file-1"]}, repository))
    assert result.success is True, result.error
    path = "/files/file-1/device-download-url"
    assert repository.events == [
        # Checks the file and takes its name before any device.
        ("issued", path, "https://s3.example/img.bin?signature=1"),
        ("issued", path, "https://s3.example/img.bin?signature=2"),
        ("transfer", "sw1", "https://s3.example/img.bin?signature=2"),
        ("issued", path, "https://s3.example/img.bin?signature=3"),
        ("transfer", "sw2", "https://s3.example/img.bin?signature=3"),
    ]


async def test_a_url_that_cannot_be_issued_fails_that_device():
    repository = _Repository(fail_from=3)
    result = await UpgradeStageHandler().execute(_ctx({"file_ids": ["file-1"]}, repository))
    assert result.success is False
    assert result.metrics["success_count"] == 1
    assert [event[1] for event in repository.events if event[0] == "transfer"] == ["sw1"]
    failed = result.evidence[1]
    assert failed["name"] == "Stage Error: sw2"
    assert failed["content_json"]["error"] == "File not found: file-1"


async def test_a_manual_source_url_is_used_as_given():
    repository = _Repository()
    config = {"source_url": "https://repo.example/img.bin", "dest_filename": "img.bin"}
    result = await UpgradeStageHandler().execute(_ctx(config, repository))
    assert result.success is True, result.error
    assert repository.issued == 0
    assert [event[2] for event in repository.events] == ["https://repo.example/img.bin"] * 2
