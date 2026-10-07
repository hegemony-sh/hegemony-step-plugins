# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Shared fakes for the IOS-XE upgrade tests.

``ScriptedTransport`` answers device commands from a script, the way the
netmiko and scrapli transports report them: they never raise, a dropped or
refused connection is ``exit_code=-1`` with empty output and an ``error``,
and a CLI error is ``exit_code=1``.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from hegemony_step_sdk import HandlerContext

DEVICE = {"id": "11111111-1111-1111-1111-111111111111", "name": "sw1", "mgmt_host": "192.0.2.10"}


@dataclass
class Result:
    """One command result (the SDK's CommandResult shape)."""

    output: str = ""
    exit_code: int = 0
    error: str | None = None
    command: str = ""
    latency_ms: float = 0.0


#: What every command returns when the device cannot be reached.
UNREACHABLE = Result(exit_code=-1, error="Connection timeout: TCP connection to device failed.")


class ScriptedTransport:
    """A device transport that answers from ``replies`` and records every call.

    ``replies`` maps a command prefix to a ``Result``, or to a list of them
    used in order (the last one repeats). The first matching prefix wins;
    unscripted commands get ``default`` (an empty success unless given).
    """

    def __init__(
        self,
        replies: dict[str, Result | list[Result]] | None = None,
        *,
        default: Result | None = None,
        transferred: bool = True,
    ) -> None:
        self.replies: dict[str, list[Result]] = {}
        for prefix, reply in (replies or {}).items():
            self.replies[prefix] = [reply] if isinstance(reply, Result) else list(reply)
        self.default = default or Result()
        self.transferred = transferred
        # One entry per call: the command list of execute_commands, or the
        # single timing command.
        self.calls: list[list[str]] = []
        self.timing_kwargs: dict[str, dict[str, Any]] = {}
        self.transfers: list[str] = []

    @property
    def commands(self) -> list[str]:
        return [command for call in self.calls for command in call]

    def _reply(self, command: str) -> Result:
        for prefix, replies in self.replies.items():
            if command.startswith(prefix):
                reply = replies.pop(0) if len(replies) > 1 else replies[0]
                return replace(reply, command=command)
        return replace(self.default, command=command)

    async def execute_commands(self, commands: list[str]) -> list[Result]:
        self.calls.append(list(commands))
        return [self._reply(command) for command in commands]

    async def execute_command(self, command: str) -> Result:
        return (await self.execute_commands([command]))[0]

    async def execute_command_timing(
        self,
        command: str,
        *,
        read_timeout: float = 120.0,
        delay_factor: int = 2,
        expect: list[str] | None = None,
        answers: dict[str, str] | None = None,
        wait_for_patterns: list[str] | None = None,
    ) -> Result:
        self.calls.append([command])
        self.timing_kwargs[command] = {"answers": answers, "wait_for_patterns": wait_for_patterns}
        return self._reply(command)

    async def scp_put(
        self, *, local_path: str, dest_fs: str, dest_filename: str, overwrite: bool = False
    ) -> dict:
        raise NotImplementedError

    async def http_transfer(
        self, *, url: str, dest_fs: str, dest_filename: str, timeout_seconds: int = 3600
    ) -> dict:
        self.transfers.append(f"{dest_fs}{dest_filename}")
        if not self.transferred:
            return {"transferred": False, "output": ""}
        return {"transferred": True, "output": "123 bytes copied"}


class FakeServices:
    """``HandlerServices.connect`` only: hands out transports, records the calls."""

    def __init__(self, transport_factory) -> None:
        self.transport_factory = transport_factory
        self.connect_calls: list[dict[str, Any]] = []

    def connect(self, device: dict[str, Any], *, platform: str | None = None, **kwargs: Any):
        self.connect_calls.append({"device": device, "platform": platform, **kwargs})
        return self.transport_factory()


def make_ctx(config: dict[str, Any], services: Any, *, step_run_id: str = "sr-1") -> HandlerContext:
    return HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id=step_run_id,
        step_id="s",
        target_roles=["sw"],
        target_devices_by_role={"sw": [DEVICE]},
        config=config,
        services=services,
    )


class InstantClock:
    """Stands in for ``asyncio`` in the verify handler, whose waits then take no real time.

    The verify step waits at least 60 s for a device to return; patched in as
    the module's ``asyncio``, its clock jumps by each sleep instead.
    """

    def __init__(self) -> None:
        self.now = 0.0

    def get_event_loop(self) -> InstantClock:
        return self

    def time(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds

    async def wait_for(self, awaitable: Any, timeout: float | None) -> Any:
        """``asyncio.wait_for`` on this clock: work that took longer is cut off at ``timeout``."""
        start = self.now
        result = await awaitable
        if timeout is not None and self.now - start > timeout:
            self.now = start + timeout
            raise TimeoutError
        return result
