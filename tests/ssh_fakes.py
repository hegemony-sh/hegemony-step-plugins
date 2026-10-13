# SPDX-FileCopyrightText: 2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Real SSH servers in the test process, and an in-memory host-key verifier.

The host-key tests dial these servers, so the key exchange and the SSH
library's own check are what is under test. The device server answers exec
channels and runs a small router-like shell (prompt ``r1#``) for the CLI
transports; the bastion server forwards direct-tcpip channels.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import asyncssh

from hegemony_step_sdk import HostKeyRejectedError

USERNAME, PASSWORD = "admin", "device-pw"
JUMP_USERNAME, JUMP_PASSWORD = "jump", "bastion-pw"
PROMPT = "r1#"


def key_line(key: asyncssh.SSHKey) -> str:
    """``<type> <base64>`` of a key, as the verifier names keys."""
    return " ".join(key.export_public_key("openssh").decode("ascii").split()[:2])


class FakeVerifier:
    """The host's verifier, in memory: trusted keys per ``host:port`` and every call.

    ``mode`` follows the platform's: ``accept_new`` learns a key on first
    contact, ``strict`` refuses a host without a trusted key, ``off`` checks
    nothing.
    """

    def __init__(self, mode: str = "accept_new") -> None:
        self.mode = mode
        self.keys: dict[tuple[str, int], list[str]] = {}
        self.calls: list[tuple[str, str, int, str | None]] = []
        #: Runs after a key is recorded, before the transport logs in.
        self.after_learn: Callable[[], Awaitable[None]] | None = None

    def trust(self, host: str, port: int, *keys: asyncssh.SSHKey) -> None:
        self.keys[(host, port)] = [key_line(key) for key in keys]

    def operations(self) -> list[str]:
        return [call[0] for call in self.calls]

    async def trusted_keys(self, host: str, port: int) -> tuple[str, ...] | None:
        self.calls.append(("trusted_keys", host, port, None))
        if self.mode == "off":
            return None
        keys = tuple(self.keys.get((host, port), ()))
        if not keys and self.mode == "strict":
            raise HostKeyRejectedError(f"no SSH host key of {host}:{port} is trusted (strict)")
        return keys

    async def learn(self, host: str, port: int, presented_key: str) -> None:
        self.calls.append(("learn", host, port, presented_key))
        known = self.keys.setdefault((host, port), [])
        if known and presented_key not in known:
            raise HostKeyRejectedError(f"another SSH host key of {host}:{port} was recorded")
        if presented_key not in known:
            known.append(presented_key)
        if self.after_learn is not None:
            await self.after_learn()

    async def rejected(
        self, host: str, port: int, presented_key: str | None
    ) -> HostKeyRejectedError:
        self.calls.append(("rejected", host, port, presented_key))
        return HostKeyRejectedError(f"The SSH host key of {host}:{port} does not match")


def checks_off() -> FakeVerifier:
    """A verifier for an organization that switched checks off: every key is accepted.

    The transports refuse to connect without a verifier, so tests that are not
    about host keys pass this one.
    """
    return FakeVerifier(mode="off")


class _Device(asyncssh.SSHServer):
    """Accepts one password; records every login attempt and connection."""

    def __init__(self, seen: Seen, password: str) -> None:
        self._seen = seen
        self._password = password

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self._seen.connections.append(conn)

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        self._seen.passwords.append(password)
        return password == self._password


class _Bastion(_Device):
    """A device that also forwards direct-tcpip channels (a jump host)."""

    def connection_requested(self, dest_host: str, dest_port: int, orig_host: str, orig_port: int):
        self._seen.forwards.append((dest_host, dest_port))
        return True


async def _session(process: asyncssh.SSHServerProcess) -> None:
    """An exec command answers once; a shell is a router-like prompt loop."""
    if process.command is not None:
        process.stdout.write(f"ran {process.command}\n")
        process.exit(0)
        return
    process.stdout.write(PROMPT)
    while True:
        try:
            line = await process.stdin.readline()
        except asyncssh.TerminalSizeChanged:
            continue
        except (asyncssh.BreakReceived, asyncssh.SignalReceived, asyncssh.DisconnectError):
            break
        if not line:
            break
        command = line.strip()
        if command in ("exit", "logout", "quit"):
            break
        if command and not command.startswith("terminal"):
            process.stdout.write(f"output of {command}\r\n")
        process.stdout.write(PROMPT)
    with contextlib.suppress(Exception):
        process.exit(0)


@dataclass
class Seen:
    """What the servers saw: connections, passwords tried, channels forwarded."""

    connections: list[Any] = field(default_factory=list)
    passwords: list[str] = field(default_factory=list)
    forwards: list[tuple[str, int]] = field(default_factory=list)


class Servers:
    """Starts SSH servers on 127.0.0.1 and stops them all at the end."""

    def __init__(self) -> None:
        self.seen = Seen()
        self._servers: list[Any] = []

    async def device(self, *host_keys: asyncssh.SSHKey, port: int = 0, **options: Any) -> int:
        """A device presenting ``host_keys``; returns its port.

        ``options`` go to ``asyncssh.create_server``, e.g. ``kex_algs``.
        """
        return await self._listen(_Device, PASSWORD, host_keys, port, options)

    async def bastion(self, *host_keys: asyncssh.SSHKey, port: int = 0, **options: Any) -> int:
        """A jump host presenting ``host_keys``; returns its port."""
        return await self._listen(_Bastion, JUMP_PASSWORD, host_keys, port, options)

    async def _listen(
        self,
        factory: type[_Device],
        password: str,
        host_keys: Any,
        port: int,
        options: dict[str, Any] | None = None,
    ) -> int:
        server = await asyncssh.create_server(
            lambda: factory(self.seen, password),
            "127.0.0.1",
            port,
            server_host_keys=list(host_keys),
            process_factory=_session,
            **(options or {}),
        )
        self._servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def restart(self, port: int, *host_keys: asyncssh.SSHKey) -> None:
        """Stop every server and start the device on ``port`` with new keys."""
        await self.stop()
        await self.device(*host_keys, port=port)

    async def stop(self) -> None:
        # A connection a failing test left open would keep wait_closed waiting.
        for conn in self.seen.connections:
            conn.close()
        for server in self._servers:
            server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(server.wait_closed(), timeout=5)
        self._servers.clear()


@contextlib.asynccontextmanager
async def ssh_servers() -> AsyncIterator[Servers]:
    servers = Servers()
    try:
        yield servers
    finally:
        await servers.stop()
