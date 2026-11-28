# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The ``napalm`` transport's NAPALM sessions.

Its CLI side runs the shared host-key and SSH-algorithm suites
(``test_transport_host_keys``, ``test_ssh_algorithms``). These tests open
NAPALM driver sessions against the real SSH servers of ``ssh_fakes``, so the
key exchange and paramiko's own host-key check are what is under test: a
NAPALM session must log in through the netmiko transport's hardened login and
never on its own.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import asyncssh
import pytest

from hegemony_step_sdk import (
    NAPALM_GETTERS,
    DeviceConnectionSpec,
    HostKeyRejectedError,
    JumpHostSpec,
    NapalmSession,
)
from hegemony_transport_napalm import (
    ALL_TRANSPORTS,
    PLATFORM_TO_DRIVER,
    NapalmSessionClosedError,
    NapalmTransport,
    driver_for,
    register,
    transport as napalm_transport,
)
from tests.ssh_fakes import (
    JUMP_PASSWORD,
    JUMP_USERNAME,
    PASSWORD,
    USERNAME,
    FakeVerifier,
    Servers,
    key_line,
    ssh_servers,
)

HOST = "127.0.0.1"


@pytest.fixture
async def servers() -> AsyncIterator[Servers]:
    async with ssh_servers() as started:
        yield started


def _key() -> asyncssh.SSHKey:
    return asyncssh.generate_private_key("ssh-ed25519")


def _transport(
    port: int,
    verifier: FakeVerifier | None,
    *,
    platform: str = "ios-xe",
    jump_port: int | None = None,
    registry: Any = None,
) -> NapalmTransport:
    jump = (
        JumpHostSpec(host=HOST, port=jump_port, username=JUMP_USERNAME, password=JUMP_PASSWORD)
        if jump_port is not None
        else None
    )
    spec = DeviceConnectionSpec(
        host=HOST,
        port=port,
        username=USERNAME,
        password=PASSWORD,
        platform=platform,
        connect_timeout=5.0,
        command_timeout=5.0,
        jump_host=jump,
    )
    kwargs: dict[str, Any] = {"host_key_verifier": verifier}
    if registry is not None:
        kwargs.update(cancellation_registry=registry, step_run_id="sr-1")
    return NapalmTransport(spec, **kwargs)


# --- registration and platforms ----------------------------------------------------------


def test_it_registers_the_napalm_transport():
    registered: list[type] = []

    class _Registry:
        def register_transport(self, transport_class: type) -> None:
            registered.append(transport_class)

    register(_Registry())
    assert registered == list(ALL_TRANSPORTS) == [NapalmTransport]
    assert NapalmTransport.transport_id == "napalm"
    assert NapalmTransport.supports_host_key_verifier is True
    assert NapalmTransport.supports_napalm_sessions is True


@pytest.mark.parametrize(
    ("platform", "driver", "device_type"),
    [
        ("ios-xe", "ios", "cisco_ios"),
        ("ios", "ios", "cisco_ios"),
        ("eos", "eos", "arista_eos"),
        ("nxos", "nxos_ssh", "cisco_nxos"),
    ],
)
def test_each_platform_has_its_driver_and_netmiko_device_type(platform, driver, device_type):
    assert driver_for(platform) == driver
    assert _transport(22, FakeVerifier(), platform=platform).device_type == device_type


@pytest.mark.parametrize("platform", ["junos", "ios-xr", "linux"])
def test_a_platform_without_a_secured_driver_is_refused(platform):
    with pytest.raises(NotImplementedError, match=f"platform '{platform}'"):
        driver_for(platform)
    assert platform not in PLATFORM_TO_DRIVER


async def test_an_unsupported_platform_is_refused_before_anything_is_dialled(servers):
    port = await servers.device(_key())
    transport = _transport(port, FakeVerifier(), platform="junos")

    with pytest.raises(NotImplementedError, match="junos"):
        await transport.open_napalm()

    assert servers.seen.connections == []
    assert servers.seen.passwords == []


def test_eos_and_ios_drivers_are_kept_on_ssh():
    transport = _transport(22, FakeVerifier(), platform="eos")
    for name in ("eos", "ios"):
        driver_class = napalm_transport._driver_class(name, transport)
        driver = driver_class(
            hostname=HOST,
            username=USERNAME,
            password="",
            optional_args=dict(napalm_transport._DRIVER_OPTIONS[name]),
        )
        # EOS defaults to eAPI over HTTPS and IOS can use telnet: neither is
        # covered by the SSH host-key trust.
        assert driver.transport == "ssh"


def test_ios_sends_candidates_through_the_session_not_scp():
    # netmiko's SCP opens a second SSH client with no trusted keys (their file
    # is removed after the login) and no way through the jump host.
    transport = _transport(22, FakeVerifier())
    driver = napalm_transport._driver_class("ios", transport)(
        hostname=HOST,
        username=USERNAME,
        password="",
        optional_args=dict(napalm_transport._DRIVER_OPTIONS["ios"]),
    )
    assert driver.inline_transfer is True


# --- sessions over the hardened login ------------------------------------------------------


class _Registry:
    def __init__(self) -> None:
        self.live: list[Any] = []

    def register(self, key: str | None, connection: Any) -> None:
        self.live.append(connection)

    def unregister(self, key: str | None, connection: Any) -> None:
        self.live.remove(connection)

    def is_cancelled(self, key: str | None) -> bool:
        return False


async def test_first_contact_learns_the_key_then_the_driver_logs_in_through_the_transport(
    servers,
):
    key = _key()
    port = await servers.device(key)
    verifier = FakeVerifier()
    registry = _Registry()
    transport = _transport(port, verifier, registry=registry)

    session: NapalmSession = await transport.open_napalm()
    try:
        assert session.driver == "ios"
        assert verifier.keys[(HOST, port)] == [key_line(key)]
        assert verifier.operations() == ["trusted_keys", "learn"]
        assert servers.seen.passwords == [PASSWORD]
        # The driver holds the transport's connection, registered for
        # cancellation, and never a password of its own.
        driver = session._driver  # type: ignore[attr-defined]
        assert driver.password == ""
        assert registry.live == [driver.device]
        # NAPALM's getters pass no read timeout; the step's Command Timeout
        # (5 s here) replaces netmiko's 10 s default.
        assert driver.device.read_timeout_override == 5.0
    finally:
        await session.close()
    assert registry.live == []


async def test_a_changed_host_key_refuses_the_session_before_the_password_is_sent(servers):
    trusted, presented = _key(), _key()
    port = await servers.device(presented)
    verifier = FakeVerifier()
    verifier.trust(HOST, port, trusted)

    with pytest.raises(HostKeyRejectedError, match="does not match"):
        await _transport(port, verifier).open_napalm()

    assert servers.seen.passwords == []
    assert verifier.calls[-1] == ("rejected", HOST, port, key_line(presented))


async def test_without_a_verifier_no_session_is_opened(servers):
    port = await servers.device(_key())

    with pytest.raises(HostKeyRejectedError, match="no SSH host-key verifier"):
        await _transport(port, None).open_napalm()

    assert servers.seen.passwords == []


async def test_the_session_rides_the_jump_host_with_both_hops_checked(servers):
    device_key, bastion_key = _key(), _key()
    device_port = await servers.device(device_key)
    jump_port = await servers.bastion(bastion_key)
    verifier = FakeVerifier()
    verifier.trust(HOST, jump_port, bastion_key)
    verifier.trust(HOST, device_port, device_key)

    session = await _transport(device_port, verifier, jump_port=jump_port).open_napalm()
    await session.close()

    assert servers.seen.forwards == [(HOST, device_port)]
    assert servers.seen.passwords == [JUMP_PASSWORD, PASSWORD]


# --- the session surface -------------------------------------------------------------------


async def test_a_cancelled_open_closes_the_login_that_finishes_after_it(monkeypatch):
    import asyncio
    import threading
    import types

    transport = _transport(22, FakeVerifier())
    release = threading.Event()
    started = threading.Event()
    connection = types.SimpleNamespace()
    logged_out: list[Any] = []

    def slow_login() -> Any:
        started.set()
        release.wait(5)
        return connection

    monkeypatch.setattr(transport, "_login", slow_login)
    monkeypatch.setattr(transport, "_logout", logged_out.append)

    task = asyncio.create_task(transport.open_napalm())
    await asyncio.to_thread(started.wait, 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # Any clean-up started at cancellation has run by now, before the login
    # finishes: it must not be the only chance to close the connection.
    await asyncio.sleep(0.3)
    assert logged_out == []
    # The login finishes after the caller gave up: the thread closes it.
    release.set()
    for _ in range(100):
        if logged_out:
            break
        await asyncio.sleep(0.02)
    assert logged_out == [connection]


class _FakeDriver:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any]] = []
        self.closed = 0

    def get_config(self, sanitized: bool = False) -> dict[str, Any]:
        self.calls.append(("get_config", sanitized))
        return {"running": "snmp-server community <removed>" if sanitized else "secret"}

    def get_bgp_config(self) -> dict[str, Any]:
        self.calls.append(("get_bgp_config", None))
        return {
            "core": {
                "authentication_key": "group-pw",
                "neighbors": {"192.0.2.2": {"authentication_key": "peer-pw", "remote_as": 65001}},
            }
        }

    def get_facts(self) -> dict[str, Any]:
        self.calls.append(("get_facts", None))
        return {"hostname": "r1"}

    def get_users(self) -> dict[str, Any]:  # pragma: no cover - must never be called
        raise AssertionError("get_users returns credentials and must not be reachable")

    def load_merge_candidate(self, config: str) -> None:
        self.calls.append(("merge", config))

    def load_replace_candidate(self, config: str) -> None:
        self.calls.append(("replace", config))

    def compare_config(self) -> str:
        return ""

    def commit_config(self, message: str = "", revert_in: int | None = None) -> None:
        self.calls.append(("commit", revert_in))

    def close(self) -> None:
        self.closed += 1


def _session(driver: _FakeDriver) -> Any:
    transport = _transport(22, FakeVerifier())
    return napalm_transport.NapalmDriverSession(transport, "ios", driver)


async def test_only_listed_getters_can_be_read():
    driver = _FakeDriver()
    session = _session(driver)

    assert await session.get("facts") == {"hostname": "r1"}
    for getter in ("users", "snmp_information", "route_to", "__class__"):
        assert getter not in NAPALM_GETTERS
        with pytest.raises(ValueError, match="not a NAPALM getter"):
            await session.get(getter)
    assert driver.calls == [("get_facts", None)]


async def test_the_session_maps_its_calls_onto_the_driver():
    driver = _FakeDriver()
    session = _session(driver)

    await session.load_config("hostname r2")
    await session.load_config("hostname r3", replace=True)
    assert await session.compare_config() == ""
    await session.commit_config(revert_in=120)

    assert driver.calls == [("merge", "hostname r2"), ("replace", "hostname r3"), ("commit", 120)]


async def test_close_is_idempotent_and_ends_the_session():
    driver = _FakeDriver()
    session = _session(driver)

    await session.close()
    await session.close()

    assert driver.closed == 1
    with pytest.raises(NapalmSessionClosedError):
        await session.get("facts")


async def test_getters_never_return_credentials():
    driver = _FakeDriver()
    session = _session(driver)

    config = await session.get("config")
    bgp = await session.get("bgp_config")

    assert ("get_config", True) in driver.calls
    assert config == {"running": "snmp-server community <removed>"}
    assert bgp == {"core": {"neighbors": {"192.0.2.2": {"remote_as": 65001}}}}
    assert "pw" not in repr(bgp)


async def test_nxos_replace_is_refused_before_anything_is_sent():
    driver = _FakeDriver()
    session = napalm_transport.NapalmDriverSession(
        _transport(22, FakeVerifier(), platform="nxos"), "nxos_ssh", driver
    )

    with pytest.raises(NotImplementedError, match="SCP"):
        await session.load_config("hostname n1", replace=True)
    await session.load_config("hostname n1")

    assert driver.calls == [("merge", "hostname n1")]


async def test_a_failure_after_the_login_still_closes_the_connection(monkeypatch):
    transport = _transport(22, FakeVerifier())
    connection = object()  # takes no attributes: the step after the login fails
    logged_out: list[Any] = []
    monkeypatch.setattr(transport, "_login", lambda: connection)
    monkeypatch.setattr(transport, "_logout", logged_out.append)

    with pytest.raises(AttributeError):
        await transport.open_napalm()

    assert logged_out == [connection]


async def test_close_waits_for_a_driver_call_its_caller_gave_up_on():
    import asyncio
    import threading

    release, started = threading.Event(), threading.Event()
    events: list[str] = []

    class SlowDriver(_FakeDriver):
        def commit_config(self, message: str = "", revert_in: int | None = None) -> None:
            started.set()
            release.wait(5)
            events.append("commit done")

        def close(self) -> None:
            events.append("close")

    session = _session(SlowDriver())
    call = asyncio.create_task(session.commit_config())
    await asyncio.to_thread(started.wait, 5)
    call.cancel()
    closing = asyncio.create_task(session.close())
    await asyncio.sleep(0.2)
    # The commit still runs in its thread: the driver is not closed under it.
    assert events == []
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await call
    await closing
    assert events == ["commit done", "close"]


async def test_cancelling_a_pending_commit_uses_each_platforms_own_command():
    class EosDriver(_FakeDriver):
        config_session = "napalm_42"

        def _run_commands(self, commands: list[str], encoding: str = "json") -> None:
            self.calls.append(("run", commands))

    class IosDriver(_FakeDriver):
        def _commit_handler(self, cmd: str) -> None:
            self.calls.append(("commit_handler", cmd))

    eos, ios = EosDriver(), IosDriver()
    await napalm_transport.NapalmDriverSession(
        _transport(22, FakeVerifier(), platform="eos"), "eos", eos
    ).cancel_pending_commit()
    await napalm_transport.NapalmDriverSession(
        _transport(22, FakeVerifier()), "ios", ios
    ).cancel_pending_commit()

    assert eos.calls == [("run", ["configure session napalm_42 abort"])]
    assert eos.config_session is None
    assert ios.calls == [("commit_handler", "configure revert now")]
    with pytest.raises(NotImplementedError, match="no confirmed commit"):
        await napalm_transport.NapalmDriverSession(
            _transport(22, FakeVerifier(), platform="nxos"), "nxos_ssh", _FakeDriver()
        ).cancel_pending_commit()
