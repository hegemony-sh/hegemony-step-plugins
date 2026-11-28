# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The ``napalm`` device transport: network CLI plus NAPALM driver sessions.

NAPALM's SSH drivers (``ios``, ``eos`` over SSH, ``nxos_ssh``) run every
operation on one netmiko connection, which they open themselves with
``_netmiko_open``. This transport extends the netmiko transport and hands
those drivers the connection *its* login opens instead
(:meth:`SSHTransport._login`), so a NAPALM session gets the same SSH
hardening as a CLI step: the organization's trusted host keys on both hops,
the jump host, the SSH algorithm policy and its recorded agreement, and
cancellation through the host's registry. The driver itself is never given a
password: it has nothing to log in with but the connection it is handed.

Drivers with their own connection stacks are not offered: Junos (PyEZ, which
does not check host keys unless told to, and NAPALM does not tell it), the
eAPI and NX-API drivers (HTTPS, outside the SSH trust model) and IOS-XR.

As a CLI transport (``connect()`` on a device whose
``access_config.ssh.transport`` is ``napalm``) it behaves as the netmiko
transport does, so ``netcli.*`` steps work on the same device.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import re
from collections.abc import Callable
from typing import Any, TypeVar

from hegemony_step_sdk import NAPALM_GETTERS
from hegemony_transport_netmiko.transport import SSHTransport, _LoginHandoff

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

#: Hegemony device platform -> (NAPALM driver, netmiko device type it runs on).
PLATFORM_TO_DRIVER: dict[str, tuple[str, str]] = {
    "ios-xe": ("ios", "cisco_ios"),
    "ios": ("ios", "cisco_ios"),
    "eos": ("eos", "arista_eos"),
    "nxos": ("nxos_ssh", "cisco_nxos"),
}

#: Options every driver is built with. ``transport`` keeps EOS on SSH (its
#: default is eAPI over HTTPS, which this transport does not secure) and IOS
#: off telnet. ``inline_transfer`` makes IOS send a candidate through the
#: session itself (the device's TCL shell) instead of SCP: netmiko's SCP opens
#: a second SSH client, which has neither the trusted host keys (their file is
#: gone once the login is done) nor a way through the jump host.
_DRIVER_OPTIONS: dict[str, dict[str, Any]] = {
    "ios": {"transport": "ssh", "inline_transfer": True},
    "eos": {"transport": "ssh"},
    "nxos_ssh": {},
}

#: Drivers whose replace copies the candidate to the device with SCP, which
#: this transport cannot secure (see ``_DRIVER_OPTIONS``). Merge stays open.
_NO_REPLACE = {"nxos_ssh": "Cisco NX-OS copies a replacement configuration with SCP"}

#: Fields that hold credentials in NAPALM getter results (``get_bgp_config``
#: returns BGP neighbor passwords as ``authentication_key``). They are dropped
#: from every result, whatever the getter, before it leaves the session.
_SECRET_FIELDS = frozenset({"authentication_key", "auth_key", "password", "secret"})


def _without_secrets(value: Any) -> Any:
    """``value`` with every credential field dropped, at any depth."""
    if isinstance(value, dict):
        return {
            key: _without_secrets(item)
            for key, item in value.items()
            if not (isinstance(key, str) and key.lower() in _SECRET_FIELDS)
        }
    if isinstance(value, list):
        return [_without_secrets(item) for item in value]
    return value


def driver_for(platform: str) -> str:
    """The NAPALM driver for a Hegemony platform; ``NotImplementedError`` when none."""
    entry = PLATFORM_TO_DRIVER.get(platform)
    if entry is None:
        supported = ", ".join(sorted(PLATFORM_TO_DRIVER))
        raise NotImplementedError(
            f"NAPALM steps do not support the device platform {platform!r}; "
            f"supported platforms: {supported}"
        )
    return entry[0]


def _driver_class(name: str, transport: NapalmTransport) -> type:
    """NAPALM's driver class ``name``, opening and closing through ``transport``."""
    from napalm import get_network_driver

    base = get_network_driver(name)

    def _netmiko_open(self: Any, device_type: str, netmiko_optional_args: Any = None) -> Any:
        # The hardened login: host keys, jump host, algorithm policy,
        # cancellation registration and enable mode.
        del device_type, netmiko_optional_args
        connection = transport._login()
        # Recorded first, so a failure below still finds it to close.
        self._netmiko_device = connection
        # NAPALM's getters call send_command without a read timeout, so
        # netmiko would wait its own 10 s default; the step's Command Timeout
        # applies instead.
        connection.read_timeout_override = transport.command_timeout
        return connection

    def _netmiko_close(self: Any) -> None:
        connection = getattr(self, "_netmiko_device", None)
        self._netmiko_device = None
        self.device = None
        if connection is not None:
            transport._logout(connection)

    return type(
        f"Hegemony{base.__name__}",
        (base,),
        {"_netmiko_open": _netmiko_open, "_netmiko_close": _netmiko_close},
    )


class NapalmSessionClosedError(RuntimeError):
    """A call on a session that was closed."""


class NapalmDriverSession:
    """One open NAPALM driver; satisfies ``hegemony_step_sdk.NapalmSession``.

    Calls run one at a time in an executor thread (the driver is not
    thread-safe), on the transport's thread so the host-key verifier is
    reached from the event loop the session was opened on.
    """

    def __init__(self, transport: NapalmTransport, driver_name: str, driver: Any) -> None:
        self.driver = driver_name
        self._transport = transport
        self._driver: Any = driver
        self._lock = asyncio.Lock()

    async def _call(self, func: Callable[[Any], _T]) -> _T:
        async with self._lock:
            driver = self._driver
            if driver is None:
                raise NapalmSessionClosedError("the NAPALM session is closed")
            # A running executor call cannot be stopped. If the caller is
            # cancelled, the lock stays held until the call returns, so
            # close() never tears the driver down under a commit in progress.
            future = asyncio.ensure_future(self._transport._run_in_thread(lambda: func(driver)))
            try:
                return await asyncio.shield(future)
            except asyncio.CancelledError:
                # asyncio.wait never raises the call's own error, so the
                # cancellation is what the caller gets, whatever the call did.
                while not future.done():
                    with contextlib.suppress(asyncio.CancelledError):
                        await asyncio.wait({future})
                if not future.cancelled():
                    future.exception()  # retrieved: the cancellation wins
                raise

    async def get(self, getter: str) -> Any:
        if getter not in NAPALM_GETTERS:
            raise ValueError(f"{getter!r} is not a NAPALM getter a step may read")
        if getter == "config":
            # NAPALM's own sanitizing: passwords, keys and community strings
            # are masked in the configuration text.
            result = await self._call(lambda driver: driver.get_config(sanitized=True))
        else:
            method = f"get_{getter}"
            result = await self._call(lambda driver: getattr(driver, method)())
        return _without_secrets(result)

    async def load_config(self, config: str, *, replace: bool = False) -> None:
        if replace and self.driver in _NO_REPLACE:
            raise NotImplementedError(
                f"{_NO_REPLACE[self.driver]}, which this transport cannot secure; use merge instead"
            )
        if replace:
            await self._call(lambda driver: driver.load_replace_candidate(config=config))
        else:
            await self._call(lambda driver: driver.load_merge_candidate(config=config))

    async def compare_config(self) -> str:
        diff = await self._call(lambda driver: driver.compare_config())
        return diff or ""

    async def discard_config(self) -> None:
        await self._call(lambda driver: driver.discard_config())

    async def commit_config(self, *, message: str = "", revert_in: int | None = None) -> None:
        await self._call(lambda driver: driver.commit_config(message=message, revert_in=revert_in))

    async def has_pending_commit(self) -> bool:
        name = self.driver
        return await self._call(lambda driver: _pending(name, driver))

    async def confirm_commit(self) -> None:
        await self._call(lambda driver: driver.confirm_commit())

    async def rollback(self) -> None:
        await self._call(lambda driver: driver.rollback())

    async def cancel_pending_commit(self) -> None:
        # The platforms' own commands for "undo the pending confirmed commit".
        # Each does nothing when no commit is pending (its timer fired), so a
        # race with the timer is harmless. NAPALM's rollback() would instead
        # fall back to restoring the copy saved at commit time.
        name = self.driver

        def _cancel(driver: Any) -> None:
            if name == "eos":
                session = getattr(driver, "config_session", None)
                if not session:
                    raise RuntimeError("no EOS configuration session waits for confirmation")
                reply = driver._run_commands(
                    [f"configure session {session} abort"], encoding="text"
                )
                driver.config_session = None
            elif name == "ios":
                reply = driver._commit_handler("configure revert now")
            else:
                raise NotImplementedError(f"the {name} driver has no confirmed commit to cancel")
            # Both drivers return the device's reply rather than raise on a
            # refused command. Ask the device instead of trusting the reply:
            # a commit still pending means it was not cancelled.
            if _pending(name, driver):
                raise RuntimeError(
                    f"the device did not cancel the pending commit: {_reply_text(reply)}"
                )

        await self._call(_cancel)

    async def close(self) -> None:
        async with self._lock:
            driver, self._driver = self._driver, None
            if driver is None:
                return

            def _close() -> None:
                try:
                    driver.close()
                except Exception:  # noqa: BLE001 - closing is best effort
                    logger.debug("closing the NAPALM driver failed", exc_info=True)
                    # The driver's own clean-up failed; the connection must
                    # still go.
                    with contextlib.suppress(Exception):
                        driver._netmiko_close()

            await self._transport._run_in_thread(_close)


class NapalmTransport(SSHTransport):
    """The netmiko transport, plus NAPALM driver sessions over its login."""

    transport_id = "napalm"

    #: Feature flag the host checks before calling :meth:`open_napalm`.
    supports_napalm_sessions = True

    def __init__(self, spec: Any, **kwargs: Any) -> None:
        super().__init__(spec, **kwargs)
        entry = PLATFORM_TO_DRIVER.get(spec.platform)
        if entry is not None:
            # NX-OS is not in the netmiko transport's platform table.
            self.device_type = entry[1]

    async def open_napalm(self) -> NapalmDriverSession:
        """Open a NAPALM driver for this device, logged in through this transport."""
        name = driver_for(self.platform)
        driver_class = _driver_class(name, self)
        driver = driver_class(
            hostname=self.host,
            username=self.username or "",
            # Never used: the driver logs in through _netmiko_open above.
            password="",
            timeout=int(max(self.command_timeout, 1)),
            optional_args=dict(_DRIVER_OPTIONS[name]),
        )
        handoff = _LoginHandoff()

        def _open() -> Any:
            try:
                driver.open()
            except BaseException:
                # A login that worked before the driver failed (EOS reads the
                # version first) must not stay open.
                _quiet_close(driver)
                raise
            if not handoff.deliver(driver):
                # The caller was cancelled while this ran; nobody owns it.
                _quiet_close(driver)
            return driver

        try:
            await self._run_in_thread(_open)
        except asyncio.CancelledError:
            # The open runs on in its thread. Whichever side comes second
            # closes the connection: this one if the open already finished,
            # otherwise the thread once it does.
            orphan = handoff.abandon()
            if orphan is not None:
                _quiet_close(orphan)
            raise
        return NapalmDriverSession(self, name, driver)


#: What IOS says when no confirmed commit is pending, or cannot be.
_IOS_NOTHING_PENDING = ("No Rollback Confirmed Change pending", "Archive feature not enabled")
#: Fields IOS shows for a pending confirmed commit.
_IOS_PENDING_FIELDS = re.compile(r"^\s*(?:Timer value|Time configured)\b", re.MULTILINE)


def _pending(name: str, driver: Any) -> bool:
    """Whether a confirmed commit waits for confirmation; raises when it cannot tell.

    NAPALM's IOS driver answers False for any output it does not recognise
    (an error, a changed format), which would read as "nothing pending".
    Here only IOS's explicit answers count; anything else is unknown.
    """
    if name != "ios":
        return bool(driver.has_pending_commit())
    output = str(driver.device.send_command("show archive config rollback timer") or "")
    if any(text in output for text in _IOS_NOTHING_PENDING):
        return False
    if _IOS_PENDING_FIELDS.search(output):
        return True
    raise RuntimeError(f"cannot tell whether a commit is pending: {_reply_text(output)}")


def _reply_text(reply: Any) -> str:
    """A device reply for an error message: plain text, short."""
    if isinstance(reply, list):
        reply = " ".join(
            str(item.get("output", item)) if isinstance(item, dict) else str(item) for item in reply
        )
    text = " ".join(str(reply or "").split())
    return (text[:300] + "…") if len(text) > 300 else (text or "no reply")


def _quiet_close(driver: Any) -> None:
    with contextlib.suppress(Exception):
        driver._netmiko_close()
