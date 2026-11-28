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
from collections.abc import Callable
from typing import Any, TypeVar

from hegemony_step_sdk import NAPALM_GETTERS
from hegemony_transport_netmiko.transport import SSHTransport

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
#: off telnet.
_DRIVER_OPTIONS: dict[str, dict[str, Any]] = {
    "ios": {"transport": "ssh"},
    "eos": {"transport": "ssh"},
    "nxos_ssh": {},
}


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
        self._netmiko_device = connection
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
            return await self._transport._run_in_thread(lambda: func(driver))

    async def get(self, getter: str) -> Any:
        if getter not in NAPALM_GETTERS:
            raise ValueError(f"{getter!r} is not a NAPALM getter a step may read")
        method = f"get_{getter}"
        return await self._call(lambda driver: getattr(driver, method)())

    async def load_config(self, config: str, *, replace: bool = False) -> None:
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
        return bool(await self._call(lambda driver: driver.has_pending_commit()))

    async def confirm_commit(self) -> None:
        await self._call(lambda driver: driver.confirm_commit())

    async def rollback(self) -> None:
        await self._call(lambda driver: driver.rollback())

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
        try:
            await self._run_in_thread(driver.open)
        except asyncio.CancelledError:
            # The open runs on in its thread; close whatever it opened.
            asyncio.get_running_loop().run_in_executor(None, _quiet_close, driver)
            raise
        except BaseException:
            _quiet_close(driver)
            raise
        return NapalmDriverSession(self, name, driver)


def _quiet_close(driver: Any) -> None:
    with contextlib.suppress(Exception):
        driver._netmiko_close()
