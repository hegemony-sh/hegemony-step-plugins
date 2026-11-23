# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""What a step may read from, and record on, the platform about its own run.

Handlers call these functions, and the named methods of
:class:`HandlerServices` such as ``fetch_run_artifacts``, instead of building
internal-API requests with :meth:`HandlerServices.open_api_client`. Each one
reaches only the step's own run or the run's organization, which is what a
worker outside the platform's network (an edge worker) will be allowed to
do; a raw internal path is not part of the plugin contract and may be
refused there.

Each function uses the host's named method when the host has it, and falls
back to the internal route on a host from before those methods existed
(platform releases up to 1.0.0-rc.19). Drop the fallbacks once no supported
platform lacks the methods.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from .contract import HandlerContext

_TIMEOUT_SECONDS = 30.0


def _host_method(services: object, name: str) -> Any:
    """The host's own implementation of ``name``, or None when it has none.

    A host that subclasses :class:`HandlerServices` without implementing a
    newer method inherits the protocol's empty stub, which returns None:
    that counts as missing, so the fallback is used.
    """
    from .services import HandlerServices

    method = getattr(services, name, None)
    if not callable(method):
        return None
    stub = getattr(HandlerServices, name, None)
    if stub is not None and getattr(method, "__func__", None) is stub:
        return None
    return method


class PlatformRequestError(RuntimeError):
    """The platform could not answer a step's request; ``status_code`` when it said why."""

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


async def fetch_notification_destination(
    ctx: HandlerContext, destination_id: str
) -> dict[str, Any] | None:
    """A notification destination of the run's organization, or None when there is none.

    None covers an unknown, disabled or other organization's destination alike.
    The mapping holds ``id``, ``name``, ``type`` and ``config_json``. Raises
    :class:`PlatformRequestError` when the platform does not answer, also on
    a network error (``status_code`` is then None), on any host: the error
    the host raised is its ``__cause__``. An id
    that is not a UUID answers None: it could change the request's path.
    """
    try:
        destination_id = str(UUID(str(destination_id)))
    except ValueError:
        return None
    services = ctx.require_services()
    method = _host_method(services, "fetch_notification_destination")
    if method is not None:
        try:
            return await method(destination_id)
        except PlatformRequestError:
            raise
        except Exception as exc:  # the host's own error type
            raise PlatformRequestError(f"the platform did not answer: {exc}") from exc
    try:
        async with services.open_api_client(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.get(f"/internal/notification-destinations/{destination_id}")
    except Exception as exc:  # the host's client: httpx or another transport
        raise PlatformRequestError(f"the platform did not answer: {exc}") from exc
    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise PlatformRequestError(
            f"the notification destination could not be read (HTTP {response.status_code})",
            status_code=response.status_code,
        )
    return response.json()


async def emit_run_event(
    ctx: HandlerContext,
    message: str,
    *,
    kind: str = "log",
    attrs: dict[str, Any] | None = None,
) -> None:
    """Record an event on the step's own run, attributed to the step.

    The step's run, step run, step id and phase come from ``ctx``. Raises
    :class:`PlatformRequestError` when the platform does not record it, also
    on a network error (``status_code`` is then None). This function does
    not retry; the host may retry safely (its retries carry one
    ``Idempotency-Key``).
    """
    services = ctx.require_services()
    phase = ctx.tags.get("phase", "")
    method = _host_method(services, "emit_run_event")
    if method is not None:
        try:
            await method(message, kind=kind, attrs=attrs or {}, phase=phase)
        except PlatformRequestError:
            raise
        except Exception as exc:  # the host's own error type
            raise PlatformRequestError(f"the platform did not record the event: {exc}") from exc
        return
    try:
        async with services.open_api_client(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"/internal/runs/{ctx.run_id}/events",
                json={
                    "step_run_id": ctx.step_run_id,
                    "step_id": ctx.step_id,
                    "phase": phase,
                    "kind": kind,
                    "message": message,
                    "attrs": attrs or {},
                },
            )
    except Exception as exc:  # no retry here: a repeat could record the event twice
        raise PlatformRequestError(f"the platform did not answer: {exc}") from exc
    if response.status_code not in (200, 201):
        raise PlatformRequestError(
            f"the run event was not recorded (HTTP {response.status_code})",
            status_code=response.status_code,
        )
