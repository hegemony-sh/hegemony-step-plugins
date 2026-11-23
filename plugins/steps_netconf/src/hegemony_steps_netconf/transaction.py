# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""One configuration change as a NETCONF transaction.

On the candidate datastore (the safe path, RFC 6241 sections 8.3 and 8.4):

1. lock running, then candidate, and discard anything left in the candidate;
2. read running, apply the change to the candidate, read the candidate, and
   diff the two: no difference ends the step with nothing committed;
3. validate the candidate (``:validate``), and stop there for a dry run;
4. commit: directly; or as a confirmed commit that the step confirms itself
   once a second NETCONF session shows the device is still manageable; or as
   a confirmed commit with a persist id, left for a later step to confirm or
   cancel, and rolled back by the device when nobody does in time;
5. optionally save running to startup, then unlock.

Any failure after the locks discards the candidate. On the running datastore
(devices without a candidate) the change applies at once, with
``rollback-on-error`` where the device offers it.

The change and the reads are callables, so ``netconf.edit_config`` (an
``edit-config``) and vendor change steps (a vendor RPC) share the whole
sequence.
"""

from __future__ import annotations

import asyncio
import contextlib
import difflib
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Literal

from .client import (
    CAP_CANDIDATE,
    CAP_CONFIRMED_11,
    CAP_ROLLBACK_ON_ERROR,
    CAP_WRITABLE_RUNNING,
    NetconfError,
    NetconfSession,
)

CommitMode = Literal["check", "later", "direct"]

#: Time kept before the confirm timeout for the confirmation to reach the
#: device (at most a quarter of the timeout).
CONFIRM_MARGIN_SECONDS = 10.0


@dataclass(frozen=True)
class ChangeOptions:
    """How the change is committed."""

    commit_mode: CommitMode = "check"
    confirm_timeout_seconds: int = 600
    dry_run: bool = False
    validate: bool = True
    save_config: bool = False


@dataclass
class ChangeResult:
    """What happened to one device's configuration."""

    datastore: str = "candidate"
    changed: bool = False
    committed: bool = False
    pending: bool = False
    persist_id: str = ""
    validated: bool = False
    saved: str = ""
    #: Why saving to startup failed after the change was made ("" if it did not).
    save_error: str = ""
    #: Save to startup was asked for but waits for the commit to be confirmed:
    #: the netconf.commit step that confirms it saves.
    save_requested: bool = False
    diff: str = ""
    before: str = ""
    after: str = ""
    notes: list[str] = field(default_factory=list)


class CheckFailed(NetconfError):
    """The device did not answer a second NETCONF session after a confirmed commit."""


def unified_diff(before: str, after: str, *, before_name: str, after_name: str) -> str:
    """A unified diff of two texts ("" when they are equal)."""
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=before_name,
            tofile=after_name,
        )
    )


def commit_mode_error(session: NetconfSession, mode: CommitMode) -> str | None:
    """Why ``mode`` cannot run on this device, or None."""
    if mode == "later" and not session.supports(CAP_CONFIRMED_11):
        return (
            "Commit 'confirm in a later step' needs the device's :confirmed-commit:1.1 "
            "capability (a persist id); use 'confirm in this step' or 'commit directly'"
        )
    if mode == "check" and not session.can_confirm:
        return "the device has no :confirmed-commit capability; set Commit to 'commit directly'"
    return None


async def change_candidate(
    session: NetconfSession,
    *,
    apply: Callable[[], Awaitable[None]],
    read: Callable[[str], Awaitable[str]],
    options: ChangeOptions,
    check: Callable[[], Awaitable[None]],
    diff_complete: bool = True,
) -> ChangeResult:
    """Run the change on the candidate datastore (see the module docstring).

    ``diff_complete`` is False when ``read`` returns only part of the
    configuration (a diff filter): an empty diff then proves nothing, so the
    change is validated and committed all the same.
    """
    if not session.supports(CAP_CANDIDATE):
        raise NetconfError("the device has no candidate datastore (:candidate capability)")
    if not options.dry_run:
        error = commit_mode_error(session, options.commit_mode)
        if error:
            raise NetconfError(error)
    result = ChangeResult(datastore="candidate")
    locked: list[str] = []
    try:
        await session.lock("running")
        locked.append("running")
        await session.lock("candidate")
        locked.append("candidate")
        # Left over from a session that ended without committing or discarding.
        await session.discard_changes()
        result.before = await read("running")
        await apply()
        result.after = await read("candidate")
        result.diff = unified_diff(
            result.before, result.after, before_name="running", after_name="candidate"
        )
        result.changed = bool(result.diff)
        if not result.changed and diff_complete:
            await session.discard_changes()
            result.notes.append("the change leaves the configuration as it is: nothing committed")
            return result
        if not result.changed:
            # Unknown, so counted as changed: the part outside the filter may differ.
            result.changed = True
            result.notes.append(
                "the filtered diff shows no difference; the part outside the filter may "
                "differ, so the change is committed as asked and counted as changed"
            )
        if options.validate and session.can_validate:
            await session.validate("candidate")
            result.validated = True
        if options.dry_run:
            await session.discard_changes()
            result.notes.append("dry run: the candidate was discarded, nothing committed")
            return result
        await _commit(session, options, result, check)
        if options.save_config and result.pending:
            result.save_requested = True
        elif options.save_config and result.committed:
            await _save(session, result)
        return result
    except BaseException:
        if "candidate" in locked and not result.committed and not result.pending:
            with contextlib.suppress(Exception):
                await session.discard_changes()
        raise
    finally:
        for target in reversed(locked):
            with contextlib.suppress(Exception):
                await session.unlock(target)


async def _commit(
    session: NetconfSession,
    options: ChangeOptions,
    result: ChangeResult,
    check: Callable[[], Awaitable[None]],
) -> None:
    timeout = options.confirm_timeout_seconds
    if options.commit_mode == "direct":
        await session.commit()
        result.committed = True
        return
    if options.commit_mode == "later":
        result.persist_id = secrets.token_urlsafe(18)
        await session.commit(confirmed=True, confirm_timeout=timeout, persist=result.persist_id)
        result.pending = True
        result.notes.append(
            f"confirmed commit pending: confirm it with netconf.commit within {timeout} s, "
            "or the device restores the previous configuration"
        )
        return
    loop = asyncio.get_running_loop()
    # Counted from before the request, so the step's clock runs ahead of the
    # device's; the margin leaves the confirmation time to arrive.
    started = loop.time()
    margin = min(CONFIRM_MARGIN_SECONDS, timeout / 4)
    await session.commit(confirmed=True, confirm_timeout=timeout)
    try:
        budget = timeout - margin - (loop.time() - started)
        if budget <= 0:
            raise TimeoutError("the confirmed commit itself used up the confirm timeout")
        try:
            await asyncio.wait_for(check(), timeout=budget)
        except TimeoutError:
            raise TimeoutError(
                f"the check did not finish within the confirm timeout of {timeout} s"
            ) from None
    except Exception as exc:
        # Roll back now rather than wait out the timeout. Without
        # :confirmed-commit:1.1 there is no cancel-commit; closing this
        # session (the caller does) rolls the commit back instead.
        if session.supports(CAP_CONFIRMED_11):
            with contextlib.suppress(Exception):
                await session.cancel_commit()
        raise CheckFailed(
            "after the confirmed commit the device did not accept a second NETCONF "
            f"session ({exc}); the change was rolled back"
        ) from exc
    if loop.time() - started >= timeout - margin:
        # Too late to confirm: the device may already have restored the old
        # configuration, and a plain commit now would not confirm the change.
        raise CheckFailed(
            f"the confirm timeout of {timeout} s ran out during the check; the device "
            "restores the previous configuration, so the change was not confirmed"
        )
    await session.commit()
    result.committed = True


async def _save(session: NetconfSession, result: ChangeResult) -> None:
    """Save running to startup; a failure is recorded, not raised: the change stands."""
    try:
        result.saved = await session.save_config()
    except Exception as exc:  # noqa: BLE001 - reported with the change kept
        result.save_error = str(exc) or type(exc).__name__


async def change_running(
    session: NetconfSession,
    *,
    apply: Callable[[], Awaitable[None]],
    read: Callable[[str], Awaitable[str]],
    options: ChangeOptions,
    diff_complete: bool = True,
) -> ChangeResult:
    """Apply the change to the running datastore at once (no candidate).

    With ``diff_complete`` False (a diff filter) an empty diff does not show
    that nothing changed, so the change counts as made and is saved.
    """
    if not session.supports(CAP_WRITABLE_RUNNING):
        raise NetconfError("the device's running datastore is not writable (:writable-running)")
    if options.dry_run:
        raise NetconfError("a dry run needs the candidate datastore")
    result = ChangeResult(datastore="running")
    locked = False
    try:
        await session.lock("running")
        locked = True
        result.before = await read("running")
        await apply()
        result.after = await read("running")
        result.diff = unified_diff(
            result.before, result.after, before_name="running (before)", after_name="running"
        )
        result.changed = bool(result.diff)
        if not result.changed and not diff_complete:
            # Unknown, so counted as changed (and saved): the part outside the filter may differ.
            result.changed = True
            result.notes.append(
                "the filtered diff shows no difference; the part outside the filter may "
                "have changed, so the change is counted as changed"
            )
        result.committed = result.changed
        if not session.supports(CAP_ROLLBACK_ON_ERROR):
            result.notes.append(
                "the device has no :rollback-on-error, so a failed edit may have applied in part"
            )
        if options.save_config and result.committed:
            await _save(session, result)
        return result
    finally:
        if locked:
            with contextlib.suppress(Exception):
                await session.unlock("running")
