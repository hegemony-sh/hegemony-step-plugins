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
    RpcFailed,
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


class CommitUncertain(NetconfError):
    """A confirmed commit with a persist id got no reply: it may be pending on the device.

    ``persist_id`` lets a netconf.commit or netconf.cancel_commit step settle
    it anyway (the device refuses the id when nothing is pending).
    """

    def __init__(self, message: str, persist_id: str) -> None:
        super().__init__(message)
        self.persist_id = persist_id


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
    persist_id: str = "",
    check_pending: bool = False,
) -> ChangeResult:
    """Run the change on the candidate datastore (see the module docstring).

    ``persist_id`` is the id a "confirm in a later step" commit is made
    under. A caller passes one that is the same on every attempt of the step
    for the device. With ``check_pending`` (a retry of the step, never a
    first attempt) the step first asks whether an earlier attempt left a
    commit pending under that id; when it did, the change is still applied
    and diffed, and anything it adds is committed under the same id, so the
    commit stays one pending commit that rolls back as a whole.

    ``diff_complete`` is False when ``read`` returns only part of the
    configuration (a diff filter, or a vendor's modelled view): an empty diff
    then proves nothing, so the change is validated and committed all the
    same.
    """
    if not session.supports(CAP_CANDIDATE):
        raise NetconfError("the device has no candidate datastore (:candidate capability)")
    if not options.dry_run:
        error = commit_mode_error(session, options.commit_mode)
        if error:
            raise NetconfError(error)
    result = ChangeResult(datastore="candidate")
    locked: list[str] = []
    # Only on a retry: a first attempt cannot have left anything pending,
    # and does not depend on how a server answers an unknown persist id.
    recover = (
        check_pending
        and not options.dry_run
        and options.commit_mode == "later"
        and bool(persist_id)
    )
    try:
        earlier_pending = False
        if recover:
            # A device refuses to lock running while a confirmed commit is
            # pending (RFC 6241 7.5), so the check comes first, under the
            # candidate lock; running is locked only when nothing is pending.
            await session.lock("candidate")
            locked.append("candidate")
            await session.discard_changes()
            earlier_pending = await _still_pending(session, options, result, persist_id)
            if not earlier_pending:
                await session.lock("running")
                locked.insert(0, "running")
        else:
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
        if earlier_pending and not result.changed and diff_complete:
            # The pending commit already holds the change: report it as pending.
            await session.discard_changes()
            result.notes.append(
                "an earlier attempt of this step left this change pending under the same "
                "persist id; its confirm timeout restarted: confirm it with netconf.commit "
                f"within {options.confirm_timeout_seconds} s"
            )
            return result
        if not result.changed and diff_complete:
            await session.discard_changes()
            result.notes.append("the change leaves the configuration as it is: nothing committed")
            if options.save_config and not options.dry_run:
                # Running already holds the change, perhaps from an earlier
                # attempt whose save failed: save it now, as asked.
                await _save(session, result)
            return result
        if not result.changed:
            # Unknown, so counted as changed: the part the reads leave out may differ.
            result.changed = True
            result.notes.append(
                "the diff shows no difference, but it covers only part of the configuration; "
                "the rest may differ, so the change is committed as asked and counted as changed"
            )
        if options.validate and session.can_validate:
            await session.validate("candidate")
            result.validated = True
        if options.dry_run:
            await session.discard_changes()
            result.notes.append("dry run: the candidate was discarded, nothing committed")
            return result
        await _commit(session, options, result, check, persist_id)
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


#: rpc-error tags that say a persist id names no pending commit (RFC 6241 8.4;
#: servers differ in the tag). Any other refusal leaves the outcome open.
_NOTHING_PENDING_TAGS = ("invalid-value", "unknown-element", "bad-element", "missing-element")


def _refuses_the_persist_id(exc: RpcFailed) -> bool:
    """Whether every error refuses the persist id itself, not another parameter.

    The tags also report other bad parameters (RFC 6241 appendix A), such as
    a confirm timeout the device does not accept; an error whose path names
    something else, or whose message is about the timeout, leaves the
    outcome open.
    """
    return bool(exc.errors) and all(
        error.tag in _NOTHING_PENDING_TAGS
        and ("persist-id" in error.path if error.path else "timeout" not in error.message.lower())
        for error in exc.errors
    )


async def _still_pending(
    session: NetconfSession, options: ChangeOptions, result: ChangeResult, persist_id: str
) -> bool:
    """Whether an earlier attempt of this step left its commit pending under ``persist_id``.

    A follow-up confirmed commit with that persist id (RFC 6241 8.4) succeeds
    only while the commit is pending, and restarts its confirm timeout; the
    candidate it commits equals running here, so it changes nothing else.
    """
    timeout = options.confirm_timeout_seconds
    try:
        await session.commit(
            confirmed=True, confirm_timeout=timeout, persist=persist_id, persist_id=persist_id
        )
    except RpcFailed as exc:
        if _refuses_the_persist_id(exc):
            return False  # the device refused the id: nothing is pending under it
        # Refused for another reason (operation-failed, in-use...): the
        # earlier commit may still be pending, so the id is kept.
        raise CommitUncertain(
            f"{exc}; a commit from an earlier attempt may be pending under persist id "
            f"{persist_id}: confirm or cancel it, or let it roll back",
            persist_id,
        ) from exc
    except Exception as exc:
        # No answer (a timeout, a dropped session, a channel error): the
        # earlier commit may still be pending, so the id is kept.
        raise CommitUncertain(
            f"{exc}; a commit from an earlier attempt may be pending under persist id "
            f"{persist_id}: confirm or cancel it, or let it roll back",
            persist_id,
        ) from exc
    result.pending = True
    result.persist_id = persist_id
    result.save_requested = options.save_config
    return True


async def _final_commit(session: NetconfSession) -> None:
    """The commit that makes the change final; a timeout may hide that it happened."""
    try:
        await session.commit()
    except RpcFailed:
        raise  # refused: nothing was committed
    except Exception as exc:
        # No answer (a timeout, a dropped session, a channel error).
        raise NetconfError(
            f"{exc}; the device may already have committed the change, so check its "
            "configuration before running the step again"
        ) from None


async def _commit(
    session: NetconfSession,
    options: ChangeOptions,
    result: ChangeResult,
    check: Callable[[], Awaitable[None]],
    persist_id: str = "",
) -> None:
    timeout = options.confirm_timeout_seconds
    if options.commit_mode == "direct":
        await _final_commit(session)
        result.committed = True
        return
    if options.commit_mode == "later":
        # A commit an earlier attempt left pending is extended, not replaced:
        # a follow-up confirmed commit under its persist id (RFC 6241 8.4).
        follow_up = result.pending
        result.persist_id = persist_id or secrets.token_urlsafe(18)
        try:
            await session.commit(
                confirmed=True,
                confirm_timeout=timeout,
                persist=result.persist_id,
                persist_id=result.persist_id if follow_up else "",
            )
        except RpcFailed as exc:
            if not follow_up:
                raise  # refused: nothing was committed
            # Refused, but the earlier attempt's commit is still pending.
            with contextlib.suppress(Exception):
                await session.discard_changes()
            raise CommitUncertain(
                f"{exc}; the commit an earlier attempt left pending under persist id "
                f"{result.persist_id} is still pending without this change: confirm or "
                "cancel it, or let it roll back",
                result.persist_id,
            ) from exc
        except Exception as exc:
            # No answer (a timeout, a dropped session, a channel error, broken
            # framing): the device may have taken the commit, so the id is kept.
            raise CommitUncertain(
                f"{exc}; the commit may be pending on the device under persist id "
                f"{result.persist_id}: confirm or cancel it, or let it roll back after "
                f"{timeout} s",
                result.persist_id,
            ) from None
        result.pending = True
        if follow_up:
            result.notes.append(
                "an earlier attempt of this step left a commit pending under the same persist "
                "id; this change was added to it, so confirming or cancelling settles both"
            )
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
    await _final_commit(session)
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
        try:
            await apply()
        except NetconfError as exc:
            if session.supports(CAP_ROLLBACK_ON_ERROR):
                raise
            raise NetconfError(
                f"{exc}. The device has no :rollback-on-error, so the failed edit may "
                "have applied in part: check its running configuration"
            ) from exc
        result.after = await read("running")
        result.diff = unified_diff(
            result.before, result.after, before_name="running (before)", after_name="running"
        )
        result.changed = bool(result.diff)
        if not result.changed and not diff_complete:
            # Unknown, so counted as changed (and saved): the part the reads leave out may differ.
            result.changed = True
            result.notes.append(
                "the diff shows no difference, but it covers only part of the configuration; "
                "the rest may have changed, so the change is counted as changed"
            )
        result.committed = result.changed
        if options.save_config:
            # Also when nothing changed: an earlier attempt may have applied
            # the change and failed to save it.
            await _save(session, result)
        return result
    finally:
        if locked:
            with contextlib.suppress(Exception):
                await session.unlock("running")
