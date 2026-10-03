# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Read, and afterwards remove, ``secret.write``'s source files in the run's shared workspace.

The workspace is written by step containers, which the worker does not trust:
a container can leave a symbolic link where a file is expected, pointing at
the worker's own files, or swap one in while this step runs. So every
component below the workspace root is opened relative to its parent directory
with ``O_NOFOLLOW`` (no symbolic link is followed anywhere on the path), the
file must be a regular file, and the file opened must be the one inspected. A
``realpath`` check that the path stays inside the workspace comes first, so a
link that escapes it is named as such.

Messages name keys and paths inside the workspace, never file contents.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from .paths import workspace_relative

#: Largest source file accepted.
MAX_FILE_BYTES = 64 * 1024
#: Largest total of all source files of one step.
MAX_TOTAL_BYTES = 1024 * 1024

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_CHUNK = 64 * 1024


class WorkspaceError(ValueError):
    """A source file cannot be used, or the workspace cannot be read. Names no content."""


@dataclass(frozen=True, slots=True)
class SourceFile:
    """One source file as read: the key it is stored under and its bytes."""

    key: str
    #: Path inside the run's shared workspace (``out/cert.pem``).
    path: str
    data: bytes = field(repr=False)
    #: Identity of the file read (device, inode, size, modification time), so
    #: its removal touches that file only, even when its inode number was
    #: reused for another file meanwhile.
    identity: tuple[int, int, int, int]


def _require_safe_open() -> None:
    if not (_O_NOFOLLOW and _O_DIRECTORY) or os.open not in os.supports_dir_fd:
        raise WorkspaceError(
            "this worker's operating system cannot open files without following symbolic "
            "links, so the step reads no files from the shared workspace on it"
        )


def _reason(exc: OSError) -> str:
    return exc.strerror or type(exc).__name__


def _open_root(root: str) -> int:
    try:
        return os.open(root, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC)
    except FileNotFoundError:
        raise WorkspaceError(
            "the run's shared workspace does not exist on this worker: no step of this run "
            "has written files to it here"
        ) from None
    except OSError as exc:
        raise WorkspaceError(
            f"the run's shared workspace cannot be opened ({_reason(exc)})"
        ) from None


def _check_inside(root: str, rel: str, label: str) -> None:
    real_root = os.path.realpath(root)
    real = os.path.realpath(os.path.join(root, rel))
    if os.path.commonpath([real_root, real]) != real_root:
        raise WorkspaceError(
            f"{label} resolves outside the run's shared workspace through a symbolic link; refused"
        )


def _component_error(dir_fd: int, segment: str, where: str, exc: OSError) -> str:
    """Why a path component could not be opened without following links."""
    if isinstance(exc, FileNotFoundError):
        return f"{where!r} does not exist in the run's shared workspace"
    try:
        info = os.stat(segment, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return f"{where!r} cannot be opened ({_reason(exc)})"
    if stat.S_ISLNK(info.st_mode):
        return f"{where!r} is a symbolic link; refused"
    if not stat.S_ISDIR(info.st_mode):
        return f"{where!r} is not a directory"
    return f"{where!r} cannot be opened ({_reason(exc)})"


def _open_parent(root_fd: int, rel: str, label: str) -> tuple[int, str]:
    """Open the directory holding ``rel``'s last component, following no link on the way.

    Returns ``(dir_fd, name)``; the caller closes ``dir_fd`` unless it is ``root_fd``.
    """
    *dirs, name = rel.split("/")
    current = root_fd
    try:
        for index, segment in enumerate(dirs):
            try:
                opened = os.open(
                    segment,
                    os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC,
                    dir_fd=current,
                )
            except OSError as exc:
                where = "/".join(dirs[: index + 1])
                raise WorkspaceError(
                    f"{label}: {_component_error(current, segment, where, exc)}"
                ) from None
            if current != root_fd:
                os.close(current)
            current = opened
    except BaseException:
        if current != root_fd:
            os.close(current)
        raise
    return current, name


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def _read_bounded(fd: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        chunk = os.read(fd, min(_CHUNK, limit - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _too_large(label: str) -> WorkspaceError:
    return WorkspaceError(f"{label} is larger than {MAX_FILE_BYTES} bytes; refused")


def _read_one(root_fd: int, key: str, rel: str) -> SourceFile:
    label = f"file {rel!r} (key {key!r})"
    dir_fd, name = _open_parent(root_fd, rel, label)
    try:
        try:
            before = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise WorkspaceError(f"{label} does not exist in the run's shared workspace") from None
        except OSError as exc:
            raise WorkspaceError(f"{label} cannot be read ({_reason(exc)})") from None
        if stat.S_ISLNK(before.st_mode):
            raise WorkspaceError(f"{label} is a symbolic link; refused")
        if not stat.S_ISREG(before.st_mode):
            raise WorkspaceError(f"{label} is not a regular file; refused")
        if before.st_size > MAX_FILE_BYTES:
            raise _too_large(label)
        try:
            fd = os.open(name, os.O_RDONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, dir_fd=dir_fd)
        except OSError as exc:
            raise WorkspaceError(f"{label} cannot be opened ({_reason(exc)})") from None
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
                before.st_dev,
                before.st_ino,
            ):
                raise WorkspaceError(f"{label} changed while it was being read; refused")
            data = _read_bounded(fd, MAX_FILE_BYTES + 1)
        finally:
            os.close(fd)
    finally:
        if dir_fd != root_fd:
            os.close(dir_fd)
    if len(data) > MAX_FILE_BYTES:
        raise _too_large(label)
    if not data:
        raise WorkspaceError(f"{label} is empty")
    return SourceFile(key=key, path=rel, data=data, identity=_identity(opened))


def read_source_files(root: str, files: Mapping[str, str]) -> list[SourceFile]:
    """Read ``{key: file}`` from the workspace at ``root``, in order.

    Each file is written as the step container sees it (``/shared/<rel>``) or
    relative to the workspace. Refuses a symbolic link anywhere on the path, a
    path that resolves outside the workspace, anything but a regular file, an
    empty file, a file over :data:`MAX_FILE_BYTES` and files totalling over
    :data:`MAX_TOTAL_BYTES`, with :class:`WorkspaceError`.
    """
    _require_safe_open()
    wanted: list[tuple[str, str]] = []
    for key, written in files.items():
        try:
            wanted.append((key, workspace_relative(written)))
        except ValueError as exc:
            raise WorkspaceError(f"'files.{key}' {exc}") from None
    root_fd = _open_root(root)
    try:
        sources: list[SourceFile] = []
        total = 0
        for key, rel in wanted:
            _check_inside(root, rel, f"file {rel!r} (key {key!r})")
            source = _read_one(root_fd, key, rel)
            total += len(source.data)
            if total > MAX_TOTAL_BYTES:
                raise WorkspaceError(
                    f"the source files together are larger than {MAX_TOTAL_BYTES} bytes; refused"
                )
            sources.append(source)
        return sources
    finally:
        os.close(root_fd)


def _write_zeros(fd: int, size: int) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    zeros = bytes(_CHUNK)
    remaining = size
    while remaining > 0:
        written = os.write(fd, zeros[: min(_CHUNK, remaining)])
        if written <= 0:
            raise OSError("short write")
        remaining -= written
    os.fsync(fd)


def _scrub_one(root_fd: int, source: SourceFile) -> None:
    label = f"file {source.path!r}"
    dir_fd, name = _open_parent(root_fd, source.path, label)
    try:
        try:
            fd = os.open(name, os.O_WRONLY | _O_NOFOLLOW | _O_NONBLOCK | _O_CLOEXEC, dir_fd=dir_fd)
        except FileNotFoundError:
            raise WorkspaceError(f"{label} is already gone") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or _identity(info) != source.identity:
                raise WorkspaceError(f"{label} changed since it was read; left in place")
            # A file with other names (hard links) keeps its content under them;
            # overwriting it would change those too, so it is only unlinked.
            if info.st_nlink <= 1:
                _write_zeros(fd, info.st_size)
        finally:
            os.close(fd)
        os.unlink(name, dir_fd=dir_fd)
    finally:
        if dir_fd != root_fd:
            os.close(dir_fd)


def scrub_source_files(root: str, sources: Sequence[SourceFile]) -> dict[str, str]:
    """Overwrite each source file with zeros, then unlink it. Best effort.

    Not a secure wipe: a copy-on-write or journaling file system, a snapshot,
    or a backup may still hold the old bytes. A file that changed since it was
    read (another inode at the path) is left alone. Returns ``{path: reason}``
    for every file not removed; an empty dict means all are gone.
    """
    failures: dict[str, str] = {}
    try:
        _require_safe_open()
        root_fd = _open_root(root)
    except WorkspaceError as exc:
        return {source.path: str(exc) for source in sources}
    try:
        done: set[str] = set()
        for source in sources:
            if source.path in done:
                continue
            done.add(source.path)
            try:
                _scrub_one(root_fd, source)
            except WorkspaceError as exc:
                failures[source.path] = str(exc)
            except OSError as exc:
                failures[source.path] = f"file {source.path!r} not removed ({_reason(exc)})"
    finally:
        os.close(root_fd)
    return failures
