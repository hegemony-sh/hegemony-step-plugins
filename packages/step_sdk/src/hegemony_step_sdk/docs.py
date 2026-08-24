# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Plugin-owned documentation bundles.

A plugin wheel documents its own handlers: the package ships a flat ``docs/``
directory containing one Markdown page per registered handler id
(``<package>/docs/<handler_id>.md``), included in the wheel as ordinary
package data. The host reads the bundle with :func:`load_docs_bundle` and
renders pages beside the step being configured, so documentation installs,
upgrades, and uninstalls with the wheel it describes — and works air-gapped,
because nothing is fetched.

The loader is deliberately strict, and the strictness is the contract:

- **Enumeration only.** Pages are discovered by listing the ``docs``
  directory; a requested id is looked up in the returned mapping, never
  joined onto a path (``Traversable.joinpath`` accepts ``..``).
- **Flat bundle.** Subdirectories and non-Markdown files are violations, so
  a bundle cannot smuggle other content into the wheel's documented surface.
- **Bounded reads.** Per-page and per-bundle byte caps, strict UTF-8, no
  NUL bytes. A host must be able to read an untrusted bundle without
  reading an unbounded amount.

Every violation raises :class:`DocsBundleError`. Producer-side gates want
the failure; a host wraps the call so a bad bundle degrades to "no docs"
and can never fail plugin registration or a catalog request.
"""

from __future__ import annotations

import re
from importlib.resources import files

#: Valid doc id (equals the handler id the page documents).
DOC_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

#: Name of the bundle directory inside the plugin package.
DOCS_DIR_NAME = "docs"

#: Upper bound for one page's raw size. Pages are reference prose for a
#: single handler; anything larger belongs in the platform documentation.
MAX_PAGE_BYTES = 16 * 1024

#: Upper bound for one package's whole bundle.
MAX_BUNDLE_BYTES = 128 * 1024


class DocsBundleError(ValueError):
    """A docs bundle violates the contract (shape, id, size, or encoding)."""


def load_docs_bundle(package: str) -> dict[str, str]:
    """Return ``{doc_id: markdown}`` for an importable plugin package.

    A package without a ``docs`` directory has an empty bundle — absence is
    not an error, so wheels predating this contract keep working. A ``docs``
    directory that exists but breaks the contract raises
    :class:`DocsBundleError` naming the offending entry.

    Args:
        package: Import name of the plugin package
            (e.g. ``"hegemony_steps_netcli"``).
    """
    docs_dir = files(package) / DOCS_DIR_NAME
    if not docs_dir.is_dir():
        if docs_dir.is_file():
            raise DocsBundleError(
                f"{package}: {DOCS_DIR_NAME} is not a directory; a bundle is a "
                "flat directory of <handler_id>.md pages"
            )
        return {}

    pages: dict[str, str] = {}
    total_bytes = 0
    for entry in docs_dir.iterdir():
        name = entry.name
        if entry.is_dir():
            raise DocsBundleError(f"{package}: docs/{name} is a directory; bundles are flat")
        if not name.endswith(".md"):
            raise DocsBundleError(
                f"{package}: docs/{name} is not a Markdown page; only "
                "<handler_id>.md files belong in a bundle"
            )
        doc_id = name[: -len(".md")]
        if not DOC_ID_RE.fullmatch(doc_id):
            raise DocsBundleError(
                f"{package}: docs/{name} has an invalid doc id (must match {DOC_ID_RE.pattern})"
            )
        # Bounded read: never pull more than the cap plus one sentinel byte
        # into memory, whatever size the resource claims to be.
        with entry.open("rb") as stream:
            raw = stream.read(MAX_PAGE_BYTES + 1)
        if len(raw) > MAX_PAGE_BYTES:
            raise DocsBundleError(
                f"{package}: docs/{name} exceeds the page cap ({MAX_PAGE_BYTES} bytes)"
            )
        total_bytes += len(raw)
        if total_bytes > MAX_BUNDLE_BYTES:
            raise DocsBundleError(f"{package}: docs bundle exceeds {MAX_BUNDLE_BYTES} bytes")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise DocsBundleError(f"{package}: docs/{name} is not valid UTF-8: {exc}") from exc
        if "\x00" in text:
            raise DocsBundleError(f"{package}: docs/{name} contains a NUL byte")
        pages[doc_id] = text

    return dict(sorted(pages.items()))
