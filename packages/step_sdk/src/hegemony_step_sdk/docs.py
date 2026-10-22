# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
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

Beside the loader lives the page contract's checker, :func:`check_page`:
the structural and renderability rules a page must satisfy (SPDX header,
exactly one leading H1, subject-naming title, handler id in a code span, no
raw HTML or images in prose, https-only links). It ships in the SDK - not in
any one repository's scripts - so the producer gate, a host's sanitizer or
claims tooling, and a documentation harvest all validate with *identical*
logic instead of divergent regex approximations: the contract and its
checker travel together, versioned. The regexes are deliberate CommonMark
approximations (no parser dependency); they live in exactly one place so a
parsing fix lands everywhere at once.
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


# --- The page contract -------------------------------------------------------
#
# Shared by the producer gate (scripts/check_docs.py in this repository), and
# importable by hosts and harvest tooling so every consumer of a page judges
# it by the same rules.

# A copyright holder line, then any further holder or SPDX-FileContributor
# lines (a first-party page names Rexonix s.r.o. and then its author), a blank
# line and the licence.
# REUSE-IgnoreStart
SPDX_HEADER_RE = re.compile(
    r"\A<!--\nSPDX-FileCopyrightText: [^\n]+\n"
    r"(?:SPDX-File(?:CopyrightText|Contributor): [^\n]+\n)*"
    r"\nSPDX-License-Identifier: [^\n]+\n-->\n"
)
# REUSE-IgnoreEnd
H1_RE = re.compile(r"^# (.+)$", re.MULTILINE)
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
FENCE_RE = re.compile(r"^[ \t]*(```+|~~~+).*?^[ \t]*\1[ \t]*$", re.DOTALL | re.MULTILINE)
CODE_SPAN_RE = re.compile(r"(`+)(.+?)\1(?!`)", re.DOTALL)
PARAGRAPH_SPLIT_RE = re.compile(r"(\n[ \t]*\n)")
RAW_TAG_RE = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>")
IMAGE_RE = re.compile(r"!\[")
NON_HTTPS_LINK_RE = re.compile(r"\]\((?!https://|#)[^)]+\)")
REF_LINK_DEF_RE = re.compile(r"^ {0,3}\[[^\]]+\]:[ \t]*(\S+)", re.MULTILINE)
AUTOLINK_RE = re.compile(r"<([A-Za-z][A-Za-z0-9+.-]*:[^<>\s]*)>")
TITLE_PROCESS_RE = re.compile(
    r"\b(draft|final|improved|new|obsolete|proposal|revised|tbd|todo|updated|wip)\b",
    re.IGNORECASE,
)
TITLE_SUFFIX_RE = re.compile(
    r"\b(doc|docs|documentation|guide|notes|plan|readme|spec|specification|study)\s*$",
    re.IGNORECASE,
)
TITLE_VERSION_RE = re.compile(r"\bv\d+(\.\d+)*\b", re.IGNORECASE)
TITLE_SUBTITLE_RE = re.compile(r"\s[-–—]\s|:")


def _blank(match: re.Match[str]) -> str:
    """Newline-preserving replacement, so blanked stretches keep line geometry."""
    return "\n" * match.group(0).count("\n")


def prose_outside_code(text: str) -> str:
    """The page's prose with the SPDX comment, fences, and code spans blanked."""
    text = HTML_COMMENT_RE.sub(_blank, text)
    text = FENCE_RE.sub(_blank, text)
    # Code spans are matched per paragraph (a span cannot contain a blank
    # line), so one stray backtick cannot invert code and prose for the
    # rest of the page.
    return "".join(
        part if PARAGRAPH_SPLIT_RE.fullmatch(part) else CODE_SPAN_RE.sub(_blank, part)
        for part in PARAGRAPH_SPLIT_RE.split(text)
    )


def check_page(doc_id: str, text: str, *, where: str | None = None) -> list[str]:
    """Structural and renderability violations for one page, as messages.

    An empty list means the page satisfies the contract. ``where`` prefixes
    each message (defaults to ``docs/<doc_id>.md``); callers with more
    context - a gate naming the package, a harvest naming the wheel - pass
    their own.
    """
    where = where or f"{DOCS_DIR_NAME}/{doc_id}.md"
    problems: list[str] = []

    if not SPDX_HEADER_RE.match(text):
        problems.append(f"{where}: must open with the SPDX HTML-comment header")

    # Headings are counted with fenced code blanked, so a `# comment` line
    # inside a shell example is not mistaken for a second H1.
    body = FENCE_RE.sub(_blank, HTML_COMMENT_RE.sub("", text))
    h1s = H1_RE.findall(body)
    if len(h1s) != 1:
        problems.append(f"{where}: needs exactly one H1, found {len(h1s)}")
    elif not body.lstrip().startswith(f"# {h1s[0]}"):
        problems.append(f"{where}: the H1 must be the first heading on the page")
    if h1s:
        title = h1s[0].strip()
        for pattern, why in (
            (TITLE_PROCESS_RE, "contains an authoring-process word"),
            (TITLE_SUFFIX_RE, "ends in a genre suffix"),
            (TITLE_VERSION_RE, "pins a version"),
            (TITLE_SUBTITLE_RE, "carries a subtitle after a dash or colon"),
        ):
            if pattern.search(title):
                problems.append(f"{where}: title {title!r} {why}")
        if title.endswith("."):
            problems.append(f"{where}: title {title!r} ends with a period")

    if f"`{doc_id}`" not in text:
        problems.append(f"{where}: must name its handler id in a code span (`{doc_id}`)")

    prose = prose_outside_code(text)
    for tag in sorted(set(RAW_TAG_RE.findall(prose))):
        problems.append(
            f"{where}: {tag} in prose is raw HTML the renderer drops - wrap it in backticks"
        )
    if "{{" in prose:
        problems.append(f"{where}: bare {{{{ in prose - template examples belong in code spans")
    if IMAGE_RE.search(prose):
        problems.append(f"{where}: images are not allowed in plugin docs")
    if "```mermaid" in text:
        problems.append(f"{where}: mermaid diagrams are not allowed in plugin docs")
    for link in NON_HTTPS_LINK_RE.findall(prose):
        problems.append(
            f"{where}: link {link!r} must be absolute https:// or an in-page anchor - "
            "a bundled page has no base to resolve anything else against"
        )
    # Reference-style definitions ([name]: destination) render links too;
    # CommonMark allows the destination in angle brackets.
    for match in REF_LINK_DEF_RE.finditer(prose):
        dest = match.group(1).strip("<>")
        if not dest.startswith(("https://", "#")):
            problems.append(
                f"{where}: link definition {dest!r} must be absolute https:// or an "
                "in-page anchor - a bundled page has no base to resolve anything "
                "else against"
            )
    # Autolinks (<scheme:...>) render as links and carry their own scheme.
    for match in AUTOLINK_RE.finditer(prose):
        dest = match.group(1)
        if not dest.startswith("https://"):
            problems.append(
                f"{where}: autolink <{dest}> must use https:// - plain-http and "
                "other schemes are not allowed in plugin pages"
            )

    return problems
