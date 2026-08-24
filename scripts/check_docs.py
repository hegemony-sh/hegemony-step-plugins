# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Gate the plugin-owned documentation contract at its source.

Every wheel this repository builds documents its own handlers: one Markdown
page per registered handler id inside the package's ``docs/`` directory
(read by hosts via :mod:`hegemony_step_sdk.docs`), and ``title=`` plus
``description=`` on every config-model field (rendered as form help in the
flow editor and in the platform's generated step-handler reference).

This script is the producer-side enforcement of that contract - the host's
gate fires only when it bumps its pin, which is too late to help the person
who forgot the page. Checks:

- registered handler ids and doc pages match 1:1 both ways, per package;
- every page carries the SPDX header, exactly one H1 (first), a title that
  names the subject (no process words, no subtitle, no version, no trailing
  period), and the handler id in a code span;
- prose survives rendering: no raw HTML outside the SPDX comment, no bare
  ``{{`` outside code, no images, no mermaid, no relative links;
- every config-model field has a non-empty ``title`` and ``description``;
- each plugin README mentions every handler id the plugin registers.

Exit is non-zero with one line per violation; run via ``task docs:check``.
``tests/test_docs_bundles.py`` runs the same checks under pytest so plain
``uv run pytest`` enforces the contract too.
"""

from __future__ import annotations

import re
import sys
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

from hegemony_step_sdk.docs import DocsBundleError, load_docs_bundle

ROOT = Path(__file__).resolve().parents[1]

SPDX_HEADER_RE = re.compile(
    r"\A<!--\nSPDX-FileCopyrightText: [^\n]+\n\nSPDX-License-Identifier: [^\n]+\n-->\n"
)
H1_RE = re.compile(r"^# (.+)$", re.MULTILINE)
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
FENCE_RE = re.compile(r"^[ \t]*```.*?^[ \t]*```[ \t]*$", re.DOTALL | re.MULTILINE)
CODE_SPAN_RE = re.compile(r"(`+)(.+?)\1(?!`)", re.DOTALL)
PARAGRAPH_SPLIT_RE = re.compile(r"(\n[ \t]*\n)")
RAW_TAG_RE = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*\s*/?>")
IMAGE_RE = re.compile(r"!\[")
RELATIVE_LINK_RE = re.compile(r"\]\((?!https://|#)[^)]+\)")
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


class _CollectingRegistry:
    """Minimal registry facade for enumerating a plugin's handlers."""

    api_version = 1

    def __init__(self) -> None:
        # Plugin handler classes, duck-typed: attribute access is dynamic.
        self.handlers: list[Any] = []

    def register_handler_type(self, handler_class: type) -> None:
        self.handlers.append(handler_class)


def registered_handlers() -> dict[str, list[Any]]:
    """Package import name -> handler classes it registers."""
    by_package: dict[str, list[Any]] = {}
    for ep in sorted(entry_points(group="hegemony.step_handlers"), key=lambda e: e.name):
        registry = _CollectingRegistry()
        ep.load()(registry)
        package = ep.value.split(":", 1)[0].split(".", 1)[0]
        by_package.setdefault(package, []).extend(registry.handlers)
    return by_package


def prose_outside_code(text: str) -> str:
    """The page's prose with the SPDX comment, fences, and code spans blanked."""

    def blank(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")

    text = HTML_COMMENT_RE.sub(blank, text)
    text = FENCE_RE.sub(blank, text)
    # Code spans are matched per paragraph (a span cannot contain a blank
    # line), so one stray backtick cannot invert code and prose for the
    # rest of the page.
    return "".join(
        part if PARAGRAPH_SPLIT_RE.fullmatch(part) else CODE_SPAN_RE.sub(blank, part)
        for part in PARAGRAPH_SPLIT_RE.split(text)
    )


def check_page(package: str, doc_id: str, text: str) -> list[str]:
    """Structural and renderability violations for one page."""
    where = f"{package}/docs/{doc_id}.md"
    problems: list[str] = []

    if not SPDX_HEADER_RE.match(text):
        problems.append(f"{where}: must open with the SPDX HTML-comment header")

    body = HTML_COMMENT_RE.sub("", text)
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
    for link in RELATIVE_LINK_RE.findall(prose):
        problems.append(f"{where}: relative link {link!r} has nothing to resolve against")

    return problems


def check_config_models(handlers: list[Any]) -> list[str]:
    """Every config-model field must carry a non-empty title and description."""
    problems: list[str] = []
    for cls in handlers:
        model = getattr(cls, "config_model", None)
        if model is None:
            continue
        for name, field in model.model_fields.items():
            for attr in ("title", "description"):
                if not (getattr(field, attr) or "").strip():
                    problems.append(
                        f"{cls.handler_id}: config field '{name}' has no {attr} - it "
                        "renders as form help in the flow editor and in the generated "
                        "step-handler reference"
                    )
    return problems


def check_readme(package: str, handler_ids: set[str]) -> list[str]:
    """The owning plugin's README must mention every id it registers."""
    matches = list(ROOT.glob(f"*/*/src/{package}"))
    if not matches:
        return [f"{package}: cannot locate the plugin directory for its README"]
    readme = matches[0].parents[1] / "README.md"
    if not readme.is_file():
        return [f"{package}: README.md not found next to pyproject.toml"]
    text = readme.read_text(encoding="utf-8")
    return [
        f"{readme.relative_to(ROOT)}: does not mention registered handler `{hid}`"
        for hid in sorted(handler_ids)
        if hid not in text
    ]


def main() -> int:
    """Run every check; print violations; non-zero exit if any."""
    problems: list[str] = []

    for package, handlers in registered_handlers().items():
        handler_ids = {cls.handler_id for cls in handlers}
        try:
            bundle = load_docs_bundle(package)
        except DocsBundleError as exc:
            problems.append(str(exc))
            bundle = {}
        else:
            for missing in sorted(handler_ids - bundle.keys()):
                problems.append(
                    f"{package}: registered handler `{missing}` has no doc page "
                    f"(add src/{package}/docs/{missing}.md)"
                )
            for orphan in sorted(bundle.keys() - handler_ids):
                problems.append(
                    f"{package}: docs/{orphan}.md documents no registered handler - "
                    "remove it or fix the filename"
                )
            for doc_id in sorted(bundle.keys() & handler_ids):
                problems.extend(check_page(package, doc_id, bundle[doc_id]))

        problems.extend(check_config_models(handlers))
        problems.extend(check_readme(package, handler_ids))

    if problems:
        print("Plugin documentation contract violations:", file=sys.stderr)
        for problem in sorted(problems):
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nEvery wheel documents its own handlers; see CONTRIBUTING.md "
            "and hegemony_step_sdk.docs for the contract.",
            file=sys.stderr,
        )
        return 1
    print("ok: plugin docs bundles, config-field docs, and READMEs are complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
