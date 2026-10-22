# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
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
- every page satisfies the page contract - the structural and renderability
  rules live in :func:`hegemony_step_sdk.docs.check_page`, beside the bundle
  loader, so hosts and harvest tooling validate with identical logic;
- every config-model field has a non-empty ``title`` and ``description``;
- each plugin README mentions every handler id the plugin registers. This
  check is substring-weak by design: an id appearing anywhere in the README
  (a comment included) passes. It proves the README was touched when a
  handler was added, not that the mention is prose - do not mistake it for
  more.

Exit is non-zero with one line per violation; run via ``task docs:check``.
``tests/test_docs_bundles.py`` runs the same checks under pytest so plain
``uv run pytest`` enforces the contract too.
"""

from __future__ import annotations

import sys
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

from hegemony_step_sdk.docs import (
    DocsBundleError,
    check_page as sdk_check_page,
    load_docs_bundle,
    prose_outside_code,
)

__all__ = ["check_page", "main", "prose_outside_code", "registered_handlers"]

ROOT = Path(__file__).resolve().parents[1]


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


def check_page(package: str, doc_id: str, text: str) -> list[str]:
    """The SDK's page contract, with violations prefixed by this repo's layout."""
    return sdk_check_page(doc_id, text, where=f"{package}/docs/{doc_id}.md")


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
    """The owning plugin's README must mention every id it registers.

    Substring matching on purpose (see the module docstring): cheap, zero
    false negatives on missing mentions, and honest about proving presence
    rather than prose quality.
    """
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
