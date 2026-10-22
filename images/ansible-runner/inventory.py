# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Print every installed Python distribution, its version and declared licence.

Run once while the image is built (bind-mounted, so it is not left in any
layer); the output is /usr/share/doc/hegemony/python-packages.txt, which the
image's THIRD-PARTY-NOTICES.md points to. With --fail-on it exits non-zero when
a distribution declares one of the listed licence identifiers, which the Images
workflow uses to keep review-tier licences out of the published image.
"""

import argparse
import importlib.metadata as metadata
import re
import sys


def declared_licence(dist: metadata.Distribution) -> str:
    """The licence a distribution declares: expression, field, or classifiers."""
    meta = dist.metadata
    expression = meta.get("License-Expression")
    if expression:
        return expression
    field = (meta.get("License") or "").strip().splitlines()
    if field and len(field[0]) <= 80:
        return field[0]
    classifiers = [
        c.split(" :: ")[-1] for c in meta.get_all("Classifier") or [] if c.startswith("License ::")
    ]
    return "; ".join(classifiers) or "see its dist-info licence files"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fail-on", nargs="*", default=[], help="licence identifiers to refuse")
    args = parser.parse_args()
    refused = []
    for dist in sorted(metadata.distributions(), key=lambda d: d.metadata["Name"].lower()):
        licence = declared_licence(dist)
        print(f"{dist.metadata['Name']} | {dist.version} | {licence}")
        if any(re.search(rf"\b{re.escape(ident)}\b", licence) for ident in args.fail_on):
            refused.append(f"{dist.metadata['Name']} ({licence})")
    if refused:
        print("refused licences: " + ", ".join(refused), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
