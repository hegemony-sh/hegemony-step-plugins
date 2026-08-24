<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Contributing

This repository is part of the Hegemony project. Public source is licensed under
`AGPL-3.0-or-later`, and Hegemony may also offer separate commercial licenses.

External contributions are accepted only under the
[Hegemony Contributor License Agreement](CLA.md). The CLA must grant Hegemony the
rights needed to distribute accepted contributions under both the public AGPL
license and separate commercial terms.

The CLA check is expected to run in pull requests. Until that automation is in
place, maintainers should not merge external contributions unless the contributor
has already signed the [Hegemony CLA](CLA.md).

## Documentation

Every wheel documents its own handlers, and CI enforces it
(`task docs:check`, also run by plain `pytest`):

- **One page per handler id** at `src/<package>/docs/<handler_id>.md`,
  shipped in the wheel as package data and read by hosts through
  `hegemony_step_sdk.docs.load_docs_bundle`. A page opens with the SPDX
  header, has exactly one H1 naming its subject, names its handler id in a
  code span, and describes the step for the flow author using it - not for
  a developer of this repository. No raw HTML outside the SPDX comment, no
  images, no mermaid, no relative links; placeholders and `{{ ... }}`
  template examples always go in backticks or fences.
- **Every config-model field carries `title=` and `description=`.** These
  are user-facing three times over: the flow editor renders them as form
  help, the platform publishes them in its generated step-handler
  reference, and the in-app help shows them beside the step.
- **A plugin's README names every handler id it registers**, so the README
  cannot drift from the registry.

`scripts/smoke_install_wheels.py` additionally proves the docs bundle made
it into the built artifact: it loads every bundle from the *installed*
wheels and asserts one page per registered handler.
