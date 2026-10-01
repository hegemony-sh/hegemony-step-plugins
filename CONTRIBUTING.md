<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Contributing

This repository is part of the Hegemony project. Its source is licensed under
`AGPL-3.0-or-later`. Your contribution is licensed under the same terms, and you
keep the copyright in it. There is no Contributor License Agreement.

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO),
version 1.1. A `Signed-off-by:` line certifies that you wrote the change, or
otherwise have the right to submit it under the project licence. Sign off with
`git commit -s`. The DCO GitHub App checks every commit in a pull request: the
sign-off's name and email must match the commit's author or committer. Merge
commits and commits by GitHub bot accounts are skipped. To add a missing
sign-off to every commit on your branch, run
`git rebase --signoff origin/main` and force-push the branch.

A commit written by an AI coding agent is signed off by the person who directs
the agent and submits the work, as its committer; the agent never signs off in
its own name. See the platform's
[CONTRIBUTING.md](https://github.com/hegemony-sh/hegemony/blob/develop/CONTRIBUTING.md#licensing-and-dco).

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

## Releasing

A merge to `main` is a release. The `Release` workflow calls the shared
[`plugin-release.yml`](https://github.com/hegemony-sh/hegemony-workflows)
workflow, which runs [semantic-release](https://semantic-release.gitbook.io/):
it reads the Conventional Commits since the last tag, derives the next
version from them, bumps every package and SDK pin (`scripts/set_version.py`),
refreshes `uv.lock`, builds and smoke-installs the wheels, prepends
`CHANGELOG.md`, commits `chore(release): X.Y.Z [skip ci]`, tags `vX.Y.Z` and
publishes the wheels plus `SHA256SUMS` as the GitHub Release. Publishing that
Release starts the `Images` workflow, which publishes the steps' runner images
(`ansible-runner`, `opentofu-runner`) as `X.Y.Z` and `X.Y` from the tag; the
release commit carries the steps' defaults moved to `X.Y`. There is no manual
step any more: do not bump versions or push `v*` tags by hand.

| Commits since the last tag | Release |
|---|---|
| `fix`, `perf`, `revert` | patch |
| `feat` | minor |
| breaking change (`feat!:`, `fix!:` or a `BREAKING CHANGE:` footer) | **minor, while the major is 0** |
| `chore`, `docs`, `ci`, `test`, `refactor`, `build`, `style` | none |

The 0.x rule is the `"breaking": true` entry in `.releaserc.json`'s
`releaseRules`; once the packages reach 1.0, change its `release` to
`major`. Deleting it is not enough: the rules are tried in order and the
first match wins, so a breaking `feat` would still match the `feat` rule and
release a minor.

Releases are immutable. The pipeline refuses to run when a GitHub Release for
the next tag already exists and never replaces published assets: fix forward
with a new commit, which becomes the next release. Attestations are created
only for public repositories, so releases cut while this repository is
private ship checksums only.

One failure a re-run cannot repair: semantic-release pushes the release
commit and the `vX.Y.Z` tag before it publishes the GitHub Release, so if
publication fails after that push the tag exists without a Release, and the
next run reads the tag as the last release. Publish that tag's assets by hand
from a checkout of the tag, as the shared workflow's
[README](https://github.com/hegemony-sh/hegemony-workflows#recovering-a-tag-without-a-release)
describes (`gh release create vX.Y.Z --verify-tag ... dist/*.whl
dist/SHA256SUMS` after rebuilding the wheels at that tag).

The shared workflow is pinned by commit in `.github/workflows/release.yml`;
a change merged to it reaches this repository through a pull request that
bumps that SHA.
