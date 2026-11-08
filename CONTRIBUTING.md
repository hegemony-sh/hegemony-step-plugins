<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Contributing

This repository is part of the Hegemony project: the step-handler SDK and the
plugin wheels the platform runs. See the [README](README.md) for what is here
and how it relates to the platform.

## Code of Conduct and security

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

Report vulnerabilities privately through the process in
[SECURITY.md](SECURITY.md). Do **not** open public issues for vulnerabilities, leaked secrets, exploit details, or suspected
compromise.

## Licensing and DCO

The [Code of Conduct](CODE_OF_CONDUCT.md) is adapted third-party documentation
under CC-BY-4.0; preserve its attribution and license when editing it. The
source-code licensing and contribution rules below continue to apply to code.

The source is licensed under `AGPL-3.0-or-later`, apart from the one MIT file
that [LICENSING.md](LICENSING.md) describes. Your contribution is licensed
under the same terms, and contributing it transfers no copyright to the
project. There is no Contributor License Agreement.

The project's own files name Rexonix s.r.o. as the copyright holder, and those
with an SPDX header also name Jakub Trávník as the author (see
[LICENSING.md](LICENSING.md)). If you do not write on behalf of Rexonix s.r.o.,
you keep the copyright in your contribution and may add your own
`SPDX-FileCopyrightText` line to the header of a file you change, as REUSE
recommends.

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO),
version 1.1. A `Signed-off-by:` line certifies that you wrote the change, or
otherwise have the right to submit it under the project licence. Sign off with
`git commit -s`. The DCO GitHub App checks every commit in a pull request: the
sign-off's name and email must match the commit's author. Merge
commits and commits by GitHub bot accounts are skipped. To add a missing
sign-off to every commit on your branch, run
`git rebase --signoff origin/main` and force-push the branch.

A commit written by an AI coding agent is signed off by the person who directs
the agent and submits the work, as its author; the agent is credited in a
`Co-authored-by:` trailer and never signs off in its own name. See the
platform's
[CONTRIBUTING.md](https://github.com/hegemony-sh/hegemony/blob/develop/CONTRIBUTING.md#licensing-and-dco).

## Local setup and checks

You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/);
[Task](https://taskfile.dev/) is optional, because every task is a plain
`uv run` command. CI runs these, and a pull request needs them green:

```bash
uv sync --frozen --all-packages
uv run ruff check packages plugins probes transports tests scripts fuzz
uv run ruff format --check packages plugins probes transports tests scripts fuzz
uv run reuse lint
uv run ty check
uv run pytest
uv run python scripts/check_docs.py
uv run python scripts/build_wheels.py
uv run python scripts/smoke_install_wheels.py
```

`task setup` installs the workspace and the pre-commit hooks (formatting,
typos, secret scan with gitleaks, workflow scan with zizmor, REUSE, commit
message lint); `task ci` runs the checks above plus the licence checks
(`task licenses:images`, `task licenses:packages`). Every new file carries an
SPDX header, as the existing ones do, so that `reuse lint` passes.

A first-party file with an SPDX header names Rexonix s.r.o. as the copyright
holder and Jakub Trávník as the author, in the file's own comment syntax:

<!-- REUSE-IgnoreStart -->

```python
# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later
```

<!-- REUSE-IgnoreEnd -->

### Tests

Every change that adds or changes behaviour comes with tests in the same pull
request, and a pull request is not merged while CI is red:

- A new step handler, transport, probe or config field gets tests of its normal
  use and of how it fails (invalid input, an unreachable device, a refused
  credential).
- A bug fix adds a regression test that fails without the fix.
- Tests use synthetic credentials, hosts and keys only, and run offline: a test
  that needs a server starts a local one, as the SSH and HTTP tests do.
- Tests live under `tests/`, one module per handler or transport
  (`test_<area>.py`); `uv run pytest` runs them all, and CI runs the same
  command on every pull request to `main` or `develop` and on every push to
  them.

### Fuzzing

The Atheris targets in `fuzz/*_fuzzer.py` exercise HTTP JSON paths, status
specifications and Dockerfile image discovery. Each input tests both raw
malformed text and generated valid structures with correctness assertions.
`fuzz/seed_corpus.py` supplies reproducible seeds, including oversized numbers,
Unicode digits, overlapping status ranges and multi-stage Dockerfiles.
Dockerfile and status seeds are plain UTF-8; JSON-path seeds contain a path,
a newline, then JSON. When a bug is found, add a unit regression and a seed.

PRs replay every seed in ordinary CI and run ClusterFuzzLite for a 300-second
budget. The build includes seeds and any restored nightly corpus. PRs only
read the shared cache. `.github/workflows/fuzz_nightly.yml` runs on the default
branch daily, spends ten minutes on each target, minimizes the corpus with
libFuzzer's merge mode, and caches successful results for later runs. Cache
entries can be evicted; seeds remain available even on a cold start. A crash
fails the job and its reproducer is uploaded with the Python branch coverage
report as `fuzz-results`. The scheduled workflow starts after it is merged.
It requires no storage repository or additional credentials.

To run a short campaign, including corpus pruning and coverage:

```bash
uv sync --frozen --all-packages --group fuzz
uv run --frozen --group fuzz python fuzz/run_campaign.py --seconds 60
```

Use `--seconds 0` to replay the corpus without mutation. Read
`build/fuzz-coverage/html/index.html` to see which branches remain unvisited;
the report includes the whole HTTP request module, so it is not a project-wide
coverage target. Keep generators bounded and deterministic, and strengthen
properties before adding targets just to increase their count. Replay a saved
crash with `uv run --group fuzz python fuzz/<target>_fuzzer.py <crash-file>`.
Changing the input encoding requires bumping the workflow corpus cache prefix.

To test the same packaged targets as ClusterFuzzLite:

```bash
docker build -t cflite -f .clusterfuzzlite/Dockerfile .
docker run --rm -e SANITIZER=address -e FUZZING_LANGUAGE=python \
  -v "$PWD/build/fuzz:/out" cflite compile
docker run --rm -v "$PWD/build/fuzz:/out" cflite /out/jsonpath_fuzzer -max_total_time=60
```

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/);
`commitlint.config.mjs` holds the rules, and the pull request's commits are
linted. The type decides whether a merge releases (see [Releasing](#releasing)).

## Documentation

Every wheel documents its own handlers, and CI enforces it
(`task docs:check`, also run by plain `pytest`):

- **One page per handler id** at `src/<package>/docs/<handler_id>.md`,
  shipped in the wheel as package data and read by hosts through
  `hegemony_step_sdk.docs.load_docs_bundle`. A page opens with the SPDX
  header in an HTML comment (holder, `SPDX-FileContributor`, blank line,
  licence), has exactly one H1 naming its subject, names its handler id in a
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
[`plugin-release.yml`](https://github.com/hegemony-sh/hegemony-github-workflows)
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
with a new commit, which becomes the next release. Build provenance
attestations are created only for public repositories, so releases cut while
this repository was private ship `SHA256SUMS` only. Those checksums detect a
damaged download, not a replaced release.

One failure a re-run cannot repair: semantic-release pushes the release
commit and the `vX.Y.Z` tag before it publishes the GitHub Release, so if
publication fails after that push the tag exists without a Release, and the
next run reads the tag as the last release. Publish that tag's assets by hand
from a checkout of the tag, as the shared workflow's
[README](https://github.com/hegemony-sh/hegemony-github-workflows#recovering-a-tag-without-a-release)
describes (`gh release create vX.Y.Z --verify-tag ... dist/*.whl
dist/SHA256SUMS` after rebuilding the wheels at that tag).

The shared workflow is pinned by commit in `.github/workflows/release.yml`;
a change merged to it reaches this repository through a pull request that
bumps that SHA.
