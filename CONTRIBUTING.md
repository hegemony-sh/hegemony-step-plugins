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
[CONTRIBUTING.md](https://github.com/hegemony-sh/hegemony/blob/main/CONTRIBUTING.md#licensing-and-dco).

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
version from them, sets it on every package except the SDK and rewrites
every SDK pin from the SDK's own version (`scripts/set_version.py`),
refreshes `uv.lock`, builds the wheels and sdists, smoke-installs the wheels,
prepends `CHANGELOG.md`, commits `chore(release): X.Y.Z [skip ci]`, tags
`vX.Y.Z` and publishes the wheels, the sdists and `SHA256SUMS` as the GitHub
Release. Once that Release is published, the `pypi` job of `release.yml`
uploads the same wheels and sdists to PyPI with trusted publishing and PEP 740
attestations. That job is in this repository's workflow, not the shared one,
because trusted publishing does not work inside a reusable workflow; it runs
in the `pypi` environment, which waits for a required reviewer. The SDK's
wheel and sdist carry the SDK's own version; when it has not changed, PyPI
already holds them and the upload skips them. If the job fails (a package
without a matching trusted publisher, say), fix the cause and re-run the
failed job; it downloads the files from the published Release, so a re-run
works for as long as GitHub re-runs the run (30 days), and files PyPI already
holds are skipped. After that, upload by hand as described below. Publishing the
Release also starts the `Images` workflow, which publishes the steps' runner
images (`ansible-runner`, `opentofu-runner`, `git-runner`) as `X.Y.Z` and
`X.Y` from the tag; the release commit carries the steps' defaults moved to
`X.Y`. There is no manual step any more: do not bump the release version or
push `v*` tags by hand. The one version you do set by hand is the SDK's (next
section).

| Commits since the last tag | Release |
|---|---|
| `fix`, `perf`, `revert` | patch |
| `feat` | minor |
| breaking change (any type with `!`, such as `feat!:` or `refactor!:`, or a `BREAKING CHANGE:` footer) | **minor, while the major is 0** |
| `chore`, `docs`, `ci`, `test`, `refactor`, `build`, `style` | none |

A change of the series (the `X.Y`) of a tool the steps run by default is a
`feat`, whatever else the commit does: ansible-core
(`images/ansible-runner/Dockerfile`), OpenTofu
(`images/opentofu-runner/Dockerfile`) and Terraform (`DEFAULT_IMAGES` in
`plugins/steps_tf/src/hegemony_steps_tf/common.py`). Flows on the default
image get the new tool with the upgrade, so it must be a minor release with
its own changelog line, such as `feat(tf): build the runner image on
OpenTofu 1.13`. `scripts/verify_release_version.py` refuses a patch release
whose tools differ in series from the previous release of that minor; if a
release fails on it, push a `feat` commit that names the change. A newer
patch release of the same series (1.12.6 to 1.12.7) may ship as a `fix`. The
files that state a series (the steps' docs, READMEs and Image field help) are
checked against the one that sets it, by the same script and by
`tests/test_release_versions.py`.

The series a step can choose (**ansible-core version**, **OpenTofu version**)
are the entries of `images/<name>/variants.json`: the Images workflow builds
the image's Dockerfile once per entry, with the entry's build arguments, and
tags it `X.Y.Z-<tag><series>` and `X.Y-<tag><series>`; the default series
also gets the plain tags. To offer another series, add its entry, a matrix
entry for it in `.github/workflows/images.yml`, the series in the step's
`Literal` (`AnsibleCoreVersion`, `OpenTofuVersion`) and in the step's docs;
the same script and test check that these agree, and that the Dockerfile's
`ARG` defaults are the default series' entry. An OpenTofu series needs its
own `GO_MODULE_RAISES`: build it on a pull request and raise what the scan
flags. Adding a series is a `feat`. Dropping one breaks the flows that name
it, so it needs a minor release too (the script refuses a patch release that
drops one): mark that commit as breaking.

The 0.x rule is the `"breaking": true` entry in `.releaserc.json`'s
`releaseRules`; once the packages reach 1.0, change its `release` to
`major`. Deleting it is not enough: the analyzer applies every rule that
matches and keeps the largest release, so a breaking `feat` would still get
the `feat` rule's minor and a breaking `fix` the `fix` rule's patch.

Do not add a `"release": false` rule for a type. Such a rule overrides every
other match, the breaking one included, so a breaking `refactor!:` would
release nothing. Types that no rule names already release nothing.

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
dist/*.tar.gz dist/SHA256SUMS` after rebuilding the wheels and sdists at that
tag, with `SHA256SUMS` covering `*.whl *.tar.gz`). The `pypi` job does not run
for such a tag, so that release reaches PyPI only if its files are uploaded
separately.

When the `pypi` job cannot do the upload, a maintainer uploads that Release's
files to PyPI by hand. This covers a tag recovered by hand (the job does not
run for it), a Release cut while the repository was private (it has no
attestations, and the job refuses files without one), and a failed `pypi` job
whose run is older than 30 days (GitHub no longer re-runs it):

```bash
(
  set -euo pipefail
  mkdir pypi-upload && cd pypi-upload
  gh release download vX.Y.Z --repo hegemony-sh/hegemony-step-plugins \
    --pattern '*.whl' --pattern '*.tar.gz' --pattern SHA256SUMS
  sha256sum --check --strict SHA256SUMS
  shopt -s nullglob
  files=(*.whl *.tar.gz)
  for file in "${files[@]}"; do
    grep -q "  ${file}\$" SHA256SUMS || { echo "${file} is not in SHA256SUMS" >&2; exit 1; }
  done
  TWINE_USERNAME=__token__ uvx twine upload --skip-existing "${files[@]}"
)
```

The subshell stops at the first failed step, so nothing is uploaded unless
every file downloaded, matched `SHA256SUMS` and is listed there.

Check the files with `gh attestation verify` first when the Release has
attestations. A PyPI token scoped to one project can upload only that
project, and the command above uploads every project in the Release. So
either create a short-lived account-wide token, paste it when twine asks for
the password and delete it right after, or keep project tokens and run the
upload once per project with only that project's files. A hand upload
carries no PEP 740 attestations.

### The SDK's own version

`hegemony-step-sdk` does not take the release version. Its version changes
only when the SDK changes, so a new SDK version always means a new contract
or an SDK fix, and a plugin-only release keeps it. Every release still
attaches the SDK wheel; an unchanged SDK builds to the same bytes, so the
same version is always the same wheel.

Set it in the pull request that changes anything in `packages/step_sdk`:

```bash
uv run python scripts/sdk_version.py bump minor   # or major, or patch
uv lock
```

This sets the version in the SDK's `pyproject.toml` and `_version.py`, every
wheel's SDK requirement, and the SDK's recorded public surface,
`packages/step_sdk/api-surface.json` (rewrite only that file with
`scripts/sdk_version.py write`). Which bump:

| Change in `packages/step_sdk` since the last release tag | SDK version |
|---|---|
| none | unchanged (a bump without a change fails) |
| code, docs or dependencies, but not the public surface | at least patch |
| the surface gains a name, an optional parameter or an optional field | at least minor |
| the internal device-transport interface changes (the names `hegemony_step_sdk.transports` lists as internal) | at least minor |
| the surface loses or changes something | major, and `SDK_ABI_VERSION` moves with it |

The device-transport interface needs no major because only the built-in
transports use it and they pin the SDK exactly; `DeviceCredentials` and
`JumpHostSpec` are part of the handler contract and follow the
additions-only rule. The SDK's major is always `SDK_ABI_VERSION`, and the platform refuses
plugins built for another ABI, so avoid a major: keep an old name working
and add a new one instead. CI runs `scripts/sdk_version.py check`, which
compares the tree with the newest release tag and fails when the version
does not match the change; the release runs it again. The surface record
holds names, call shapes and fields, not types or constants' values, so a
change the record cannot show (a constant's value, a narrower type, new
behaviour) is the author's and reviewer's call: the check accepts a larger
bump than it requires. Only one bump per release: a second pull request
before the next release keeps the version the first one set unless it needs
a larger bump.

Commit an SDK change with a type that releases (`feat(sdk):`, `fix(sdk):`),
so the new SDK version is published.

The shared workflow is pinned by commit in `.github/workflows/release.yml`;
a change merged to it reaches this repository through a pull request that
bumps that SHA.
