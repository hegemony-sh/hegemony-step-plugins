<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Hegemony Step Plugins

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![CI](https://github.com/hegemony-sh/hegemony-step-plugins/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/hegemony-sh/hegemony-step-plugins/actions/workflows/ci.yml)
[![REUSE status](https://api.reuse.software/badge/github.com/hegemony-sh/hegemony-step-plugins)](https://api.reuse.software/info/github.com/hegemony-sh/hegemony-step-plugins)
[![Latest release](https://img.shields.io/github/v/release/hegemony-sh/hegemony-step-plugins?label=Release)](https://github.com/hegemony-sh/hegemony-step-plugins/releases)

Step-handler SDK and plugin wheels for [Hegemony](https://github.com/hegemony-sh/hegemony),
a self-hosted orchestration platform for long-running infrastructure changes.
The platform's documentation is at [hegemony.sh](https://hegemony.sh).

Step handlers implement the work one flow step performs (run CLI commands on
devices, launch a container, stage an upgrade image, …). Handler types are
pluggable: wheels register handler classes under the `hegemony.step_handlers`
entry-point group and the platform discovers them at startup.

## How this repository relates to the platform

- **The platform runs these wheels.** `hegemony-sh/hegemony` loads whatever
  is installed under the `hegemony.step_handlers` entry-point group, so a
  step type exists in a deployment when its wheel is installed there. The
  [Packages](#packages) section says which wheels the platform's images
  install.
- **The platform pins a release of this repository.** Its
  `.github/plugin-pins.json` names a release tag and commit, and its
  `pyproject.toml` accepts only the matching version range of each wheel.
  A release of the platform is built against exactly that tag.
- **The wheels share one version.** Every package here carries the SDK's
  version, and that version is the release tag `vX.Y.Z`. The wheels are
  versioned in lockstep with one another, not with the platform's own version
  number. The pins and the release workflow are described in
  [CONTRIBUTING.md](CONTRIBUTING.md#releasing).
- **Plugins never import platform code.** A handler reaches every platform
  facility (device transports, secret and template resolution, the internal
  API) through `ctx.services`; the SDK (`packages/step_sdk`) is the whole
  contract between the two sides.

## Packages

- `packages/step_sdk` — `hegemony-step-sdk`: the public, dependency-light
  (pydantic only) SDK. Defines the handler contract (`BaseHandler`,
  `HandlerContext`, `HandlerResult`), the injected services ABI
  (`HandlerServices`, `Transport`), canonical enums (`StepKind`), and the
  registration protocol.
- Handler wheels, one namespace prefix each (see `CONVENTIONS.md` for the
  naming/grouping rules — the entry-point name is the claimed prefix).
  Every wheel in the table is installed in the platform's api and worker
  images unless it is marked opt-in; see below for how each one is limited
  and how a deployment leaves one out:

  | Wheel | Namespace | Handlers |
  | --- | --- | --- |
  | `plugins/steps_general` | `general.` | noop (hidden), sleep |
  | `plugins/steps_probe` | `probe.` | connectivity, http, dns, tls, wait_reachable |
  | `plugins/steps_netcli` | `netcli.` | execute, collect_evidence |
  | `plugins/steps_evidence` | `evidence.` | assert, compare |
  | `plugins/steps_container` | `container.` | run |
  | `plugins/steps_flow` | `flow.` | run, notify |
  | `plugins/steps_cisco_iosxe` | `cisco.iosxe.` | upgrade.preflight/stage/install/verify/cleanup (opt-in) |
  | `plugins/steps_shell` | `shell.` | execute — commands on Linux/Unix hosts over SSH |
  | `plugins/steps_monitor` | `monitor.` | connectivity — start a background monitor that probes targets on a schedule (the platform runs the monitor itself) |
  | `plugins/steps_ansible` | `ansible.` | playbook (built on `container.run`'s runner) |
  | `plugins/steps_tf` | `tf.` | plan, apply — OpenTofu or Terraform (built on `container.run`'s runner) |
  | `plugins/steps_http` | `http.` | request |
  | `plugins/steps_secret` | `secret.` | write — store, swap or delete a secret in the organization's secret store |
  | `plugins/steps_inventory` | `inventory.` | sync — sync an inventory provider of the run's organization now |
  | `plugins/steps_netbox` | `netbox.` | request, ipam.allocate/release, render_config — NetBox objects, IP address management and config rendering (needs `hegemony-steps-http`) |

Device transports (`transports/`: netmiko, scrapli, asyncssh) and the network
probes (`probes/probe_net`) are wheels of the same kind and release with the
rest. `hegemony-steps-cisco-iosxe` is opt-in: install the released wheel
explicitly (the platform's demo pins it in `demo-plugin-wheels.txt` in
[`hegemony-demo-data`](https://github.com/hegemony-sh/hegemony-demo-data)).
Every other wheel ships in the platform's images. The platform has no runtime
switch that hides an installed step, so a deployment that must not offer one
builds its api and worker images without the wheel (`uv pip uninstall` in a
derived image; see the platform's
[production hardening guide](https://github.com/hegemony-sh/hegemony/blob/develop/docs/deployment/production-hardening.md#step-handlers-in-the-images)).
Hardened deployments may do that with `hegemony-steps-container` to disable
container execution entirely.

The wheels that reach outside the worker are limited in different ways:

- `hegemony-steps-shell`: only devices whose access config holds SSH
  credentials, checked against the organization's trusted host keys.
- `hegemony-steps-http` and `hegemony-steps-netbox` (which needs
  `hegemony-steps-http`): the flow's egress policy. A flow without one can
  reach any address the worker can, except loopback, link-local (cloud
  metadata included), unspecified and multicast addresses.
- `hegemony-steps-secret`: writes nothing until an organization admin turns on
  secret writes by steps, and then only under the path prefixes they name.
- `hegemony-steps-inventory`: syncs nothing until an administrator ticks
  "Flows may sync this provider" on a provider.

## Install the wheels

The wheels are not on PyPI. Each release publishes them as assets of its
[GitHub Release](https://github.com/hegemony-sh/hegemony-step-plugins/releases)
`vX.Y.Z`, with a `SHA256SUMS` file listing every wheel. Install by hand to add
the opt-in wheel, or a wheel of your own, to a derived platform image, or to
use the SDK on its own; the platform's images already carry the rest.

A wheel pins `hegemony-step-sdk` to its own exact version, and the SDK is not
on an index, so name the SDK wheel of the same release in the same command,
together with any wheel that the wheels you install depend on
(`hegemony-steps-netbox` needs `hegemony-steps-http`; `hegemony-steps-ansible`
and `hegemony-steps-tf` need `hegemony-steps-container`):

```bash
version=X.Y.Z   # a release tag without the leading v
base="https://github.com/hegemony-sh/hegemony-step-plugins/releases/download/v${version}"
curl -fsSLO "${base}/SHA256SUMS"
for wheel in hegemony_step_sdk hegemony_steps_http hegemony_steps_netbox; do
  curl -fsSLO "${base}/${wheel}-${version}-py3-none-any.whl"
done
sha256sum -c --ignore-missing SHA256SUMS
uv pip install ./hegemony_step_sdk-*.whl ./hegemony_steps_http-*.whl ./hegemony_steps_netbox-*.whl
```

Replace `X.Y.Z` with a published version (the newest is on the Releases page).
`pip install` takes the same wheel files. The wheel file names use underscores
(`hegemony_steps_http-X.Y.Z-py3-none-any.whl`), the package names dashes
(`hegemony-steps-http`). `SHA256SUMS` is published beside the wheels in the
same release, so it detects a damaged download, not a replaced release.

## Develop a handler

A handler is a `BaseHandler` subclass with a pydantic config model, shipped in
a wheel that exposes a `register(registry)` callable under the
`hegemony.step_handlers` entry-point group. The entry-point name is the
handler-id namespace prefix the wheel claims; a third-party wheel claims its
own prefix (`acme.`) and organises ids below it.

- [`packages/step_sdk/README.md`](packages/step_sdk/README.md) is the handler
  contract: a worked example, `parse_config`, timeouts, and the services a
  handler may call through `ctx.services`.
- [`CONVENTIONS.md`](CONVENTIONS.md) holds the rules that keep ids and setting
  names stable (they are stored in flows and run histories), how to build a
  handler that runs a tool in a container, and which values must stay data.
- [`CONTRIBUTING.md`](CONTRIBUTING.md#documentation) describes what CI
  enforces for every handler: one documentation page per handler id, a title
  and a description on every config field, and a README that names the ids.
- A small wheel to start from: [`plugins/steps_general`](plugins/steps_general)
  (`general.sleep`) or [`plugins/steps_http`](plugins/steps_http).

To work on this repository you need Python 3.11 or newer and
[uv](https://docs.astral.sh/uv/); [Task](https://taskfile.dev/) is optional,
since every task is a `uv run` command:

```bash
git clone https://github.com/hegemony-sh/hegemony-step-plugins.git
cd hegemony-step-plugins
task setup   # uv sync --all-packages, then install the pre-commit hooks
task ci      # lint, typecheck, REUSE, plugin docs, tests, build wheels, smoke-install
```

Without Task, `uv sync --frozen --all-packages` followed by `uv run pytest`
runs the tests; the commands CI runs are in
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) and listed in
[CONTRIBUTING.md](CONTRIBUTING.md#local-setup-and-checks).

## Community

- [CONTRIBUTING.md](CONTRIBUTING.md): how to contribute, the DCO sign-off every
  commit needs, and how releases are made.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): the Contributor Covenant.
- [SECURITY.md](SECURITY.md): report vulnerabilities privately to
  [security@hegemony.sh](mailto:security@hegemony.sh), not in a public issue.

## Licence

`AGPL-3.0-or-later`, apart from one MIT-licensed file that runs inside
Ansible; see [LICENSE](LICENSE) and [LICENSING.md](LICENSING.md). The repository
is [REUSE](https://reuse.software/) compliant: every file carries its licence
in an SPDX header.
