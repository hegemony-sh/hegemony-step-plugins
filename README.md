<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Hegemony Step Plugins

Step-handler SDK and plugin wheels for [Hegemony](https://github.com/hegemony-sh/hegemony).

Step handlers implement the work one flow step performs (run CLI commands on
devices, launch a container, stage an upgrade image, …). Handler types are
pluggable: wheels register handler classes under the `hegemony.step_handlers`
entry-point group and the platform discovers them at startup.

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
  | `plugins/steps_ansible` | `ansible.` | playbook (built on `container.run`'s runner) |
  | `plugins/steps_tf` | `tf.` | plan, apply — OpenTofu or Terraform (built on `container.run`'s runner) |
  | `plugins/steps_http` | `http.` | request |
  | `plugins/steps_secret` | `secret.` | write — store, swap or delete a secret in the organization's secret store |
  | `plugins/steps_inventory` | `inventory.` | sync — sync an inventory provider of the run's organization now |
  | `plugins/steps_netbox` | `netbox.` | request, ipam.allocate/release, render_config — NetBox objects, IP address management and config rendering (needs `hegemony-steps-http`) |

Wheels are versioned in lockstep with the platform. `hegemony-steps-cisco-iosxe`
is opt-in: install the released wheel explicitly (the demo pins it via
demo-plugin-wheels.txt). Every other wheel ships in the platform's images. The
platform has no runtime switch that hides an installed step, so a deployment
that must not offer one builds its api and worker images without the wheel
(`uv pip uninstall` in a derived image; see the platform's
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

## Development

```bash
task setup   # install workspace + pre-commit hooks
task ci      # lint, typecheck, REUSE, tests, build wheels, smoke-install
```

Handlers reach every platform facility (device transports, secret/template
resolution, the internal API) through `ctx.services` — plugin code never
imports Hegemony internals.

See `CONTRIBUTING.md` and `LICENSING.md` for contribution and licensing terms.
