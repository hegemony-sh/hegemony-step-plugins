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
  naming/grouping rules — the entry-point name is the claimed prefix):

  | Wheel | Namespace | Handlers |
  | --- | --- | --- |
  | `plugins/steps_general` | `general.` | noop (hidden), sleep |
  | `plugins/steps_probe` | `probe.` | connectivity, http, dns, wait_reachable |
  | `plugins/steps_netcli` | `netcli.` | execute, collect_evidence |
  | `plugins/steps_evidence` | `evidence.` | assert, compare |
  | `plugins/steps_container` | `container.` | run |
  | `plugins/steps_flow` | `flow.` | run, notify |
  | `plugins/steps_cisco_iosxe` | `cisco.iosxe.` | upgrade.preflight/stage/install/verify/cleanup (opt-in) |
  | `plugins/steps_shell` | `shell.` | execute (opt-in) |
  | `plugins/steps_ansible` | `ansible.` | playbook (built on `container.run`'s runner) |
  | `plugins/steps_tf` | `tf.` | plan, apply — OpenTofu or Terraform (built on `container.run`'s runner) |
  | `plugins/steps_secret` | `secret.` | write — store, swap or delete a secret in the organization's secret store |

Wheels are versioned in lockstep with the platform. Most are auto-installed;
`hegemony-steps-cisco-iosxe` and `hegemony-steps-shell` are opt-in (install the
released wheels explicitly — the demo pins them via demo-plugin-wheels.txt),
and hardened deployments may omit `hegemony-steps-container` to disable
container execution entirely, or `hegemony-steps-secret` to keep flows from
writing secrets.

## Development

```bash
task setup   # install workspace + pre-commit hooks
task ci      # lint, typecheck, REUSE, tests, build wheels, smoke-install
```

Handlers reach every platform facility (device transports, secret/template
resolution, the internal API) through `ctx.services` — plugin code never
imports Hegemony internals.

See `CONTRIBUTING.md` and `LICENSING.md` for contribution and licensing terms.
