<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Handler naming and grouping conventions

Handler ids are a **persistence contract**: they are stored in flow
definitions, git-synced flow YAML, and Temporal run histories. Once released,
an id is renamed only via a coordinated data migration (no legacy alias
resolution exists). These rules keep the taxonomy stable as vendors,
platforms, transports, and libraries multiply.

## Id shape

```text
<namespace-prefix>.<name>
```

- The **namespace prefix** is claimed by exactly one plugin wheel and equals
  that wheel's entry-point name under `hegemony.step_handlers` (e.g.
  `netcli`, `cisco.iosxe`). The host registry rejects ids a plugin registers
  outside its claimed prefix.
- The **local name** after the prefix is normally one snake_case segment.
  Dotted local names are allowed only for a genuine workflow family
  (`cisco.iosxe.upgrade.preflight` … `.upgrade.cleanup`).
- Never derive a handler's group by splitting its id on dots — ownership
  comes from the registry's claimed prefix, and editor grouping comes from
  the handler's `category` metadata.

## Namespace kinds

1. **Capability namespaces** — vendor/protocol-neutral semantics:
   `general`, `probe`, `evidence`, `container`, `flow`, `http`
   (and host-owned `monitor` for the in-tree background-monitor family).
2. **Device-interaction paradigms** — protocol families whose config schemas
   differ fundamentally: `netcli` today; `netconf`, `gnmi`, `shell` when they
   exist. A NETCONF edit-config step is not a CLI step with a different
   transport — its config is payload-shaped, so it is a different handler in
   a different namespace.
3. **Vendor-platform namespaces** — only for workflows whose semantics are
   themselves platform-specific: `cisco.iosxe` today; `cisco.nxos`,
   `cisco.iosxr`, `arista.eos` as they appear. Vendor first, platform second.

4. **Tool namespaces** — handlers that drive one external tool whose own
   concepts shape the config schema (a playbook, a plan file): `ansible`,
   `tf` (OpenTofu and Terraform share `.tf` files and plan/apply semantics,
   so the implementation is a config field, not part of the id — rule 3).
   Tool handlers that run the tool in a container build on `container.run`'s
   runner (`hegemony_steps_container.runner`), declare `container_backed`,
   and depend on `hegemony-steps-container`, so omitting container execution
   omits them too (see [Building a tool handler](#building-a-tool-handler)).

Third-party plugins claim their own prefix (e.g. `acme.`) and organize
below it (`acme.ipam.allocate`).

## Building a tool handler

A tool handler (`ansible.playbook`, `tf.plan`, `tf.apply`, the next
containerlab or NETCONF tool) runs its tool in a container on the sandbox
through `hegemony_steps_container.runner` instead of copying
`container.run`'s execution. The contract:

- **Config.** Subclass `ContainerExecutionConfig`, which carries the shared
  container fields (timeout, memory, CPUs, env, egress policy, attachments).
  Expose no host-access options (network mode, privileged, Docker socket,
  extra mounts): tool steps always run isolated and need no admin gate.
  Build the job's config with `container_config_from`, which forwards only
  the shared fields and applies the tool's own env after the step's.
- **Validation.** `validate_config` checks the tool's fields and also runs
  `RunContainerHandler().validate_config(container_config_from(...))`, so
  the image reference, env keys, and egress rules are refused before a run.
- **Declaration.** Set `container_backed = True`, so the host applies the
  egress policy and admission rules of `container.run`, and depend on
  `hegemony-steps-container` at the same version, so a deployment without
  container execution has no tool handlers either. Set
  `platform_api_access = True` only when the container itself calls the
  platform API (the tf steps' managed state through
  `services.open_state_backend`).
- **Secrets.** List secret fields in `raw_config_keys` so they arrive as
  written, resolve them with `resolve_secret_values` (checked with
  `secret_map_errors`), and hand them to the tool as staged files
  (`StagedFile`), never as environment variables or arguments, which are
  visible in the sandbox's container metadata.
- **Running.** Describe a `ContainerJob` (config, staged files, collect
  roots, the handler's id for the `hegemony.handler_id` label) and call
  `run_container_job`. A failed `HandlerResult` is a failure before or
  around the run; return it. A `ContainerJobResult` means the container
  ran, whatever its exit code.
- **Stopping.** Start the run script with `exec` (`exec sh /hegemony/run.sh`)
  so it is the container's PID 1, which `docker stop` signals, and run the
  tool through `bounded` (`deadline_shell_lines`): it stops the tool at the
  step's deadline even when the worker is gone, and passes a SIGTERM the
  script receives on to the tool. A tool that must not be cut off mid-change
  (it writes state, holds a lock) sets `ContainerJob.stop_grace_seconds`: a
  cancelled step's container then gets SIGTERM and that long before it is
  removed, instead of `docker rm -f`. Give the in-script deadline the same
  margin before the step's timeout (`tool_deadline` in the tf wheel), and
  let its kill wait out that whole margin (`tool_kill_after`).
- **Step I/O.** `/hegemony` is reserved in every step container. Write
  structured results under `/hegemony/out` (collected after exit, at most
  8 MiB per job) and read them from `collected`; `collect_errors` tells a
  result that could not be copied out from one the tool never wrote. Bulky
  output belongs in the new-artifacts folder, which uploads to storage
  rather than worker memory. Never guess a result that is missing: fail
  the step or report it as unknown.
- **Docs.** Each handler has its page under `docs/` in the wheel, and the
  wheel README names its handlers and links there.
- **Default image and licences.** Declare the image a step pulls when its
  author sets none as a module-level `DEFAULT_IMAGE` (a string) or
  `DEFAULT_IMAGES` (a dict of strings) literal. `scripts/check_image_licenses.py`
  reads those with `ast`, and every image they name, like every image,
  package and collection a Dockerfile under `images/` uses, must have a
  reviewed row in the matching `images/.*-allowed.txt`. An image the Images
  workflow publishes also carries a `THIRD-PARTY-NOTICES.md` naming what it
  installs, with the written source offer. See LICENSING.md.
- **Code that runs inside a third-party tool.** A file the step stages into
  the tool's own process (the Ansible callback plugin runs inside
  `ansible-playbook`) forms one program with that tool. When the tool is
  GPL, license the file MIT rather than AGPL, as `callback_plugin.py` is, and
  keep it in its own module so the licence boundary is a file boundary.

## Decision rules for a new handler

Apply in order:

1. **Would the config schema and behavior description read identically for
   another vendor?** Yes → paradigm or capability namespace. No →
   vendor-platform namespace. (This is why `netcli.execute` is not
   `cisco.iosxe.execute_cli`: "send CLI lines, capture output" is
   vendor-neutral — the dialect comes from `device.platform` — while the
   IOS-XE upgrade workflow's install/bundle modes shape its config schema.)
2. **Does it authenticate into a target's management plane, or observe from
   outside?** Outside observation → `probe.` (background variants →
   `monitor.`). Credentialed interaction → a paradigm namespace.
3. **Transports and libraries never appear in ids.** SSH/telnet/WinRM,
   netmiko/scrapli/asyncssh are resolved from `device.access_config` and
   (in the pluggable-transport phase) transport/driver plugins beneath the
   handler layer. Worked example: "run shell commands on a Linux server over
   SSH" is `shell.execute`, **not** `ssh.execute` — if WinRM execution
   arrives later, it is the same paradigm over a different transport, same
   namespace.

## Rendered values are data

The host renders a step's `{{ }}` templates before `execute` runs, so a
config value can carry a run input, another step's output or a device
attribute. A handler that hands such a value to something that interprets
text again must keep it data:

- **Shell command lines.** Refuse unquoted values before they are rendered:
  override `template_errors(config)`, which the host calls with the step's
  config as written on every run and fails the step on (`shell.execute`
  parses each command with Jinja and a shell-quoting scanner and requires
  every `{{ }}` value to end with the host's `| quote` filter and stand in an
  unquoted word position). Prefer passing values as quoted environment
  variables.
- **Text another template engine reads** (Ansible variable files): escape it,
  as `ansible.playbook` does with `literal()` for inventory, secrets and extra
  variables.
- **Destinations.** A host, nameserver or URL the handler dials itself goes
  through `services.enforce_egress` first, and must be an address the policy
  can evaluate (`probe.dns` accepts only an IP address as its resolver).

## Setting names

Setting names are a persistence contract too: steps store them.

- **Durations end in their unit**: `_seconds`, or `_ms` only where
  sub-second precision is part of the setting's meaning (`interval_ms`).
  No `_sec` or `_s`, and no bare `seconds`, `interval` or `timeout`.
- **A limit on one operation names the operation**
  (`command_timeout_seconds`, `attempt_timeout_seconds`,
  `connect_timeout_seconds`). Declare a limit on the whole step
  (`timeout_seconds`, probe.wait_reachable's `max_wait_seconds`) as the
  handler's `run_timeout_field`, so the host gives the step that long plus a
  margin; a limit that applies to each device in turn is not one.
- **A tool's own setting keeps the tool's form** when the value is passed to
  the tool as written (tf's `lock_timeout` is a duration string such as `5m`).
- **Renaming a setting keeps the old name working.** Give the field
  `validation_alias=AliasChoices("new_name", "old_name")` and
  `json_schema_extra={"x_legacy_keys": ["old_name"]}`, and keep both for
  good: saved flows and committed versions are never rewritten. The schema
  then shows only the new name, the editor shows a step saved under the old
  one in the new field, and `parse_config` maps it for the handler. This
  works only for a handler that reads its settings through `parse_config`.
- **Model defaults are the handler's defaults.** The editor and the reference
  docs show the model's defaults, so a handler must not fall back to other
  values. A setting whose default depends on the step ("empty = the step's
  timeout") is `Optional` with a `None` default.

`supported_kinds` (and `StepKind`) only describes a handler: the platform
lists it as a capability, and nothing reads it when a step runs.

## Wheel granularity

One wheel = one namespace prefix = `hegemony-steps-<prefix-with-dashes>`.
Cut wheels along boundaries operators care about (excludable security
surface — e.g. `container` is alone so hardened deployments can omit Docker
execution entirely) and along growth axes (per-platform wheels for
platform-specific workflows). Prefer a new wheel over widening a namespace's
meaning.

Every wheel declares its licence as an SPDX expression (`license =
"AGPL-3.0-or-later"`) with `license-files = ["LICENSE-*.txt"]`, and carries a
copy of `LICENSES/<id>.txt` as `LICENSE-<id>.txt` for each identifier, so the
installed wheel has the texts under `*.dist-info/licenses/`. A new package gets
them from `python scripts/package_licenses.py`; `task licenses:packages` and a
test check they match.

## Plugin kinds and their entry-point groups

Step handlers are one of several plugin kinds this repo ships. All kinds
build on `hegemony-step-sdk` and live in **this monorepo** — a transport or
probe wheel is useless without the exact SDK protocol version it implements,
so they release in lockstep with the SDK (this is why they are *not* split
into per-domain repos the way inventory/notification/secret plugins are).

| Kind | Entry-point group | Workspace dir | Wheel name |
|------|-------------------|---------------|------------|
| Step handlers | `hegemony.step_handlers` | `plugins/steps_*` | `hegemony-steps-<prefix>` |
| Device transports | `hegemony.device_transports` | `transports/transport_*` | `hegemony-transport-<name>` |
| Probes | `hegemony.probes` | `probes/probe_*` | `hegemony-probe-<name>` |

The group-name constants live in the SDK next to
`STEP_HANDLER_ENTRY_POINT_GROUP`. The host consumes every kind the same way:
entry-point discovery, a pin in the host's `.github/plugin-pins.json`, and a
release line in the demo's `demo-plugin-wheels.txt` (auto-installed kinds ship
in the images and are omitted from the demo manifest).

### Transports and probes

- **Device transports** implement the SDK `Transport` protocol: `netmiko`
  (default; full surface incl. SCP/HTTP staging), `scrapli` (CLI surface;
  staging raises `NotImplementedError`), and `asyncssh` (exec channels with
  real exit codes, for server-like devices); platform drivers come later.
  They sit *beneath* the handler layer and are selected from
  `device.access_config` — never named in a handler id (see decision rule 3).
  Handlers reach them through `services.connect()` / `services.open_shell()`;
  the host resolves credentials into a `DeviceConnectionSpec` and injects its
  cancellation registry, so a transport wheel stays free of the platform's
  secret pipeline.
- **Probes** implement tcp/icmp/http/dns checks (`hegemony-probe-net`) and are
  consumed by BOTH the one-shot `probe.*` step handlers (via
  `services.run_probe`) and the host `MonitorManager` tick loop — one
  implementation, not a copy in each. A handler's `check_type` is registry-driven
  (the host injects the options from `x_options_source`), so a probe wheel adds a
  check type with no config-model edit.
- The `monitor.*` handlers live in `plugins/steps_monitor` and reach the host
  monitor machinery through `services.start_monitor`;
  MonitorManager and the engine's monitor-node semantics (until-join, run
  cleanup — keyed off the `monitor.` id prefix) remain host forever.
