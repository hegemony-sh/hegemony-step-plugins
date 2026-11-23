<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# IOS XE Atomic Config Replace

`cisco.iosxe.config_replace` replaces an IOS XE device's configuration with
Atomic Configuration Replace (ACR) over NETCONF. You give the whole
configuration as CLI text; the device checks it (syntax and dependencies,
naming the line it rejects), and it applies as one transaction: all of it or
nothing. The step shows the diff against running first, and commits with a
confirmed commit, so a configuration that cuts the device off is rolled back
by the device itself.

## Using It

Configuration is the CLI text, as `show running-config` prints it, at most
524,288 characters (the limit of Cisco's model from 17.15; 17.12 to 17.14
take 60,000); templates such as `{{ inputs.hostname }}` are filled in. For one file per
device, leave it empty and set Configuration File to a flow attachment
path: `{device}` in the path is the device's name (`configs/{device}.cfg`).
The step refuses to start when two target devices resolve to the same file.

Operation:

- **Full replace** (the default) makes the device's whole configuration this
  one, removing everything it leaves out. Give the complete configuration,
  including what keeps the device manageable: `netconf-yang`, AAA, users,
  the management interface and its routes.
- **Selective replace** replaces only the sections the configuration names.
- **Merge** adds and changes lines.

The step sends the configuration with Cisco's `config-ios-cli-trans` RPC
into the candidate datastore (`do-commit` false), then works like
`netconf.edit_config` on a candidate: it locks running and candidate,
discards leftovers, reads running and the candidate as CLI text
(`get-modelled-config-clis`), diffs them, validates, and stops for a Dry run, or commits as Commit says:
confirmed and checked with a second session in this step (the default),
confirmed and left pending for `netconf.commit` or `netconf.cancel_commit`
(Confirm Timeout, default 600 s), or directly. Save to startup saves with
Cisco's `save-config` RPC. Max Parallel Devices defaults to 1.

The diff covers modelled configuration only: `get-modelled-config-clis`
leaves out wireless, app-hosting and telemetry configuration (Cisco's model
says so). An empty diff therefore does not show that the replace changes
nothing, so the step commits it all the same, counts the device as changed,
and says so in `notes`.

The device needs IOS XE 17.15 or later (the release whose
`config-ios-cli-trans` has the operation leaf: merge, selective-replace,
full-replace), ACR (an early-field-trial feature on Catalyst 9300 and 9500
in 2025) and this configuration:

```text
netconf-yang
netconf-yang feature candidate-datastore
yang-interfaces feature atomic-config
yang-interfaces feature deprecated disable
```

ACR validates the device's own configuration only, not how it fits the
network, and covers the features Cisco lists for it. What a full replace
does to configuration the model leaves out (wireless, app-hosting,
telemetry, and banners) has not been verified on a device yet: test it on a
lab device before relying on it. The step finds `Cisco-IOS-XE-cli-rpc` in
the hello or, as a YANG 1.1 module, in the device's YANG library. Port, timeouts and Allow legacy SSH
work as in `netconf.get`.

## Output

The summary counts the devices changed, committed and pending. Each device
that changed adds `cli_output` evidence: `<device>:running-config diff`,
`<device>:running-config before` and `<device>:running-config candidate`,
and `<device>:acr result` holds the device's result text for the replace.

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `operation`, `acr_result`, `datastore`, `changed`, `committed`, `pending`,
  `persist_id`, `validated`, `saved`, `save_error`, `save_requested`,
  `commit_uncertain`, `device_id`, `diff` and `notes`.
- `steps.NODE_ID.output.truncated`: diffs cut short in the output (16 KiB a
  device, 64 KiB the step); the evidence keeps them whole.

## When It Fails

The step fails without connecting when both or neither of Configuration and
Configuration File are set, and when the platform cannot open NETCONF
sessions. A device fails when its configuration file is not attached to the
flow or is empty (a full replace with nothing would remove everything), when
its configuration is longer than 524,288 characters, when it lacks the
candidate datastore or the `Cisco-IOS-XE-cli-rpc` model (the error lists
the configuration ACR needs), when its release predates 17.15 (no operation
leaf), when ACR rejects the configuration (any `error-message` or
`rpc-error` in the reply fails the device, whatever the result text says;
the error quotes the device, which names the line), when a
datastore is locked by another session, when validation or the commit is
refused, and when the second session after a confirmed commit does not
open. Every failure before the commit discards the candidate.
