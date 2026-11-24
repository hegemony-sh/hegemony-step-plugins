<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# IOS XE Get Config (CLI)

`cisco.iosxe.get_config` reads an IOS XE device's running or candidate
configuration as CLI text over NETCONF, with Cisco's
`get-modelled-config-clis` RPC. Use it as the starting point of an Atomic
Config Replace, or to compare configurations with `evidence.compare`.

It is not a full backup: it returns modelled CLI only, and Cisco's model
leaves out wireless, app-hosting and telemetry configuration. A file that
`git.commit` stores from it is a record of the modelled configuration, not
something to restore a device from on its own.

## Using It

Datastore is running (the default) or candidate. The text holds the
configuration IOS XE models in YANG; configuration it does not model is not
returned. The device needs the `Cisco-IOS-XE-cli-rpc` model, found in the
hello or in the device's YANG library (`netconf-yang`;
the candidate needs `netconf-yang feature candidate-datastore`). Max
Parallel Devices defaults to 10. Port, timeouts and Allow legacy SSH work as
in `netconf.get`.

## Output

The summary reads `IOS XE <datastore>-config: N/M devices`. Each device adds
one `cli_output` evidence record named `<device>:<datastore>-config`, with
the command `<datastore>-config`, so `git.commit` with Path
`configs/{device}.cfg` backs up one file per device.

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `datastore` and `config`, the CLI text.
- `steps.NODE_ID.output.truncated`: texts cut short in the output (16 KiB a
  device, 64 KiB the step); the evidence keeps them whole.

## When It Fails

A device fails when it cannot be reached, when it lacks the
`Cisco-IOS-XE-cli-rpc` model, and when the RPC returns an error, which the
step error quotes. One failing device fails the step.
