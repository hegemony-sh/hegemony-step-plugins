<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NETCONF Confirm Commit

`netconf.commit` confirms the confirmed commit an earlier change step left
pending, so the change stays. Put it after the checks (or the approval) that
follow a `netconf.edit_config` or `cisco.iosxe.config_replace` step whose
Commit is "Confirm in a later step".

## Using It

Change Step chooses that change step. Its output names each device's
pending commit by a persist id; for each target device this step opens a new
NETCONF session and sends `<commit>` with that persist id (RFC 6241,
`:confirmed-commit:1.1`). Target the same devices as the change step.

Save to startup saves running to startup after confirming: copy-config when
the device has a startup datastore, else Cisco's `save-config` RPC. Port,
timeouts, Allow legacy SSH and Max Parallel Devices (default 10) work as in
`netconf.get`.

The confirmation must arrive before the change step's Confirm Timeout runs
out; after that the device has already restored the previous configuration.

## Output

The summary reads `netconf commit: N/M devices`.

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `persist_id`, `confirmed` and `saved`.
- `steps.NODE_ID.output.truncated`: always empty for this step.

## When It Fails

The step fails when Change Step is not set or has no output in this run.
A device fails when the change step left no pending commit on it, when it
lacks `:confirmed-commit:1.1`, when it cannot be reached, and when it
refuses the persist id: the commit was confirmed or cancelled already, or
rolled back when its timeout ran out.
