<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NETCONF Cancel Commit

`netconf.cancel_commit` rolls back, at once, the confirmed commit an earlier
change step left pending, instead of waiting for its timeout. Put it on the
failure branch after the checks that follow a change step whose Commit is
"Confirm in a later step".

## Using It

Change Step chooses that change step. For each target device this step
opens a new NETCONF session and sends `<cancel-commit>` with the device's
persist id from the change step's output (RFC 6241,
`:confirmed-commit:1.1`); the device restores the configuration it had
before the commit. Target the same devices as the change step. Port,
timeouts, Allow legacy SSH and Max Parallel Devices (default 10) work as in
`netconf.get`.

## Output

The summary reads `netconf cancel-commit: N/M devices`.

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `persist_id` and `cancelled`.
- `steps.NODE_ID.output.truncated`: always empty for this step.

## When It Fails

The step fails when Change Step is not set or has no output in this run.
A device fails when the change step left no pending commit on it, when it
lacks `:confirmed-commit:1.1`, when it cannot be reached, and when it
refuses the persist id because the commit was already confirmed, cancelled
or rolled back.
