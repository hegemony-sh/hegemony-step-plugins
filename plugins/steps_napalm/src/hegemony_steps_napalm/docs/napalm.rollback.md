<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NAPALM Rollback

`napalm.rollback` returns each target device to the configuration it had
before the last commit NAPALM made, for example on the failure path of a
check after `napalm.config`.

## Using It

Targets come from the step's target picker; the session opens as for
`napalm.get`. There is nothing else to set but the advanced connection
settings and Max Parallel Devices (default 1).

What it returns to is what the NAPALM driver saved at that commit:

- Cisco IOS and IOS XE: a commit still waiting for its confirmation is
  reverted now. Otherwise the copy of the configuration NAPALM saved on
  flash before the commit is restored.
- Arista EOS: the copy of the startup configuration saved before the
  commit is restored.
- Cisco NX-OS: the checkpoint NAPALM saved before the commit is restored.

A device with nothing saved (no NAPALM commit was ever made on it) fails
with the driver's message.

## Output

The summary reads `napalm rollback: N/M devices`.
- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error` and `driver`.
- `steps.NODE_ID.output.truncated`: always empty for this step.

## Failure

A device fails when its session cannot open or the driver cannot roll back.
The step fails when any device fails.
