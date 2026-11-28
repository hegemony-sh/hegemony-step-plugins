<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NAPALM Config

`napalm.config` changes each target device's configuration with NAPALM's
candidate workflow: load the new configuration as a candidate, compare it
with the running one, then commit it or discard it. It works the same way on
Cisco IOS and IOS XE, Arista EOS and Cisco NX-OS.

## Using It

Targets come from the step's target picker; the session opens as for
`napalm.get`. Configuration is the text in the device's own syntax.
Templates are filled in before it is sent:

```text
interface Loopback100
 ip address {{ inputs.service_address }} 255.255.255.255
```

Mode picks how it is applied. Merge (the default) adds the lines to the
running configuration. Replace makes the text the whole configuration, so
anything it leaves out is removed: use it only with a complete
configuration.

For every device the step loads the candidate and records the difference.
When there is no difference, the candidate is discarded and nothing is
committed, so running the step twice changes nothing the second time.

Dry run only records the difference and discards the candidate. A common
flow is a dry run step, an approval step where a person reads the
difference, then the same step without Dry run.

Confirm Within (sec) makes the commit a confirmed commit. The device rolls
the change back by itself after that long unless it is confirmed. The step
confirms it only after a second, new session to the device succeeds. When
that session fails, the step rolls back at once, or, if even that fails,
the device's own timer does. The value is 0 (commit at once) or a multiple
of 60 of at least 60.

What each platform needs:

- Cisco IOS and IOS XE: loading a candidate writes it to the device's flash
  through the same session, with the device's TCL shell (`tclsh`), so no SCP
  server is needed. Confirm Within needs the `archive` feature. NAPALM turns on `file prompt quiet` during
  the session and turns it off again when it closes.
- Arista EOS: uses configuration sessions; nothing extra is needed.
- Cisco NX-OS: Merge only. Replace would copy the file with SCP, outside
  the secured session, so the device fails with that reason. Confirm Within
  is not supported either.

Max Parallel Devices defaults to 1, so devices change one after another.
Connect Timeout (sec), Command Timeout (sec) and Allow legacy SSH are
advanced.

## Output

The summary reads `napalm config <mode>: N/M devices ok, K changed` (or
`would change` for a dry run). Each device adds one `cli_output` evidence
record named `<device>:napalm diff` with its difference, or
`(no difference)`. Its command is `napalm diff`.

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `driver`, `diff`, `changed`, `committed` and `confirmed`, and
  `rolled_back` when a confirmed commit was undone.
- `steps.NODE_ID.output.truncated`: differences cut short in the output, as
  `device.diff`; the evidence keeps all of each.

## Failure

A device fails when its session cannot open, NAPALM refuses the candidate
(a syntax error on the device), the commit fails, or the check after a
confirmed commit fails. A failed load or compare discards the candidate.
The step fails when any device fails.
