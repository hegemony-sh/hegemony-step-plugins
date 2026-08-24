<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Execute CLI

`netcli.execute` runs a list of CLI commands on each target device as an
action step. It is vendor-neutral: the platform dialect and transport are
resolved from each device's access configuration, so the same step works
across device families that speak a command-line interface.

## Using It

Write the commands one per line; they are sent to each device together in a
single session, in order. Command lines accept `{{ variable }}` templates
for flow inputs and earlier step results, resolved before the step runs.
Targets are chosen with the role-based target picker; there is no
additional-IP list for this step.

When the first line is `configure terminal` (or `conf t` / `config t`), the
whole set is treated as one configuration session: the session transcript is
saved as a single consolidated "Configuration" evidence artifact per device,
and the recorded command list omits mode wrappers (`configure terminal`,
`end`, `exit`) and `write`/`copy run` save commands. Any other first line
means show/exec mode: each command gets its own evidence artifact, named
after the command (first line, shortened to 80 characters), with the device
name appended when more than one device is targeted.

Max Parallel Devices controls the fan-out: 1 (the default) processes devices
strictly one after another, higher values run up to that many devices
concurrently (capped at 32). Results are always aggregated in device order.
Command output reaches the step's live log per device, once that device's
whole command batch has finished.

## Output

Later steps can read `steps.NODE_ID.stdout` — the combined output of all
commands across all devices, capped at 4096 characters. Full outputs are
preserved in the `cli_output` evidence artifacts described above, which also
record the device, the command(s), the exit code, and any error text. A
device that throws an error contributes an "Error" artifact with the message
instead. Metrics record `command_count` (configured commands),
`device_count`, and `total_executions` (commands actually run across
devices).

## When It Fails

The step fails immediately when no target devices or no commands are
configured. Per device, it fails when the device has no management host,
when the connection or execution raises an error, or when any command
returns a non-zero exit code. One failing device does not stop the others:
every device is still processed and its evidence kept, but all devices must
succeed for the step to succeed. In a configuration session the error
text lists each failing device with its first failure detail; in show/exec
mode every failing command contributes its own entry. The handler imposes no timeout of its own on
command execution.
