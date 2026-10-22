<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

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

When the first line that is not blank is `configure terminal` (or `conf t`
/ `config t`), the list is a configuration session. `configure terminal`
starts a configuration block and only `end` closes it. `exit` is sent to the
device like any other configuration line, so it can leave an interface or
other sub-mode without ending the block. Lines after `end` and before the
next `configure terminal`, and `write` or `copy run` save commands, run at
the exec prompt. Everything runs in the order written. Configuration lines are
sent one at a time, and each is checked before the next is sent. When a
command fails, including a configuration line the device rejects, the
commands after it do not run and are recorded as skipped, so a
`write memory` never saves a change that failed part way.
When the run is cancelled part way through, the commands that have not run
are recorded as skipped because the run was cancelled, not because a command
failed.

With the netmiko and scrapli transports, a copy to `startup-config` (such as
`copy running-config startup-config` or `copy run start`) answers the
questions the device asks first with Enter: the destination file name, and
the `[confirm]` some platforms ask before they overwrite it. It then waits
for the prompt like any other command.

A configuration session's transcript is saved as a single consolidated
"Configuration" evidence artifact per device, and the recorded command list
omits `configure terminal`, `end` and the save commands. Any other first
line that is not blank means show/exec mode: each command gets its own
evidence artifact, named after the command (first line, shortened to 80
characters), with the device name appended when more than one device is
targeted.

Max Parallel Devices controls the fan-out: 1 (the default) processes devices
strictly one after another, higher values run up to that many devices
concurrently (capped at 32). Results are always aggregated in device order.
Command output reaches the step's live log per device, once that device's
whole command batch has finished.

Command timeout (30 seconds by default, at most 3600) limits how long one
command, or one configuration line, may run on a device; a command that runs
longer fails. The step's own timeout still applies to the whole step, so it
must leave time for every command on every device. With the netmiko
transport, a configuration block that holds a `banner`, `macro name` or
`crypto pki certificate chain` line takes about two seconds a line: free
text gets no prompt back, so each line waits for the device to go quiet.

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
returns a non-zero exit code. With the netmiko and scrapli transports, a
device error message in the output, such as `% Invalid input detected`, also
counts as a failed command. One failing device does not stop the others:
every device is still processed and its evidence kept, but all devices must
succeed for the step to succeed. In a configuration session the error
text lists each failing device with its first failure detail; in show/exec
mode every failing command contributes its own entry. A command that runs
past Command timeout counts as failed.
