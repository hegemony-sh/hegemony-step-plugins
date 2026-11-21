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

## Commands That Ask Questions

Some commands stop at a question before the device prompt returns, such as
the file name and `[confirm]` of a `delete`. The step waits for the prompt,
so such a command runs into the command timeout, and the error then
suggests listing the question. List the questions a command may ask, and
what to answer, under `prompts`:

```yaml
commands:
  - delete flash:old-image.bin
prompts:
  - command: '^delete '               # regular expression on the command text
    expect: 'Delete filename \[.*\]\?'  # regular expression on the last line
    answer: ''                        # empty: Enter alone
  - command: '^delete '
    expect: '\[confirm\]'
```

Each entry applies to the commands its `command` pattern finds (an empty
`command` applies it to every command), and is matched against the last line
the device printed. It answers once per command; set `repeat: true` to answer
it every time it is asked, such as the per-file confirmations of a
`delete /recursive`, up to 50 answers. Only listed questions are answered: a
question nobody listed, or a question asked again after its one answer, fails
the command with the line the device is waiting at. The command timeout
applies to each wait, from the command or an answer to the next question or
the prompt. An answer can hold a `{{ secret(...) }}` reference; it is masked
like other secret values.

In the step form, Answers to questions has one row per entry: the command
pattern, the question, the answer and "Every time" (`repeat`). Prompts apply
to commands run at the exec prompt, not to configuration lines, and need the
netmiko or scrapli transport; with another transport the step fails rather
than skip them.

## Commands That End the Session

A `reload` (or an `install ... activate` that reloads) ends the SSH session
while the command runs, which normally fails it. Turn on **Allow disconnect
after the last command** (`allow_disconnect_after_last_command`, under the
advanced settings) to count that as success:

```yaml
commands:
  - reload
prompts:
  - command: '^reload'
    expect: '\[confirm\]'
allow_disconnect_after_last_command: true
```

Only the last command that is not blank may end the session; blank lines
after it are skipped once it closed. A session that closes during an
earlier command still fails, and the commands after it are skipped. The
command must still be answered up to the point the device goes down: list
its questions under `prompts`, as with any other command.

The setting accepts only a session the device closed. A command that fails
with a device error, also one the device printed just before it closed the
session, or that times out while the session stays open (the device
stopped answering without closing it, or waits at a question nobody
listed), still fails, as does a session closed because the run was
cancelled. A device that closes the session cleanly shows it
at once while the command answers questions; otherwise the closed session
may only be noticed when Command timeout runs out. The setting does not
check that the device really reloads: follow the step with
`probe.wait_unreachable` and then `probe.wait_reachable`. It needs the
netmiko or scrapli transport; with another transport the step fails rather
than ignore it.

## SSH Compatibility

Allow legacy SSH algorithms defaults to off. Enable `allow_legacy_ssh` only
for older devices which require weak algorithms or small host keys; it applies
to the device and jump host for this step. Host-key verification still applies,
and a failed secure connection never retries weakly. Prefer upgrading the
device; use legacy mode only on a trusted network. The override enables only
algorithms the selected transport library still supports.

To allow them for one old device in every step, set `allow_legacy_ssh` in the
device's SSH access configuration instead (the jump host has its own flag). It
covers that hop only and needs a Hegemony version that reads it.

## Output

Later steps can read `steps.NODE_ID.output.stdout` — the combined output of all
commands across all devices, capped at 4096 characters — and
`steps.NODE_ID.output.disconnected`, the devices that closed the session
during the last command while Allow disconnect after the last command was
on (empty otherwise). The evidence of that command says so, with
`disconnected` set and the output the device sent before it closed; with
the netmiko transport that output is kept only for a command that answers
questions under `prompts`, which a `reload` does. Full outputs are
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
