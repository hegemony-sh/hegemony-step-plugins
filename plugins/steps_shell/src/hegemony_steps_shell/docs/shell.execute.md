<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Execute Shell

`shell.execute` runs a list of shell commands on each target host over the
device's remote-shell transport (SSH, resolved from the device's access
configuration). Unlike the interactive network-CLI steps, it uses exec-channel
semantics: every command returns a real exit code and separate stdout and
stderr, which makes it the right step for Linux/Unix hosts.

## Using It

Write the commands one per line. Each line is sent as its own exec-channel
command, in order, on every target device, and succeeds or fails on its own
exit code. Targets are chosen with the role-based target picker; there is no
additional-IP list for this step.

Command lines accept `{{ variable }}` templates for flow inputs and earlier
step results, resolved before the step runs. A rendered value becomes part of
the remote shell's command line, so every `{{ }}` value must end with the
`quote` filter, which turns it into one literal word:
`systemctl restart {{ inputs.service | quote }}`. Without it, an input such as
`nginx; rm -rf ~` would run a second command. The quoted value must also
stand where the shell reads words, not inside `'...'` or `"..."`, a `#`
comment, backticks or a here-document: there the quoting does not hold, and
`echo "{{ inputs.msg | quote }}"` would let a value containing `"` end the
string. `{% if %}` and `{% for %}` statements are fine where a value would
be (`{% if inputs.force %}--force{% endif %}`); `{% filter %}`,
`{% include %}`, imports and macros are not supported. The step refuses to
run a line that breaks these rules, before anything is rendered. Quoting
keeps a value one word; a command that runs its argument as code (`eval`,
`sh -c`, `ssh host`) still runs it.

The other safe way in is an environment variable: set
`SERVICE={{ inputs.service }}` under Environment Variables and write
`systemctl restart "$SERVICE"` in the command. `{{ device.* }}` refers to
the first target only, so with several targets use values that are the same
for every host.

The Interpreter field controls how each line is wrapped on the remote host.
The default runs the line as-is in the account's login shell. `sh` and `bash`
quote the line into `sh -c '...'` or `bash -c '...'`, which keeps pipelines
and quoting predictable regardless of the login shell. `pwsh` wraps the line
in `pwsh -NoProfile -Command '...'` for PowerShell hosts. Environment
variables are quoted and set for every command: with the default interpreter
they are exported in the login shell first (`export KEY=VALUE; ...`, so a
POSIX login shell is needed), with `sh` and `bash` they are prefixed as
`env KEY=VALUE`. Either way `"$KEY"` works anywhere in the line. Their values
appear on the remote command line (for example in the host's process list),
so they are not a place for secrets. They cannot be combined with the `pwsh`
interpreter — that combination is rejected before anything runs.

"Stop on first failure" (on by default) skips a device's remaining commands
after the first non-zero exit code; turn it off to run every command and
collect all failures. Each command is limited by the per-command timeout
(60 seconds by default). Max Parallel Devices controls the fan-out: 1 (the
default) processes hosts strictly one after another, higher values run up to
that many hosts concurrently (capped at 32). Results are always aggregated in
device order, and command output streams into the step's live log as it
arrives.

## Output

Later steps can read `steps.NODE_ID.stdout` — the combined standard output
of all commands across all hosts, capped at 4096 characters. Full outputs are
preserved as `cli_output` evidence artifacts: one per command per device,
named after the command's first line (shortened to 80 characters) with the
device name appended when more than one host is targeted. Each artifact
records the device, the command, the exit code, and the captured stderr
(capped like the chainable stdout); a failed command's artifact shows its
stderr in place of stdout - or its stdout, when nothing was written to
stderr - and a host that
cannot be reached contributes an "Error" artifact with the connection message.
Metrics record `command_count` (configured commands), `device_count`, and
`total_executions` (commands actually run across all hosts).

## When It Fails

The step fails immediately — before contacting any host — when a command
line inserts a `{{ }}` value without `| quote` or inside quotes, a comment,
backticks or a here-document, when no target devices or no
commands are configured, or when environment variables are combined with the
`pwsh` interpreter. Per host, it fails when the device has
no management host, when the shell connection cannot be opened, when a command
exits non-zero, or when a command times out or the transport raises an error
(which also skips that host's remaining commands). One failing host does not
stop the others: every host is still processed and its evidence kept, but all
hosts must succeed for the step to succeed. The error text lists each failing
host with its exit code and the first line of its error output. The connection
to each host is closed when its commands finish, whether they succeeded or
not.
