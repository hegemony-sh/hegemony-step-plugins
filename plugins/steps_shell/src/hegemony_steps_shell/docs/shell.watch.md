<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Watch Shell Output

`shell.watch` runs one long command, such as `tail -F /var/log/syslog` or
`journalctl -f -u nginx`, on every target host at the same time, and follows
its output for a set time. Use it to watch a host's logs while a change runs
in a parallel branch of the flow: put it next to the change, before the join,
with a Duration that covers the change.

## Using It

Command is the command to follow; it runs in `sh -c` or `bash -c`, as
Interpreter says (sh by default), so a pipeline works. A program in a
pipeline that buffers its output when it does not write to a terminal, such
as `grep`, needs its own option to write each line at once
(`grep --line-buffered`), or its lines arrive only at the end. Command
accepts `{{ }}` values under the rules of `shell.execute`: every value ends
with `| quote` and stands outside quotes.

Duration (sec), 300 by default, is how long the step watches. The step runs
the command under the host's `timeout` tool (GNU coreutils or BusyBox), which
stops it on the host when Duration is up: first with a TERM signal, then
with KILL 5 seconds later. A host without `timeout` fails the step with
`timeout: not found` (exit 127). The step's timeout is raised to cover
Duration. On a platform that does not raise it, the step watches only for
the time its timeout leaves, and says so in its metrics.

The output streams into the run's Logs tab as it arrives, per host. All
selected hosts are watched together, so a step takes at most 32 hosts.
Connect Timeout (sec) bounds each login (10 s by default). Allow legacy SSH
works as in `shell.execute`.

Two optional patterns check the output. Each is a regular expression (Python
syntax) searched for in each line of the command's standard output and
standard error; start it with `(?i)` to ignore case.

- **Fail Pattern**: a host fails when any line matches, such as
  `(?i)error|out of memory`.
- **Expect Pattern**: a host fails unless at least one line matches, such as
  `Started nginx`.

The step checks the patterns after Duration is up; a matching line does not
stop the watch early.

## Output

The summary names the command, the host count and the duration. Each host
adds one `cli_output` evidence record, named after the command (with the
host's name when several hosts are watched). It holds the command's standard
output, the last million characters of it when it printed more; its data
records the exit code, how the watch ended, the line count, the lines that
matched Fail Pattern, whether Expect Pattern matched and the end of the
standard error.

- `steps.NODE_ID.output.passed`: true when every host watched to the end
  (or the command ended by itself with exit code 0) and passed both
  patterns.
- `steps.NODE_ID.output.devices`: each host's result by name: `ended`
  (`duration` when Duration was up, `exited` when the command ended by
  itself with exit code 0, `failed` when it ended with another exit code),
  `exit_code`, `lines` (lines printed), `fail_matches` (the first 20 lines
  that matched Fail Pattern, each cut at 500 characters), `expect_matched`
  (true or false, or null without Expect Pattern) and `error`.
- `steps.NODE_ID.output.stdout`: the last 4096 characters of the combined
  standard output of every host.

Metrics record `device_count`, `duration_seconds` (the time watched) and
`elapsed_seconds`.

## When It Fails

The step fails without connecting when no targets are selected, when more
than 32 hosts are selected, when Command is empty, or when a pattern is not
a valid regular expression. A host fails when it has no management address,
when the login fails, when the connection is lost during the watch, when the
command ends with an exit code other than 0 before Duration is up (such as a
file that `tail` cannot read), when a line matches Fail Pattern, and when no
line matches Expect Pattern. One failing host fails the step; the others'
results and evidence are kept.

`timeout` reports the end of Duration as exit code 124 (GNU coreutils), or
143 or 137 (BusyBox). The step reads each of these as the end of the watch,
so a command that ends by itself with one of them also counts as watched to
the end.
