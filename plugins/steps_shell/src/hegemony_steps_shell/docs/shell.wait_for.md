<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Wait For Shell Output

`shell.wait_for` runs one shell command on each target host again and again
until its output matches a regular expression, or until Max Wait (sec) runs
out. Use it after a reboot or a package install, when the host answers on
the network but a service is not up yet. It is the server counterpart of
`netcli.wait_for`.

## Using It

Command is one command, such as `systemctl is-active nginx`, and Interpreter
wraps it as in `shell.execute`. A `{{ }}` value must end with `| quote` and
stand outside quotes, as in `shell.execute`. Pattern is a regular
expression (Python syntax) searched for in the command's standard output,
and Wait Until says whether the step waits for the output to match it or to
stop matching it. Match Scope "Whole output" searches the whole output at
once; "Any line" searches each line on its own, so `^` and `$` mark the
start and end of a line. Start the pattern with `(?i)` to ignore case.

The step polls every Poll Interval (sec), 10 by default. Stable For (polls)
asks for that many polls in a row that meet the condition. A poll whose
command exits with a non-zero code never meets the condition, in either
mode, and starts that count again; `systemctl is-active` exits non-zero
while the service is not active.

Each host keeps one shell connection for all its polls. When the connection
drops (the host reboots), the command runs out of Command Timeout (sec) or
it ends without an exit status, the step opens a new connection at the next
poll, and keeps trying at the poll interval while the host cannot be
reached. That time counts against Max Wait (sec); it is not a failure. A
login refused for wrong credentials, a host key the platform does not trust
and a destination the network policy denies stop the wait for that host at
once.

Connect Timeout (sec) bounds each login (10 s by default). Max Parallel
Devices (default 10) sets how many hosts are waited on at the same time;
Max Wait (sec) covers the whole step. Allow legacy SSH works as in
`shell.execute`.

Every poll writes to the run's Logs tab: the command, its standard output
and error as `shell.execute` writes them, then a status line such as
`[attempt 5, 40 s elapsed] match not yet; next poll in 10 s`,
`session lost (...); reconnecting in 10 s` or `matched`. The platform
removes the secrets it resolved from these lines, as it does for
`shell.execute`.

## Output

The summary names how many hosts met the condition. Each host adds one
`cli_output` evidence record, named after the command, holding the last
standard output in full; its data records the pattern and the counters
below.

- `steps.NODE_ID.output.matched`: true when every host met the condition in
  time.
- `steps.NODE_ID.output.devices`: each host's result by name: `matched`,
  `attempts` (polls, including those that could not reach the host),
  `elapsed_seconds` (from the start of the step), `reconnects` (connections
  opened after one was lost), `matched_at` (UTC time, ISO 8601),
  `last_output` (the last standard output, cut at 4096 characters) and
  `error`.
- `steps.NODE_ID.output.truncated`: the hosts whose `last_output` was cut.

## When It Fails

The step fails without connecting when no targets are selected, when
Command or Pattern is empty, when Pattern is not a valid regular expression,
and when a `{{ }}` value in Command is not quoted as described above. A host
fails when its output does not meet the condition within Max Wait (sec),
and at once when the login is refused for good or the host has no
management address. The error names the host, the number of attempts and
what the last poll saw. One failing host fails the step; the others'
results are kept.
