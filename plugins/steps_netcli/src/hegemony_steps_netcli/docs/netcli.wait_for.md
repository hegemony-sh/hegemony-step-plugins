<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Wait For CLI Output

`netcli.wait_for` runs one CLI command on each target device again and again
until its output matches a regular expression, or until Max Wait (sec) runs
out. Use it after a reload or a software install: `probe.wait_reachable`
shows only that a device answers on the network, while this step waits until
it is ready, such as an install committed, an interface up or a routing
neighbor established.

## Using It

Command is one exec-mode command, such as `show install summary`. Pattern
is a regular expression (Python syntax) searched for in its output, and Wait
Until says whether the step waits for the output to match it or to stop
matching it. Match Scope "Whole output" searches the whole output at once,
so a pattern can span lines; "Any line" searches each line on its own, so
`^` and `$` mark the start and end of a line. Start the pattern with `(?i)`
to ignore case. Output longer than a million characters
is not searched and never meets the condition, in either mode.

The step polls every Poll Interval (sec), 10 by default. Stable For (polls)
asks for that many polls in a row that meet the condition, so a value that
flaps is not taken as settled. A poll whose command fails (the device prints
an error such as `% Invalid input`) never meets the condition, in either
mode, and starts that count again.

Each device keeps one login for all its polls. When the device closes the
session (it reloads) or the command gets no answer in Command Timeout
(sec), the step logs in again at the next poll, and keeps trying at the poll
interval while the device cannot be reached. That time counts against Max
Wait (sec); it is not a failure. A login that the device refuses for wrong
credentials, a host key the platform does not trust and a destination the
network policy denies stop the wait for that device at once, since trying
again cannot help and may lock the account.

Connect Timeout (sec) bounds each login (10 s by default). Max Parallel
Devices (default 10) sets how many devices are waited on at the same time;
Max Wait (sec) covers the whole step, so a device that waits for others has
less time left. Allow legacy SSH works as in `netcli.execute`.

The netmiko, scrapli and AsyncSSH transports keep the login between polls.
A transport without that support logs in for every poll; the step works the
same otherwise.

Every poll writes to the run's Logs tab: the command and its output as
`netcli.execute` writes them, then a status line such as
`[attempt 5, 40 s elapsed] match not yet; next poll in 10 s`,
`session lost (the device closed the session); reconnecting in 10 s`,
`not reachable (...)` or `matched`. The platform removes the secrets it
resolved (device and enable passwords, `secret()` values) from these lines,
as it does for `netcli.execute`.

## Output

The summary names how many devices met the condition. Each device adds one
`cli_output` evidence record, named after the command, holding the last
output in full; its data records the pattern and the counters below.

- `steps.NODE_ID.output.matched`: true when every device met the condition
  in time.
- `steps.NODE_ID.output.devices`: each device's result by name: `matched`,
  `attempts` (polls, including those that could not reach the device),
  `elapsed_seconds` (from the start of the step), `reconnects` (logins after
  the session was lost), `matched_at` (UTC time, ISO 8601), `last_output`
  (the last output, cut at 4096 characters) and `error`.
- `steps.NODE_ID.output.truncated`: the devices whose `last_output` was cut.

## When It Fails

The step fails without connecting when no targets are selected, when
Command or Pattern is empty, and when Pattern is not a valid regular
expression. A device fails when its output does not meet the condition
within Max Wait (sec), and at once when the login is refused for good (see
above) or the device has no management address. The error names the
device, the number of attempts and what the last poll saw. One failing
device fails the step; the others' results are kept.
