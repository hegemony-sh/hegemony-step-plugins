<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Watch CLI Output

`netcli.watch` logs in to every target device at the same time, sends a few
setup commands, and then reads what the devices print on that session for a
set time. With the default setup command, `terminal monitor`, a Cisco device
sends its log messages to the session, so the step records what the devices
log while a change runs. Put it in a parallel branch next to the change,
before the join, with a Duration that covers the change.

## Using It

Setup Commands are exec-mode commands sent one by one before the watch
starts, on the same session, at most 10; `terminal monitor` by default. Each
one waits for the prompt, as in `netcli.execute`, within Command Timeout
(sec) (30 by default). When one fails (the device prints an error such as
`% Invalid input`, or it does not answer in time) the device is not watched
and fails. For a device that needs another command to send its log messages
to the session, write that command instead. A device that only prints, such
as one showing a debug, can have no setup commands at all.

Duration (sec), 300 by default, is how long the step reads after the setup
commands. The step's timeout is raised to cover it. On a platform that does
not raise it, the step watches only for the time its timeout leaves, and its
metrics show the time it watched.

A device's line `exec-timeout` (10 minutes by default on Cisco IOS) counts
the time since the device last received input, so it would end a long watch.
Keepalive (sec), 300 by default, sends an empty line that often, which makes
the device print its prompt into the output. Set it to 0 to send nothing.

All selected devices are watched together, so a step takes at most 32
devices. Connect Timeout (sec) bounds each login (10 s by default). Allow
legacy SSH works as in `netcli.execute`.

Two optional patterns check the output. Each is a regular expression (Python
syntax) searched for in each line the device printed after the login: the
setup commands' output, where a log message that arrives while a command
runs lands, and everything printed during the watch. Start it with `(?i)` to
ignore case.

- **Fail Pattern**: a device fails when any line matches, such as
  `%LINK-3-UPDOWN` or `%OSPF-5-ADJCHG.*Down`.
- **Expect Pattern**: a device fails unless at least one line matches, such
  as `%BGP-5-ADJCHANGE.*Up`.

The step checks the patterns after the watch; a matching line does not stop
the watch early.

The step needs a device transport that can follow output: the netmiko
(default) and scrapli transports can. A device on another transport, such as
AsyncSSH, fails with a message naming the transports that work. The output
streams into the run's Logs tab as it arrives, per device, after the setup
commands' transcript.

## Output

The summary names the device count and the duration. Each device adds one
`cli_output` evidence record named "Watch" (with the device's name when
several devices are watched). It holds the setup commands' transcript and
then what the device printed, the last million characters of it when it
printed more; its data records the commands, the time watched, how the
watch ended, the line count, the lines that matched Fail Pattern and
whether Expect Pattern matched.

- `steps.NODE_ID.output.passed`: true when every device was watched to the
  end and passed both patterns.
- `steps.NODE_ID.output.devices`: each device's result by name: `ended`
  (`duration` when Duration was up, `disconnected` when the device closed
  the session first, `cancelled` when the run was cancelled, `failed` when
  the login or a setup command failed), `elapsed_seconds` (the time
  watched), `lines` (lines checked that are not blank), `fail_matches` (the
  first 20 lines that matched Fail Pattern, each cut at 500 characters),
  `expect_matched` (true or false, or null without Expect Pattern) and
  `error`.
- `steps.NODE_ID.output.stdout`: the last 4096 characters of the combined
  output of every device.

Metrics record `device_count`, `duration_seconds` (the time watched) and
`elapsed_seconds`.

## When It Fails

The step fails without connecting when no targets are selected, when more
than 32 devices are selected, when more than 10 setup commands are given,
or when a pattern is not a valid regular expression. A device fails when it
has no management address, when its transport cannot follow output, when
the login fails, when a setup command fails, when the device closes the
session before Duration is up (it reloads), when the run is cancelled, when
a line matches Fail Pattern, and when no line matches Expect Pattern. One
failing device fails the step; the others' results and evidence are kept.
