<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Poll Until

`netcli.poll_until` repeatedly runs one CLI command on each target device
until the output satisfies a match condition, or gives up after a maximum
number of attempts. Use it as a check or wait step for convergence-style
conditions — an HSRP state becoming Active, a route appearing, a neighbor
coming up — where a plain sleep would be a guess.

## Using It

Command to Poll is required, and so is a match condition: fill in Match
Regex, Match String, or both. The regex is evaluated case-insensitively in
multiline mode against the command output; the string is a case-insensitive
substring test. When both are set, only the regex is used. Turn on Invert
Match to flip the test — the poll then succeeds once the pattern no longer
matches, useful for waiting until something disappears from the output.
The command accepts `{{ variable }}` templates, resolved before the step
runs. Targets are chosen with the role-based target picker.

Each device is polled independently: the command runs, the output is
tested, and if it does not satisfy the condition the step waits Interval
(sec) seconds (default 5) and tries again, up to Max Attempts times
(default 12). Polling stops on the first satisfying attempt; no wait
follows the final attempt. Max Parallel Devices controls how many devices
poll concurrently (default 1 = one after another, capped at 32). Every
attempt's output streams into the step's live log.

## Output

The step adds no custom chainable output keys; its results are recorded as
evidence. Each device yields one `poll_result` artifact - named `poll_` plus the
first word of the command (so any `show ...` poll is `poll_show`), with
the device name appended when more than one device is targeted - recording
the command, the match condition, whether it matched,
the number of attempts used, and the final output. When the condition was
never met, the artifact also includes a 500-character output preview from
every attempt. A device that errors yields a `poll_result` artifact displayed as
`poll_error_<device>`, with the message. Metrics record `device_count`, `max_attempts`, and
`interval_seconds`.

## When It Fails

Configuration errors fail the step before any polling: no target devices,
no command, no match condition, or a regex that does not compile. During
the run, a device fails when it has no management host, when connecting or
executing raises an error, or when the condition is still unsatisfied after
Max Attempts tries. Every device must satisfy the condition for the step to
succeed; the error lists each failing device. There is no separate timeout
— the step's duration is bounded by attempts times interval plus the time
the command itself takes on each device.
