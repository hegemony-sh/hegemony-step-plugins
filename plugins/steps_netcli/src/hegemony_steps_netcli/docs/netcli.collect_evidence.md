<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Collect Evidence

`netcli.collect_evidence` is a check step that runs CLI commands on each
target device and captures every command's output as an evidence artifact.
Use it to record device state — before-and-after snapshots, verification
output, audit trails. It is meant for read-only show commands, but nothing
enforces that: a configured command runs as written, so keep anything that
changes device state in `netcli.execute`.

## Using It

List the commands one per line, typically show/exec commands such as
`show version` or `show interfaces`. Command lines accept `{{ variable }}`
templates for flow inputs and earlier step results, resolved before the
step runs. On each device all commands are executed together in one
session, in order, and each command's output becomes its own artifact.
Targets are chosen with the role-based target picker; there is no
additional-IP list for this step.

Leaving the command list empty is not an error: as long as at least one
target device is configured, the step succeeds with a "No commands
configured" summary and collects nothing. Max Parallel Devices
controls the fan-out: 1 (the default) processes devices strictly one after
another, higher values run up to that many devices concurrently (capped at
32). Command output reaches the step's live log per device, once that
device's whole command batch has finished.

## Output

The step adds no custom chainable output keys; what it produces lives in
its evidence. Each command on each device yields a `cli_output` artifact
named `<device>:<command>`, holding the raw output plus the device, the
command, the exit code, and any error text. A device without a management
host or one that fails to connect contributes an error artifact with the
message instead. Metrics record `device_count`, `command_count`,
`total_success` and `total_failure` (per-command results across devices),
and `failed_devices`. The summary reports how many devices were collected
from and how many commands succeeded.

## When It Fails

The step fails when no target devices are configured, or when the commands
value is malformed (not a list, or containing empty or non-string entries).
Per device, it counts as failed when the device has no management host,
when connecting or executing raises an error, or when any command returns a
non-zero exit code. Collection continues on the remaining devices either
way, and all collected evidence is kept — but if any device failed, the
step fails and its error names the failing devices. The handler imposes no
timeout of its own on command execution.
