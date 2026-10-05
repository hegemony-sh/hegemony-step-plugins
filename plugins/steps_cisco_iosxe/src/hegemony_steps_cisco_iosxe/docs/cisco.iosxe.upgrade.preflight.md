<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Upgrade Preflight

`cisco.iosxe.upgrade.preflight` runs read-only readiness checks on every
targeted Cisco IOS-XE device before an upgrade: it records the running
version, measures free space on the destination filesystem, and optionally
checks whether the upgrade image is already staged and whether the target
version is already installed. It is safe to run at any time and is meant to
gate the rest of the upgrade flow.

## Using It

The step targets devices by role and connects to each one over SSH. Upgrade
Mode selects the workflow being validated: install mode (modern devices using
the `install` command) additionally verifies that `show install summary`
works on the device, while bundle mode inspects the boot configuration
instead. Devices that only support bundle mode fail the install-mode check.

Image Filename is optional; when set, the step looks for that file on the
destination filesystem. If the image is already present, a shortfall against
Min Free Space is downgraded from a failure to a warning: staging can
reuse the file already there when its MD5 checksum verifies. A stage that
re-transfers anyway - no checksum to verify, or overwrite turned on -
still needs the space. Target Version is also optional; in install mode it is
matched against committed versions in `show install summary`, and in bundle
mode against the running version, so a device that already runs the target is
reported rather than failed.

Max Parallel Devices controls how many devices are checked concurrently
(1 means one at a time). Config fields accept `{{ ... }}` templates,
resolved before the step runs.

## Output

Later steps can read the step's result under its node id, for example
`{{ steps.NODE_ID.summary }}`. The step's metrics contain
`success_count`, `failure_count`, and `output_context`, a mapping keyed by
device id whose entries hold `current_version`, `free_bytes`, `image_exists`,
`install_mode_supported`, and `target_version_installed` for each device.

One evidence artifact is saved per device, named `Preflight: <device>`
whether its checks passed or failed; a device that could not be checked at
all (no management host, an unexpected error) gets
`Preflight Error: <device>` instead. The artifact contains a human-readable summary plus the raw output of the show commands
that were run. The same command outputs also stream to the step's live logs
while it runs.

## When It Fails

The step fails when no target devices are configured, when no upgrade driver
exists for the configured platform and mode, or when any single device fails
its checks; per-device results are still recorded in evidence. Per-device
failure causes include a missing management host, a device that cannot be
reached, a check command that fails (`show version`, `dir`, and in bundle
mode `show boot`), insufficient free space (unless the image is already
staged), and - in install mode - a device that does not support the install
command. A device that answers `show install summary` with an error does
not support install mode; a session that fails is a command error instead.

All devices must pass for the step to succeed. The step's default timeout is
7200 seconds; because the checks are read-only, rerunning after a failure is
harmless.
