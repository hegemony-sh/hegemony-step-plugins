<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Upgrade Cleanup

`cisco.iosxe.upgrade.cleanup` reclaims flash space on each targeted Cisco
IOS-XE device after an upgrade has been verified, removing software that is
no longer in use. Run it as the last step of the upgrade flow.

## Using It

What gets removed depends on Upgrade Mode. In install mode the step runs
`install remove inactive`, letting the device delete packages that are not
part of the running software; confirmation prompts are answered
automatically. In bundle mode the step lists the `.bin` images on flash,
keeps every image referenced by the boot configuration, keeps the newest
old images up to Versions to Keep (default 1, sorted by filename), and
deletes the rest with `delete /force`.

The "Remove inactive packages/old images" toggle is the master switch: when
it is off, the step does nothing and succeeds immediately with a "skipped"
summary. Versions to Keep applies to bundle mode only. Max Parallel Devices
controls how many devices are cleaned concurrently.

## Output

Later steps can read the step's result under its node id, for example
`{{ steps.NODE_ID.summary }}`. The step's metrics contain
`success_count`, `failure_count`, `total_removed` (items removed across all
devices), and `output_context`, a mapping keyed by device id whose entry
holds `removed_packages`, the list of packages or files removed on that
device.

One evidence artifact is saved per device, named `Cleanup: <device>` (or
`Cleanup Error: <device>` for a device that failed), with
the cleanup transcript and the list of removed items. The summary line
reports how many devices were cleaned and how many items were removed.

## When It Fails

The step fails when no target devices are configured, when no upgrade driver
exists for the configured platform and mode, or when any device fails:
a missing management host, an SSH or command error, or — in install mode —
`install remove inactive` output containing an error or failure marker. In
bundle mode a single image that cannot be deleted is logged and skipped
without failing the device, so the step reports the files it did remove.

All devices must succeed for the step to succeed. The step's default timeout
is 7200 seconds; the `install remove inactive` command itself is given up to
five minutes per device. Cleanup only removes inactive software, so it is
safe to rerun.
