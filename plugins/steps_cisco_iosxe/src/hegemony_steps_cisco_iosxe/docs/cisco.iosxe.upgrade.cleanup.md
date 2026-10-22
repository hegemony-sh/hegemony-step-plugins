<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

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
keeps every image the boot variables name (for the current boot and the
next reload), keeps the newest
old images up to Versions to Keep (default 1, sorted by filename), and
deletes the rest with `delete /force`. When the boot variable names no
image, the device boots the first image it finds, so the step deletes
nothing and fails that device.

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

One evidence artifact is saved per device, named `Cleanup: <device>` -
success or failure; a device that could not be attempted at all (no
management host, an unexpected error) gets `Cleanup Error: <device>`
instead - with the cleanup transcript and the list of removed items. The summary line
reports how many devices were cleaned and how many items were removed.

## When It Fails

The step fails when no target devices are configured, when no upgrade driver
exists for the configured platform and mode, or when any device fails: a
missing management host, a device that cannot be reached, or a command that
fails. In install mode `install remove inactive` must end with
`SUCCESS: install_remove` or say there is nothing to remove; an error, a
`FAILED` line or no answer fails the device. In bundle mode `show boot` and
the `.bin` listing must succeed and the boot variable must name an image.
An image that cannot be deleted fails the device, but the step goes on with
the other images and reports the files it did remove.

All devices must succeed for the step to succeed. The step's default timeout
is 7200 seconds; the `install remove inactive` command itself is given up to
five minutes per device. Cleanup only removes inactive software, so it is
safe to rerun.
