<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Upgrade Install

`cisco.iosxe.upgrade.install` activates a previously staged image on each
targeted Cisco IOS-XE device. This is the disruptive part of the upgrade
flow: with default settings the device reloads, so run it inside a
maintenance window and follow it with the verify step once devices are back.

## Using It

Image Filename names the staged image on the destination filesystem; the two
are combined into the full path used by the install commands. Upgrade Mode
must match how the device boots. In install mode the step first makes sure
the boot system points at packages.conf (reconfiguring and saving if it does
not), then runs `install add file` with the activate and commit keywords
according to the Activate and Commit options, answering the confirmation
prompts automatically. In bundle mode it rewrites the boot system to the new
image, keeps the previously configured image as a fallback boot entry, saves
the configuration, and issues a reload.

Uncheck Activate to prepare the upgrade without reloading: install mode omits
the activate step, and bundle mode stops after saving the boot configuration,
leaving the reload pending. Commit applies to install mode only and prevents
the automatic rollback timer from reverting the upgrade. A device that is
already running the target image is reported as success with a note and no
reboot. Max Parallel Devices controls how many devices are upgraded
concurrently; keep it at 1 to reload devices one at a time.

## Output

Later steps can read the step's result under its node id, for example
`{{ steps.NODE_ID.summary }}`. The step's metrics contain
`success_count`, `failure_count`, and `output_context`, a mapping keyed by
device id whose entries hold `reboot_triggered`, `activated`, and
`committed` for each device.

One evidence artifact is saved per device, named `Install: <device>` -
success or failure; a device that could not be attempted at all (no
management host, an unexpected error) gets `Install Error: <device>`
instead - with the full install-session transcript and status flags. The summary line
reports how many devices started installing and how many are rebooting.

## When It Fails

The step fails when Image Filename is missing, when no upgrade driver exists
for the configured platform and mode, or when any device fails: a missing
management host, an install command that reports failure (for example
`FAILED: install_...` or `Cannot activate`), or — in bundle mode — a boot
system that does not show the new image after configuration.

Losing the SSH connection during activation is expected and is treated as
success with `reboot_triggered` set: the device is assumed to be reloading.
This step does not wait for devices to come back; use
`cisco.iosxe.upgrade.verify` for that. The step's default timeout is 7200
seconds, and the install command itself is given up to 30 minutes per device
to report completion.
