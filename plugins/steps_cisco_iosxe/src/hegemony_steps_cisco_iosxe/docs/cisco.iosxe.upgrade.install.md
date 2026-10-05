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
must match how the device boots. In install mode the step runs
`install add file` with the activate and commit keywords according to the
Activate and Commit options, answering the confirmation prompts
automatically. In bundle mode it rewrites the boot system to the new image,
keeps the previously configured image as a fallback boot entry, saves the
configuration, and issues a reload.

An install-mode activation boots packages.conf, so with Activate on the step
first reads `show boot`. The first boot entry must be packages.conf on the
destination filesystem, for example `flash:packages.conf` (`flash:` and
`bootflash:` count as the same). If it is not, the device fails and nothing
is changed. Turn on Fix Boot Setting to let the step correct it: it sends
`no boot system` and `boot system` with the destination filesystem in one
configuration session, saves with `write memory`, and reads `show boot`
again before installing. Saving also stores any other unsaved change in the
running configuration. When `show boot` fails or shows no boot variable, the
device fails; the step never changes the boot setting on a guess.

Uncheck Activate to prepare the upgrade without reloading: install mode runs
`install add file` only, without activate or commit, and bundle mode stops
after saving the boot configuration, leaving the reload pending. Commit
applies to install mode only and prevents the automatic rollback timer from
reverting the upgrade. When the install completes without changing anything
because the device already runs the image (for example
`Same Image File-No Change`), the device succeeds with a note and no reboot.
If the install also reports a failure, the device fails. Max Parallel
Devices controls how many devices are upgraded concurrently; keep it at 1 to
reload devices one at a time.

## Output

Later steps can read the step's result under its node id, for example
`{{ steps.NODE_ID.summary }}`. The step's metrics contain
`success_count`, `failure_count`, and `output_context`, a mapping keyed by
device id whose entries hold `reboot_triggered`, `activated`, `committed`,
`boot_config_changed` (the step set and saved the boot variable) and
`previous_boot` (the boot entries it found) for each device.

One evidence artifact is saved per device, named `Install: <device>` -
success or failure; a device that could not be attempted at all (no
management host, an unexpected error) gets `Install Error: <device>`
instead - with the full install-session transcript and status flags. The
transcript includes `show boot` before and after, and the configuration
session when the step changed the boot setting. The summary line reports
how many devices started installing and how many are rebooting.

## When It Fails

The step fails when Image Filename is missing, when no upgrade driver exists
for the configured platform and mode, or when any device fails. A device
fails when it has no management host, cannot be reached or refuses the
login, when its boot variable is wrong and Fix Boot Setting is off, when a
boot setting change or its save fails, or when the install output shows an
error: `% Invalid input`, `%Error`, `% Incomplete command`,
`% Ambiguous command`, `FAILED: install_...` or `Cannot activate`. In
install mode the install must
also report completion: a `SUCCESS: install_...` line, the install's
completion message, or the device starting to reload. Without one within
30 minutes the device fails. In bundle mode a device also fails when the
boot system does not show the new image after configuration.

The SSH session ends when the device reloads. A session that closes counts
as the reload only when the output already shows that activation finished or
the reload started; a session that closes earlier fails the device. This
step does not wait for devices to come back; use
`cisco.iosxe.upgrade.verify` for that. The step's default timeout is 7200
seconds.
