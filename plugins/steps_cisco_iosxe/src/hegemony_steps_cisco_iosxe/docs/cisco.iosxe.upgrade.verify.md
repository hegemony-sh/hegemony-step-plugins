<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Upgrade Verify

`cisco.iosxe.upgrade.verify` waits for each targeted Cisco IOS-XE device to
come back after the install step's reload, then confirms the upgrade took
effect. Place it after `cisco.iosxe.upgrade.install` in the flow; unless its
Reload Wait is 0, the install step finishes only once each reloading device
has gone down, so this step does not reach a device still on its old image.

## Using It

For each device the step repeatedly reconnects and runs `show clock` until
the device answers, retrying every Retry Interval seconds for up to Max Wait
seconds (defaults: every 30 seconds, up to 600 seconds). Once the device is
reachable, verification runs.

Target Version, when set, must be the running version from `show version`
— for example `17.09.04a`. Leave it empty to skip the version comparison.
Pre-upgrade Version, when set, is the version the devices ran before the
upgrade (for example from the preflight step's output); a device still
running it fails. Versions are compared as releases: the major, minor and
rebuild numbers and the letter suffix must all be equal, so `17.9.4a` is
`17.09.04a`, but `17.09.04` is not `17.09.04a`.

Upgrade Mode selects what else is checked: in install mode the step reads
`show install summary` and requires the new software to be committed; with
Auto-commit on (the default) it runs `install commit` itself when the
software is activated but uncommitted, then re-checks. In bundle mode there
is no commit concept — the step records the boot configuration and checks
the version only.

Max Parallel Devices controls how many devices are verified concurrently.

## Output

Later steps can read the step's result under its node id, for example
`{{ steps.NODE_ID.summary }}`. The step's metrics contain
`success_count`, `failure_count`, and `output_context`, a mapping keyed by
device id whose entries hold `current_version`, `version_match`,
`version_changed`, and `committed` for each device.

One evidence artifact is saved per device, named `Verify: <device>`
whether verification passed or failed; a device that never came back gets
`Verify Timeout: <device>`, and one that could not be checked at all (no
management host, an unexpected error) gets `Verify Error: <device>`. The
artifact carries
the verification transcript plus the number of reconnect attempts and how
long the device took to come back. Command outputs also stream to the step's
live logs.

## When It Fails

A device that does not come back within Max Wait seconds fails with a
timeout; the evidence records the last connection error. A reachable device
fails verification when its running version is not the configured Target
Version, when it still runs the Pre-upgrade Version (the version did not
change), or — in install mode — when the software is not committed even
after the auto-commit attempt. A verification command that
fails, including `install commit`, also fails that device.

All devices must verify for the step to succeed; per-device evidence is
recorded either way. The step's overall default timeout is 7200 seconds, so
with many devices verified sequentially, keep Max Wait and device count
within that budget: Max Wait applies to each device in turn. Steps saved
with Retry Interval's old name, `retry_interval`, keep working.
