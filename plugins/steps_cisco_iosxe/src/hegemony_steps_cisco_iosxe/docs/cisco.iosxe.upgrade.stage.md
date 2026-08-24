<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Upgrade Stage

`cisco.iosxe.upgrade.stage` copies the upgrade image onto each targeted
Cisco IOS-XE device and verifies its integrity, so the disruptive install
step can run later without waiting on a long transfer.

## Using It

Pick exactly one image source. Either select a file from the platform's file
repository (File Repository File), or enter a Source URL directly. When a
repository file is selected, the platform issues a short-lived download URL
that devices can reach, and Destination Filename defaults to the stored
filename; with a manual Source URL, Destination Filename is required.
Configuring both sources at once fails the step before touching any device.

Transfer Method defaults to auto, which prefers a device-side HTTPS or HTTP
pull when the source is an HTTP(S) URL. Selecting SCP is not yet supported by
this step and fails with an explanatory error, so keep auto or an explicit
HTTP(S) method.

The transfer runs on every execution: a file already on the destination
filesystem under the same name is replaced (the overwrite toggle exists for
a future skip-if-verified path, but no documented field supplies the
expected size that path needs, so today it does not change behavior). After
a transfer, the MD5 checksum, when given, is verified on the device with
`verify /md5`; note that only MD5 is checked on the device. Max Parallel
Devices controls how many devices are staged concurrently.

## Output

Later steps can read the step's result under its node id, for example
`{{ steps.NODE_ID.summary }}`. The step's metrics contain
`success_count`, `failure_count`, and `output_context`, a mapping keyed by
device id whose entries hold `staged`, `skipped`, `full_path`,
`hash_verified`, and `transferred_bytes` for each device.

One evidence artifact is saved per device, named `Stage: <device>` (or
`Stage Error: <device>` for a device that failed), with the
transfer transcript, method, duration, and verification results. The summary
line reports how many devices were staged and how many already had the file.

## When It Fails

The step fails immediately when both or neither image source is configured,
when the selected repository file cannot be resolved to a device-reachable
URL, or when no upgrade driver exists for the configured platform and mode.
Per-device failures include a missing management host, a failed HTTP
transfer, a failed MD5 verification, an explicit SCP transfer method, and
SSH errors. Any single
device failing fails the whole step, though per-device evidence is still
recorded.

The step's default timeout is 7200 seconds, and each device-side HTTP
transfer is capped at one hour. Rerunning after a partial failure is safe -
already-staged devices simply transfer the image again.
