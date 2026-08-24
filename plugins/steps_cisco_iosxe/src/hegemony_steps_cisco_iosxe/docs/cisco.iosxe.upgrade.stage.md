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
pull when the source is an HTTP(S) URL. Only the HTTP(S) pull is implemented:
selecting SCP fails with an explanatory error, so keep auto or an explicit
HTTP(S) method.

The MD5 checksum makes staging idempotent: when one is configured and a
file already exists under the destination name, it is verified on the
device with `verify /md5` and, if it matches, the transfer is skipped -
that is what makes rerunning after a partial failure cheap. A file that
fails the check, or an existing file with no checksum to prove it, is
transferred again (advanced: a step's raw definition may carry an
`expected_size` - with no checksum, a size match also skips the
transfer); turn on the overwrite option to force a fresh transfer
regardless. After every transfer the checksum, when given, is verified the
same way. Only MD5 is checked on the device - IOS-XE's `verify` offers no
SHA-256 - so there is no SHA-256 field. Max Parallel Devices controls how
many devices are staged concurrently.

## Output

Later steps can read the step's result under its node id, for example
`{{ steps.NODE_ID.summary }}`. The step's metrics contain
`success_count`, `failure_count`, and `output_context`, a mapping keyed by
device id whose entries hold `staged`, `skipped`, `full_path`,
`hash_verified`, and `transferred_bytes` for each device.

One evidence artifact is saved per device: `Stage: <device>` - success or
failure - holds the transfer transcript, method, duration, and
verification results, while a device that could not be attempted at all
(no management host, an unexpected error) gets `Stage Error: <device>`
with the error text instead. The summary
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
transfer is capped at one hour. Rerunning after a partial failure is cheap
when an MD5 checksum is configured: devices whose staged image verifies are
skipped. Without a checksum, a rerun transfers the image again unless the
raw definition's `expected_size` matches the staged file.
