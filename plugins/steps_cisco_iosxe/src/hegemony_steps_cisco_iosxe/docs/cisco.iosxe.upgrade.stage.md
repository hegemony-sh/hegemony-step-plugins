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
filename; with a manual Source URL, Destination Filename is required. The
step asks for a fresh URL for each device right before staging it, so a
device staged late in a long step does not get an expired one.
Configuring both sources at once fails the step before touching any device.

Transfer Method defaults to auto, which prefers a device-side HTTPS or HTTP
pull when the source is an HTTP(S) URL - the only transfer implemented, so
the source must be an `http://` or `https://` URL. Prefer an HTTPS source or
set the MD5 checksum for plain-http sources; an unverified http transfer has
no integrity check. Legacy stored values such as `scp` or `tftp`, and a step
definition still carrying the removed `expected_sha256` field, fail with an
explanatory error.

The MD5 checksum makes staging idempotent: when one is configured and a
file already exists under the destination name, it is verified on the
device with `verify /md5` and, if it matches, the transfer is skipped -
that is what makes rerunning after a partial failure cheap. A file that
fails the check, or an existing file with no checksum to prove it, is
transferred again. With no checksum, the advanced Expected Size setting
stands in: an existing file of that size is reused, a weaker guarantee than
a checksum, and a transferred file of another size fails the device. Turn on
the overwrite option to force a fresh transfer regardless. After every
transfer the checksum, when given, is verified the same way. Only MD5 is
checked on the device - IOS-XE's `verify` offers no SHA-256 - so there is no
SHA-256 field.

The checksum is 32 hexadecimal digits; it can come from a run input as a
`{{ }}` template, and the step checks the value once it is filled in. The
check passes only when the device prints its `Verified (<file>) = <hash>`
line for the staged file with that same hash (`flash:` and `bootflash:`
count as one filesystem). An error, a mismatch report or any other output
fails the check. Max Parallel Devices controls how many devices are staged
concurrently.

## Output

Later steps can read the step's result under its node id, for example
`{{ steps.NODE_ID.summary }}`. The step's metrics contain
`success_count`, `failure_count`, and `output_context`, a mapping keyed by
device id whose entries hold `staged`, `skipped`, `full_path`,
`hash_verified`, and `transferred_bytes` for each device.

One evidence artifact is saved per device: `Stage: <device>` - success or
failure - holds the transfer transcript, method, duration, and
verification results, including the MD5 hash the device computed (also in
its `computed_hash` field), while a device that could not be attempted at all
(no management host, an unexpected error) gets `Stage Error: <device>`
with the error text instead. The summary
line reports how many devices were staged and how many already had the file.

## When It Fails

The step fails immediately when both or neither image source is configured,
when a setting is invalid (such as a legacy `scp` or `tftp` transfer
method), when the MD5 checksum is not 32 hexadecimal digits, when the
selected repository file cannot be resolved to a device-reachable URL, or
when no upgrade driver exists for the configured platform and mode.
Per-device failures include a missing management host, a download URL that
cannot be issued for the device, a `dir` of the destination that fails, a
failed HTTP transfer, an image missing from `dir` after the transfer, a
checksum the device does not confirm, a non-HTTP(S) source URL, and SSH
errors. Any single device failing fails the whole step, though per-device
evidence is still recorded.

The step's default timeout is 7200 seconds, and each device-side HTTP
transfer is capped at one hour. Rerunning after a partial failure is cheap
when an MD5 checksum is configured: devices whose staged image verifies are
skipped. Without a checksum, a rerun transfers the image again unless
Expected Size matches the staged file.
