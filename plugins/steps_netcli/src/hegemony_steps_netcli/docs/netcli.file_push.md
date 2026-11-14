<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Push File to Device

`netcli.file_push` copies one file from a file repository to each target over
the SSH connection the other steps use: SCP on a network device, SFTP on a
server. The worker fetches the file once and sends it to every target.

Use it when the targets cannot reach the platform, so they cannot download
the file by themselves. When they can, `netcli.file_download` (Download File
to Device) is the lighter choice: the file then does not pass through the
worker.

## Using It

Pick the file with **File Repository File**; the step takes exactly one.
The field stores the file's id, and it also accepts a `{{ variable }}`
template that gives one, so a run input can choose the file. A file the
field names directly cannot be deleted from the repository while the flow
uses it. The file must be in a repository of the run's organization, or in
one the shared organization publishes.

**Destination** is where the file goes on the target: a device filesystem
with its colon (`flash:`, the default, or `bootflash:`), or a directory on a
server (`/var/tmp`). **Destination Filename** names it there; left empty, the
file keeps the name it has in the repository. It is a file name only, with no
slash: a directory belongs in Destination. Neither field may contain a line
break or another control character, or a question mark, because a network
device's command line reads both. Targets are chosen with the role-based
target picker.

The step works in two parts:

1. It asks the platform for a download link, fetches the file onto the worker
   through it, and checks the size and the SHA-256 checksum against the stored
   file's. The link is ended as soon as the file is there. The platform
   records the issued link in the audit log, with the run, the step and the
   file.
2. It connects to each target and copies the file:
   - With the netmiko transport (network devices), over SCP. The device must
     have its SCP server on (on Cisco IOS and IOS XE, `ip scp server enable`).
     Before the copy the step checks that the device has room for the file;
     after it, it compares the MD5 checksum the device computes with the
     file's.
   - With the asyncssh transport (servers), over SFTP. After the copy the
     step compares the size of the file on the server with the file's.
   - The scrapli transport cannot do this; the step fails such a device and
     says to use the netmiko transport.

**Overwrite** decides what happens when the target already has a file of that
name. Off (the default): a network device that holds the very same file (same
MD5 checksum) counts as done and nothing is copied; any other existing file
fails that target. On: the file is replaced.

The worker needs free space for the file under its directory for temporary
files, plus a small margin; the step checks this before it fetches anything
and fails when there is too little. The worker's copy is removed when the
step ends, whether it succeeded or not.

**Max Parallel Devices** controls the fan-out: 1 (the default) handles
targets one after another, higher values up to that many at once (capped at
32). The step's timeout (two hours unless set) covers the fetch and every
copy, so it must leave time for every target.

## SSH Compatibility

Allow legacy SSH algorithms defaults to off. Enable `allow_legacy_ssh` only
for older devices which require weak algorithms or small host keys; it applies
to the device and jump host for this step. Host-key verification still applies,
and a failed secure connection never retries weakly. Prefer upgrading the
device; use legacy mode only on a trusted network.

## Output

Later steps can read:

- `steps.NODE_ID.output.filename` and `steps.NODE_ID.output.file_id`: the stored file.
- `steps.NODE_ID.output.dest_fs` and `steps.NODE_ID.output.dest_filename`: where it went.
- `steps.NODE_ID.output.size_bytes`, `steps.NODE_ID.output.sha256` and `steps.NODE_ID.output.md5`:
  the stored file's size and checksums. `md5` is null for a file stored
  without one, so check it before a step uses it.
- `steps.NODE_ID.output.transferred_count`: how many targets the file was copied to.
- `steps.NODE_ID.output.already_present_count`: how many targets already held the same file.

Each target contributes a "File push" evidence artifact with the file's
details, whether it was copied or already there, and the time taken. A target
that fails contributes an "Error" artifact instead. Metrics record
`device_count`, `transferred_count`, `already_present_count` and `size_bytes`.

## When It Fails

The step fails immediately, before it contacts any target, when no target
devices are configured, when no file or more than one is selected, when
Destination or Destination Filename contains a line break, another control
character or a question mark, when Destination Filename has a directory part,
when the stored file's name has one of these and no Destination Filename is
set, on a platform that cannot issue download links, when the file is not one
the run's organization may read, when the worker has too little free space,
and when the worker cannot fetch the file or the file it received does not
match the stored file's size or SHA-256 checksum.

Per target, it fails when the device has no management host, when the
connection fails, when the target's transport cannot copy files, when the
target has no room for the file or its SCP server is off, when a different
file of that name is already there and Overwrite is off, and when the copy on
the target does not match the file. One failing target does not stop the
others, but all must succeed for the step to succeed.
