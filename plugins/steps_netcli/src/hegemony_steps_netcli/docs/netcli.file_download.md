<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Download File to Device

`netcli.file_download` has each target download one file from a file
repository by itself, over HTTP or HTTPS: a software image onto a network
device, an archive onto a server. The file does not pass through the worker.

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
file keeps the name it has in the repository. Targets are chosen with the
role-based target picker.

For each target, the step asks the platform for a download link, connects to
the target and has it fetch the link:

- With the netmiko transport (network devices), it runs
  `copy <link> <destination><filename>` and answers the questions the device
  asks before it starts (the destination file name, a confirmation to
  overwrite).
- With the asyncssh transport (servers), it runs `curl` on the server, which
  must have it installed.
- The scrapli transport cannot do this; the step fails such a device and says
  to use the netmiko transport.

The link looks like `<platform address>/dl/<token>/<filename>`. It has no
query string and is not a redirect, because the HTTP clients of network
devices often handle neither. The token in it opens that one file and nothing
else. Each target gets a link of its own, issued right before its download and
ended right after it; an unused link expires after ten minutes. The platform
records each issued link in the audit log, with the run, the step and the file.

Targets must be able to reach the platform at the address an administrator set
as `HEGEMONY_API_EXTERNAL_URL`. They do not need to reach the object store.
With an `https://` address the target must trust the platform's certificate; a
device that cannot needs an `http://` address on a trusted management network.

**Transfer timeout** (one hour by default, at most 24 hours) limits one
target's download. The step's own timeout (two hours unless set) still covers
the whole step, so it must leave time for every target. **Max Parallel
Devices** controls the fan-out: 1 (the default) handles targets one after
another, higher values up to that many at once (capped at 32).

The step transfers the file and reports what the target said. It does not
check free space first and does not verify the file afterwards: follow it
with a `netcli.execute` step for that (on Cisco IOS XE,
`verify /md5 flash:<filename> <md5>`, with the checksum from this step's
output).

## SSH Compatibility

Allow legacy SSH algorithms defaults to off. Enable `allow_legacy_ssh` only
for older devices which require weak algorithms or small host keys; it applies
to the device and jump host for this step. Host-key verification still applies,
and a failed secure connection never retries weakly. Prefer upgrading the
device; use legacy mode only on a trusted network.

## Output

Later steps can read:

- `steps.NODE_ID.filename` and `steps.NODE_ID.file_id`: the stored file.
- `steps.NODE_ID.dest_fs` and `steps.NODE_ID.dest_filename`: where it went.
- `steps.NODE_ID.size_bytes`, `steps.NODE_ID.sha256` and `steps.NODE_ID.md5`:
  the stored file's size and checksums, for a verification step. `md5` is
  empty for a file stored without one.
- `steps.NODE_ID.transferred_count`: how many targets completed the download.

Each target contributes a "File download" evidence artifact with what it
printed during the transfer, the file's details and the time taken; the
download link is replaced by a placeholder there. A target that fails
contributes an "Error" artifact instead. Metrics record `device_count`,
`transferred_count` and `size_bytes`.

## When It Fails

The step fails immediately when no target devices are configured, when no
file or more than one is selected, and on a platform too old to issue
download links. Per target, it fails when the device has no management host,
when the file is not one the run's organization may read, when the platform
has no `HEGEMONY_API_EXTERNAL_URL`, when the connection fails, when the
target's transport cannot do the transfer, and when the target does not
report a completed download (it could not reach the platform, the destination
is full or does not exist, the transfer timed out). One failing target does
not stop the others, but all must succeed for the step to succeed.
