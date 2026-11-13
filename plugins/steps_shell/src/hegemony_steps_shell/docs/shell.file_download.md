<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Download File to Host

`shell.file_download` has each target Linux/Unix host download one file from
a file repository by itself, with `curl`, over HTTP or HTTPS: a release
archive, a package, a configuration bundle. The file does not pass through
the worker. For a network device, use `netcli.file_download` (Download File
to Device) instead.

## Using It

Pick the file with **File Repository File**; the step takes exactly one. The
field stores the file's id, and it also accepts a `{{ variable }}` template
that gives one, so a run input can choose the file. A file the field names
directly cannot be deleted from the repository while the flow uses it. The
file must be in a repository of the run's organization, or in one the shared
organization publishes.

**Destination Directory** is the directory the file goes into, as an absolute
path (`/var/tmp` by default). It must exist, and the account the step logs in
with must be able to write to it; the step does not create it and does not use
`sudo`. **Destination Filename** names the file there; left empty, the file
keeps the name it has in the repository. It is a file name only, with no
slash. Neither field may contain a line break or another control character.
Targets are chosen with the role-based target picker.

For each host, the step connects over the device's remote-shell transport
(SSH, resolved from the device's access configuration, as `shell.execute`
does), asks the platform for a download link, and runs on the host:

1. `test -d <destination>`: a directory of that name is refused, before
   anything is downloaded.
2. `curl -fsS --max-time <timeout> -o <destination>.<random>.part <link>`
3. `sha256sum < <destination>.<random>.part`, when **Verify checksum** is on
   (the default): the result must equal the stored file's SHA-256.
4. `mv -f <destination>.<random>.part <destination>`

So the file appears under its name only once it is complete and, with the
check on, verified. A download that fails or does not match leaves nothing
behind: the `.part` file is removed, as far as the host still answers. Every
transfer has a `.part` file of its own, so two runs staging the same file on
one host do not disturb each other; the one that finishes last provides the
file. An existing file of that name is replaced. The host needs `curl`, and
`sha256sum` for the check; turn **Verify checksum** off on a host without it.

The link looks like `<platform address>/dl/<token>/<filename>`. The token in
it opens that one file and nothing else. Each host gets a link of its own,
issued right before its download and ended right after it; an unused link
expires after ten minutes. While `curl` runs, the link is visible in the
host's process list to other accounts on that host. The platform records each
issued link in the audit log, with the run, the step and the file.

Hosts must be able to reach the platform at the address an administrator set
as `HEGEMONY_API_EXTERNAL_URL`. They do not need to reach the object store.
With an `https://` address the host must trust the platform's certificate.

**Transfer timeout** (one hour by default, at most 24 hours) limits one
host's download. The step's own timeout (two hours unless set) still covers
the whole step, so it must leave time for every host. **Max Parallel
Devices** controls the fan-out: 1 (the default) handles hosts one after
another, higher values up to that many at once (capped at 32).

## SSH Compatibility

Allow legacy SSH algorithms defaults to off. Enable `allow_legacy_ssh` only
for older hosts which require weak algorithms or small host keys; it applies
to the host and jump host for this step. Host-key verification still applies,
and a failed secure connection never retries weakly. Prefer upgrading the
host; use legacy mode only on a trusted network. The setting needs a Hegemony
version that supports it for shell steps; an older one refuses the step rather
than connecting securely in its place.

## Output

Later steps can read:

- `steps.NODE_ID.output.filename` and `steps.NODE_ID.output.file_id`: the
  stored file.
- `steps.NODE_ID.output.dest_dir`, `steps.NODE_ID.output.dest_filename` and
  `steps.NODE_ID.output.dest_path`: where it went (`dest_path` is the two
  joined).
- `steps.NODE_ID.output.size_bytes`, `steps.NODE_ID.output.sha256` and
  `steps.NODE_ID.output.md5`: the stored file's size and checksums. `md5` is
  null for a file stored without one.
- `steps.NODE_ID.output.verified`: whether every host's copy passed the
  checksum check.
- `steps.NODE_ID.output.transferred_count`: how many hosts completed the
  download.

Each host contributes a "File download" evidence artifact with the file's
details and where it went. A host that fails contributes an "Error" artifact
instead; the download link never appears in either. Metrics record
`device_count`, `transferred_count` and `size_bytes`.

## When It Fails

The step fails immediately when no target devices are configured, when no
file or more than one is selected, when Destination Directory is not an
absolute path, when Destination Directory or Destination Filename contains a
line break or another control character, when Destination Filename has a
directory part, and on a platform that cannot issue download links. Per host,
it fails when the device has no management host, when the connection fails,
when the file is not one the run's organization may read, when the stored
file's name contains a control character or a directory part and no
Destination Filename is set, when the platform has no
`HEGEMONY_API_EXTERNAL_URL`, when `curl` fails (it is not installed, the host
cannot reach the platform, the directory does not exist or is not writable,
the disk is full, the transfer timed out), when the destination is a
directory, when the checksum cannot be
computed or does not match, and when the file cannot be moved into place. One
failing host does not stop the others, but all must succeed for the step to
succeed.
