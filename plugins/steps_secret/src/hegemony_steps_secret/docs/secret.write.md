<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Write Secret

`secret.write` stores keys in a secret of the run's organization: the
content of files an earlier step left in the run's shared workspace (a
certificate and its private key a container step produced, for example),
values read through secret references, or literal values. It can also swap
the keys of two secrets, or delete one. The step never names a secret
backend: it gives a path under the organization's own secret root, and the
platform decides where that path lives.

## Using It

Secret path names the secret under the organization's secret root, such as
`certs/web`: segments of letters, digits, `_`, `.` and `-` joined by `/`, at
most 256 characters, with no leading `/`, no empty segment and no segment
starting with `.` (so no `..`). A secret reference such as `vault://...` is
refused here, because the platform builds the backend path itself. The path
may use templates with the step's variables, for example
`certs/{{ inputs.site }}`; it is checked again once rendered. So may Keep
previous values at, Swap with and the files in Keys from files.

Operation picks what the step does:

- **Write keys** (the default) stores the keys given in Keys from files and
  Keys from values: at least one key in all, each key name given once. A key
  name starts with a letter or underscore, followed by letters, digits, `_`,
  `.` or `-`, at most 128 characters.
- **Swap two secrets** exchanges the keys of Secret path and Swap with. Both
  secrets must exist; afterwards each holds the keys the other held.
- **Delete the secret** removes the secret at Secret path with all its keys.
  With Succeed when absent on (the default), a secret that does not exist is
  not an error.

### Keys from files

Each line `KEY=file` stores the content of one file from the run's shared
workspace under `KEY`. Write the file as the container step that produced it
saw it, `/shared/out/cert.pem`, or relative to the workspace, `out/cert.pem`
(the only form when that step mounted the workspace somewhere other than
`/shared`). The files are read on the worker, so this step must run with shared (or
explicit) execution affinity, on the same worker as the step that wrote the
files, and that worker must have shared workspaces enabled.

File encoding decides what is stored. **base64** (the default) stores the
base64 encoding of the file's bytes: any file survives intact, and a
multi-line text file such as a PEM certificate keeps its line breaks even in
stores that change them. Whatever reads the key decodes it (`base64 -d`).
**text** stores the file as it is, and requires it to be UTF-8.

A file may be at most 64 KiB and all files of the step together at most
1 MiB; an empty file is refused.

Delete source files is on by default: after the write succeeded, each
source file is overwritten with zeros and deleted from the workspace, so the
plain copy does not outlive the step. The step first moves the file to a
private name and checks it is the file it read, so a file a container writes
at the same path meanwhile is never touched. This is best effort, not a secure wipe:
a copy-on-write file system, a snapshot or a backup can still hold the old
bytes. A file with other hard links is deleted without being overwritten. So
is a file the worker may delete but not write (one a container's root user
wrote, say), after the step checked it is the file it read, and a file whose
overwriting fails. A file that cannot be deleted, or is deleted without being
overwritten for either reason, does not fail the step; the summary and the
evidence say which.

### Keys from values

Each line `KEY=value` is one of:

- a bare secret reference, such as `vault://orgs/acme/secrets/db/password`,
  resolved by the platform;
- a template, such as `{{ secret('vault://orgs/acme/secrets/db/password') }}`,
  rendered by the platform;
- anything else: a literal, stored exactly as written.

Keys from values reaches the step as written, and each value is resolved on
its own: a template here is rendered without the step's variables, so it can
read a secret but not a run input or another step's output. A value is
resolved only once, so a secret whose value looks like a template or a
reference is stored as is. The path fields are different: the platform
renders them with the step's variables before the step runs.

Text shaped like `scheme://...` is always read as a reference, so a URL
cannot be stored as a literal: store it in a secret backend and reference it.
A literal is not redacted where it is written: it is part of the flow
definition, readable by anyone who can read the flow. Use literals only for
values that are not sensitive (a user name, a format marker) and references
for everything else.

### Replacing, merging and keeping the previous keys

With Keep other keys off (the default), the secret holds exactly the keys
written by this step afterwards; keys it held before and this step does not
write are removed. With it on, those keys are kept.

Keep previous values at names a second secret path. Before writing, the
step copies the current keys of Secret path there, replacing what that path
held, so a later step can swap them back. Nothing is copied when no secret
exists at Secret path yet; the summary says so. It must differ from Secret
path.

A step run again after a failure keeps the copy it made before: when Secret
path already holds exactly what the step writes (every key written has the
same value and, with Keep other keys off, no other key is there) and a secret
exists at Keep previous values at, the step does not copy again, since that
would replace the previous keys with the new ones. The summary then says the
previous keys were kept by an earlier attempt, and `previous_path` names
where they are.

## Output

Later steps read the step's output as `steps.NODE_ID.output.KEY`:

- `operation`: `write`, `swap` or `delete`.
- `path`: the secret path the step wrote, swapped or deleted.
- `reference`: the reference a later step reads a key through, without the
  key: append `/` and the key name. With `vault://orgs/acme/secrets/certs/web`
  here, the key `cert` is `vault://orgs/acme/secrets/certs/web/cert`, usable
  as a bare reference or in `{{ secret('...') }}`. Null for a delete.
- `keys`: the names of every key the secret holds after the step, sorted;
  with Keep other keys on, the kept keys too.
- `created`: true when no secret existed at the path before the write.
- `previous_path`: where the previous keys were copied, or null.
- `swapped_with`: the other secret of a swap, or null.
- `deleted`: true when a delete removed a secret.

Every key is present when the step fails too. Then `reference` is null,
`keys` is empty and the flags are false, while `operation` and `path` name
what was asked, even when the config was refused for another reason; each is
null only when the config gives no usable value for it (an unknown
operation, a missing or empty path). `previous_path` names where the
previous keys were copied if that happened before the failure.

Metrics record `keys`, the number of keys written (for a swap, the keys now
at Secret path), and for files `source_files` and `source_files_deleted`.
One `step_result` evidence record, named `secret_OPERATION_STEPID`, holds the
same fields plus which keys came from files and which from values, the file
encoding, the source files, those that could not be deleted and those
deleted without being overwritten. After a swap that the platform reported
as failed but both secrets show finished, it also holds that error.

The step never outputs a secret value or a file's content: not in its
output, evidence, summary or error.

## Security

The platform decides what a step may write, not the step:

- An administrator must enable secret writes by steps for the organization,
  and sets the path prefixes steps may write. A path outside them is
  refused, and so is every path of another organization and of the
  platform's shared organization. Keep previous values at and Swap with are
  held to the same rules, and the step reads back only paths it may write.
- The organization's secret backend must be writable: one marked read-only
  refuses writes and deletes.
- The worker must provide and support the secret store services; on an
  older worker, or one that does not support them, the step fails as
  "Secret writes unavailable" without changing anything.
- Every value the step writes or reads is registered for redaction before
  anything about it is shown, and every write, read and delete is audited
  with the run and the step, naming paths and keys, never values.

Source files are read without following symbolic links anywhere on their
path; a link, a path that leads out of the workspace, and anything but a
regular file are refused. A container that wrote the workspace cannot make
the step read the worker's own files.

A swap is two writes, not one atomic change, and a write the platform
reports as failed may have been stored all the same (the store committed and
then timed out, say). So when a write fails, the step reads both secrets
back and goes by what they hold:

- both hold the swapped keys: the swap is done, and the step succeeds; the
  summary says the platform reported an error;
- both hold their original keys: nothing changed, and the step fails;
- one secret was written and the other not: the step writes the original
  keys it read before the swap back to the written one and fails, saying so,
  with both holding what they held before;
- anything else, a restore that fails too, or secrets that cannot be read
  back: the step fails, and the error says which secret holds (or may hold)
  which keys, and whose original keys are stored at neither path, to be put
  right by hand.

A step stopped during the swap (cancelled, or past its time limit) settles
the same way before it stops, and finishes settling even if it is stopped
again meanwhile.

Something else writing either secret during the swap can be overwritten, as
it can during Keep other keys, which the platform carries out as a read
followed by a write.

## When It Fails

The step fails, without writing anything, when:

- the config is invalid: a malformed path or key name, a key given in both
  Keys from files and Keys from values, a write without keys, Keep previous
  values at or Swap with equal to Secret path, or a swap without Swap with;
- the platform does not provide secret writes to steps (its worker predates
  them);
- a source file cannot be used: the step has no shared workspace (no shared
  or explicit affinity, or a worker with shared workspaces disabled), or the
  file is missing, a symbolic link, not a regular file, empty, too large,
  or not UTF-8 with text encoding;
- a reference in Keys from values resolves to nothing;
- a swap finds no secret at one of its two paths.

It fails with the platform's own message when the platform refuses the
operation (secret writes not enabled for the organization, a path outside
the allowed prefixes, a read-only backend), rejects a path, or cannot reach
the secret store. All files and values are read and resolved before the
first write, so a failure there changes nothing. When copying the previous
keys succeeded and the write itself then fails, the error says the previous
keys were already copied. A write or delete the platform reports as failed
may have been carried out all the same; running the step again is safe, and
keeps the previous keys copied the first time (see Keep previous values at).
A delete fails when no secret exists and Succeed when absent is off. How a
failed swap ends is described under Security.
