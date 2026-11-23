<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NETCONF Edit Config

`netconf.edit_config` changes each target device's configuration over
NETCONF as one transaction. On a device with a candidate datastore it shows
the change as a diff before anything is committed, can stop there (dry
run), and commits with a confirmed commit, so a change that cuts the device
off is rolled back by the device itself.

## Using It

Configuration is the XML that goes inside `<config>`: one or more top nodes,
each with its namespace. Templates such as `{{ inputs.hostname }}` are filled
in before the step runs.

```xml
<native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
  <hostname>{{ inputs.hostname }}</hostname>
</native>
```

Default Operation is merge (add and change), replace (every node in
Configuration ends up exactly as written: with a model's whole tree it
replaces that model's configuration), or none (only nodes with their own
`operation` attribute change).

Datastore (advanced) is auto by default: the candidate when the device has
one, else running. On the candidate the step:

1. locks running and candidate and discards what an earlier session left in
   the candidate;
2. reads running, applies Configuration to the candidate, reads the
   candidate, and diffs the two. No difference ends the step: nothing is
   committed;
3. validates the candidate when the device has `:validate` (Validate,
   advanced, on by default);
4. with Dry run on, discards the candidate and stops: the diff shows what
   the change would do;
5. commits as Commit says, then saves running to startup when Save to
   startup is on, and unlocks.

Commit:

- **Confirm in this step** (the default): a confirmed commit; the step then
  opens a second NETCONF session to the device. When it opens in time, the
  step confirms the commit. When it does not, or not before Confirm Timeout
  less a short margin (10 s, or a quarter of the timeout), the step cancels
  the commit (or ends its session, which rolls it back on devices without
  `:confirmed-commit:1.1`), never confirms it late, and fails. Needs
  `:confirmed-commit`.
- **Confirm in a later step**: a confirmed commit left pending under a
  persist id, for a `netconf.commit` step to confirm (after checks or an
  approval) or `netconf.cancel_commit` to roll back. The device restores the
  previous configuration on its own after Confirm Timeout (sec) (default
  600). Needs `:confirmed-commit:1.1`. The persist id comes from the run,
  the step run and the device, so it is the same when the platform runs the
  step again (a worker restart). A step run again finds the change already
  in running, so its diff is empty: it then sends a follow-up confirmed
  commit under the same persist id. When that succeeds, the device is
  reported as pending again and its confirm timeout restarts; when the
  device refuses it, nothing is pending.
- **Commit directly**: a plain commit.

On running (a device without a candidate, or Datastore running) the change
applies at once with `rollback-on-error` when the device offers it: no dry
run, no confirmed commit, and the diff shows running before and after.

Diff Filter (advanced) is a subtree filter limiting what is read for the
diff, for devices with a large configuration. With a filter, an empty diff
does not show that nothing changed outside it, so the step validates and
commits the change all the same, counts it as changed, and says so in
`notes`. Save to startup uses
copy-config when the device has a startup datastore, else Cisco's
`save-config` RPC (IOS XE). With Commit "confirm in a later step" the save
waits for the confirmation: the output sets `save_requested`, and the
`netconf.commit` step saves after confirming. Max Parallel Devices defaults to 1, so devices
change one after another. Port, timeouts and Allow legacy SSH work as in
`netconf.get`.

## Output

The summary counts the devices changed, committed and pending. Each device
that changed adds `cli_output` evidence: `<device>:netconf diff`,
`<device>:netconf before` and `<device>:netconf candidate` (or `running`).

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `datastore`, `changed`, `committed`, `pending` (a confirmed
  commit waits for `netconf.commit`), `persist_id`, `validated`, `saved`
  (`copy-config` or `save-config` when saved), `save_error`,
  `save_requested` (saved by `netconf.commit`), `diff` and `notes`. When saving fails after the commit, the device fails with
  `committed` true and `save_error` set: the change stands, unsaved.
- `steps.NODE_ID.output.truncated`: diffs cut short in the output (16 KiB a
  device, 64 KiB the step); the evidence keeps them whole.

## When It Fails

The step fails without connecting when Configuration is empty or not
well-formed XML, when a dry run asks for running, and when the platform
cannot open NETCONF sessions. A device fails when it cannot be reached,
when a datastore is locked by another session (`lock-denied`), when it
refuses the edit, the validation or the commit (the step error quotes its
`rpc-error`), when it lacks what Commit or Datastore needs, and when the
second session after a confirmed commit does not open. Every failure before
the commit discards the candidate, so nothing half-applied is left behind.
On running without `:rollback-on-error`, a failed edit may have applied in
part, and the step error says so.

When the device does not answer the final commit in time, the step fails
and says the device may already have committed the change: check the
device before running the step again. After any request times out the
session is not used again.
