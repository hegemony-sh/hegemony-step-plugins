<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# gNMI Set

`gnmi.set` changes configuration on each target device over gNMI (gRPC
Network Management Interface) as one transaction: it deletes, replaces and
updates paths, and the device applies all of them or none. The step reads
the changed paths before and after, so the change shows in the output and
can be compared; a dry run reads them and changes nothing.

## Using It

Connection, Login, TLS, network and timeouts work as in
`gnmi.get`: the device's SSH login by default, TLS verified
against the system authorities and the organization's trusted CAs, the
flow's network policy on every address, Port 9339 by default.

Three lists say what changes. The device applies them in this order, as one
transaction:

- Delete: one path per line, removed with everything under it.
- Replace: one `PATH = JSON` per line. The path's whole content becomes
  the value; anything under the path the value leaves out is removed.
- Update: one `PATH = JSON` per line. The value is merged into the path;
  what it leaves out stays as it is.

```text
/interfaces/interface[name=Ethernet1]/config/description = "uplink to core"
/interfaces/interface[name=Ethernet1]/config = {"mtu": 9000, "enabled": true}
```

Each value is JSON on one line: text in double quotes, numbers and `true`
or `false` as they are, an object for a container. Lines starting with `#`
are comments. Encoding (advanced) is Auto: values go as JSON_IETF (RFC 7951)
when the device lists it, else as JSON.

Dry run connects, reads the current values of every path and reports what
would be sent, then stops. gNMI has no check of a change on the device
before it is applied, so a dry run cannot tell whether the device would
accept it; for that, use a device with a candidate datastore and
`netconf.edit_config`.

Read before and after (advanced, on by default) reads the configuration of
every path before the change and after it, one request per path. A path the
device does not have yet is listed as missing instead of failing. Off sends
the change alone.

Max Parallel Devices is 1 by default: devices are changed one after
another. A device that fails does not stop the others.

### Templates

A rendered value stays one value. In a path, a template is a whole key
value with `tojson`; in a value, a template stands where a JSON value goes,
not inside quotes, and ends with `tojson`:

```text
/interfaces/interface[name={{ inputs.interface | tojson }}]/config/description = {{ inputs.description | tojson }}
/interfaces/interface[name={{ inputs.interface | tojson }}]/config = {"mtu": {{ inputs.mtu | tojson }}}
```

Any other template in these lists is refused before the step runs.

## Output

The summary reads `gnmi set applied: N/M devices`, or `gnmi set dry run:
N/M devices`. Each device adds `cli_output` evidence records:
`<device>:gnmi set before` and `<device>:gnmi set after` (the values read, as
indented JSON, which `evidence.compare` can diff), and `<device>:gnmi set
request` (the operations sent).

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `applied` (whether the change was sent and accepted),
  `operations` (each `op`, `path` and `value`), `encoding`, `before` and
  `after` (each path read and its configuration), `missing` (paths the
  device did not have before), `changed` (paths whose value differs after),
  `results` (the operations the device reported) and `timestamp` (the
  device's time of the change, in nanoseconds).
- `steps.NODE_ID.output.dry_run`: true when the step only read.
- `steps.NODE_ID.output.truncated`: values cut short in the output, as
  `<device>.before`. A device's part is cut at 16 KiB and the whole step's
  at 64 KiB; the evidence keeps all of it.

## When It Fails

The step fails without connecting when no targets or nothing to change is
set, when a line does not parse (a path, or a value that is not JSON), and
for the reasons `gnmi.get` gives. A device fails when it cannot be reached
or refuses the login, when reading before fails (nothing is sent then), and
when it refuses the change: its gRPC status and text are in the error, and
the device has applied none of it. When the change was applied but reading
it back failed, the device fails with `applied` true and an error that says
so. One failing device fails the step; the others keep their results.
