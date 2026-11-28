<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# gNMI Get

`gnmi.get` reads configuration or state data from each target device over
gNMI (gRPC Network Management Interface). Use it to check a value before or
after a change, to keep a device's configuration as evidence, or to hand
data to a later step.

## Using It

Targets come from the step's target picker. The step connects to each
device's management address on Port (9339, the IANA port, by default;
Arista EOS uses 6030, Nokia SR Linux and Cisco IOS XR 57400, Junos 32767).
The device must have gNMI enabled.

Paths lists what to read, one gNMI path per line:

```text
/interfaces/interface[name=Ethernet1]/state/counters
/system/config/hostname
openconfig:/network-instances
```

Keys go in brackets, `[name=value]`; a `/` inside a key value needs no
escape, while `]` and `\` are written `\]` and `\\`. Write `origin:/path` for
an origin other than the device's default. A key value may also be a JSON
string in double quotes, `[name="Ethernet1/1"]`.

Data picks Configuration and state (the default), Configuration, State, or
Operational state. Encoding (advanced) is Auto by default: JSON_IETF, else
JSON, else PROTO, whichever the device lists.

### Login

Login is the device's SSH username and password from the inventory by
default; gNMI devices usually share it with SSH. This step's own Username and
Password apply the same login to every device; Password takes a secret
reference (`vault://...`) or a `{{ secret('...') }}` template. No login sends
none, for a device that authenticates by client certificate alone. The login
travels as the `username` and `password` call metadata.

### TLS

The connection uses TLS and verifies the device's certificate against the
worker's system authorities and the organization's trusted CAs (Settings,
Trusted CAs), for the device's management address. Advanced settings:

- CA Bundle trusts only the certificates given, which pins them. For a lab
  device with a self-signed certificate, give that certificate here. There
  is no setting that skips verification.
- TLS Server Name checks another name than the management address, for a
  certificate issued to the device's DNS name while the inventory holds its
  IP address.
- Client Certificate and Client Key present a certificate to the device
  (mutual TLS). Client Key must be a secret reference or template.
- Use TLS off sends gRPC in plaintext, for lab devices only. A login then
  also needs Allow login without TLS.

### Network

The flow's network policy is asked about the device's name and about every
address it resolves to, and the step dials a checked address, never the
name again. Loopback, link-local (cloud metadata included), unspecified and
multicast addresses are refused. The worker's HTTP proxy settings are not
used. A device behind a jump host cannot be reached by gNMI steps.

### Templates

A key value from a run input or another step is written with `tojson`, so
it stays one key value whatever it holds:

```text
/interfaces/interface[name={{ inputs.interface | tojson }}]/state
```

A template anywhere else in a path is refused before the step runs.

Connect Timeout (sec) bounds connecting, the TLS handshake and the first
request (Capabilities); Request Timeout (sec) bounds each request after it.
Max Parallel Devices (default 10) sets how many devices are read at the same
time.

Every gNMI step writes to the run's Logs tab as it works, one line per
device for each event: the connection (port, TLS or plaintext), the
device's gNMI version, model count and encodings, each request with its
outcome and time (`Get: ok (14 ms)`, or the gRPC status), and the connection
closing. The lines never hold values or the login.

## Output

The summary reads `gnmi get <data>: N/M devices`. Each device adds one
`cli_output` evidence record named `<device>:gnmi get <data>` holding the
values as indented JSON, so `evidence.assert`, `evidence.compare` and
`git.commit` can use it like command output.

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `values` (each path the device returned and its value, as
  `{"/system/config/hostname": "r1"}`), `data` (the same as JSON text),
  `data_type` and `encoding`.
- `steps.NODE_ID.output.truncated`: values and texts cut short in the
  output, as `<device>.values` or `<device>.data`. A device's part is cut at
  16 KiB and the whole step's at 64 KiB; the evidence keeps all of it.

## When It Fails

The step fails without connecting when no targets or no paths are set, when
a path does not parse, when a secret does not resolve, and when the platform
cannot apply the flow's network policy to the connection (an older
Hegemony). A device fails when it has no management address or a jump host,
when the network policy or the address rules refuse it, when it does not
answer within Connect Timeout (sec), when its certificate does not verify
(the error quotes gRPC's reason), when it refuses the login
(`UNAUTHENTICATED`), and when it answers a request with an error, which the
step error quotes with its gRPC status (`NOT_FOUND` for a path it does not
have). One failing device fails the step; the others' data is kept.
