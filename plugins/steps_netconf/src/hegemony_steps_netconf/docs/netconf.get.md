<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NETCONF Get

`netconf.get` reads configuration or state data from each target device over
NETCONF (RFC 6241 over SSH). Use it to check a value before or after a
change, to keep a device's configuration as evidence, or to hand data to a
later step.

## Using It

Targets come from the step's target picker. The platform opens each session
with the device's SSH credentials (`access_config.ssh`), the flow's network
policy, the organization's trusted host keys and the device's jump host, on
Port (advanced, 830 by default). The device must have NETCONF enabled; on
IOS XE that is `netconf-yang`.

Read picks what is read. Running, Candidate and Startup configuration read
that datastore with get-config; the step fails on a device without that
datastore. Configuration and state reads both, operational data included,
with get.

Filter selects the data. A subtree filter is XML naming the nodes, each top
node with its namespace:

```xml
<interfaces xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/>
```

An XPath filter (Filter Type XPath) is one expression, and needs the
device's `:xpath` capability. An empty filter reads everything, which on a
large device is a lot of data.

Connect Timeout (sec), Request Timeout (sec) and Allow legacy SSH are
advanced. Max Parallel Devices (default 10) sets how many devices are read
at the same time.

## Output

The summary reads `netconf get <read>: N/M devices`. Each device adds one
`cli_output` evidence record named `<device>:netconf <read>` holding the
data, indented one element per line, so `evidence.assert`,
`evidence.compare` and `git.commit` can use it like command output.

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `source` and `data`, the XML read.
- `steps.NODE_ID.output.truncated`: texts cut short in the output, as
  `<device>.data`. A device's text is cut at 16 KiB and the whole step's at
  64 KiB; the evidence keeps all of it.

## When It Fails

The step fails without connecting when no targets are selected, when Filter
is not well-formed XML, and when the platform cannot open NETCONF sessions
(an older Hegemony). A device fails when the connection, its host key or the
network policy refuses it, when it sends no hello in time, when it lacks the
datastore or the `:xpath` capability asked for, and when it answers with an
`rpc-error`, which the step error quotes. One failing device fails the step;
the others' data is kept.
