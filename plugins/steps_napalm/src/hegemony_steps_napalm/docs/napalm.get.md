<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NAPALM Get

`napalm.get` reads structured data from each target device with NAPALM
getters. A getter returns the same data shape on every platform, so one
check works on Cisco and Arista devices alike. Use it to check a value
before or after a change, or to hand data to a later step.

## Using It

Targets come from the step's target picker. The platform opens each session
with the device's SSH credentials (`access_config.ssh`), the flow's network
policy, the organization's trusted host keys and the device's jump host. The
NAPALM driver follows the device's platform:

| Device platform | Driver |
| --- | --- |
| `ios-xe`, `ios` | Cisco IOS |
| `eos` | Arista EOS, over SSH |
| `nxos` | Cisco NX-OS, over SSH |

A device on another platform fails with that reason; the other devices still
run.

Getters lists what to read, one per line, without the `get_` prefix:

```text
facts
interfaces
bgp_neighbors
```

The getters offered are `arp_table`, `bgp_config`, `bgp_neighbors`,
`bgp_neighbors_detail`, `config`, `environment`, `facts`, `interfaces`,
`interfaces_counters`, `interfaces_ip`, `ipv6_neighbors_table`,
`lldp_neighbors`, `lldp_neighbors_detail`, `mac_address_table`,
`network_instances`, `ntp_peers`, `ntp_servers`, `ntp_stats`, `optics` and
`vlans`. Getters that return credentials (`users`, `snmp_information`) are
not offered. `config` is read with NAPALM's sanitizing, which masks
passwords, keys and community strings, and credential fields such as a BGP
neighbor's `authentication_key` are dropped from every result. A driver that has no such getter fails the device with
"not supported".

Connect Timeout (sec), Command Timeout (sec) and Allow legacy SSH are
advanced. Max Parallel Devices (default 10) sets how many devices are read
at the same time.

The run's Logs tab shows one line per device for each operation: the session
opening (with the driver and how long it took), each getter, and the
session closing. Data read is in the output and the evidence, not the log.

## Output

The summary reads `napalm get <getters>: N/M devices`. Each device adds one
`cli_output` evidence record per getter, named `<device>:<getter>`, holding
the result as JSON with sorted keys. Its command is the getter name, so
`evidence.assert` checks it with Command `bgp_neighbors`, for example with
the operator `contains` and the expected text `"is_up": true`.

- `steps.NODE_ID.output.devices`: each device's result by name: `ok`,
  `error`, `driver`, `data` and `omitted`. `data` maps each getter to its
  result, such as `data.facts.os_version`. A result larger than 16 KiB of
  JSON is left out of `data` and named in `omitted`; the evidence still has
  all of it.
- `steps.NODE_ID.output.truncated`: texts cut short in the output, as
  `device.key` (none for this step: large results go to `omitted`).

## Failure

A device fails when its session cannot open (unreachable, refused
credentials, an untrusted host key, a platform without a driver) or a getter
fails. The step fails when any device fails, and its error names each
device and why.
