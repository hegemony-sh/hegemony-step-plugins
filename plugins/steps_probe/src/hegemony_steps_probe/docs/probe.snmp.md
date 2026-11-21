<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# SNMP Check

`probe.snmp` reads values from each target's SNMP agent and passes them to
later steps. It only reads: it sends GET, GETNEXT and GETBULK requests and
never SET, so it cannot change a device. Use it to check that the agent
answers, to read a device's identity or uptime before and after a change,
or to read an interface table for a later step to act on.

## Using It

Targets come from the step's target picker: each device is queried at its
management address, and explicit IP selectors add literal addresses. A host
name is resolved on the worker first, and the step queries the first
address it gets.

Operation decides what is read. Get (the default) reads exactly the listed
OIDs, in one request per target. Walk reads every value under each listed
OID, such as a whole table (`1.3.6.1.2.1.2.2.1.8`, the interfaces'
operational status), with GETBULK requests, and stops after Max Rows values
per OID (default 100, at most 1000). OIDs are numeric, one per line, at most
64; MIB names are not accepted. With none listed the step reads sysDescr.0,
sysObjectID.0, sysUpTime.0 and sysName.0.

SNMP Version picks SNMPv2c (the default) or SNMPv3. SNMPv2c needs a
Community. SNMPv3 needs a User, and by default authenticates with SHA-256
and encrypts with AES-128. Authentication (None, SHA-1 or SHA-2) and Privacy
(None or AES) can be lowered for agents that need it; Privacy needs
Authentication. AES-192 and AES-256 use the key extension Cisco and most
vendors use, and the Blumenthal variants the one Net-SNMP uses. MD5, DES and
3DES are not offered. Context sets the SNMPv3 context name.

Community, Authentication Key and Privacy Key must be secret references
(`vault://orgs/acme/secrets/snmp/community`) or `{{ secret('...') }}`
templates. A value written in clear is refused, because it would be stored
in the flow and not redacted. The resolved values are redacted from the
step's output; one shorter than 4 characters fails the step, as it cannot be
redacted reliably, and SNMPv3 keys need at least 8. SNMPv2c sends the
community unencrypted, so prefer SNMPv3 outside a lab.

Each request waits Timeout (sec) for the answer (default 5) and is sent up
to Attempts times (default 2), because SNMP runs over UDP and a lost packet
is common. Port (advanced) is the agent's UDP port, 161 by default. Max
Parallel Devices sets how many targets are queried at the same time
(default 10, up to 32). The step dials each agent itself, so the flow's
network policy must allow UDP to the target's address and port. A SOCKS5
proxy is not used: SNMP runs over UDP.

## Output

The summary reads `snmp <operation>: N/M targets OK, V values`. Metrics
record one `<device name>_ms` time per target that answered and
`values_read`. Each target adds one `transport_meta` evidence record named
`snmp_<operation>_<device name>` with the address, version, operation,
OIDs, every value read and its type, the OIDs without a value, and the
error.

`steps.NODE_ID.output.targets` maps each target's name to its result:
`ok`, `error`, `latency_ms`, `address`, `values` (the values by OID),
`types` (the SNMP type by OID), `missing` (OIDs without a value and why)
and `truncated` (walked OIDs that hit Max Rows). A later step reads one
value as
`{{ steps.NODE_ID.output.targets['r1'].values['1.3.6.1.2.1.1.5.0'] }}`.
Numbers (integers, counters, gauges, time ticks in hundredths of a second)
are numbers, OIDs and IP addresses dotted text, and octet strings text when
they are printable, else `0x` and hex. A value is cut at 1024 characters.
Inventory names are unique per site only, and an IP target is named by its
address: a name two targets share is keyed as `name (device id)`.

The values of all targets together are kept to 48 KiB in the output. A
target whose values would go past that keeps `ok` and `error` there, with
empty `values` and `types`, and is listed in
`steps.NODE_ID.output.omitted`; its values stay in the evidence.

## When It Fails

The step fails without querying when no targets are configured, when the
settings are invalid (an OID that is not numeric, a credential written in
clear, a missing User or key), when a credential resolves to nothing or to
too short a value, when the platform cannot apply the flow's network
policy, and when the policy does not allow a target's agent (the policy's
reason is then the step error).

A target fails when its address cannot be resolved, when the agent does not
answer in time (`No SNMP response received before timeout`), when it
refuses the request (a wrong SNMPv3 key reads `Wrong SNMP PDU digest`, an
unknown user `Unknown USM user`; a wrong SNMPv2c community gets no answer at
all), when a Get OID has no value (`noSuchObject`, `noSuchInstance`), and
when a walked OID has no values under it. One failing target fails the
whole step, with each target's reason in the step error; the values of the
targets that answered stay in the output and the evidence.
