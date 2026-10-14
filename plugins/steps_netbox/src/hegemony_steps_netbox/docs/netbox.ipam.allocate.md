<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NetBox Allocate

`netbox.ipam.allocate` takes the next free IP address, prefix, VLAN or ASN
from a NetBox pool and creates it in NetBox, or returns what an earlier
attempt of the same work already took. Pair it with `netbox.ipam.release` to
give it back when the flow rolls back. The step has no targets.

## Using It

The connection fields (NetBox URL, API Token, Token Type, TLS and Branch) are
those of `netbox.request`. Allocate picks what to take and from where:

| Allocate | Pool | NetBox route |
| --- | --- | --- |
| IP address from a prefix | a prefix | `ipam/prefixes/<id>/available-ips/` |
| IP address from an IP range | an IP range | `ipam/ip-ranges/<id>/available-ips/` |
| Prefix from a prefix | a prefix | `ipam/prefixes/<id>/available-prefixes/` |
| VLAN from a VLAN group | a VLAN group | `ipam/vlan-groups/<id>/available-vlans/` |
| ASN from an ASN range | an ASN range | `ipam/asn-ranges/<id>/available-asns/` |

Pool ID is the pool's NetBox ID; or Pool Filters find it (`NAME=value` lines,
such as `prefix=10.20.0.0/24` and `vrf_id=3`, or `name=servers` for a VLAN
group), and must match exactly one. A prefix needs Prefix Length, such as 28.
Data holds the new object's fields as JSON, such as
`{"status": "active", "dns_name": "web-01.example.com"}`; a VLAN needs a
`name`. Count (default 1, at most 256) takes several in one request. Change
Log Message is recorded with the change (NetBox 4.4 and later).

NetBox hands out free space under a lock, so two runs never get the same
address. A re-run of the same work should not take a second one: Existing
Filters find what an earlier attempt already took, such as
`dns_name=web-01.example.com` or `description=order-4711`. When they match
Count objects, the step returns those without taking anything; when they
match none, it allocates; any other number fails the step. The search stays
inside the pool for prefixes (the prefix and its VRF), VLAN groups and ASN
ranges (between the range's first and last ASN); for IP ranges it stays in
the range's VRF but covers every address there, so make the filters specific.
Empty Existing Filters always allocate.

## Output

- `allocated`: true when the step took new objects, false when Existing
  Filters found earlier ones.
- `value` and `values`: the address (`10.20.0.5/24`), prefix, VLAN ID or ASN
  of the first object, and of all of them.
- `id` and `ids`: their NetBox IDs.
- `object` and `objects`: the objects as NetBox returned them (left out when
  larger than 64 KiB).
- `resource` and `pool_id`: what was taken, and from which pool.

Later steps read `steps.<id>.output.value`, for example to configure the
address on a device, and pass `steps.<id>.output.id` to `netbox.ipam.release`.

## Security

The step sends its requests through `http.request`'s client, with the same
rules as `netbox.request`: the egress policy before each request, refused
local and metadata addresses, size-capped answers, and the token resolved by
the host, never sent over plain HTTP unless allowed, and scrubbed from
everything the step reports. Creating the allocation is never retried, so a
lost answer cannot take a second address; reading the pool is.

## When It Fails

The step fails when the pool is not found (or Pool Filters match none or more
than one), when the pool has not enough free space for Count, when Existing
Filters match another number than none or Count, and when NetBox refuses the
request (with its message: a field it rejects, a missing `name` for a VLAN, a
token without permission).
