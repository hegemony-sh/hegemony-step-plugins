<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NetBox Release

`netbox.ipam.release` gives back IP addresses, prefixes, VLANs or ASNs by
deleting them from NetBox, typically what `netbox.ipam.allocate` took, when a
flow rolls back or a service is removed. It succeeds when they are already
gone, so a re-run of a clean-up passes. The step has no targets.

## Using It

The connection fields (NetBox URL, API Token, Token Type, TLS and Branch) are
those of `netbox.request`. Resource is what to release: an IP address, a
prefix, a VLAN or an ASN. Object ID names one object, such as
`{{ steps.allocate.output.id }}`; or Filters find the objects (`NAME=value`
lines, such as `address=10.20.0.5/24` or `dns_name=web-01.example.com`).

Max Objects (default 1) is the most objects Filters may match: when more
match, the step fails and releases nothing, so a filter that is too broad
cannot empty a pool. Missing is OK (on by default) makes "nothing matches" and
"already gone" a success; turned off, they fail the step. Change Log Message
is recorded with the deletion (NetBox 4.4 and later).

## Output

- `released`: how many objects were deleted.
- `ids` and `values`: their NetBox IDs, and their addresses, prefixes, VLAN
  IDs or ASNs (when found by Filters).
- `resource`, `status` and `ok`.

## Security

The step sends its requests through `http.request`'s client, with the same
rules as `netbox.request`. It deletes only objects of the chosen resource's
endpoint, only those Object ID or Filters name, and never more than Max
Objects; the deletion itself is never retried.

## When It Fails

The step fails when Filters match more than Max Objects, when nothing matches
and Missing is OK is off, and when NetBox refuses the deletion (with its
message, for example a token without delete permission).
