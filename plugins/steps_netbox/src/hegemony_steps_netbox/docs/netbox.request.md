<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NetBox Request

`netbox.request` reads and changes NetBox objects from a flow: get one object,
list objects across pages, create, update or delete one object or many, or
post to an endpoint such as `render-config`. The object, or the list of
objects, comes back as output for later steps. The step has no targets.

## Using It

NetBox URL is NetBox's address without `/api`, such as
`https://netbox.example.com`. API Token takes a bare secret reference such as
`vault://orgs/acme/secrets/netbox/token`, a `{{ secret('...') }}` template, or
literal text. Token Type Auto sends a token that starts with `nbt_` as a v2
token (`Authorization: Bearer`, NetBox 4.5 and later) and any other as a v1
token (`Authorization: Token`). The token needs an `https://` URL; Allow token
over HTTP sends it to an `http://` URL anyway, for an internal NetBox without
HTTPS. Give the token only the permissions the flow needs.

With Verify TLS certificate on (the default), NetBox's certificate is checked
against the public certificate authorities plus the organization's trusted
CAs, which administrators manage under Settings, Trusted CAs; a NetBox behind
a private CA the organization added needs no CA Bundle. CA Bundle trusts only
the certificates it holds instead of both, which pins them.

Endpoint is the REST path after `/api/`, such as `dcim/devices`,
`ipam/ip-addresses` or `plugins/<plugin>/<objects>`; a leading `/api/` and
slashes are dropped. Action decides what the step does:

| Action | Request | Needs |
| --- | --- | --- |
| Get one object | `GET <endpoint>/<id>/` | Object ID, or Filters that match exactly one object |
| List objects | `GET <endpoint>/` page by page | nothing; Filters narrow it |
| Create | `POST <endpoint>/` | Data: one object, or a list |
| Update | `PATCH <endpoint>/<id>/` | Object ID and Data, or a list in Data of objects with their `id` |
| Delete | `DELETE <endpoint>/<id>/` | Object ID, or a list in Data of IDs or `{"id": n}` objects |
| Post to an endpoint | `POST <endpoint>/[<id>/]<route>/` | Route |

Route is a path after the object or the endpoint, such as `render-config`,
`available-ips` or `trace`; with get it reads such a route, for example the
free addresses of a prefix (`ipam/prefixes`, Object ID, Route
`available-ips`). Filters (`NAME=value` lines) are sent as the query, such as
`name=web-01`, `site=paris` or `tag=managed`; a list repeats the filter, and
`true`/`false` and numbers are sent as text. They also carry NetBox's own
options such as `brief=true` or `fields=id,name`. `limit` and `offset` are set
by the step.

Get with neither Object ID nor Filters reads the endpoint itself, which suits
one that answers with a single object, such as `status`. On an endpoint that
lists objects it fails, because NetBox answers with a page of them: give an
Object ID or Filters, or use list.

Data is JSON: an object, or a list for many objects at once. Written as text,
it is parsed as JSON first, so a template that renders JSON works:

```json
{"status": "active", "description": {{ inputs.note | tojson }}}
```

A value from a template inside an object written as YAML arrives as text;
NetBox reads numbers and booleans from text for most fields, but a JSON
field, a list or a null needs the whole Data written as JSON text with
`tojson`. Change Log Message is recorded with a create, update or delete in
NetBox's change log (NetBox 4.4 and later), for example
`Hegemony run {{ run_id }}`.

Missing is OK (get and delete only) makes a missing object a success with
`found` false: get a record if it exists, or delete one that may already be
gone. Max Results (list, default 1000, at most 100000) bounds a list, fetched
in pages of up to 1000. Expected Status replaces the action's own (200 for
get, list and update, 201 for create, 204 for delete, 200-299 for post).
Branch works in a NetBox Branching branch (its schema ID, sent as
`X-NetBox-Branch`), so changes stay in the branch until it is merged.

Retries (default 2, at most 5) repeat a read while NetBox is busy or
unreachable: HTTP 429, 502, 503 or 504, a timeout, or a dropped connection,
waiting as `Retry-After` asks (seconds or a date, at most 30 s) or 1, 2, 4 s.
Writes are never repeated, because NetBox may already have made the change.
Timeout (sec), default 30, bounds each request; Max Response Size (default
4 MiB, at most 16 MiB) bounds everything the step reads.

## Output

- `status`, `ok`, `action`, `endpoint`, `method`: the last response's status,
  whether the step succeeded, and what it did.
- `object`: the object (get, create, update, post), or null.
- `id`: the object's `id`, or null.
- `objects`, `ids`, `count`, `returned`, `more`: for a list and for many
  objects at once: the objects, their IDs, NetBox's total, how many came back,
  and whether Max Results stopped the list early.
- `found`: with Missing is OK, whether the object existed.
- `data`: what a route that answers with something other than an object or a
  list returned.
- `data_truncated`: true when the object or list is larger than 64 KiB and
  was left out of the output; Extract still reads all of it.
- `extracted`: the values Extract picked (`NAME=path` lines). Paths start at
  the object, or at the list of objects (`[0].id`): dots separate keys, `[n]`
  picks a list item.

Later steps read `steps.<id>.output.object.name` or
`steps.<id>.output.ids`. The step's `netbox` evidence record lists each
request with its method, URL, status and timing (the first 1000; past that,
`requests_not_listed` counts the rest), and `http.request`'s own record is
kept for a request that failed.

## Security

Every request goes through `http.request`'s client, so the same rules apply:
the flow's egress policy is checked before each request, loopback,
link-local (cloud instance metadata included), unspecified and multicast
addresses are refused, and NetBox's answers are size-capped. The token is
resolved by the host and registered for redaction, sent only to the NetBox
URL's own scheme, host and port, never over plain HTTP unless allowed, and
scrubbed from the output, evidence and errors. Pages are fetched by offset
from the URL the step was given, never from NetBox's `next` links.

## When It Fails

The step fails, with NetBox's own message, when NetBox answers with another
status than expected: 401 (the token is wrong or expired; check API Token and
Token Type), 403 (the token may not do this), 404 (no such object or
endpoint), or 400 with the fields it refused (`name: This field is
required.`; for many objects, per item). It also fails when Filters for get
match no object or more than one, when NetBox cannot be reached after the
retries, when the egress policy refuses NetBox, or when the response is larger
than Max Response Size.
