<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# HTTP Request

`http.request` sends one HTTP or HTTPS request from the worker and returns the
response as structured output for later steps: call a REST API, create or
update a record, fetch a token, or read a paged list. The step has no targets;
the URL says where the request goes.

## Using It

URL is the only required field: an `https://` or `http://` address such as
`https://api.example.com/v1/items`, which may use templates such as
`{{ inputs.base_url }}/items` or `{{ steps.NODE_ID.output.data.next }}`.
Credentials never go in the URL (`user:password@` is refused): use
Authentication. Method is GET (the default), POST, PUT, PATCH, DELETE, HEAD or
OPTIONS. Query Parameters (`NAME=value` lines) are added to the URL, replacing
a parameter of the same name the URL already carries. Headers (`Name=value`
lines) are sent as written; their values may use templates. Host,
Content-Length, Transfer-Encoding and Connection are set by the step.

A body is either JSON Body or Text Body, never both, and GET, HEAD and OPTIONS
send none. JSON Body is sent as compact JSON with `Content-Type:
application/json`; written as text, it is parsed as JSON first, so a template
that renders JSON works:

```json
{"name": "{{ inputs.name }}", "tags": ["managed"]}
```

A value inserted into JSON text must itself be valid inside it (quotes
escaped). Text Body is sent as written, with `Content-Type: text/plain;
charset=utf-8`. A Content-Type in Headers replaces either default, for
example `application/merge-patch+json`.

Authentication is None (the default), Bearer token (`Authorization: Bearer`
and the secret), Basic (Username, which may not contain a colon, and the
secret as password), or Custom header: Header Name (default `Authorization`)
carries Value Prefix (for example `Token ` with its trailing space) followed
by the secret. Secret takes a bare secret reference such as
`vault://orgs/acme/secrets/api/token`, a `{{ secret('...') }}` template, or
literal text; any `scheme://...` text is read as a reference. A Header in
Headers with the same name as the credential header is refused.

Expected Status lists the status codes that count as success, as values and
ranges such as `200-299,304`; the default is `200-299`. Timeout (sec), default
30, bounds each request: connecting, sending and reading the whole response.
Follow redirects is off by default, so a 3xx response is the result (add it to
Expected Status to accept it); switched on, the step follows up to 10
redirects and reports the final response. A 303 becomes a GET, while 307 and
308 repeat the method and body.

Verify TLS certificate is on by default. CA Bundle trusts the PEM
certificates you give (an internal CA, say) for this request instead of the
public certificate authorities; like Secret it may be PEM text, a secret
reference or a template. Turn verification off only for test endpoints.

Max Response Size (default 1 MiB, at most 16 MiB) is the largest response
body the step reads, summed over all pages. A larger body fails the step; it
is never cut short silently. The step asks for uncompressed, gzip or deflate
bodies and decompresses them itself, stopping at Max Response Size, so a
small compressed body cannot expand past it; a body in any other encoding
fails the step.

### Extracting values

Extract picks values out of the JSON response, one `NAME=path` line each, for
example `id=results[0].id` or `token=$.auth.token`. A path is keys separated
by dots, `[n]` for a list item (`[-1]` is the last), `["a.b"]` for a key with
dots or spaces, and an optional leading `$.`. A path that matches nothing gives
`null` rather than an error. Later steps read
`{{ steps.NODE_ID.output.extracted.id }}`.

### Pagination

For an API that returns one page at a time with a link to the next, set Next
Page Path to where that link sits (for example `next`), Items Path to the list
of items (for example `results`), and Max Pages above 1 (at most 100). The
step then follows the links with GET, the same headers and credentials, until
the link is missing, `null` or empty, or Max Pages is reached; `more_pages`
tells which. A relative link is resolved against the page's URL. Next pages,
and any redirect while paginating, must stay on the first request's scheme,
host and port, and a link back to a page already fetched stops pagination
with an error. Pagination needs the GET method, and each page must be JSON
with a list at Items Path.

## Output

The summary reads like `GET https://api.example.com/v1/items -> 200 (85 ms)`
(the query string left out), and `(3 pages, 240 ms)` when paginating. Later
steps read the output as `steps.NODE_ID.output.KEY`:

- `status`: the HTTP status of the last response (`null` if none arrived).
- `ok`: whether that status is in Expected Status.
- `url`: the URL of the last request, after redirects; `method`: the method.
- `headers`: the last response's headers, names lower-cased; repeated headers
  joined with `, `. `set-cookie`, `set-cookie2`, `authorization`,
  `proxy-authorization` and `cookie` are always left out.
- `body`: the last response's body as text, at most 64 KiB, with
  `body_truncated` telling whether it was cut.
- `data`: the body parsed as JSON, or `null` when it is not JSON. With
  pagination, the first page with the list at Items Path replaced by the
  items of every page.
- `extracted`: the Extract values by name.
- `elapsed_ms`: the time spent on all requests; `size_bytes`: the body bytes
  read, all pages together; `body_sha256`: the SHA-256 of the last body.
- `pages`: the number of pages fetched; `more_pages`: whether Max Pages
  stopped the step while another page was linked.

When the status is not expected, the step fails but its output is still
filled in from that response, so a failure branch can read `status`, `body`
and `data`. Metrics record `elapsed_ms`, `size_bytes` and `status`. One
`transport_meta` evidence record named `http_request` keeps the method, the
URL as sent, every request made (redirect hops and pages, each with its status
and time), the names of the request headers sent, the response headers as
above, the first 4096 characters of the body, its size and SHA-256.

Sensitive response keeps `body`, `body_truncated`, `data` and `extracted`
out of both output and evidence, for a response that carries a secret; the
status, headers, size and SHA-256 remain. Extract cannot be combined with it.

## Security

- **Destinations.** Only `http` and `https` are sent; a redirect to any other
  scheme is refused. Before any connection, every request, redirect hops and
  next pages included, passes the flow's egress policy, and a request to a
  loopback, link-local, unspecified or multicast address is refused: a literal
  IP is judged as written, a host name by every address it resolves to (it is
  refused if any of them is such an address). The cloud instance metadata
  services at `169.254.169.254`, `fd00:ec2::254` and `100.100.100.200` are
  refused too. Private network addresses are left to the egress policy.
- **Worker settings.** The step ignores the worker's proxy variables, `.netrc`
  and certificate-file variables: the request goes directly to the URL, and
  trusts the public authorities or CA Bundle only.
- **Credentials.** Credentials are sent only to the URL's own scheme, host and
  port: a redirect to anywhere else drops them, and drops every header set in
  Headers except Accept, Accept-Language, Content-Type and User-Agent. So put
  tokens in Authentication, not in Headers.
- **What is recorded.** The secret, request header values and the request body
  never appear in the output, evidence, summary or error; request headers are
  recorded by name only. A secret the response repeats is replaced with
  `[redacted]` in the output and evidence.
- **Redaction.** A value the platform resolves from a secret reference or
  template is redacted from the run's logs. Literal text in Secret is not
  registered for redaction and is stored in the flow as written, so prefer a
  secret reference.

## When It Fails

The step fails before sending anything when the config is invalid: a URL that
is not `http(s)` or carries credentials, both bodies or a body on GET, HEAD or
OPTIONS, JSON Body text that is not valid JSON once rendered, an Expected
Status that does not parse, an invalid path, a missing Secret or Username, or
incomplete pagination settings. It also fails when a secret reference
resolves to nothing, the secret is shorter than 4 characters (too short to
keep reliably out of the output), or CA Bundle holds no certificate.

During the request it fails on a refused destination, a DNS failure, a
connection or TLS error, a timeout, more than 10 redirects, a response over
Max Response Size or in an encoding the step does not decode, a status
outside Expected Status (output still filled in), or a page that is not JSON,
has no list at Items Path, links to another origin or back to an earlier
page, or redirects to another origin. A denial by the flow's egress policy fails the step with the policy's
own reason.
