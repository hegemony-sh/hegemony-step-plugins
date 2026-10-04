<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# TLS Certificate Check

`probe.tls` connects to TLS endpoints and reports the certificate each one
serves: who it was issued to and by, when it expires, its key and
fingerprint, whether it chains to a trusted CA, and whether it matches the
name it was reached by. Use it to catch certificates before they expire, to
confirm a renewal reached every node, or to pin the exact certificate an
endpoint must present. It observes from outside, without device credentials,
and it can also evaluate a pasted certificate without connecting anywhere.

## Using It

Endpoints come from two places, used together. The step's targets (each
selected role's devices by management address, plus explicit IP selectors)
are checked on Port, 443 by default. Server Name (SNI), when set, is sent to
them during the handshake and checked against their certificates; otherwise
each target's own address is used. Endpoints adds more, one per line as
`host:port` or `host:port:sni`, with IPv6 addresses in brackets
(`[2001:db8::1]:443`); a missing port means Port. A template that renders a
comma- or newline-separated list works as well, for example
`{{ steps.inventory.output.hosts }}`. An endpoint listed twice is checked
once, and one step checks at most 500 endpoints.

Certificate PEM checks a certificate you paste instead of connecting: put the
server certificate first and any chain certificates after it. It cannot be
combined with targets or endpoints. Server Name then names the host the
certificate is checked against.

Each endpoint is contacted twice, each attempt bounded by Timeout (sec)
(default 10). The first handshake reads what the server presents and accepts
any certificate, even from servers that only offer outdated protocol
versions; the second verifies the chain with the worker's normal TLS
settings. Chains are verified against the worker's system trust store or,
when CA bundle is set, against only the certificates in that bundle. Every
certificate in the bundle counts as trusted, so an internal intermediate or
a single pinned server certificate works too. CA bundle takes PEM text or a
secret reference, either bare (`vault://orgs/acme/secrets/tls/internal-ca`)
or as a `{{ secret('...') }}` template. A pasted certificate is verified
offline by the same rules, with the chain certificates you pasted as
intermediates: every certificate is within its validity dates, signed by the
next and free of critical extensions the verifier does not handle; every CA
is marked as one, may sign certificates (key usage) and respects its path
length; the server certificate's extended key usage and key usage allow a
TLS server; and every name stays within the name constraints of the CAs
above it.

The host name is checked against the certificate itself. A name must match
one of its DNS names, where a wildcard covers exactly one left-most label:
`*.example.com` covers `www.example.com` but neither `example.com` nor
`a.b.example.com`. An IP address must match one of its IP addresses. The
subject common name counts only when the certificate carries no DNS or IP
names at all.

Check OCSP asks the responder named in each certificate whether the
certificate has been revoked. The issuer certificate the question needs comes
from the pasted or served chain where available, from CA bundle, or is
downloaded from the address the certificate names. A response counts only
when the issuer, or a responder the issuer authorised whose own certificate
is currently valid, signed it, and only when it names this certificate.

Parallel checks (default 10, up to 50) sets how many endpoints are checked at
once. When the flow runs under an egress policy, every connection the step
makes, OCSP requests and issuer downloads included, is checked against it.

### Assertions

The step fails when an endpoint breaks an enabled assertion:

- Require reachable (on by default): the endpoint completed a TLS handshake
  and presented a certificate.
- Minimum days left: the certificate has at least this many whole days left.
  `0` fails only expired certificates; empty (the default) never fails on
  expiry.
- Require valid chain: the chain verified.
- Require host name match: the host name check passed.
- Expected fingerprint: the certificate's SHA-256 fingerprint equals this
  value; colons and case are ignored. Expected fingerprints per endpoint sets
  one per `host:port` or `host:port:sni` and overrides the general one for
  that endpoint. An entry with a server name applies only to that name; one
  without applies to every server name on that host and port.
- Require OCSP good, with Check OCSP on: the responder reported the
  certificate good.

With Require reachable off, an endpoint that cannot be reached passes; the
certificate assertions apply only to endpoints that presented a certificate.
Warning windows (30, 14 and 7 days by default) never fail the step; they only
feed the counters in the summary.

## Output

Later steps read the results as `steps.NODE_ID.output.KEY`:

- `endpoints`: one record per endpoint, targets first. Each carries `source`
  (`target`, `endpoint`, or `pem`), `host`, `port`, `sni` (the server name
  sent, empty for an IP address), `device_id`, `device_name`, `reachable`,
  `error`, `tls_version`, `cipher`, `chain_ok`, `chain_error`, `hostname_ok`,
  `matches_expected`, `ocsp` (`good`, `revoked`, `unknown`, `error`, or
  `unavailable`), `ocsp_detail`, and `revocation_time`. The certificate is
  described by `subject_cn`, `sans`, `issuer_cn`, `issuer`, `serial`,
  `fingerprint_sha256`, `not_before`, `not_after`, `days_left`, `expired`,
  `key_type` (`rsa`, `ec`, `ed25519`, `ed448`, or `dsa`), `key_bits`,
  `key_curve`, `signature_algorithm`, `is_ca`, and `certificate_pem` when
  Include certificate PEM is on. Finally `ok` and `failures` say whether the
  endpoint passed and, if not, why.
- `summary`: the counts `total`, `reachable`, `unreachable`, `expired`,
  `chain_failures`, `hostname_failures`, `mismatches`, `ocsp_revoked`, and
  `failed`, one `warn_N` per warning window (such as `warn_30`: certificates
  with fewer than 30 days left, expired ones included), and `min_days_left`.
- `all_ok`: whether every endpoint passed every enabled assertion.
- `min_days_left`: the fewest days left over all certificates, empty when no
  certificate was read.

Every key is present on every record; a value that could not be determined
is empty (null), for instance the certificate fields of an unreachable
endpoint, `hostname_ok` when there was no name to check, or
`matches_expected` when no fingerprint was expected. Times are ISO 8601 in
UTC (`2026-11-14T08:00:00Z`). `days_left` is rounded down, so it turns
negative once a certificate has expired. Fingerprints and serial numbers are
lowercase hex without colons.

The summary reads `tls: N endpoints, R reachable, min D days left` (or
`tls: pem certificate, min D days left`), with `, F failing` appended when
endpoints fail. Metrics record `endpoints`, `unreachable`, and
`min_days_left`. Each endpoint adds one `transport_meta` evidence record named
`tls_HOST_PORT` (`tls_pem` for a pasted certificate) holding its full record,
tied to the device when the endpoint came from a device target.

## When It Fails

Configuration problems stop the step before any connection: nothing to check
(no targets, endpoints, or certificate), a pasted certificate combined with
targets or endpoints, a malformed endpoint, more than 500 endpoints, a
fingerprint that is not 64 hex digits, a CA bundle or certificate PEM
without a readable certificate, or a CA bundle reference that resolves to
nothing.

Otherwise the step checks every endpoint and fails when any of them broke an
enabled assertion, listing each failing endpoint with its reasons in the step
error, for example `portal.example.com:443 (12 days left (minimum 30))`. The
output is complete either way, so a failure branch can read which endpoints
failed and why. A target without a management address always fails. A
connection the egress policy denies fails the whole step with the policy's
reason rather than counting as an unreachable endpoint.
