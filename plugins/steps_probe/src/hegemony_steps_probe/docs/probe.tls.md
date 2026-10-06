<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# TLS Certificate Check

`probe.tls` connects to TLS endpoints and reports the certificate each one
serves: who it was issued to and by, when it expires, its key and
fingerprint, whether it chains to a trusted CA, whether it matches the name
it was reached by, and, on request, whether it has been revoked. Use it to
catch certificates before they expire, to confirm a renewal reached every
node, to confirm a revocation took effect, or to pin the exact certificate an
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
(default 10), which also bounds each OCSP request and each download as a
whole, the response body included. The first handshake reads what the server
presents and accepts any certificate, even from servers that only offer
outdated protocol versions; the second verifies the chain with the worker's
normal TLS settings. A server that presents another certificate to the second
handshake than to the first (one that verifies) gets no chain verdict:
`chain_ok` stays empty and `chain_error` says why. Chains are verified against
the worker's system trust store or, when CA bundle is set, against only the
certificates in that bundle. Every certificate in the bundle counts as
trusted, so an internal intermediate or a single pinned server certificate
works too. CA bundle takes PEM text or a secret reference, either bare
(`vault://orgs/acme/secrets/tls/internal-ca`) or as a `{{ secret('...') }}`
template.

A pasted certificate is verified offline by the same rules OpenSSL applies,
with the chain certificates you pasted as intermediates: every certificate is
within its validity dates, signed by the next and free of critical extensions
the verifier does not handle; every CA is marked as one by basicConstraints,
may sign certificates (key usage), allows a TLS server in its extended key
usage (the trust anchor too) and respects its path length, while a trust
anchor without basicConstraints counts as a CA only as a self-issued version 1
root or when its key usage allows signing certificates; the server
certificate's extended key usage and key usage allow a TLS server; and every
name stays within the name constraints of the CAs above it, with directory
names compared regardless of letter case and runs of spaces. A path never
continues from a self-signed certificate to an untrusted one. Certificate PEM
holds at most 20 certificates, and the check spends at most 1,000 signature
checks on them: pasted certificates that share names and keys can offer more
issuer paths than that, and the chain is then reported as not verified
(`chain_ok` empty, with the reason in `chain_error`).

The host name is checked against the certificate itself. A name must match
one of its DNS names, where a wildcard covers exactly one left-most label:
`*.example.com` covers `www.example.com` but neither `example.com` nor
`a.b.example.com`. An IP address must match one of its IP addresses. The
subject common name counts only when the certificate carries no DNS or IP
names at all.

Check OCSP asks the responder named in each certificate whether the
certificate has been revoked. The issuer certificate the question needs is
looked for among the certificates the server sent after its own in the
handshake (or, for a pasted certificate, those pasted after it), which the
step reads on every Python version it supports, then in CA bundle, and is
otherwise downloaded from the first three caIssuers addresses the
certificate names. A response counts only
when the issuer, or a responder the issuer authorised whose own certificate
is currently valid, signed it, only when it names this certificate, and only
while it is current: before its next update, or, when it names none, for 7
days after it was produced. The same 7-day limit applies to a CRL without a
next update.

Check CRL downloads the certificate revocation list (CRL) the certificate
names in its CRL distribution points and looks the certificate up in it. HTTP
and HTTPS addresses are tried in order, at most three of them, until one
gives an answer; others, such as `ldap://`, are skipped. A list counts only
when it is a complete CRL (not a delta CRL) from the certificate's own
issuer, its signature verifies with the issuer's key, the issuer's key usage
allows CRL signing, its next update has not passed, and its scope covers the
certificate: an issuing distribution point on the list, when present, must
name the distribution point the list came from and must not leave this kind
of certificate out. Indirect CRLs and lists that cover only some revocation
reasons are reported as errors. The issuer certificate comes from the same
places as for OCSP. Each list is downloaded once per step, up to 20 MiB, and
shared by every endpoint whose issuer names it; a list that fails these
checks is not kept, only the reason. All downloads of one step together, OCSP
responses, issuer certificates and CRLs, stop at 64 MiB: a request past that
is an `error` (or, for an issuer certificate, `unavailable`) for its
endpoint, saying the step reached its download limit. Like Check OCSP, it
checks the server certificate, not the CAs above it; `crl_next_update` says
when the issuer publishes its next list, which a flow can watch to catch a CA
that stopped publishing. An OCSP response or CRL the step cannot read, such
as one signed with an algorithm it does not know, is an `error` for that
endpoint only; the other endpoints keep their results. The same holds for a
certificate: an extension holding a name form the step cannot read (such as
an x400Address) counts as absent, and a certificate it cannot describe at all
leaves that endpoint's certificate fields empty with the reason in `error`,
which fails a pasted certificate and, with Require reachable on, the
endpoint.

Max Parallel Devices sets how many endpoints are checked at the same time
(default 10, up to 32); 1 checks them one after another. When the flow runs
under an egress policy, every connection the step makes, OCSP requests, CRL
downloads and issuer downloads included, is checked against it.

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
- Require CRL good, with Check CRL on: a current CRL that counts (see above)
  leaves the certificate off. A revoked certificate, a stale or unverifiable
  list, or no list fails.

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
  `unavailable`), `ocsp_detail`, and `revocation_time` (from OCSP); `crl`
  (`good`, `revoked`, `error`, or `unavailable`), `crl_detail`, `crl_url`
  (the list used), `crl_next_update` (when the issuer publishes its next
  list, set once the list's signature verified), and `crl_revocation_time`.
  The certificate is
  described by `subject_cn`, `sans`, `issuer_cn`, `issuer`, `serial`,
  `fingerprint_sha256`, `not_before`, `not_after`, `days_left`, `expired`,
  `key_type` (`rsa`, `ec`, `ed25519`, `ed448`, or `dsa`), `key_bits`,
  `key_curve`, `signature_algorithm`, `is_ca`, and `certificate_pem` when
  Include certificate PEM is on. Finally `ok` and `failures` say whether the
  endpoint passed and, if not, why.
- `summary`: the counts `total`, `reachable`, `unreachable`, `expired`,
  `chain_failures`, `hostname_failures`, `mismatches`, `ocsp_revoked`,
  `crl_revoked`, and `failed`, one `warn_N` per warning window (such as `warn_30`: certificates
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
`tls_HOST_PORT`, or `tls_HOST_PORT_SNI` when a server name was sent, so
endpoints that share an address and port stay apart when evidence is compared
(`tls_pem` for a pasted certificate). It holds the endpoint's full record and
is tied to the device when the endpoint came from a device target.

## When It Fails

Configuration problems stop the step before any connection: nothing to check
(no targets, endpoints, or certificate), a pasted certificate combined with
targets or endpoints, a malformed endpoint, more than 500 endpoints, a
fingerprint that is not 64 hex digits, a CA bundle or certificate PEM
without a readable certificate, a certificate PEM with more than 20
certificates, a CA bundle reference that resolves to
nothing, or a platform that cannot apply the flow's network policy to the
step's connections (only a pasted certificate without revocation checks runs
there).

Otherwise the step checks every endpoint and fails when any of them broke an
enabled assertion, listing each failing endpoint with its reasons in the step
error, for example `portal.example.com:443 (12 days left (minimum 30))`. The
output is complete either way, so a failure branch can read which endpoints
failed and why. A target without a management address always fails. A
connection the egress policy denies fails the whole step with the policy's
reason rather than counting as an unreachable endpoint.
