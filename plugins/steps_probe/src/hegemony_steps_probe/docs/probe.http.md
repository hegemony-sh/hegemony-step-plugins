<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# HTTP Check

`probe.http` sends an HTTP or HTTPS request to each target of the step and
asserts the response. Use it to verify a management UI, REST API, or health
endpoint answers correctly — a status code in the expected set, optionally a
body containing expected text — without any device credentials.

## Using It

Targets come from the step's target picker: each selected role resolves to
its devices' management addresses, and explicit IP selectors add literal
addresses (an IPv6 address is put in brackets in the URL; one already in
brackets is used as is). The request URL is built from Scheme
(HTTP by default), Port (defaulting to 80 or 443 by scheme), and Path
(default `/`; a missing leading slash is added). Method is GET, HEAD, or
POST — keep in mind a HEAD response has no body for Body Contains to match.

Expected Status lists acceptable status codes as comma-separated values and
ranges, for example `200-299,301`; the default `200-399` accepts success and
redirect responses. Body Contains, when set, additionally requires the
response body to contain that exact text. Follow redirects (on by default)
chases redirects and asserts the final response; switch it off to assert the
redirect response itself. Verify TLS certificate (on by default) applies to
HTTPS: it checks the certificate against the public certificate authorities
plus the organization's trusted CAs (Settings, Trusted CAs), and can be
switched off for self-signed device certificates. Timeout
(sec) bounds each request attempt (default 10; steps saved with its old name,
`timeout_sec`, keep working), and Attempts (default 1, up
to 10) retries failing targets with a half-second pause between tries. Max
Parallel Devices sets how many targets are requested at the same time
(default 10, up to 32); 1 requests them one after another. Evidence and
metrics always follow target order.

When the flow runs under an egress policy, every request — each redirect hop
included — is checked against it, and a denied destination raises the
policy's reason as the step error rather than counting as a failed check;
the requests still running are then stopped.

## Output

The summary reads `http <method> <path>: N/M targets OK` and is available to
later steps as `steps.NODE_ID.summary`. Metrics record one `<device name>_ms`
request latency per successful target. Each target adds one `transport_meta`
evidence record named `http_<device name>` capturing the full URL, the
method, the response status and latency, and the error text when the check
failed.

## When It Fails

The step fails before any request when Expected Status cannot be parsed, or
when no target devices or IPs are configured. A target fails when its
address does not make a valid URL, when the request errors (refused, TLS
failure, or timeout — the timeout applies per attempt, not to the step as a
whole), when the response status is outside the expected set, or when the
body does not contain the Body Contains text; the other targets are still
requested. One failing target fails the whole step, with per-target reasons
listed in the step error. Evidence is kept for every target that was
actually requested; a device without a management address fails the step
but leaves no evidence record.
