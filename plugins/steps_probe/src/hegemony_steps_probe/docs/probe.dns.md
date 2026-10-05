<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# DNS Check

`probe.dns` resolves a DNS name and asserts the answers. The lookups run
from the worker executing the flow, so the step verifies what the network
around your automation sees: that a device's name resolves at all, that it
resolves to the addresses you expect, or that a given resolver serves the
right records. No device credentials are involved.

## Using It

By default the step resolves each target's own name: every device from the
step's target picker is looked up by its hostname (falling back to its
management address). Set Name to Resolve to query one explicit name instead —
the same question is then asked once per target. Direct-IP targets only make
sense together with an explicit Name to Resolve; an IP literal is not a DNS
question, and such a target fails with a clear message otherwise.

Record Type picks the query (A by default; AAAA, CNAME, MX, NS, and TXT are
also available). Resolver optionally directs the query at a specific
nameserver IP address; when empty the worker's system resolver is used. A
resolver is a destination the step dials, so the flow's network policy must
allow it on port 53 for both UDP and TCP (DNS falls back to TCP for large
answers); host names, ports and URLs are refused. Expected
Values lists answers, one per line, that must all appear in the response —
comparison is normalized, so case, trailing dots, and surrounding quotes do
not matter, and extra answers beyond the expected ones are fine. With no
expected values, any successful resolution passes. Timeout (sec) bounds each
attempt (default 5), and Attempts (default 1, up to 10) retries failed
lookups with a half-second pause between tries.

## Output

The summary reads `dns <record type>: N/M lookups OK` and is available to
later steps as `steps.NODE_ID.summary`. Metrics record one `<device name>_ms`
resolution latency per successful lookup. Each target adds one
`transport_meta` evidence record named `dns_<record type>_<device name>`
capturing the queried name, record type, resolver (`system` when none was
set), the normalized answers, any missing expected values, and the error
text when resolution failed.

## When It Fails

The step fails when no target devices or IPs are configured, when Resolver
is not an IP address, and when the flow's network policy does not allow the
resolver; the policy's reason is then the step error. A target fails
when the lookup errors (NXDOMAIN, refusal, or timeout — the timeout applies
per attempt, not to the step as a whole), when any Expected Value is missing
from the answers, when the target has no name to resolve, or when it is a
direct-IP target without an explicit Name to Resolve. One failing target
fails the whole step, with the per-target reasons listed in the step error.
Evidence is kept for every target that was actually looked up; a target
skipped for having no name to resolve appears only in the step error.
