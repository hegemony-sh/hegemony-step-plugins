<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Connectivity Check

`probe.connectivity` runs a one-shot reachability probe against every target
of the step and records the result as evidence. It needs no device
credentials — it observes targets from the outside, the way the background
monitor does, and it uses the same probe implementations the monitor uses.
Use it as a checkpoint in a flow: prove the devices answer before a change,
or that they still answer after one.

## Using It

Targets come from the step's target picker: each selected role resolves to
its devices' management addresses, and explicit IP selectors add literal
addresses probed the same way. Check Type picks the probe — a TCP connection
attempt (the default), an ICMP echo, an HTTP health request, or a DNS lookup;
the list is registry-driven, so it shows whatever checks the platform
provides, and the value is validated when the step runs.

Port applies to the port-based checks and is ignored by ICMP Ping and DNS
Resolve; left empty, HTTP Health uses port 80 and the other checks port 22.
Timeout (sec) bounds each attempt (default 10), and Attempts (default 1, up
to 10) retries a failing target with a half-second pause between tries —
one success ends the retries for that target. Max Parallel Devices sets how
many targets are checked at the same time (default 10, up to 32); 1 checks
them one after another. Evidence and metrics always follow target order.

URL Path applies only to the HTTP Health check and falls back to `/health`
when omitted. HTTP Health passes on any status below 400 and does not
follow redirects, so a redirect counts as a healthy answer. Hostname to
Resolve applies only to the DNS Resolve check: the worker's system resolver
looks the name up once per target, and the target itself is not asked. Left
empty, each target's own name is looked up, so an IP address target fails
unless Hostname to Resolve is set. An IP address in Hostname to Resolve fails
the check too: the resolver hands an address back without a lookup.

The optional SOCKS5 Proxy routes the TCP-based checks through a
`socks5://user:pass@host:port` proxy (credentials optional; `socks5h://`
resolves DNS at the proxy), such as a lab bastion,
and its value may pull the password from a `{{ secret('...') }}` template.
Checks that cannot carry a proxy — ICMP Ping among them — reject a
configured one instead of silently probing the wrong path.

## Output

The summary reads `<check type>: N/M targets OK` and is available to later
steps as `steps.NODE_ID.summary`. Metrics record one `<device name>_ms`
latency per successful target, taken from the probe's round-trip or connect
time when it reports one. Each probed target adds one `transport_meta`
evidence record named `connectivity_<check type>_<device name>` capturing
the host, the check type, and either the probe's metrics or the error text.

## When It Fails

The step fails when no target devices or IPs are configured, and it aborts
immediately when the chosen check type is not registered on the worker. A
target with no management address counts as failed. Otherwise the step
succeeds only when every target passes its check within the configured
attempts; a single failing target fails the whole step, with the failing
targets and their errors listed in the step error. Evidence and metrics for
the targets already probed are kept even when the step fails. Timeout (sec)
bounds each probe attempt, not the step as a whole. Targets run Max Parallel
Devices at a time, so the worst case is roughly attempts times the timeout
for every group of that many targets: with the default of 10, ten slow
targets take about as long as one.
