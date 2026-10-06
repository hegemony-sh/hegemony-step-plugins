<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Wait Reachable

`probe.wait_reachable` pauses the flow until every target is not just
reachable but *stably* reachable: continuously answering a reachability
check, by default a TCP connection, for a configured stability window. Put
it after a disruptive step — a reboot, an upgrade, a failover — so the flow
resumes only once the devices have settled rather than at their first
flicker of life.

## Using It

Targets come from the step's target picker: each selected role resolves to
its devices' management addresses, and explicit IP selectors add literal
addresses. IPv4 and IPv6 targets both work. Check Type picks the check each
poll runs — a plain TCP connection by default, or another check the
platform provides, such as an ICMP echo or an HTTP health request; the list
is registry-driven, and none of them uses credentials or logs in. It runs
the same checks as `probe.connectivity`.

Port applies to the port-based checks and is ignored by ICMP Ping and DNS
Resolve. Left empty, a device is polled on its management port (22 when the
inventory sets none) and a direct IP target on port 22, while HTTP Health
uses port 80. Connect Timeout (sec) bounds each poll of a target (default 5,
up to 60); a target that does not answer in time counts as unreachable for
that poll.

The optional SOCKS5 Proxy routes the TCP-based checks through a
`socks5://user:pass@host:port` proxy (credentials optional; `socks5h://`
resolves DNS at the proxy), such as a lab bastion, and its value may pull
the password from a `{{ secret('...') }}` template. ICMP Ping and DNS
Resolve cannot use a proxy and reject a configured one.

Three timings shape the wait. Poll Interval (sec) is the pause between polls
(default 5). Stable (sec) is the stability window (default 30): a target
must answer every poll for this long, counted from its first answer to its
latest, and a target that stops answering has its window reset to zero. Max Wait (sec) is the overall deadline (default
300): the step fails once it passes without every target completing its
window. The step succeeds at the first moment all targets have been stable
for the full window; expect it to take at least Stable (sec) even when
everything is already up. The step's timeout is raised to Max Wait (sec)
plus a minute when it is shorter, so the wait ends on its own deadline and
the error names the targets that were not reachable. Steps saved with the
older names keep working: `max_wait` for Max Wait (sec), and `poll_interval`
or `check_interval` for Poll Interval (sec).

Each poll round checks every target, up to Max Parallel Devices at the same
time (default 10, up to 32; 1 polls them one after another). No poll runs
past Max Wait (sec): one that starts near the deadline gets only the time
left, and the deadline is checked again when the round ends.

When the flow runs under an egress policy, every poll is checked against
it, the proxy included, and a denied target fails the step on its first poll
with the policy's reason instead of polling until the deadline.

## Output

On success the summary reads `All N target(s) stable for Xs` and is
available to later steps as `steps.NODE_ID.summary`. Metrics record
`attempts` (poll rounds), `elapsed_seconds`, `stable_seconds`, and
`device_count`. Each target adds one `transport_meta` evidence record named
`reachability_check_<device name>` capturing the polled host, the check
type, the port (empty for a check without one), and the stability window it
met. On timeout only the `attempts` and `elapsed_seconds` metrics are
recorded, with no evidence records.

## When It Fails

The step fails immediately when no target devices or IPs are configured,
when a setting is out of range or of the wrong type, or when any device has
no management address (waiting would only time out). It fails on the first
poll when an egress policy denies a target, when the check type is not
registered on the worker, or when the check refuses its settings, such as
ICMP Ping with a SOCKS5 Proxy, a SOCKS5 Proxy that is not a `socks5://` or
`socks5h://` URL with a host and port, or DNS Resolve of an IP address: no
later poll could pass. Otherwise the only failure is the deadline: after Max
Wait (sec) the step fails, naming the targets that were unreachable at the
last poll - a target that was reachable but still partway through its
stability window caused the failure too, without being named. Momentary
failures never fail the step by themselves — an unreachable poll, including
one through a proxy that does not answer or refuses the login, just resets
that target's stability window and the polling continues until the deadline.
