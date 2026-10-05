<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Wait Reachable

`probe.wait_reachable` pauses the flow until every target is not just
reachable but *stably* reachable: continuously answering TCP connections for
a configured stability window. Put it after a disruptive step — a reboot, an
upgrade, a failover — so the flow resumes only once the devices have settled
rather than at their first flicker of life.

## Using It

Targets come from the step's target picker: each selected role resolves to
its devices, polled on their management address and management port (22 when
the inventory sets none); explicit IP selectors add literal addresses polled
on port 22. IPv4 and IPv6 targets both work. Each poll attempts a plain TCP
connection — no credentials, no login. Connect Timeout (sec) bounds each
connection attempt (default 5, up to 60); a target that does not answer in
time counts as unreachable for that poll.

Three timings shape the wait. Poll Interval (sec) is the pause between polls
(default 5). Stable (sec) is the stability window (default 30): a target
must answer every poll for this long, and a target that stops answering has
its window reset to zero. Max Wait (sec) is the overall deadline (default
300): the step fails once it passes without every target completing its
window. The step succeeds at the first moment all targets have been stable
for the full window; expect it to take at least Stable (sec) even when
everything is already up.

When the flow runs under an egress policy, every target is checked against
it once up front, and a denied target fails the step immediately with the
policy's reason instead of polling until the deadline.

## Output

On success the summary reads `All N target(s) stable for Xs` and is
available to later steps as `steps.NODE_ID.summary`. Metrics record
`attempts` (poll rounds), `elapsed_seconds`, `stable_seconds`, and
`device_count`. Each target adds one `transport_meta` evidence record named
`reachability_check_<device name>` capturing the polled host and port and
the stability window it met. On timeout only the `attempts` and
`elapsed_seconds` metrics are recorded, with no evidence records.

## When It Fails

The step fails immediately when no target devices or IPs are configured,
when a setting is out of range or of the wrong type, when any device has no
management address (waiting would only time out), or when an egress policy
denies a target. Otherwise the only failure is the
deadline: after Max Wait (sec) the step fails, naming the targets that were
unreachable at the last poll - a target that was reachable but still
partway through its stability window caused the failure too, without being
named. Momentary failures never fail the step by
themselves — an unreachable poll just resets that target's stability window
and the polling continues until the deadline.
