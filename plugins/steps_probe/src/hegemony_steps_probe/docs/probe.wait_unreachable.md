<!--
SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Wait Unreachable

`probe.wait_unreachable` pauses the flow until every target has stopped
answering a reachability check, by default a TCP connection, for a short
window. Put it right after a step that starts a reload, and before
`probe.wait_reachable`: a device can keep answering from its old software
for a while after it accepts a `reload`, so a wait for it to come back
could pass before it ever went away, and a check after it would read the
old software.

## Using It

The settings are those of `probe.wait_reachable`, with two that mean the
opposite here. Targets come from the step's target picker: each selected
role resolves to its devices' management addresses, and explicit IP
selectors add literal addresses. Check Type picks the check each poll runs
(a TCP connection by default, or an ICMP echo, an HTTP health request or
another check the platform provides); none of them logs in. Port, URL Path,
Connect Timeout (sec), SOCKS5 Proxy and Max Parallel Devices work as they
do there.

Down For (sec) (default 10) is how long a target must fail every poll
before it counts as down, counted from its first failed poll to its latest,
so one lost packet is not taken for a reload. A target that answers again
starts its count over. 0 counts the first failed poll. Once a target counts
as down it stays down for the rest of the step and is not polled again,
because a quick reload can bring it back before slower targets go down.
Max Wait (sec) (default 300) is the overall deadline, and Down For (sec)
must be shorter. The step's timeout is raised to Max Wait (sec) plus a
minute when it is shorter. Poll Interval (sec) (default 5) is the pause
between poll rounds.

A poll counts as failed when the target does not answer in time, refuses
the connection, cannot be routed to, or fails the HTTP health request,
also when a SOCKS5 proxy reports one of these for the target. A poll that
shows the check itself could not run does not count either way: a SOCKS5
proxy that fails or refuses the login, a probe that fails with an
unexpected error, a ping command missing on the worker. Such a poll starts
the target's count over, so a broken proxy cannot make a device that is
still up look down. A poll the deadline cuts short counts only when it got
an answer or a clear refusal; silence for less than Connect Timeout (sec)
proves nothing.

A target that does not answer from the first poll counts as down too
(already down), for example when it reloaded before the step began. The
output tells it apart from a target that was seen going down.

## Output

Later steps can read:

- `steps.NODE_ID.output.went_down`: the targets that answered at first and
  then stopped answering.
- `steps.NODE_ID.output.already_down`: the targets that never answered
  during the wait.
- `steps.NODE_ID.output.still_up`: the targets that were not down when the
  step ended (empty when it succeeds).
- `steps.NODE_ID.output.elapsed_seconds`: how long the wait took.

Targets are named by their device name, or by their address for an IP
target. On success the summary reads
`All N target(s) down for Xs (W went down, A already down)`. Metrics record
`attempts` (poll rounds), `elapsed_seconds`, `down_seconds` and
`device_count`. Each target adds one `transport_meta` evidence record named
`unreachability_check_<device name>` with the polled host, the check type,
the port (empty for a check without one), whether it answered first, and
how many seconds into the step it counted as down. On timeout only the
`attempts` and `elapsed_seconds` metrics are recorded, with no evidence
records.

## When It Fails

The step fails immediately when no target devices or IPs are configured,
when a setting is out of range or of the wrong type, when Down For (sec)
is not shorter than Max Wait (sec), or when any device has no management
address. It fails on the first poll when an egress policy denies a target,
when the check type is not registered on the worker, or when the check
refuses its settings, such as ICMP Ping with a SOCKS5 Proxy. Otherwise the
only failure is the deadline: after Max Wait (sec) the step fails with the
summary `Targets still reachable after Xs`, and its error names the targets
that still answered, those that had stopped answering but not yet for Down
For (sec), and those whose check could not run, with the reason.
