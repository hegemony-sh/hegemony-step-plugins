<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Connectivity Monitor

`monitor.connectivity` starts a background monitor that keeps probing the
step's targets on a schedule while the rest of the flow runs. The step itself
finishes as soon as the monitor is started; the samples are collected in the
background by the platform's monitoring pipeline. Use it to watch whether
devices stay reachable during a disruptive change — an upgrade, a failover
test, a config push — happening in parallel branches of the flow.

## Using It

Check Type picks the probe sent on every sample — a TCP connection attempt
(the default), an ICMP echo, an HTTP health request, or a DNS lookup; the
list is registry-driven, and the value is validated when the step runs. Port
applies to the port-based checks and is ignored by ICMP Ping and DNS
Resolve; left empty, HTTP Health uses 80 and the other checks 22. URL Path
applies only to the HTTP Health check and falls back to `/health` when
omitted; HTTP Health passes on any status below 400 and does not follow
redirects. Ping Count (default 3, up to 10) sets how many echo requests each
ICMP Ping sample sends. DNS Resolve looks up each target's own name with the
worker's system resolver, so every sample of an IP address target fails.
Interval (ms) sets the time between samples (default 5000), and Timeout
(sec) is the per-sample time limit (default 10). Steps saved with the old
names `timeout_sec` (Timeout) and `duration_sec` (Duration) keep working.

Schedule Mode decides when sampling stops: Fixed Count stops after Count
samples (default 10), Duration stops after Duration (sec) seconds (default
60), and Until Join keeps the monitor running until the flow engine stops it
at the branch's join point, which is how a monitor brackets the steps running
alongside it.

Targets come from the step's target picker: each selected role resolves to
its devices' management addresses, and explicit IP selectors add literal
addresses. Devices without a management address are skipped. The optional
SOCKS Proxy (advanced) tunnels the TCP-based checks — TCP Connect and HTTP
Health — through a SOCKS5 proxy, in the form
`socks5://user:pass@host:port` (credentials optional; `socks5h://`
resolves DNS at the proxy), for targets only reachable through a
bastion; ICMP Ping and DNS Resolve cannot use it and reject a configured
proxy.

## Output

The step reports only the start of the monitor — the samples themselves are
recorded by the monitoring pipeline, not in the step output. The summary
notes the check type, target count, and schedule mode, readable later as
`steps.NODE_ID.summary`. Metrics record `monitor_db_id`, `target_count`,
`schedule_mode`, and `background_monitor: true`. One `transport_meta`
evidence record named `monitor_started_<monitor id>` captures the monitor
id, check id, schedule mode, interval, and target count.

## When It Fails

The step fails without starting anything when the check type is not a
registered check, when no target devices are configured, when no target
resolves to a usable address, or when starting the monitor raises an error
(the error text is surfaced on the step). Once the monitor is started the
step succeeds immediately: failed probes observed later do not fail this
step, and Timeout (sec) bounds each individual sample, not the step itself.
