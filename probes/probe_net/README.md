<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-probe-net

Network reachability probes for [Hegemony](https://github.com/hegemony-sh/hegemony).

Registers under the `hegemony.probes` entry-point group. Each probe implements
one `check_type` and is consumed by **both** the background `MonitorManager`
tick loop and the one-shot `probe.*` step handlers (through
`HandlerServices.run_probe`) — a single implementation serves both surfaces.

| `probe_id`     | Implementation                                        |
|----------------|-------------------------------------------------------|
| `tcp_connect`  | `asyncio.open_connection`, reports `connect_ms`       |
| `icmp_ping`    | system `ping`, reports rtt/jitter/packet-loss         |
| `http_health`  | `httpx` GET, ok on status < 400, no redirects         |
| `dns_resolve`  | stdlib `getaddrinfo`, reports resolved address count  |

Probe ids are a small global vocabulary (they appear in monitor configs and run
histories) and — unlike step-handler ids — are not namespaced per wheel.
