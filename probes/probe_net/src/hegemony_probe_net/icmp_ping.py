# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""ICMP ping probe.

Runs the system ``ping`` command via an asyncio subprocess (cross-platform),
extracting RTT/jitter/packet-loss metrics.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import platform
import re
from typing import Any

from hegemony_step_sdk import BaseProbe, ProbeResult

logger = logging.getLogger(__name__)

# Regex patterns for parsing ping output.
# Linux: "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"
LINUX_RTT_PATTERN = re.compile(r"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms")
# Windows: "Minimum = 1ms, Maximum = 2ms, Average = 1ms"
WINDOWS_RTT_PATTERN = re.compile(r"Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms")
# Single ping RTT — Linux: "time=0.123 ms"
LINUX_SINGLE_RTT = re.compile(r"time=([\d.]+)\s*ms")
# Windows: "time=1ms" or "time<1ms"
WINDOWS_SINGLE_RTT = re.compile(r"time[<=]([\d.]+)ms")


def calculate_jitter(rtt_values: list[float]) -> float | None:
    """Mean absolute difference between consecutive RTTs (simplified RFC 3550)."""
    if len(rtt_values) < 2:
        return None
    diffs = [abs(rtt_values[i + 1] - rtt_values[i]) for i in range(len(rtt_values) - 1)]
    return sum(diffs) / len(diffs)


class IcmpPingProbe(BaseProbe):
    """ICMP ping probe using the system ping command.

    Options:
        count: Number of pings to send (default: 1)
        timeout_ms: Timeout per ping in milliseconds (default: 1000)

    Metrics produced:
        rtt_ms, rtt_min_ms, rtt_max_ms, rtt_mdev_ms (Linux), jitter_ms,
        packets_sent, packets_received, packet_loss_pct
    """

    probe_id = "icmp_ping"

    async def execute(self, address: str, options: dict[str, Any]) -> ProbeResult:
        # ICMP cannot traverse an SSH tunnel / SOCKS proxy (design §11.4):
        # reject the option explicitly rather than silently ignoring it and
        # reporting misleading local reachability. tcp_connect:22 is the
        # recommended liveness substitute for tunneled targets.
        if (options.get("socks_proxy") or "").strip():
            return ProbeResult(
                ok=False,
                error_kind="config_error",
                error_detail=(
                    "icmp_ping cannot use socks_proxy (ICMP does not traverse a "
                    "SOCKS/SSH tunnel); use tcp_connect for tunneled targets"
                ),
            )

        count = options.get("count", 1)
        timeout_ms = options.get("timeout_ms", 1000)
        timeout_sec = timeout_ms / 1000.0

        is_windows = platform.system().lower() == "windows"
        if is_windows:
            cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), address]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(max(1, int(timeout_sec))), address]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, _stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout_sec * count + 5,  # extra buffer
                )
            except TimeoutError:
                return ProbeResult(
                    ok=False,
                    error_kind="timeout",
                    error_detail=f"Ping command timed out after {timeout_sec * count + 5}s",
                )
            finally:
                # Our own timeout, or a caller cancelling the probe (a shorter
                # poll deadline, a sibling target's egress denial), stops
                # communicate() with ping still running. Kill and reap it
                # before returning or re-raising, so no child outlives us.
                if process.returncode is None:
                    with contextlib.suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()

            output = stdout.decode("utf-8", errors="replace")
            return self._parse_output(output, process.returncode, is_windows)

        except FileNotFoundError:
            return ProbeResult(
                ok=False,
                error_kind="command_not_found",
                error_detail="ping command not found on system",
            )
        except Exception as e:  # noqa: BLE001 - probe never raises for a single target
            logger.exception("Ping check failed for %s", address)
            return ProbeResult(ok=False, error_kind="exception", error_detail=str(e))

    def _extract_individual_rtts(self, output: str, is_windows: bool) -> list[float]:
        """Extract individual RTT values from ping output for jitter calculation."""
        pattern = WINDOWS_SINGLE_RTT if is_windows else LINUX_SINGLE_RTT
        return [float(match.group(1)) for match in pattern.finditer(output)]

    def _parse_output(self, output: str, return_code: int | None, is_windows: bool) -> ProbeResult:
        """Parse ping command output to extract metrics."""
        metrics: dict[str, Any] = {}
        individual_rtts = self._extract_individual_rtts(output, is_windows)

        if is_windows:
            match = WINDOWS_RTT_PATTERN.search(output)
            if match:
                metrics["rtt_min_ms"] = float(match.group(1))
                metrics["rtt_max_ms"] = float(match.group(2))
                metrics["rtt_ms"] = float(match.group(3))
            elif individual_rtts:
                metrics["rtt_ms"] = individual_rtts[-1]
        else:
            match = LINUX_RTT_PATTERN.search(output)
            if match:
                metrics["rtt_min_ms"] = float(match.group(1))
                metrics["rtt_ms"] = float(match.group(2))  # avg
                metrics["rtt_max_ms"] = float(match.group(3))
                metrics["rtt_mdev_ms"] = float(match.group(4))
            elif individual_rtts:
                metrics["rtt_ms"] = individual_rtts[-1]

        if len(individual_rtts) >= 2:
            jitter = calculate_jitter(individual_rtts)
            if jitter is not None:
                metrics["jitter_ms"] = round(jitter, 3)
        elif "rtt_mdev_ms" in metrics:
            metrics["jitter_ms"] = metrics["rtt_mdev_ms"]

        # Packet statistics.
        # Linux: "2 packets transmitted, 2 received, 0% packet loss"
        # Windows: "Packets: Sent = 2, Received = 2, Lost = 0 (0% loss)"
        sent_match = re.search(r"(\d+)\s*packets?\s*(?:transmitted|Sent)", output, re.I)
        recv_match = re.search(r"(\d+)\s*(?:packets?\s*)?received", output, re.I)
        loss_match = re.search(r"(\d+(?:\.\d+)?)[%]\s*(?:packet\s*)?loss", output, re.I)
        if sent_match:
            metrics["packets_sent"] = int(sent_match.group(1))
        if recv_match:
            metrics["packets_received"] = int(recv_match.group(1))
        if loss_match:
            metrics["packet_loss_pct"] = float(loss_match.group(1))

        ok = return_code == 0 and metrics.get("packets_received", 0) > 0

        if not ok and not metrics:
            error_detail = output.strip()[:500] if output else "No response"
            return ProbeResult(
                ok=False, error_kind="no_response", error_detail=error_detail, raw_text=output
            )

        return ProbeResult(
            ok=ok,
            metrics=metrics,
            raw_text=output if not ok else None,
            error_kind="packet_loss" if not ok else None,
            error_detail=f"{metrics.get('packet_loss_pct', 100)}% packet loss" if not ok else None,
        )
