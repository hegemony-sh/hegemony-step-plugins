# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The output fields the target probes declare for the editor's variable picker.

``probe.connectivity``, ``probe.dns`` and ``probe.http`` build their output
with ``chain_output``, so they declare the same fields; ``probe.tls`` is
covered in ``test_probe_tls.py``.
"""

from __future__ import annotations

from typing import cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerServices, ProbeResult
from hegemony_step_sdk.docs import load_docs_bundle
from hegemony_steps_probe.connectivity import ConnectivityCheckHandler
from hegemony_steps_probe.dns_check import DnsProbeHandler
from hegemony_steps_probe.http_check import HttpProbeHandler
from hegemony_steps_probe.targets import TARGETS_OUTPUT_FIELDS

_TARGET_PROBES = (ConnectivityCheckHandler, DnsProbeHandler, HttpProbeHandler)


async def test_the_declared_output_fields_are_the_keys_the_step_outputs():
    class _Services:
        async def run_probe(self, check_type, address, options):
            if address == "192.0.2.8":
                return ProbeResult(ok=False, error_kind="timeout", error_detail="no reply")
            return ProbeResult(ok=True, metrics={"rtt_ms": 2.5})

    ctx = HandlerContext(
        run_id="r",
        flow_id="f",
        step_run_id="sr",
        step_id="s",
        config={"check_type": "icmp_ping", "timeout_sec": 3},
        step_target_ips=["192.0.2.7", "192.0.2.8"],
        services=cast(HandlerServices, _Services()),
    )
    result = await ConnectivityCheckHandler().execute(ctx)

    declared = [field.name for field in ConnectivityCheckHandler.output_fields]
    assert len(declared) == len(set(declared))
    assert set(declared) == set(result.output)


@pytest.mark.parametrize("handler", _TARGET_PROBES)
def test_the_target_probes_declare_what_chain_output_builds(handler):
    assert handler.output_fields == TARGETS_OUTPUT_FIELDS


@pytest.mark.parametrize("handler", _TARGET_PROBES)
def test_the_docs_page_names_every_declared_output_field(handler):
    text = load_docs_bundle("hegemony_steps_probe")[handler.handler_id]
    for field in handler.output_fields:
        assert f"output.{field.name}`" in text, field.name
        assert field.description and field.type, field.name
