# SPDX-FileCopyrightText: 2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""container.run's ``trusted_cas`` option: the organization's CAs as read-only files.

Off by default, so an image that brings its own trust store runs unchanged;
on, the container gets the system store plus the organization's CAs and the
usual variables point at it, unless the step sets them itself.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from hegemony_step_sdk import HandlerContext, HandlerResult, HandlerServices
from hegemony_step_sdk.trust import CONTAINER_CA_BUNDLE, CONTAINER_ORG_CAS
from hegemony_steps_container import run as run_module
from hegemony_steps_container.run import RunContainerHandler

ORG_PEM = "-----BEGIN CERTIFICATE-----\nT1JHIENB\n-----END CERTIFICATE-----\n"
SYSTEM_PEM = "-----BEGIN CERTIFICATE-----\nU1lTVEVN\n-----END CERTIFICATE-----\n"


class _Services:
    def __init__(self, org_pem: str | None = ORG_PEM, error: BaseException | None = None):
        self.org_pem = org_pem
        self.error = error
        self.trust_calls = 0

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        return ""

    async def trusted_ca_certificates(self) -> str:
        self.trust_calls += 1
        if self.error is not None:
            raise self.error
        return self.org_pem or ""


class _OldHost:
    """A platform that predates the trusted-CA service."""

    async def resolve_secret_ref(self, ref: str | None, *, source: str) -> str | None:
        return ""


def _ctx(config: dict[str, Any], services: Any) -> HandlerContext:
    return HandlerContext(
        run_id="run-12345678",
        flow_id="flow-1",
        step_run_id="step-12345678",
        step_id="step-1",
        config={"image": "alpine:3.20", "command": ["echo hi"], **config},
        services=cast(HandlerServices, services),
    )


@pytest.fixture
def jobs(monkeypatch) -> list[Any]:
    """Capture the job ``execute`` hands to the runner instead of running it."""
    seen: list[Any] = []

    async def run_job(self, ctx, job):
        seen.append(job)
        return HandlerResult(success=True, summary="captured")

    monkeypatch.setattr(RunContainerHandler, "run_job", run_job)
    monkeypatch.setattr(run_module, "combined_ca_pem", lambda org: SYSTEM_PEM + org)
    return seen


def _ca_files(job: Any) -> dict[str, Any]:
    return {f.path: f for f in job.files if f.path.startswith("/hegemony/ca/")}


async def test_the_option_is_off_by_default(jobs):
    services = _Services()
    await RunContainerHandler().execute(_ctx({}, services))
    [job] = jobs
    assert _ca_files(job) == {}
    assert "SSL_CERT_FILE" not in (job.config.get("env") or {})
    assert services.trust_calls == 0


async def test_on_it_stages_both_bundles_read_only_and_points_the_variables_at_them(jobs):
    await RunContainerHandler().execute(_ctx({"trusted_cas": True, "env": {"A": "1"}}, _Services()))
    [job] = jobs
    files = _ca_files(job)
    assert files[CONTAINER_CA_BUNDLE].content == SYSTEM_PEM + ORG_PEM
    assert files[CONTAINER_ORG_CAS].content == ORG_PEM
    assert {f.mode for f in files.values()} == {0o444}
    assert job.config["env"] == {
        "A": "1",
        "SSL_CERT_FILE": CONTAINER_CA_BUNDLE,
        "REQUESTS_CA_BUNDLE": CONTAINER_CA_BUNDLE,
        "CURL_CA_BUNDLE": CONTAINER_CA_BUNDLE,
        "NODE_EXTRA_CA_CERTS": CONTAINER_ORG_CAS,
    }


async def test_a_variable_the_step_sets_wins(jobs):
    config = {"trusted_cas": True, "env": {"SSL_CERT_FILE": "/etc/ssl/mine.pem"}}
    ctx = _ctx(config, _Services())
    await RunContainerHandler().execute(ctx)
    [job] = jobs
    assert job.config["env"]["SSL_CERT_FILE"] == "/etc/ssl/mine.pem"
    assert job.config["env"]["REQUESTS_CA_BUNDLE"] == CONTAINER_CA_BUNDLE
    # The step's own config is left as written.
    assert "REQUESTS_CA_BUNDLE" not in ctx.config["env"]


@pytest.mark.parametrize("services", [_Services(org_pem=""), _OldHost()])
async def test_nothing_changes_without_organization_cas(jobs, services):
    await RunContainerHandler().execute(_ctx({"trusted_cas": True}, services))
    [job] = jobs
    assert _ca_files(job) == {}
    assert "env" not in job.config


async def test_an_unavailable_list_fails_before_the_container_runs(jobs):
    services = _Services(error=RuntimeError("database unavailable"))
    result = await RunContainerHandler().execute(_ctx({"trusted_cas": True}, services))
    assert result.success is False
    assert result.error == "Could not load the organization's trusted CAs: database unavailable"
    assert jobs == []
