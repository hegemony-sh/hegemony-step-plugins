# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``netconf.edit_config``: change the configuration as one NETCONF transaction."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    InvalidConfigError,
    OutputField,
    StepKind,
)

from .client import (
    CAP_CANDIDATE,
    CAP_ROLLBACK_ON_ERROR,
    NetconfError,
    NetconfSession,
    check_fragment,
    filter_xml,
)
from .common import (
    DeviceOutcome,
    NetconfConnectionConfig,
    SessionUnavailable,
    build_result,
    max_parallel_field,
    netconf_session,
    no_targets,
    persist_id_for,
    run_per_device,
    text_evidence,
    unavailable,
)
from .transaction import ChangeOptions, ChangeResult, change_candidate, change_running

HANDLER_ID = "netconf.edit_config"

#: What a change step puts in each device's entry of its output.
CHANGE_OUTPUT_FIELDS = (
    OutputField(
        "devices",
        "Each device's result by name: ok, error, datastore, changed, committed, pending, "
        "persist_id, validated, saved, save_error, save_requested (saved when confirmed), "
        "diff and notes",
        "object",
    ),
    OutputField("truncated", "Output texts cut short, as device.key", "list"),
)


class ChangeSettings(NetconfConnectionConfig):
    """How a change step commits; shared with vendor change steps built on this wheel."""

    dry_run: bool = Field(
        default=False,
        title="Dry run",
        description=(
            "Apply the change to the candidate, show the diff and validate it, then discard "
            "it: nothing is committed. Needs the candidate datastore."
        ),
    )
    commit_mode: Literal["check", "later", "direct"] = Field(
        default="check",
        title="Commit",
        description=(
            "Confirm in this step: a confirmed commit, confirmed once a second NETCONF "
            "session shows the device is still manageable, else rolled back. Confirm in a "
            "later step: a confirmed commit left pending for a netconf.commit step (or "
            "netconf.cancel_commit), which the device rolls back after Confirm Timeout. "
            "Commit directly: a plain commit. Defaults to confirm in this step."
        ),
        json_schema_extra={
            "x_option_labels": {
                "check": "Confirm in this step",
                "later": "Confirm in a later step",
                "direct": "Commit directly",
            }
        },
    )
    confirm_timeout_seconds: int = Field(
        default=600,
        ge=30,
        le=86400,
        title="Confirm Timeout (sec)",
        description=(
            "How long the device waits for the confirmation before it restores the previous "
            "configuration (30-86400). Defaults to 600."
        ),
        json_schema_extra={"x_hide_when": {"field": "commit_mode", "value": "direct"}},
    )
    validate_candidate: bool = Field(
        default=True,
        title="Validate",
        description=(
            "Validate the candidate before committing, when the device offers :validate. "
            "Defaults to on."
        ),
        json_schema_extra={"x_advanced": True},
    )
    save_config: bool = Field(
        default=False,
        title="Save to startup",
        description=(
            "After the commit is final, save running to startup: copy-config when the device "
            "has a startup datastore, else Cisco's save-config RPC. A pending commit is saved "
            "by the netconf.commit step that confirms it, whatever that step's own setting."
        ),
    )
    max_parallel_devices: int = max_parallel_field(1)

    def change_options(self) -> ChangeOptions:
        return ChangeOptions(
            commit_mode=self.commit_mode,
            confirm_timeout_seconds=self.confirm_timeout_seconds,
            dry_run=self.dry_run,
            validate=self.validate_candidate,
            save_config=self.save_config,
        )


class NetconfEditConfig(ChangeSettings):
    """Config for ``netconf.edit_config``."""

    config: str = Field(
        default="",
        title="Configuration",
        description=(
            "The configuration to apply: the XML that goes inside <config>, with each top "
            "node's namespace. Templates such as {{ inputs.vlan }} are filled in."
        ),
        json_schema_extra={
            "x_widget": "textarea",
            "x_rows": 12,
            "x_col_span": 2,
            "x_placeholder": (
                '<native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">\n'
                "  <hostname>r1</hostname>\n</native>"
            ),
        },
    )
    default_operation: Literal["merge", "replace", "none"] = Field(
        default="merge",
        title="Default Operation",
        description=(
            "Merge adds and changes nodes. Replace makes every node in Configuration match "
            "it exactly, removing what it leaves out under them: with the whole tree of a "
            "model it replaces that model's configuration. None applies only the nodes "
            "with an explicit operation attribute. Defaults to merge."
        ),
    )
    target: Literal["auto", "candidate", "running"] = Field(
        default="auto",
        title="Datastore",
        description=(
            "Where the change goes. Auto uses the candidate when the device has one, else "
            "running. Running applies at once: no dry run, diff before validation, or "
            "confirmed commit. Defaults to auto."
        ),
        json_schema_extra={"x_advanced": True},
    )
    diff_filter: str = Field(
        default="",
        title="Diff Filter",
        description=(
            "A subtree filter limiting the configuration read before and after the change "
            "for the diff, for devices with a large configuration. Empty reads it all."
        ),
        json_schema_extra={
            "x_widget": "textarea",
            "x_rows": 3,
            "x_col_span": 2,
            "x_advanced": True,
        },
    )

    @model_validator(mode="after")
    def _xml_parses(self) -> NetconfEditConfig:
        if not self.config.strip():
            raise ValueError("'config' is required")
        try:
            check_fragment(self.config, what="'config'")
            if self.diff_filter.strip():
                filter_xml("subtree", self.diff_filter)
        except NetconfError as exc:
            raise ValueError(str(exc)) from None
        if self.target == "running" and self.dry_run:
            raise ValueError("a dry run needs the candidate datastore")
        return self


def change_output(result: ChangeResult) -> dict[str, Any]:
    """A device's output entry for a change."""
    return {
        "datastore": result.datastore,
        "changed": result.changed,
        "committed": result.committed,
        "pending": result.pending,
        "persist_id": result.persist_id,
        "validated": result.validated,
        "saved": result.saved,
        "save_error": result.save_error,
        "save_requested": result.save_requested,
        "diff": result.diff,
        "notes": result.notes,
    }


def change_evidence(
    device: dict[str, Any], result: ChangeResult, *, what: str
) -> list[dict[str, Any]]:
    """The diff, and the configuration before and after, as text evidence (changes only)."""
    items: list[dict[str, Any]] = []
    if not result.changed:
        return items
    if result.diff:
        items.append(text_evidence(device, f"{what} diff", result.diff, command=f"{what} diff"))
    if result.before:
        items.append(
            text_evidence(device, f"{what} before", result.before, command=f"{what} before")
        )
    if result.after:
        items.append(
            text_evidence(
                device, f"{what} {result.datastore}", result.after, command=f"{what} after"
            )
        )
    return items


def raise_if_unsaved(result: ChangeResult) -> None:
    """Fail the device when saving failed, keeping its output and evidence."""
    if result.save_error:
        raise NetconfError(
            "the change was made, but saving it to startup failed: " + result.save_error
        )


def change_summary(prefix: str, outcomes: list[DeviceOutcome]) -> str:
    def count(key: str) -> int:
        return sum(1 for outcome in outcomes if outcome.ok and outcome.output.get(key))

    parts = [f"{count('changed')} changed", f"{count('committed')} committed"]
    if count("pending"):
        parts.append(f"{count('pending')} pending confirmation")
    failed = sum(not outcome.ok for outcome in outcomes)
    if failed:
        parts.append(f"{failed} failed")
    return f"{prefix}: " + ", ".join(parts) + f" of {len(outcomes)} devices"


def check_opener(ctx: HandlerContext, device: dict[str, Any], config: NetconfConnectionConfig):
    """The "is it still manageable" check: open and close a second session."""

    async def _check() -> None:
        async with netconf_session(ctx, device, config):
            pass

    return _check


class NetconfEditConfigHandler(BaseHandler):
    """Change each device's configuration with edit-config, as one transaction."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "NETCONF Edit Config"
    description = (
        "Change device configuration over NETCONF: candidate, diff, validate, dry run and "
        "confirmed commit."
    )
    category = "Actions"
    targeting = HandlerTargeting(ips=False)
    config_model = NetconfEditConfig
    default_config = {"default_operation": "merge", "commit_mode": "check"}
    output_fields = CHANGE_OUTPUT_FIELDS

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, NetconfEditConfig)
        except InvalidConfigError as exc:
            return exc.result()
        options = config.change_options()
        diff_filter = filter_xml("subtree", config.diff_filter)

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            outcome.text_keys = ("diff",)
            async with netconf_session(ctx, device, config) as session:
                use_candidate = config.target == "candidate" or (
                    config.target == "auto" and session.supports(CAP_CANDIDATE)
                )

                async def _read(source: str) -> str:
                    return (await session.get_config(source, diff_filter)).pretty_data()

                async def _apply() -> None:
                    await session.edit_config(
                        "candidate" if use_candidate else "running",
                        config.config,
                        default_operation=config.default_operation,
                        error_option=_error_option(session),
                    )

                if use_candidate:
                    result = await change_candidate(
                        session,
                        apply=_apply,
                        read=_read,
                        options=options,
                        check=check_opener(ctx, device, config),
                        diff_complete=not diff_filter,
                        persist_id=persist_id_for(ctx, device),
                    )
                else:
                    result = await change_running(
                        session,
                        apply=_apply,
                        read=_read,
                        options=options,
                        diff_complete=not diff_filter,
                    )
            outcome.output = change_output(result)
            outcome.evidence.extend(change_evidence(device, result, what="netconf"))
            raise_if_unsaved(result)

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except SessionUnavailable as exc:
            return unavailable(exc)
        return build_result(outcomes, summary=change_summary("netconf edit-config", outcomes))


def _error_option(session: NetconfSession) -> str:
    return "rollback-on-error" if session.supports(CAP_ROLLBACK_ON_ERROR) else ""
