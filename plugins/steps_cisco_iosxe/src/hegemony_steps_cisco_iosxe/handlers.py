# SPDX-FileCopyrightText: 2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``cisco.iosxe.config_replace`` and ``cisco.iosxe.get_config``."""

from __future__ import annotations

import re
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
from hegemony_steps_netconf.common import (
    DeviceOutcome,
    NetconfConnectionConfig,
    SessionUnavailable,
    build_result,
    device_label,
    max_parallel_field,
    netconf_session,
    no_targets,
    persist_id_for,
    run_per_device,
    text_evidence,
    unavailable,
)
from hegemony_steps_netconf.edit_config import (
    CHANGE_OUTPUT_FIELDS,
    ChangeSettings,
    change_evidence,
    change_output,
    change_summary,
    check_opener,
    raise_if_unsaved,
    uncertain_output,
)
from hegemony_steps_netconf.transaction import CommitUncertain, change_candidate

from .acr import MAX_CLIS_CHARS, apply_cli_config, read_cli_config, require_acr

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _attachment_path_error(value: str) -> str | None:
    path = value.strip()
    if not path:
        return None
    if path.startswith("/") or "\\" in path or ".." in path.split("/"):
        return "'config_attachment' must be a relative path among the flow attachments"
    return None


class ConfigReplaceConfig(ChangeSettings):
    """Config for ``cisco.iosxe.config_replace``."""

    config: str = Field(
        default="",
        title="Configuration",
        description=(
            "The configuration as CLI text, as show running-config prints it, at most "
            "524288 characters. Templates such as {{ inputs.hostname }} are filled in. "
            "Leave empty to use Configuration File."
        ),
        json_schema_extra={
            "x_widget": "textarea",
            "x_rows": 14,
            "x_col_span": 2,
            "x_placeholder": "hostname r1\n!\ninterface Loopback0\n ip address 192.0.2.1 255.255.255.255",
        },
    )
    config_attachment: str = Field(
        default="",
        title="Configuration File",
        description=(
            "A flow attachment holding the configuration as CLI text, used when "
            "Configuration is empty. {device} in the path is the device's name, so each "
            "device gets its own file (configs/{device}.cfg)."
        ),
        json_schema_extra={"x_placeholder": "configs/{device}.cfg", "x_col_span": 2},
    )
    operation: Literal["full-replace", "selective-replace", "merge"] = Field(
        default="full-replace",
        title="Operation",
        description=(
            "Full replace makes the device's whole configuration this one, removing "
            "everything it leaves out. Selective replace replaces only the sections the "
            "configuration names. Merge adds and changes lines. Defaults to full replace."
        ),
        json_schema_extra={
            "x_option_labels": {
                "full-replace": "Full replace",
                "selective-replace": "Selective replace",
                "merge": "Merge",
            }
        },
    )

    @model_validator(mode="after")
    def _one_source(self) -> ConfigReplaceConfig:
        has_text = bool(self.config.strip())
        has_file = bool(self.config_attachment.strip())
        if has_text == has_file:
            raise ValueError("set exactly one of 'config' and 'config_attachment'")
        error = _attachment_path_error(self.config_attachment)
        if error:
            raise ValueError(error)
        if len(self.config) > MAX_CLIS_CHARS:
            raise ValueError(
                f"'config' has {len(self.config)} characters; IOS XE accepts at most "
                f"{MAX_CLIS_CHARS}"
            )
        return self


def _attachment_name(path: str, device: dict[str, Any]) -> str:
    name = _SAFE_NAME.sub("_", device_label(device)).strip("._") or "_"
    return path.strip().replace("{device}", name)


def _shared_attachment(path: str, devices: list[dict[str, Any]]) -> str | None:
    """Why two devices would read the same per-device file, or None.

    A ``{device}`` path is meant to give each device its own configuration;
    two devices with the same (or the same sanitised) name would both get one
    file, so a device could be replaced with another's configuration.
    """
    if "{device}" not in path:
        return None
    seen: dict[str, str] = {}
    for device in devices:
        name = _attachment_name(path, device)
        if name in seen:
            return (
                f"devices {seen[name]!r} and {device_label(device)!r} both resolve to the "
                f"attachment {name!r}; give the devices distinct names"
            )
        seen[name] = device_label(device)
    return None


def _find_attachment(attachments: list[dict[str, Any]], path: str) -> str | None:
    for item in attachments:
        if str(item.get("filename") or item.get("path") or "") == path:
            content = item.get("content")
            if isinstance(content, bytes):
                return content.decode("utf-8", "replace")
            return content if isinstance(content, str) else None
    return None


class ConfigReplaceHandler(BaseHandler):
    """Replace the whole configuration atomically with IOS XE ACR, over NETCONF."""

    handler_id = "cisco.iosxe.config_replace"
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "IOS XE Atomic Config Replace"
    description = (
        "Replace an IOS XE device's configuration atomically (ACR over NETCONF): diff, "
        "validate, dry run and confirmed commit."
    )
    category = "Actions"
    targeting = HandlerTargeting(ips=False)
    config_model = ConfigReplaceConfig
    default_config = {"operation": "full-replace", "commit_mode": "check"}
    output_fields = (
        OutputField(
            "devices",
            CHANGE_OUTPUT_FIELDS[0].description
            + "; also operation and acr_result (the device's result text for the replace)",
            "object",
        ),
        *CHANGE_OUTPUT_FIELDS[1:],
    )

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, ConfigReplaceConfig)
        except InvalidConfigError as exc:
            return exc.result()
        options = config.change_options()
        attachments: list[dict[str, Any]] = []
        if config.config_attachment.strip():
            clash = _shared_attachment(config.config_attachment, devices)
            if clash:
                return HandlerResult(
                    success=False,
                    error=clash,
                    summary="Config validation failed",
                )
            attachments = await ctx.require_services().fetch_run_attachments(ctx.run_id)

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            outcome.text_keys = ("diff",)
            clis = config.config
            if not clis.strip():
                path = _attachment_name(config.config_attachment, device)
                found = _find_attachment(attachments, path)
                if found is None:
                    raise ValueError(f"the flow has no attachment {path!r}")
                if not found.strip():
                    # A full replace with nothing would remove the whole configuration.
                    raise ValueError(f"the attachment {path!r} is empty")
                if len(found) > MAX_CLIS_CHARS:
                    raise ValueError(
                        f"{path!r} has {len(found)} characters; IOS XE accepts at most "
                        f"{MAX_CLIS_CHARS}"
                    )
                clis = found
            acr_result = ""
            async with netconf_session(ctx, device, config) as session:
                await require_acr(session)

                async def _read(datastore: str) -> str:
                    return await read_cli_config(session, datastore)

                async def _apply() -> None:
                    nonlocal acr_result
                    acr_result = await apply_cli_config(session, clis, config.operation)

                # get-modelled-config-clis returns modelled CLI only (no
                # wireless, app-hosting or telemetry), so an empty diff does
                # not show that the replace changes nothing.
                try:
                    result = await change_candidate(
                        session,
                        apply=_apply,
                        read=_read,
                        options=options,
                        check=check_opener(ctx, device, config),
                        diff_complete=False,
                        persist_id=persist_id_for(ctx, device),
                        check_pending=ctx.attempt > 1,
                    )
                except CommitUncertain as exc:
                    outcome.output = {**uncertain_output(exc), "operation": config.operation}
                    raise
            outcome.output = {
                **change_output(result),
                "operation": config.operation,
                "acr_result": acr_result,
            }
            outcome.evidence.extend(change_evidence(device, result, what="running-config"))
            if acr_result:
                outcome.evidence.append(
                    text_evidence(device, "acr result", acr_result, command="config-ios-cli-trans")
                )
            raise_if_unsaved(result)

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except SessionUnavailable as exc:
            return unavailable(exc)
        return build_result(outcomes, summary=change_summary(f"ACR {config.operation}", outcomes))


class GetConfigConfig(NetconfConnectionConfig):
    """Config for ``cisco.iosxe.get_config``."""

    datastore: Literal["running", "candidate"] = Field(
        default="running",
        title="Datastore",
        description="Read the running or the candidate configuration. Defaults to running.",
    )
    max_parallel_devices: int = max_parallel_field(10)


class GetConfigHandler(BaseHandler):
    """Read an IOS XE device's configuration as CLI text, over NETCONF."""

    handler_id = "cisco.iosxe.get_config"
    supported_kinds = [StepKind.CHECK, StepKind.EXECUTE]
    display_name = "IOS XE Get Config (CLI)"
    description = "Read an IOS XE device's modelled configuration as CLI text over NETCONF."
    category = "Checks"
    targeting = HandlerTargeting(ips=False)
    config_model = GetConfigConfig
    output_fields = (
        OutputField(
            "devices",
            "Each device's result by name: ok, error, datastore and config (the CLI text, "
            "cut short when long)",
            "object",
        ),
        OutputField("truncated", "Output texts cut short, as device.key", "list"),
    )

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        devices = ctx.get_target_devices()
        if not devices:
            return no_targets()
        try:
            config = self.parse_config(ctx.config, GetConfigConfig)
        except InvalidConfigError as exc:
            return exc.result()

        async def _work(device: dict[str, Any], outcome: DeviceOutcome) -> None:
            outcome.text_keys = ("config",)
            async with netconf_session(ctx, device, config) as session:
                text = await read_cli_config(session, config.datastore)
            outcome.output = {"datastore": config.datastore, "config": text}
            outcome.evidence.append(
                text_evidence(
                    device,
                    f"{config.datastore}-config",
                    text,
                    command=f"{config.datastore}-config",
                )
            )

        try:
            outcomes = await run_per_device(
                ctx, devices, _work, max_parallel=config.max_parallel_devices
            )
        except SessionUnavailable as exc:
            return unavailable(exc)
        done = sum(outcome.ok for outcome in outcomes)
        return build_result(
            outcomes, summary=f"IOS XE {config.datastore}-config: {done}/{len(outcomes)} devices"
        )
