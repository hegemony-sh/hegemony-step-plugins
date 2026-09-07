# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SendNotificationHandler: send on-demand notifications from worker."""

import logging
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    StepKind,
)

logger = logging.getLogger(__name__)


class SendNotificationConfig(BaseModel):
    """Config for ``flow.notify``.

    ``title``/``message`` are raw notification templates rendered by this
    handler's own JIT renderer (see ``raw_config_keys``); the editor manages
    them with a dedicated notification-template editor, so only the
    destination is schema-driven.
    """

    model_config = ConfigDict(extra="allow")

    destination_id: str = Field(
        min_length=1,
        title="Notification Destination",
        description="Where to send the notification (Slack, Teams, etc.)",
        json_schema_extra={
            "x_widget": "destination-select",
            "x_placeholder": "Select destination...",
            "x_col_span": 2,
        },
    )
    title: str = Field(
        default="",
        title="Title",
        description=(
            "Notification title template, rendered by the notification "
            "renderer with the full notification context (run values, step "
            "outputs, secret()/env() helpers). Leave empty to use the shared "
            "default title template."
        ),
        json_schema_extra={"x_hidden": True},
    )
    message: str = Field(
        default="",
        title="Message",
        description=(
            "Notification body template, rendered by the notification "
            "renderer with the full notification context (run values, step "
            "outputs, secret()/env() helpers). Leave empty to use the shared "
            "default body template."
        ),
        json_schema_extra={"x_hidden": True},
    )


class SendNotificationHandler(BaseHandler):
    """Handler for sending on-demand notifications to configured destinations.

    This allows flows to send custom notifications at any point, using
    existing notification destinations but with custom messages.
    """

    handler_id = "flow.notify"
    supported_kinds = [StepKind.ACTION]
    display_name = "Send Notification"
    description = "Send an on-demand notification to a configured destination."
    category = "Notifications"
    targeting = HandlerTargeting(roles=False, ips=False)
    config_model = SendNotificationConfig

    # title/message are notification templates rendered by this handler with the
    # notification context (run.*, event, ui_base_url, target_lines, steps, plus
    # secret()/env()/vars). Keep them raw so the strict step engine does not try
    # to resolve notification vars it does not know about.
    raw_config_keys = frozenset({"title", "message"})

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Send a notification to the configured destination."""
        services = ctx.require_services()

        destination_id = ctx.config.get("destination_id")
        if not destination_id:
            return HandlerResult(
                success=False,
                error="Missing required config: destination_id",
                summary="No notification destination specified",
            )

        # title/message are RAW templates (see raw_config_keys); collect the ones
        # the user set as per-step overrides over the shared default templates.
        override: dict[str, str] = {}
        title_template = ctx.config.get("title")
        if isinstance(title_template, str) and title_template.strip():
            override["title"] = title_template
        message_template = ctx.config.get("message")
        if isinstance(message_template, str) and message_template.strip():
            override["body"] = message_template

        # Fetch destination info from API
        try:
            async with services.open_api_client(timeout=30) as client:
                response = await client.get(
                    f"/internal/notification-destinations/{destination_id}",
                )

                if response.status_code == 404:
                    return HandlerResult(
                        success=False,
                        error="Notification destination not found or disabled",
                        summary="Invalid destination",
                    )
                elif response.status_code != 200:
                    return HandlerResult(
                        success=False,
                        error=f"API error fetching destination: {response.status_code}",
                        summary="Failed to fetch destination",
                    )

                dest_data = response.json()

                # Validate required keys in destination response
                required_keys = {"id", "name", "type", "config_json"}
                missing = required_keys - dest_data.keys()
                if missing:
                    return HandlerResult(
                        success=False,
                        error=f"Destination response missing keys: {missing}",
                        summary="Invalid destination data from API",
                    )

        except httpx.TimeoutException:
            return HandlerResult(
                success=False,
                error="Timeout fetching destination info",
                summary="Timeout fetching destination",
            )
        except Exception as e:
            logger.error(
                f"Error fetching destination: run_id={ctx.run_id}, step_id={ctx.step_id}, error={e}"
            )
            return HandlerResult(
                success=False,
                error=str(e),
                summary="Error fetching destination info",
            )

        # Render title/body via the notification single-JIT renderer: per-step
        # overrides over the shared defaults, with the full notification context
        # (run.*, event, ui_base_url, target_lines), preceding step outputs, and
        # secret()/env()/vars resolution -- all in one pass.
        run_context = {
            "id": ctx.run_id,
            "name": ctx.run_name,
            "flow_name": ctx.flow_name,
            "status": "running",
        }
        title, rendered_message = await services.format_run_notification(
            "notification.sent",
            run_context=run_context,
            overrides=override or None,
            steps=ctx.step_outputs or None,
        )

        # Dispatch notification directly from worker
        try:
            await services.dispatch_notification(
                destination_type=dest_data["type"],
                destination_config=dest_data["config_json"],
                title=title,
                body=rendered_message,
            )

            logger.info(
                f"On-demand notification sent: run_id={ctx.run_id}, step_id={ctx.step_id}, "
                f"destination={dest_data['name']}, type={dest_data['type']}"
            )

            await self._emit_notification_event(
                ctx=ctx,
                destination_name=dest_data["name"],
                sent=1,
                failed=0,
            )

            return HandlerResult(
                success=True,
                summary="Notification sent successfully",
                metrics={"sent": 1, "failed": 0},
                evidence=[
                    {
                        "kind": "step_result",
                        "name": "notification_result",
                        "content_json": {
                            "destination_id": destination_id,
                            "destination_name": dest_data["name"],
                            "title": title,
                            "sent": True,
                        },
                    }
                ],
            )

        except Exception as e:
            error_msg = str(e)
            logger.warning(
                f"On-demand notification failed: run_id={ctx.run_id}, step_id={ctx.step_id}, "
                f"destination={dest_data['name']}, error={e}"
            )

            await self._emit_notification_event(
                ctx=ctx,
                destination_name=dest_data["name"],
                sent=0,
                failed=1,
                error=error_msg,
            )

            return HandlerResult(
                success=False,
                error=f"Notification failed: {error_msg}",
                summary="Failed to send notification",
                metrics={"sent": 0, "failed": 1},
                evidence=[
                    {
                        "kind": "step_result",
                        "name": "notification_result",
                        "content_json": {
                            "destination_id": destination_id,
                            "destination_name": dest_data.get("name", "Unknown"),
                            "title": title,
                            "sent": False,
                            "error": error_msg,
                        },
                    }
                ],
            )

    async def _emit_notification_event(
        self,
        ctx: HandlerContext,
        destination_name: str,
        sent: int,
        failed: int,
        error: str | None = None,
    ) -> None:
        """Emit a run event for an on-demand notification send."""
        message = (
            f"Notification sent to {destination_name}"
            if failed == 0
            else f"Notification failed to {destination_name}"
        )
        attrs: dict[str, Any] = {
            "event": "flow.notify",
            "destination": destination_name,
            "sent": sent,
            "failed": failed,
        }
        if error:
            attrs["error"] = error

        try:
            async with ctx.require_services().open_api_client(timeout=30) as client:
                response = await client.post(
                    f"/internal/runs/{ctx.run_id}/events",
                    json={
                        "step_run_id": ctx.step_run_id,
                        "step_id": ctx.step_id,
                        "phase": ctx.tags.get("phase", ""),
                        "kind": "notification",
                        "message": message,
                        "attrs": attrs,
                    },
                )
                if response.status_code not in (200, 201):
                    logger.warning(
                        "Failed to emit notification event: "
                        f"status={response.status_code}, run_id={ctx.run_id}, step_id={ctx.step_id}"
                    )
        except httpx.TimeoutException:
            logger.warning(
                f"Notification event emit timed out: run_id={ctx.run_id}, step_id={ctx.step_id}"
            )
        except Exception as emit_error:
            logger.warning(
                f"Failed to emit notification event: run_id={ctx.run_id}, step_id={ctx.step_id}, error={emit_error}"
            )
