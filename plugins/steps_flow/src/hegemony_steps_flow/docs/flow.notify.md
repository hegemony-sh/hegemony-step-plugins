<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Send Notification

`flow.notify` sends a custom notification from the middle of a flow to one
of the platform's configured notification destinations (Slack, Teams, and
similar). Use it to announce milestones, results, or hand-off points while
the run is still going, with a title and message you write yourself.

## Using It

Notification Destination is the only required field: pick one of the
destinations already configured on the platform. The step looks the
destination up at run time, so a destination that has since been removed or
disabled fails the step.

Title and Message are templates edited with the notification-template
editor. Unlike ordinary step config they are not resolved by the step
engine; the notification renderer evaluates them with the full notification
context — `run.*` values, the event name, the UI base URL, target lines,
the outputs of preceding steps under `steps.*`, plus `secret()`, `env()`,
and flow variables. A blank Title or Message falls back to the shared
default notification template for that part.

Besides delivering the notification, the step records a run event noting
the destination and whether the send succeeded, so on-demand notifications
show up in the run's event log.

## Output

The step returns no chainable output keys. Once a send is
attempted, it records a `notification_result` evidence artifact holding
the destination id and name, the rendered title, whether the send
succeeded, and the error text when it did not, and metrics record `sent`
and `failed` — one of them 1, the other 0. Failures before dispatch (no
destination configured, or the destination cannot be fetched) return only
the step error, with no metrics and no evidence.

## When It Fails

The step fails when no destination is configured, when the destination
cannot be fetched (unknown or disabled, an API error, or a 30-second
timeout while looking it up), or when handing the rendered notification to
the destination's provider raises an error — the provider's error text
becomes the step error. A send the provider accepts succeeds; failure to
write the informational run event is logged but never fails the step.
