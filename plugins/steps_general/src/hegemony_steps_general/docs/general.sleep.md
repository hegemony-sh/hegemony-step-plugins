<!--
SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Sleep

`general.sleep` pauses the flow for a fixed number of seconds, then lets
execution continue. Use it for settling time between actions — waiting for
a routing protocol to converge, a service to finish restarting, or a change
to propagate — when there is nothing to poll and a plain delay is enough.

## Using It

Duration sets the wait: the step pauses exactly that many
seconds (default 30; minimum 1) and then succeeds. The wait is a plain
timer — nothing is checked or polled while it runs — and the step targets
no devices, so there is no target picker. The step's timeout is raised to
the duration plus a minute when it is shorter, so a long sleep is not cut
off. A step saved with the setting's old name, `seconds`, still works.

Message is an optional note explaining why the flow is waiting, e.g.
"Waiting for BGP to converge". It is logged when the sleep starts and
becomes the step's summary when it completes. A blank or omitted message
gives the generated "Sleeping for N seconds" text. Like other config fields it
is resolved by the step template engine first, so it can reference flow
inputs or earlier steps, e.g. `Settling after {{ steps.NODE_ID.summary }}`.

## Output

The step adds no custom chainable output keys; its summary — the message,
or the generated text — is what later steps can reference as
`steps.NODE_ID.summary`. Metrics record `sleep_seconds`, the configured
duration. One `step_result` evidence record named `sleep_completed`
captures the duration and the message.

## When It Fails

The step fails before sleeping when the duration is not a whole number of
at least 1 (error: "Invalid general.sleep config: ..."); the editor form
already enforces the minimum, so this normally only occurs in hand-edited
flow definitions or with a template that renders something else. A
definition that omits the duration sleeps the default 30 seconds. Once the wait starts, the handler imposes no timeout or
interruption of its own — it sleeps the full duration and succeeds.
