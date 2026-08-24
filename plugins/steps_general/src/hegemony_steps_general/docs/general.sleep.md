<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Sleep

`general.sleep` pauses the flow for a fixed number of seconds, then lets
execution continue. Use it for settling time between actions — waiting for
a routing protocol to converge, a service to finish restarting, or a change
to propagate — when there is nothing to poll and a plain delay is enough.

## Using It

Duration is the only setting that matters: the step waits exactly that many
seconds (the editor pre-fills 30; minimum 1) and then succeeds. The wait is a plain
timer — nothing is checked or polled while it runs — and the step targets
no devices, so there is no target picker.

Message is an optional note explaining why the flow is waiting, e.g.
"Waiting for BGP to converge". It is logged when the sleep starts and
becomes the step's summary when it completes - a blank message means a
blank summary. Only a definition that omits the field entirely gets the
generated "Sleeping for N seconds" text. Like other config fields it
is resolved by the step template engine first, so it can reference flow
inputs or earlier steps, e.g. `Settling after {{ steps.NODE_ID.summary }}`.

## Output

The step adds no custom chainable output keys; its summary — the message,
or the generated text — is what later steps can reference as
`steps.NODE_ID.summary`. Metrics record `sleep_seconds`, the configured
duration. One `step_result` evidence record named `sleep_completed`
captures the duration and the message.

## When It Fails

The step fails before sleeping when the duration is not a positive number
(error: "Invalid sleep duration: must be > 0"); the editor form already
enforces the minimum of 1, so this normally only occurs in hand-edited
flow definitions - which also fail when they omit the field, since nothing
supplies the editor's 30-second pre-fill there. Once the wait starts, the handler imposes no timeout or
interruption of its own — it sleeps the full duration and succeeds.
