<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# No-op

`general.noop` is an internal handler: it is not offered in the flow
editor's step picker. It exists as a placeholder that does nothing and
succeeds — useful for testing flow wiring and for definitions that need a
step with no effect. To pause a flow on purpose, use the Sleep step
(`general.sleep`) instead.

The step accepts an optional delay in seconds (default 0, applied before
it completes), targets no devices, and always succeeds with the summary
"No-op completed" and a single `delay_seconds` metric. It produces no
evidence and no chainable output keys.
