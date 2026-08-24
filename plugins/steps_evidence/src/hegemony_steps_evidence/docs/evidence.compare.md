<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Compare Evidence

`evidence.compare` diffs the evidence artifacts collected by two steps —
typically a precheck and a postcheck taken around a change — and passes or
fails according to the chosen comparison mode. Use it to prove that a change
left the network state untouched, or that an intended change actually took
effect.

## Using It

Select the Precheck Step and Postcheck Step that collected the evidence.
Leaving the postcheck empty makes the step look at its own artifacts, which
a compare step does not normally have — in practice, select both steps.

By default every artifact name the two steps share is compared; names
present on only one side are skipped, and the newest artifact per name is
used when a step ran more than once. "Only this artifact" narrows the
comparison to one exact artifact name, and "Only artifacts matching" filters
names with a glob (ignored when the exact name is set) so volatile outputs
such as routing or neighbor tables can be left out.

Comparison mode decides what a difference means. "Must match" (the default)
passes only when both sides are identical, for drift and no-change checks.
"Must differ" inverts that: every compared artifact must differ,
confirming that an intended change took effect everywhere it was captured. The subset, superset, and structured
JSON diff modes compare structured (dict/list) evidence rather than text.

Before a text comparison, every match of the "Mask text matching" regular
expressions is removed from both sides, so uptimes, timers, and counters do
not register as differences while the rest of each line still compares.
`^` and `$` anchor to line boundaries. At most 50 patterns are applied,
invalid ones are skipped with a warning, and artifacts over one million
characters are compared unmasked. "Ignore fields" removes the listed
top-level keys from both sides of structured (dict) evidence.

## Output

The step returns no custom chainable output keys and no metrics; it records
one `comparison_result` evidence record named
`compare_evidence_<precheck step>_vs_<postcheck step>`. The record captures
which artifacts were compared, the comparison mode, the overall pass flag,
and per-artifact diff details — for text artifacts a unified diff plus the
full before and after text for side-by-side display in the run view.

## When It Fails

Configuration and missing evidence fail the step outright: no precheck step
selected, no artifacts found for the precheck step, a named artifact absent
on either side, a glob that matches nothing on either side, or no shared
artifact names between the two steps. Artifact fetches use a 30-second API
timeout, and a fetch error leaves that step's artifact list empty, failing
the comparison as missing evidence.

Otherwise the verdict follows the mode: "Must match" and structured JSON
diff fail when any compared artifact differs, "Must differ" fails when any
compared artifact is unchanged - every artifact must differ, so exclude
volatile-free outputs you expect to stay identical, and the subset and superset modes fail when the postcheck
does not contain (or does not extend) the precheck; superset always fails on
non-structured content. Invalid masking patterns never fail the step — they
are skipped and the comparison proceeds without them.
