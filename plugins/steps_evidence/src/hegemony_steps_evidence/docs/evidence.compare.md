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

By default every precheck artifact is compared with its postcheck pair.
Command output is paired by device and full command text, so two long or
multi-line commands with similar artifact names are compared separately;
other artifacts are paired by name. The newest artifact of each pair is
used when a step ran more than once. A precheck artifact with no postcheck
pair fails the step, because the device or command it covered was not
checked after the change. So does a pair whose capture failed on either
side, whatever the comparison mode: the device could not be reached or the
command returned an error, so there is no output to compare.
Artifacts found only in the postcheck are listed but do not fail the step.
"Only this artifact" narrows the comparison to one exact artifact name, and
"Only artifacts matching" filters names with a glob (ignored when the exact
name is set) so volatile outputs such as routing or neighbor tables can be
left out.

Comparison mode decides what a difference means. "Must match" (the default)
passes only when both sides are identical, for drift and no-change checks.
"Must differ" inverts that: every compared artifact must differ,
confirming that an intended change took effect everywhere it was captured.
"Postcheck keeps every precheck line" (subset) passes when every non-blank
line of the precheck output is still somewhere in the postcheck output, so
lines may be added but none removed. "Postcheck keeps every precheck line
and adds more" (superset) also needs at least one new line. On structured
evidence the same two modes work on list items and dict keys and values.
"JSON structures must match" parses JSON output on both sides and compares
the structures, so formatting and key order do not matter; output that is
not a JSON object or array must match exactly.

Before a text comparison, every match of the "Mask text matching" regular
expressions is removed from both sides, so uptimes, timers, and counters do
not register as differences while the rest of each line still compares.
`^` and `$` anchor to line boundaries. At most 50 patterns are applied,
invalid ones are skipped with a warning, and artifacts over one million
characters are compared unmasked. "Ignore fields" removes the listed
top-level keys from both sides of structured (dict) evidence, and of JSON
output in the JSON mode.

## Output

The step returns no custom chainable output keys and no metrics; it records
one `comparison_result` evidence record named
`compare_evidence_<precheck step>_vs_<postcheck step>`. The record captures
which artifacts were compared, which were missing in the postcheck and
which were found only there, the comparison mode, the overall pass flag,
and per-artifact diff details — for text artifacts a unified diff plus the
full before and after text for side-by-side display in the run view. The
subset and superset modes also list the removed and added lines, the JSON
mode records whether both sides parsed as JSON, and a failed capture
records its error as `precheck_error` or `postcheck_error`. The summary
counts the failed captures and the missing and postcheck-only artifacts.

## When It Fails

Configuration and missing evidence fail the step outright: no precheck step
selected, no artifacts found for the precheck step, a named artifact absent
on either side, or a glob that matches nothing on either side. Artifact
fetches use a 30-second API timeout, and a fetch error leaves that step's
artifact list empty, failing the comparison as missing evidence.

The step also fails when any precheck artifact has no postcheck pair, or
when a capture failed on either side. Otherwise the verdict follows the mode:
"Must match" and the JSON mode fail when any compared artifact differs,
"Must differ" fails when any compared artifact is unchanged - every artifact
must differ, so exclude volatile-free outputs you expect to stay identical,
and the subset and superset modes fail when a precheck line is gone from
the postcheck (or, for superset, when nothing was added). Invalid masking
patterns never fail the step — they are skipped and the comparison proceeds
without them.
