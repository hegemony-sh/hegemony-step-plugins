<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Assert

`evidence.assert` checks evidence collected by another step against an
expected value or pattern. Point it at a collect-evidence step, pick one of
that step's outputs, and the step passes only when the collected content
satisfies the chosen operator — for example, that a software version line
contains `17.9` or that every OSPF neighbor row reads `Full`.

## Using It

Evidence Step selects the collect-evidence step to read from, and the
Evidence Output picker chooses which of its outputs to assert: a target plus
the command that produced the output. Every device bound to that target is
asserted separately against its own collected artifact, so one assert step
can validate a whole role at once. When the collect step ran more than once
(loops, retries), the newest artifact per device is the one asserted.

The Operator (default Contains) compares the content with the Expected
Value / Pattern. The regex operators treat the expected value as a regular
expression; the ordering operators compare numerically when both sides parse
as numbers and as text otherwise. Very large artifacts are truncated to
their first million characters - by the regex operators in whole-output
scope, and by every operator in line scope.

Match Scope decides what one comparison covers. Whole output (the default)
asserts once against the entire artifact. Every line applies the operator to
each selected line and requires all of them to pass. In line scope, Line
Filter is a regex choosing which lines count (empty selects every non-empty
line), and Minimum Lines (default 1) fails the step when fewer lines are
selected - so under the default, a filter that matches nothing cannot
pass vacuously. Setting Minimum Lines to 0 removes that floor and lets
an empty selection pass.

Custom Message, when set, replaces the generated pass summary and the
generated failure error with your own wording.

## Output

The step returns no custom chainable output keys and no metrics; its results
are recorded as evidence. Each checked artifact produces one
`assertion_result` evidence record — named `assertion` for a single
artifact, or `assertion:<artifact name>` when several devices were checked —
capturing the operator, the expected and actual values (actual truncated to
500 characters), whether it passed, and in line scope the line filter, how
many lines were selected and passed, and the first failing line.

## When It Fails

The step succeeds only when every checked artifact satisfies the assertion.
It fails when the chosen target is not bound to any device, when no artifact
names can be resolved from the configuration, or when any artifact fails the
comparison; the error lists each failing artifact unless a Custom Message
replaces it. An artifact that cannot be fetched from the run (the fetch uses
a 30-second API timeout) counts as a failure for that artifact while the
remaining artifacts are still checked. In line scope the step also fails
when the artifact is not text, when the Line Filter regex is invalid, or
when fewer than Minimum Lines lines are selected. Evidence records are
written for the artifacts that were compared even when the step fails.
