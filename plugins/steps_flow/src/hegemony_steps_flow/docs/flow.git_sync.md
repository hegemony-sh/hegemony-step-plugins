<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Git Repo Sync

`flow.git_sync` is an internal handler: it is not offered in the flow
editor's step picker. It exists so the platform's git integration can run
scheduled repo-wide pull syncs of flow definitions as ordinary flow runs.
Manage sync schedules and behavior through the git repository
configuration instead of adding this step yourself.

The step calls the platform's sync API for the configured git repository,
passing the conflict policy (`reject_dirty` by default, or `overwrite` /
`skip`) and the force flag, and marking the sync as scheduled. Transient
API errors (429, 500, 502, 503, 504, and network failures) are retried
with exponential backoff, up to four attempts in total. It returns no chainable output keys;
metrics record the sync summary counts `total`, `succeeded`, `failed`,
`conflicts`, and `skipped`. The step fails when no git repository is
configured, when the sync API rejects the request or stays unreachable
after all retries, or when the sync finishes with any failed or conflicted
flows — skipped flows alone do not fail it.
