<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Sync Inventory

`inventory.sync` syncs one of the run organization's inventory providers
now, the same full sync as the provider page's **Sync now** button. Use it
when a later step needs what the source of truth holds at this moment: a
device a previous step created in NetBox is not in Hegemony's inventory
until the next sync, so a step that targets it, or reads it from the
inventory, runs after this one.

## Using It

Provider names the provider, by its id (`netbox:primary`, or
`netbox:primary:<organization id>` outside the default organization) or by
its name (`primary`). Only providers of the run's organization are found: a
shared flow running for an organization syncs that organization's
providers. When two providers of different types share the name, give the
id.

An administrator decides which providers flows may sync: the provider must
be enabled and have **Flows may sync this provider** ticked on its settings
page. Starting a sync is otherwise an administrator's action, and any
operator can add this step to a flow, so it is off for every provider until
someone ticks it.

Skip if synced within avoids syncing a source again and again (in a loop,
or when several runs start together): when the provider's last sync
succeeded no longer ago than this many seconds, no sync runs and the step
succeeds with status `fresh`. The age counts from when that sync ended. 0,
the default, always syncs.

While another sync of the provider is running (its schedule, a person's
**Sync now**, another flow), the platform starts no second one. The step
then asks again every 10 seconds, for up to Wait for a running sync seconds
(300 by default), and runs its own sync once the other has ended, unless
that one is recent enough for Skip if synced within. With 0 it fails at once.
With Skip if synced within at 0, the step syncs again right after the sync
it waited for, so where flows may overlap each other or the provider's
schedule, set Skip if synced within to a small value such as 30: the sync
that just ended then counts, and the step succeeds with status `fresh`.

A sync can take a while: the platform gives the provider's calls 15 minutes
unless an administrator changed `HEGEMONY_INVENTORY_SYNC_DEADLINE_SECONDS`.
Timeout bounds the whole step, waiting included, and is 1800 seconds by
default; the step's own timeout is raised to match, so the step is not
cancelled first.

A **partial** sync brought devices and sites up to date but failed for some
other object type, such as VLANs. The step succeeds on a partial sync unless
Fail on a partial sync is on.

## Output

Later steps read the step's output as `steps.NODE_ID.output.KEY`:

- `provider`: the provider as the step named it.
- `provider_id`, `provider_name`, `provider_type`: the provider the platform
  found (null when it found none).
- `status`: `ok`, `partial` or `error` for a sync that ran; `fresh` when
  none ran because the last one was recent enough; `busy` when another sync
  was still running after the wait. Null when the platform refused the step.
- `synced`: true when this step ran a sync.
- `history_id`, `started_at`, `finished_at`, `duration_ms`: the sync's entry
  in the provider's sync history, for a sync that ran.
- `counts`: what the sync changed: `items_added`, `items_updated`,
  `items_unchanged`, `items_stale`, `items_restored` and the same for
  `sites_`; null when no sync ran.
- `error_message`: why the sync failed or was partial, or null.
- `last_sync_at`: when the provider's last sync ended, after this step.
- `waited_seconds`: how long the step waited for another sync to end.

Every key is present when the step fails too. Metrics record
`waited_seconds`, the sync's `duration_ms` and its counts. One `step_result`
evidence record, named `inventory_sync_STEPID`, holds the output.

## Security

The step never reaches the source of truth itself, and needs no credentials:
the platform runs the sync with the provider's own settings and token, as a
scheduled sync would. A flow can only start a sync of a provider an
administrator has opened to flows, in the run's own organization. Each sync
is recorded in the provider's sync history with the trigger `flow`, and in
the audit log with the run and step (`run:<run id>/<step id>`) as the actor.
Skip if synced within and the provider's lease (one sync at a time) bound the
load a flow can put on the source.

## When It Fails

The step fails when:

- the config is invalid (no provider, a value out of range);
- the platform does not let steps sync inventory (its worker predates the
  `sync_inventory` service);
- the platform refuses the sync: the provider has not been opened to flows,
  is disabled, is not one of the organization's providers, or its name
  matches several providers;
- the sync ran and failed (`status: error`), or was partial with Fail on a
  partial sync on;
- another sync was still running when Wait for a running sync ran out
  (`status: busy`);
- the whole step took longer than Timeout. The sync may then still be
  running on the platform; its result shows in the provider's sync history.

A failed sync leaves the inventory as the previous sync had it: nothing is
marked stale on the strength of a sync that did not finish. Running the step
again is safe.
