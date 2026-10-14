<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# NetBox Render Config

`netbox.render_config` has NetBox render the intended configuration of
devices or virtual machines from their config templates and config context,
and keeps each rendered configuration as run evidence and in its output. A
later step can compare it with the running configuration (`evidence.compare`),
put it before an approval, or push it to the device.

## Using It

The connection fields (NetBox URL, API Token, Token Type, TLS and Branch) are
those of `netbox.request`. By default the step renders for its target
devices: pick the role, and each device must come from a Hegemony NetBox
inventory provider, whose NetBox device ID the step uses. When the run's
devices come from more than one NetBox, Inventory Provider (such as
`netbox:main`) names the one this step's URL serves.

Object IDs render for NetBox IDs instead (separated by commas or lines, or a
list), for steps without targets; Object Type Virtual machines renders for
virtual machines, by Object IDs only. Extra Context is a JSON object added to
each object's config context for this rendering only, such as
`{"change": "{{ inputs.change_id }}"}`.

The step asks NetBox `POST /api/dcim/devices/<id>/render-config/` (or
`virtualization/virtual-machines`) for each object in turn. Rendering changes
nothing in NetBox, so each request is retried while NetBox is busy. The
run's live view shows each object as it is rendered.

## Output

- `configs`: the rendered configurations by device name (by ID with Object
  IDs), such as `steps.render.output.configs['web-01']`; two devices with the
  same name (in different sites) are keyed `web-01 (33)` and `web-01 (34)`
  with their NetBox IDs. Null when together
  they are larger than 64 KiB (`configs_truncated` is then true), in which case
  the evidence still holds each one.
- `rendered`: one entry per configuration: `id`, `name`, `template` (the
  config template's name), `size` in bytes and `sha256`.
- `failed`: the objects that could not be rendered, with NetBox's message.
- `ok` and `object_type`.

Each configuration is also stored as evidence, `Rendered configuration
(<name>)`, attached to its device.

## Security

The step sends its requests through `http.request`'s client, with the same
rules as `netbox.request`. It only reads: rendering does not change NetBox.
A rendered configuration can hold whatever the config context holds; keep
secrets out of config contexts, because the configuration is stored as run
evidence and output.

## When It Fails

The step fails when a target device does not come from a NetBox inventory
provider (set Object IDs), when target devices come from several providers
and Inventory Provider is empty, when there are no target devices and no
Object IDs, and when NetBox cannot render an object: no config template is
assigned to it, its platform or role, or the template has an error. The other
objects are still rendered, and `failed` names the ones that were not.
