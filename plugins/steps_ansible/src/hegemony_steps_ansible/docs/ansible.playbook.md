<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Ansible Playbook

`ansible.playbook` runs an Ansible playbook against the step's target
devices. The inventory is built from Hegemony's own inventory, so the
playbook needs no hand-kept hosts file: local devices and devices from
external providers such as NetBox or Git all work the same way. The play
runs in a container on the platform's Docker-in-Docker sandbox, under the
flow's egress policy.

## Using It

Add the playbook and anything it needs (roles, group_vars, an ansible.cfg)
to the flow's attachments, set Playbook to its path such as `site.yml` or
`ansible/site.yml`, and pick the target roles. The playbook runs from its own
folder under `/attachments`, so files next to it are found as usual.

The generated inventory holds every target device once, with
`ansible_host`, `ansible_port`, `ansible_connection`, and for network
platforms `ansible_network_os` (IOS and IOS-XE, NX-OS, IOS-XR and EOS use
`network_cli` over libssh; Junos uses NETCONF; other platforms use SSH).
Each host also carries a `hegemony` variable with its id, platform, site,
tags, and attributes. A device attribute named `ansible_vars` holding a
mapping is merged into that host's variables, so inventory owners can tune
Ansible per device. Groups are derived from:

- role: the flow's role names, e.g. `routers`;
- platform: e.g. `platform_ios_xe`;
- site: every level of the site path, nested, e.g. `site_emea` containing
  `site_emea_nl` containing `site_emea_nl_ams01`;
- tag: e.g. `tag_env_prod`;
- provider: e.g. `provider_netbox_main`.

Group names use only letters, digits, and underscores; anything else becomes
`_`. Inventory scope `run` puts every device the run targets into the
inventory instead of only the step's own targets.

## Credentials And Secrets

Each device's login comes from its access configuration: the username,
the password or private key, the enable password (used as `become` with the
`enable` method on network devices), and a key-based jump host. They are
written to `host_vars` files beside the generated inventory, never into the
inventory itself, and private keys are copied to a private folder the
container's user owns. Turn off "Use device credentials" when the playbook
brings its own.

Secrets are `NAME=reference` lines; each becomes the Ansible variable NAME.
A reference is a `{{ secret('...') }}` template or a bare reference such as
`vault://orgs/acme/secrets/db/password`, resolved on its own (without step
variables) and only once. Group secrets use `GROUP:NAME` to
give a variable to one inventory group only. The Ansible Vault password and
vault IDs let playbooks with ansible-vault encrypted files run unchanged.
Every value is resolved by the platform, passed to Ansible from a file
(never an environment variable or argument), and redacted from the step's
output. Extra variables are plain `NAME=value` lines and may use templates.

## Output

Ansible's normal output streams into the step's live log and is stored as
the container output artifact. A results artifact per device lists every
task with its status, and failure messages and diffs where there are any.
The generated inventory is stored too, without credentials. Later steps
read `steps.NODE_ID.output.changed` (true when any host changed),
`changed_hosts`, `failed_hosts`, `unreachable_hosts`, the per-host counts
under `hosts`, and `stats`: values the play published with the `set_stats`
module. Check mode with "Show differences" makes a dry run: branch on
`steps.NODE_ID.output.changed` to skip an approval when nothing would change.
`changed` is null (unknown) when the play produced no results, so compare it
with `== false`, not `not`. Very large results are trimmed to fit (diffs
first, then long messages, then task records); the play recap and the counts
are always complete, and `results_trimmed` names what was left out.

## When It Fails

The step succeeds only when ansible-playbook exits with 0 and its results
were collected. Exit code 2 means a host failed, 4 means a host was
unreachable or the playbook did not parse; the error names the code. A play
that exits with 0 without results (the results callback did not run, for
example because the playbook's own `ansible.cfg` or image disabled it) fails
too: whether any host changed is then unknown. The step also fails before running anything when
the config is invalid, a device has no usable credentials, a jump host has
only a password or a host, user name or port that is not plain (a host name
or IP address; a user name of letters, digits and `. _ @ + -`), or a secret
resolves to nothing. The timeout covers the
whole run, image pull included. Installing a requirements file needs
network access to the Galaxy server under the flow's egress policy.
