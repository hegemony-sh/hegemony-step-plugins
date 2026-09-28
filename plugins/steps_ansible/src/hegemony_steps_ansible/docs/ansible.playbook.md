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
Ansible per device: playbook variables of their own, and of Ansible's
variables only `ansible_python_interpreter`, `ansible_network_os`,
`ansible_network_cli_ssh_type`, `ansible_connect_timeout`, and
`ansible_command_timeout`. How and where Ansible connects (`ansible_host`,
`ansible_port`, `ansible_connection`, the login and become variables, ssh
arguments, proxy commands, executables) comes from Hegemony only, since
whoever edits a device's attributes need not be allowed to run commands in
the step's container; any other `ansible_*` key there, and `hegemony`, is
ignored and listed in an `ansible_vars_ignored_<step id>` artifact. Groups
are derived from:

- role: the flow's role names, e.g. `routers`;
- platform: e.g. `platform_ios_xe`;
- site: every level of the site path, nested, e.g. `site_emea` containing
  `site_emea_nl` containing `site_emea_nl_ams01`;
- tag: e.g. `tag_env_prod`;
- provider: e.g. `provider_netbox_main`.

Group names use only letters, digits, and underscores; anything else becomes
`_`. Inventory scope `run` puts every device the run targets into the
inventory instead of only the step's own targets. A device that is there only
through `run` scope (none of its roles is a target of this step) and has no
usable credentials is left out of the inventory instead of failing the step,
and named with the reason in an `ansible_hosts_left_out_<step id>` artifact.

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
variables) and only once. Group secrets use `GROUP:NAME` to give a variable
to one inventory group only. The Ansible Vault password and vault IDs let
playbooks with ansible-vault encrypted files run unchanged. Every value is
passed to Ansible from a file (never an environment variable or argument).
Anything written as `scheme://…` is read as a reference; references are
resolved by the platform and their values redacted from the step's output,
while other text is used as written and not redacted. Extra variables are
plain `NAME=value` lines and may use templates.

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

## Execution Image

The default image, `ghcr.io/hegemony-sh/ansible-runner:0.5`, bundles
ansible-core, ansible-pylibssh, ncclient, and the network collections the
platform maps device platforms onto. It is built from `images/ansible-runner/`
in the hegemony-step-plugins repository and is **not published by the
release**: before the first Ansible step runs, build it and push it to a
registry the sandbox can pull from. From a checkout of that repository:

```sh
docker build -t ghcr.io/hegemony-sh/ansible-runner:0.5 images/ansible-runner
docker push ghcr.io/hegemony-sh/ansible-runner:0.5
```

To use your own registry instead, build and push under your own tag
(`docker build -t registry.example.com/ansible-runner:0.5 images/ansible-runner`,
then `docker push registry.example.com/ansible-runner:0.5`) and set Execution
image to it. The sandbox pulls the image on every run, so an image that only
exists on the sandbox's daemon is not enough. Until the image is reachable,
a step that keeps the default fails at the pull with an error saying so. Any
other Ansible execution environment image works too, as long as it has
`/bin/sh` and the collections the playbook needs.

## When It Fails

The step succeeds only when ansible-playbook exits with 0 and its results
were collected. Exit code 2 means a host failed, 4 means a host was
unreachable or the playbook did not parse. The error names the failed and
unreachable hosts (the first five of each) and, when a single host failed,
its failing task and message; when the play produced no recap it names the
exit code's meaning instead. A play that exits with 0 without results (the
results callback did not run, for example because the playbook's own
`ansible.cfg` or image disabled it, or the results could not be copied out
of the container, which the error then says) fails too: whether any host
changed is then unknown. The step also fails before running anything when
the config is invalid, a device the step targets has no usable credentials,
a jump host has only a password or a host, user name or port that is not
plain (a host name or IP address; a user name of letters, digits and `. _ @
+ -`), or a secret resolves to nothing. The timeout covers the whole run,
image pull included. Installing a requirements file needs network access to
the Galaxy server under the flow's egress policy.
