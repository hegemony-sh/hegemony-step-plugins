<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# hegemony-steps-ansible

Ansible for Hegemony flows — the `ansible.` namespace.

Handlers: `ansible.playbook` — run a playbook from the flow's attachments
against the step's target devices. The inventory is generated from
Hegemony's inventory (local devices and external providers such as NetBox or
Git alike), grouped by flow role, platform, site, tag, and provider, so a
playbook needs no hand-kept hosts file. Device credentials, secret
references, and Ansible Vault passwords are resolved by the platform, handed
to Ansible as files inside the step's container, and redacted from output. Results are
recorded per device, and check mode with diff gives a dry run to review
before an approval.

The playbook runs on the platform's Docker-in-Docker sandbox through
`container.run`'s runner (this wheel depends on `hegemony-steps-container`),
under the flow's egress policy. The default execution image,
`ghcr.io/hegemony-sh/ansible-runner:0.5`, is built from `images/ansible-runner/`
in this repository and is not published by the release: build and push it to
a registry the sandbox can pull from before the first run,

```sh
docker build -t ghcr.io/hegemony-sh/ansible-runner:0.5 images/ansible-runner
docker push ghcr.io/hegemony-sh/ansible-runner:0.5
```

or push it under your own registry's tag and set the step's Execution image.
Any Ansible execution environment image works.
