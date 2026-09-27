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
playbook needs no hand-kept hosts file. Device credentials, secrets, and
Ansible Vault passwords are resolved by the platform, handed to Ansible as
files inside the step's container, and redacted from output. Results are
recorded per device, and check mode with diff gives a dry run to review
before an approval.

The playbook runs on the platform's Docker-in-Docker sandbox through
`container.run`'s runner (this wheel depends on `hegemony-steps-container`),
under the flow's egress policy. The default execution image is built from
`images/ansible-runner/` in this repository; any Ansible execution environment
image works.
