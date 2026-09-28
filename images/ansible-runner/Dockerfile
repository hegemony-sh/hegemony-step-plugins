# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Default execution image for the ansible.playbook step.
#
# No official image bundles ansible-core with the vendor network collections,
# so this one does: ansible-core 2.19 (password SSH logins without sshpass,
# via askpass), ansible-pylibssh for network_cli (paramiko is deprecated in
# 2.19 and removed in 2.21), ncclient for Junos NETCONF, and the collections
# the platform maps device platforms onto. sshpass stays for playbooks that
# pin an older core. Runs as an unprivileged user; the step stages its files
# readable by any user and copies private keys to a folder that user owns.
#
# Not published by the release: build and push it to a registry the sandbox
# can pull from (the step pulls on every run), or push it under your own tag
# and set the step's Execution image:
#
#   docker build -t ghcr.io/hegemony-sh/ansible-runner:0.5 images/ansible-runner
#   docker push ghcr.io/hegemony-sh/ansible-runner:0.5
#
# The tag follows the wheels' minor version (DEFAULT_IMAGE in
# plugins/steps_ansible/src/hegemony_steps_ansible/playbook.py).

FROM python:3.12-slim-bookworm

ARG ANSIBLE_CORE_VERSION=2.19.2

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client sshpass git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        "ansible-core==${ANSIBLE_CORE_VERSION}" \
        ansible-pylibssh \
        ncclient \
        jmespath \
        netaddr \
    && ansible-galaxy collection install --collections-path /usr/share/ansible/collections \
        ansible.netcommon \
        ansible.utils \
        ansible.posix \
        community.general \
        cisco.ios \
        cisco.nxos \
        cisco.iosxr \
        arista.eos \
        junipernetworks.junos \
    && rm -rf /root/.ansible

RUN useradd --create-home --uid 1000 runner
USER runner
WORKDIR /home/runner

ENTRYPOINT ["/bin/sh"]
