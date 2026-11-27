# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
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
# The Images workflow (.github/workflows/images.yml) publishes it for every
# release tag vX.Y.Z as ghcr.io/hegemony-sh/ansible-runner:X.Y.Z and :X.Y. The
# step's default names X.Y (DEFAULT_IMAGE in
# plugins/steps_ansible/src/hegemony_steps_ansible/playbook.py), currently
# ghcr.io/hegemony-sh/ansible-runner:0.59. That tag names a plugin release, not
# the ansible-core inside: the image's sh.hegemony.ansible-core.version label
# names it, and so does every run (the step's ansible_version output). A patch
# release of the plugins stays on ansible-core 2.19; another series needs a
# minor release, so commit that change as feat
# (scripts/verify_release_version.py refuses the release otherwise).
#
# The workflow also publishes the image for every ansible-core series in
# variants.json, as X.Y.Z-core<series> and X.Y-core<series> (0.51-core2.21, say):
# the same Dockerfile built with that entry's build arguments. The step's
# "ansible-core version" names one of them. The ARG default below is the
# default series' entry (tests/test_release_versions.py checks it), so a plain
# build is the default image.
#
# To customise the image, build and push it under your own tag and set the
# step's Execution image:
#
#   docker build --no-cache -t registry.example.com/ansible-runner:custom images/ansible-runner
#   docker push registry.example.com/ansible-runner:custom

# Pinned by digest, so a build uses exactly the reviewed image; Renovate
# proposes the new digest when the tag moves (.github/renovate.json).
FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ARG ANSIBLE_CORE_VERSION=2.19.15
LABEL sh.hegemony.ansible-core.version="${ANSIBLE_CORE_VERSION}"

# The base image carries Debian's fixes only once it is rebuilt, so upgrade its
# packages first: a fix Debian has already published (libpcre2-8-0
# 10.42-1+deb12u2 for CVE-2026-103111, say) would otherwise fail the Images
# workflow's scan until the base image caught up.
RUN apt-get update \
    && apt-get upgrade -y \
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

# Everything above is third-party. The notices (with the written source offer)
# travel inside the image, next to inventories of exactly what this build
# installed: Python distributions with their declared licences, and collections.
# The inventory script refuses a distribution under a review-tier licence (the
# ones scripts/check_image_licenses.py lists), so the build fails instead of
# publishing one: the dependency closure is resolved here, not in any allowlist.
COPY THIRD-PARTY-NOTICES.md /usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md
RUN --mount=type=bind,source=inventory.py,target=/tmp/inventory.py \
    python /tmp/inventory.py --fail-on AGPL SSPL BUSL Elastic RSAL "Commons Clause" \
        > /usr/share/doc/hegemony/python-packages.txt \
    && ansible-galaxy collection list --collections-path /usr/share/ansible/collections \
        > /usr/share/doc/hegemony/ansible-collections.txt

RUN useradd --create-home --uid 1000 runner
USER runner
WORKDIR /home/runner

ENTRYPOINT ["/bin/sh"]
