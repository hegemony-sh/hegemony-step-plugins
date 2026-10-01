<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Third-party notices: ansible-runner image

`ghcr.io/hegemony-sh/ansible-runner` is the default execution image of
Hegemony's `ansible.playbook` step. It is built from
[`images/ansible-runner/Dockerfile`](Dockerfile) in the
[hegemony-step-plugins](https://github.com/hegemony-sh/hegemony-step-plugins)
repository and published by its Images workflow.

**The image contains no Hegemony code.** Every program and library in it is
third-party software, unmodified, under its own licence. Hegemony's licence
(`AGPL-3.0-or-later`; see [LICENSING.md](../../LICENSING.md)) covers none of
it, and cannot grant rights over it. This file travels inside the image at
`/usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md`, next to two inventories
written when the image is built:

- `/usr/share/doc/hegemony/python-packages.txt`: every installed Python
  distribution, its version and its declared licence;
- `/usr/share/doc/hegemony/ansible-collections.txt`: every installed Ansible
  collection and its version.

Each Debian package's copyright file is at `/usr/share/doc/<package>/copyright`,
each Python distribution's licence files are in its `*.dist-info` directory, and
each collection ships its own licence file in its directory under
`/usr/share/ansible/collections`.

## How the step uses these components

The step's script starts `ansible-playbook` as a separate program inside this
container, and Ansible starts `ssh`, `sshpass` and `git` as separate programs in
turn. Collecting separate programs in one image is mere aggregation (GPL-2.0
section 2, GPL-3.0 section 5): no copyleft reaches Hegemony's own code.

The step stages one file of Hegemony code into the container at run time: an
Ansible callback plugin that records task results. It runs inside
`ansible-playbook` (GPL-3.0-or-later), so it is licensed **MIT** rather than
AGPL: the staged copy carries its whole licence in its header and needs nothing
beside it (see the repository's LICENSING.md). It is not part of the image.

## Components

### Base image

`python` (`python:3.12-slim-bookworm`): CPython (Python-2.0) on the Debian 12
userland, which carries GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-or-later and
LGPL-2.1-or-later programs alongside MIT, BSD and Apache-2.0 ones.

### Debian packages this image adds

| Package | Licence | Used for |
| --- | --- | --- |
| `openssh-client` | SSH-OpenSSH (BSD-style) | Ansible's ssh connections, git over SSH |
| `sshpass` | GPL-2.0-or-later | Password logins for playbooks that pin an older ansible-core |
| `git` | GPL-2.0-only | Roles and collections that a playbook's requirements file names |
| `ca-certificates` | MPL-2.0 AND GPL-2.0-or-later | The Mozilla CA bundle and its update script |

### Python packages this image installs

| Package | Licence | Used for |
| --- | --- | --- |
| `ansible-core` | GPL-3.0-or-later | `ansible-playbook` itself |
| `ansible-pylibssh` | LGPL-2.1-or-later | libssh bindings for network_cli; its wheel bundles libssh (LGPL-2.1-or-later) and OpenSSL (Apache-2.0) |
| `ncclient` | Apache-2.0 | NETCONF for Junos; pulls in paramiko (LGPL-2.1-or-later) |
| `jmespath` | MIT | Ansible's `json_query` filter |
| `netaddr` | BSD-3-Clause | ansible.utils' address filters |

Their dependencies (among them jinja2, PyYAML, cryptography, lxml, paramiko)
are resolved at build time and listed, with versions and licences, in
`/usr/share/doc/hegemony/python-packages.txt`. The LGPL libraries are installed
as ordinary, replaceable Python modules, which keeps the LGPL relinking right.

### Ansible collections this image installs

| Collection | Licence |
| --- | --- |
| `ansible.netcommon` | GPL-3.0-or-later |
| `ansible.utils` | GPL-3.0-or-later |
| `ansible.posix` | GPL-3.0-or-later |
| `community.general` | GPL-3.0-or-later (some files BSD-2-Clause, MIT or PSF-2.0) |
| `cisco.ios` | GPL-3.0-or-later |
| `cisco.nxos` | GPL-3.0-or-later |
| `cisco.iosxr` | GPL-3.0-or-later |
| `arista.eos` | GPL-3.0-or-later |
| `junipernetworks.junos` | GPL-3.0-or-later |

## Corresponding Source

Some of these components are licensed under the GNU GPL or LGPL, so their
source is offered in two ways.

### Where to get the source (network distribution)

The image is offered from `ghcr.io`, so GPL-3.0 section 6(d) applies: access to
the Corresponding Source is offered with directions next to the object code.
Every component is an **unmodified upstream release**; Hegemony applies no
patches:

| Component | Corresponding Source |
| --- | --- |
| Debian packages (`git`, `sshpass`, `ca-certificates`, and the rest of the `python:3.12-slim-bookworm` userland) | <https://sources.debian.org>, or `apt-get source <package>` on Debian 12 |
| Python packages | The sdist of the installed version on <https://pypi.org>; for the pure-Python ones (ansible-core, paramiko) the installed files are themselves the source |
| libssh, as bundled by ansible-pylibssh | <https://www.libssh.org/files/>, at the version the wheel reports |
| Ansible collections | <https://galaxy.ansible.com>, or the collection's repository under <https://github.com/ansible-collections> |

The exact versions are read from the image: `dpkg -l`, and the two inventory
files above. The build instructions are
[`images/ansible-runner/Dockerfile`](Dockerfile).

### Written offer

Additionally, and to cover GPL-2.0 section 3(b), which the GPL-2.0 components
above are conveyed under and which also applies if you receive the image
embedded in a product or an appliance: the complete corresponding source code
is available on request, for three years from the date you received the image,
by writing to **<contact@hegemony.sh>** with the image name and digest. It will
be supplied on a durable physical medium or by download, at no charge beyond
the cost of performing the distribution. This offer is valid to any third
party.

## Reporting an omission

If a component is missing here, or a notice is wrong, open an issue in
hegemony-step-plugins or write to <contact@hegemony.sh>. Attribution errors are
treated as bugs.
