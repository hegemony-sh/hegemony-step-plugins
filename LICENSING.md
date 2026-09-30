<!--
SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# Licensing

The public source code in this repository is licensed under
`AGPL-3.0-or-later`. Everyone who receives the public source from this
repository receives it under those AGPL terms. See [LICENSE](LICENSE) and
[LICENSES/AGPL-3.0-or-later.txt](LICENSES/AGPL-3.0-or-later.txt).

Hegemony may also offer separate commercial licenses for Hegemony and its
first-party step-handler SDK and plugins. Commercial terms are not granted
by this public repository; they are granted only through a separate commercial
agreement with the rights holder. Contact
[contact@hegemony.sh](mailto:contact@hegemony.sh) for commercial licensing.

External contributions are accepted only under the
[Hegemony Contributor License Agreement](CLA.md). The CLA must grant Hegemony the
rights needed to distribute accepted contributions under both the public AGPL
license and separate commercial terms.

Keep source file SPDX identifiers as:

```text
SPDX-License-Identifier: AGPL-3.0-or-later
```

Do not use public SPDX expressions such as `AGPL-3.0-or-later OR Commercial`.
Commercial terms are handled by a separate agreement.

Every wheel carries the texts of its licences. Its `pyproject.toml` declares an
SPDX expression and `license-files`, and holds a copy of each named text from
`LICENSES/` as `LICENSE-<id>.txt`, which an installed wheel keeps under
`*.dist-info/licenses/`. `scripts/package_licenses.py` writes the copies;
`task licenses:packages`, a test and the wheel smoke install check them.

## One MIT file

`plugins/steps_ansible/src/hegemony_steps_ansible/callback_plugin.py` is
**MIT**, not AGPL. It holds the Ansible callback plugin that the
`ansible.playbook` step stages into its container, where it runs inside
`ansible-playbook` (GPL-3.0-or-later) and subclasses Ansible's `CallbackBase`:
at run time the two form one program. AGPL-3.0 code may be combined with
GPL-3.0 code (section 13 of each), but a copy under Hegemony's commercial terms
could not be; MIT keeps the combination open to every licensee. The rendered
file the step stages carries the same MIT header, and the
`hegemony-steps-ansible` wheel declares `AGPL-3.0-or-later AND MIT`.

Keep any other file that runs inside a third-party GPL program in its own
module under MIT in the same way; everything else stays `AGPL-3.0-or-later`.

## Container images and third-party components

The Hegemony platform's Python licence gate covers this repository's Python
dependencies: the platform installs every plugin wheel, and its gate checks the
whole installed closure. What it cannot see is container images, so this
repository reviews its own:

- **What is reviewed.** Every image a Dockerfile under `images/` builds on,
  every image a step pulls by default (a `DEFAULT_IMAGE` or `DEFAULT_IMAGES`
  literal), and every OS package, Python package and Ansible collection those
  Dockerfiles install has a row in `images/.images-allowed.txt`,
  `images/.os-packages-allowed.txt`, `images/.python-packages-allowed.txt` or
  `images/.collections-allowed.txt`: its SPDX licence, a tier that says how it
  is used, and a statement of why that is acceptable. The format is the
  platform's (`deploy/.images-allowed.txt` in the hegemony repository).
- **The gate.** `scripts/check_image_licenses.py` (`task licenses:images`,
  and `tests/test_image_licenses.py` in CI) fails on an unlisted component, on
  an install from a requirements file (whose packages it cannot see), on
  copyleft code marked as linked into a Hegemony process, and on a published
  image whose notices are missing or do not name what it installs. Review-tier
  licences (AGPL, SSPL, BUSL and the like) are warnings until accepted;
  `--strict` fails on them. The platform's licence process runs this script
  against the release it pins.
- **Published images.** `ghcr.io/hegemony-sh/ansible-runner` and
  `ghcr.io/hegemony-sh/opentofu-runner` contain no Hegemony code, but
  Hegemony conveys everything in them. Each one's `THIRD-PARTY-NOTICES.md`
  ([ansible-runner](images/ansible-runner/THIRD-PARTY-NOTICES.md),
  [opentofu-runner](images/opentofu-runner/THIRD-PARTY-NOTICES.md))
  names every component with its licence, says where to get the source, and
  makes the written offer GPL-2.0 section 3(b) requires. Each image carries
  it at `/usr/share/doc/hegemony/`, with inventories of what that build
  installed (Python distributions and collections; Alpine packages and the
  OpenTofu version). The ansible-runner build refuses a Python distribution
  under a review-tier licence. OpenTofu (MPL-2.0) is compiled from its
  release source with vulnerable Go modules raised to fixed versions; the
  image carries that change as a diff, and its notice says where the rest of
  the source is.
- **Images a step pulls by default** are pulled by the operator's Docker from
  their own registries; Hegemony conveys none of their bytes, and their
  licences bind whoever runs them. One needs attention:
  `hashicorp/terraform` is BUSL-1.1, which excludes offering it as part of a
  product that competes with HashiCorp's. It is pulled only when a `tf.plan`
  step selects the `terraform` engine; OpenTofu (MPL-2.0), in
  opentofu-runner, is the default.

