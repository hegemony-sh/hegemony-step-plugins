# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PACKAGE_DIRS = (
    ROOT / "packages" / "step_sdk",
    ROOT / "plugins" / "steps_general",
    ROOT / "plugins" / "steps_probe",
    ROOT / "plugins" / "steps_netcli",
    ROOT / "plugins" / "steps_evidence",
    ROOT / "plugins" / "steps_container",
    ROOT / "plugins" / "steps_flow",
    ROOT / "plugins" / "steps_cisco_iosxe",
    ROOT / "plugins" / "steps_shell",
    ROOT / "plugins" / "steps_monitor",
    ROOT / "plugins" / "steps_ansible",
    ROOT / "plugins" / "steps_tf",
    ROOT / "plugins" / "steps_http",
    ROOT / "plugins" / "steps_secret",
    ROOT / "plugins" / "steps_netbox",
    ROOT / "probes" / "probe_net",
    ROOT / "transports" / "transport_netmiko",
    ROOT / "transports" / "transport_scrapli",
    ROOT / "transports" / "transport_asyncssh",
)

# Everything except the SDK (index 0) pins hegemony-step-sdk and is version-locked to it.
PLUGIN_DIRS = PACKAGE_DIRS[1:]
SDK_VERSION_FILE = ROOT / "packages" / "step_sdk" / "src" / "hegemony_step_sdk" / "_version.py"

# The steps' default execution images. The Images workflow publishes each from
# images/<name> for every release tag vX.Y.Z as X.Y.Z and X.Y; the steps name
# X.Y, so the files that name an image follow the release's minor version
# (scripts/set_version.py rewrites them, scripts/verify_release_version.py
# checks them).


@dataclass(frozen=True)
class RunnerImage:
    """A step's default execution image, and every file that names its X.Y tag."""

    #: The image without its tag: ghcr.io/hegemony-sh/<name>.
    repository: str
    #: The line of ``files[0]`` that makes it a step's default; group 1 is the
    #: image reference.
    default_pattern: str
    #: ``files[0]`` holds the default; the rest mention the image.
    files: tuple[Path, ...]


_ANSIBLE = ROOT / "plugins" / "steps_ansible"
_TF = ROOT / "plugins" / "steps_tf"

RUNNER_IMAGES = (
    RunnerImage(
        repository="ghcr.io/hegemony-sh/ansible-runner",
        default_pattern=r'^DEFAULT_IMAGE = "([^"]+)"$',
        files=(
            _ANSIBLE / "src" / "hegemony_steps_ansible" / "playbook.py",
            _ANSIBLE / "src" / "hegemony_steps_ansible" / "docs" / "ansible.playbook.md",
            _ANSIBLE / "README.md",
            ROOT / "images" / "ansible-runner" / "Dockerfile",
        ),
    ),
    RunnerImage(
        repository="ghcr.io/hegemony-sh/opentofu-runner",
        default_pattern=r'^    "opentofu": "([^"]+)",$',
        files=(
            _TF / "src" / "hegemony_steps_tf" / "common.py",
            _TF / "src" / "hegemony_steps_tf" / "plan.py",
            _TF / "src" / "hegemony_steps_tf" / "docs" / "tf.plan.md",
            _TF / "README.md",
            ROOT / "images" / "opentofu-runner" / "Dockerfile",
        ),
    ),
)
