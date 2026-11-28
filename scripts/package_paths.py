# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PACKAGE_DIRS = (
    ROOT / "packages" / "step_sdk",
    ROOT / "packages" / "transport_support",
    ROOT / "plugins" / "steps_general",
    ROOT / "plugins" / "steps_probe",
    ROOT / "plugins" / "steps_netcli",
    ROOT / "plugins" / "steps_evidence",
    ROOT / "plugins" / "steps_container",
    ROOT / "plugins" / "steps_flow",
    ROOT / "plugins" / "steps_shell",
    ROOT / "plugins" / "steps_monitor",
    ROOT / "plugins" / "steps_ansible",
    ROOT / "plugins" / "steps_tf",
    ROOT / "plugins" / "steps_http",
    ROOT / "plugins" / "steps_secret",
    ROOT / "plugins" / "steps_inventory",
    ROOT / "plugins" / "steps_netbox",
    ROOT / "plugins" / "steps_git",
    ROOT / "plugins" / "steps_netconf",
    ROOT / "plugins" / "steps_napalm",
    ROOT / "probes" / "probe_net",
    ROOT / "transports" / "transport_netmiko",
    ROOT / "transports" / "transport_scrapli",
    ROOT / "transports" / "transport_asyncssh",
    ROOT / "transports" / "transport_napalm",
)

# Two version streams (CONTRIBUTING.md, "The SDK's own version"):
#
# - The SDK (index 0) has its own version, set by hand in the pull request that
#   changes it (scripts/sdk_version.py); semantic-release never touches it.
# - Every other package carries the release version, the tag vX.Y.Z.
SDK_DIR = PACKAGE_DIRS[0]
SDK_PYPROJECT = SDK_DIR / "pyproject.toml"
SDK_VERSION_FILE = SDK_DIR / "src" / "hegemony_step_sdk" / "_version.py"
#: The SDK's public surface as scripts/sdk_version.py records it; the diff of
#: this file is how a reviewer sees a contract change.
SDK_SURFACE_FILE = SDK_DIR / "api-surface.json"

# Everything except the SDK depends on hegemony-step-sdk and carries the
# release version.
PLUGIN_DIRS = PACKAGE_DIRS[1:]
RELEASE_DIRS = PLUGIN_DIRS

#: Wheels that pin the SDK exactly (``==<SDK version>``): the device transports,
#: whose interface has no stability promise, and the internal code they share.
SDK_EXACT_PIN_DIRS = tuple(
    path
    for path in PLUGIN_DIRS
    if path.parent.name == "transports" or path.name == "transport_support"
)
#: Wheels that accept the SDK's current minor and every later release of its
#: major (``>=X.Y,<X+1``): step handlers and probes, which use only the
#: additions-only contract.
SDK_RANGE_PIN_DIRS = tuple(path for path in PLUGIN_DIRS if path not in SDK_EXACT_PIN_DIRS)

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
_GIT = ROOT / "plugins" / "steps_git"
_ANSIBLE_DOCS = (
    _ANSIBLE / "src" / "hegemony_steps_ansible" / "playbook.py",
    _ANSIBLE / "src" / "hegemony_steps_ansible" / "docs" / "ansible.playbook.md",
    _ANSIBLE / "README.md",
    ROOT / "images" / "ansible-runner" / "Dockerfile",
)
_TF_DOCS = (
    _TF / "src" / "hegemony_steps_tf" / "plan.py",
    _TF / "src" / "hegemony_steps_tf" / "docs" / "tf.plan.md",
    _TF / "README.md",
)


@dataclass(frozen=True)
class BundledTool:
    """A tool a step runs by default, and where its version is set.

    The image tags name plugin releases, so the tool's series (its X.Y) is
    stated wherever a flow author reads about the default, as ``<name> X.Y``.
    A patch release of the plugins keeps the series; a new one needs a minor
    release (scripts/verify_release_version.py checks both).
    """

    #: The tool as the docs name it.
    name: str
    #: The file that sets the version, relative to the repository root, so it
    #: can be read at a release tag too.
    source: str
    #: The line of ``source`` that sets it; group 1 is the series, X.Y.
    pattern: str
    #: Every file that states the series as ``<name> X.Y``.
    files: tuple[Path, ...]
    #: The series the tool's image is published for, when a step can choose:
    #: images/<name>/variants.json, relative to the repository root.
    variants: str | None = None
    #: The files that state every one of those series, the first of them the
    #: step's own choice (a ``Literal["default", ...]``, named by ``choice``).
    variant_files: tuple[Path, ...] = ()
    choice: str = ""


BUNDLED_TOOLS = (
    BundledTool(
        name="ansible-core",
        source="images/ansible-runner/Dockerfile",
        pattern=r"^ARG ANSIBLE_CORE_VERSION=(\d+\.\d+)\.",
        files=_ANSIBLE_DOCS,
        variants="images/ansible-runner/variants.json",
        variant_files=_ANSIBLE_DOCS[:2],
        choice="AnsibleCoreVersion",
    ),
    BundledTool(
        name="OpenTofu",
        source="images/opentofu-runner/Dockerfile",
        pattern=r"^ARG OPENTOFU_VERSION=(\d+\.\d+)\.",
        files=(*_TF_DOCS, ROOT / "images" / "opentofu-runner" / "Dockerfile"),
        variants="images/opentofu-runner/variants.json",
        variant_files=(_TF / "src" / "hegemony_steps_tf" / "common.py", *_TF_DOCS[:2]),
        choice="OpenTofuVersion",
    ),
    BundledTool(
        name="Terraform",
        source="plugins/steps_tf/src/hegemony_steps_tf/common.py",
        pattern=r'^    "terraform": "hashicorp/terraform:(\d+\.\d+)\.',
        files=_TF_DOCS,
    ),
)

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
    RunnerImage(
        repository="ghcr.io/hegemony-sh/git-runner",
        default_pattern=r'^DEFAULT_IMAGE = "([^"]+)"$',
        files=(
            _GIT / "src" / "hegemony_steps_git" / "commit.py",
            _GIT / "src" / "hegemony_steps_git" / "docs" / "git.commit.md",
            _GIT / "README.md",
            ROOT / "images" / "git-runner" / "Dockerfile",
        ),
    ),
)
