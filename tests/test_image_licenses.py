# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""The image licence gate: every image, package and collection is reviewed.

Running the gate against this repository is the CI check; the rest pins what
the parser finds and what the gate refuses, on small repositories built here.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"


def _gate():
    spec = importlib.util.spec_from_file_location(
        "check_image_licenses", SCRIPTS / "check_image_licenses.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_image_licenses"] = module
    spec.loader.exec_module(module)
    return module


gate = _gate()


def test_the_repository_passes_its_image_licence_gate(capsys):
    assert gate.main(["--root", str(REPO_ROOT)]) == 0, capsys.readouterr().err


def _repo(tmp_path: Path, dockerfile: str, *, published: bool = False) -> Path:
    (tmp_path / "images" / "runner").mkdir(parents=True)
    (tmp_path / "images" / "runner" / "Dockerfile").write_text(dockerfile)
    (tmp_path / "plugins").mkdir()
    if published:
        workflows = tmp_path / ".github" / "workflows"
        workflows.mkdir(parents=True)
        (workflows / "images.yml").write_text("steps:\n  - with:\n      context: images/runner\n")
    return tmp_path


def _allow(root: Path, kind: str, *rows: str) -> None:
    (root / "images" / f".{kind}-allowed.txt").write_text("# header\n" + "\n".join(rows) + "\n")


def _found(root: Path) -> set[tuple[str, str]]:
    path = root / "images" / "runner" / "Dockerfile"
    return {(f.kind, f.name) for f in gate.scan_dockerfile(path, root)}


def test_the_parser_reads_images_packages_and_collections(tmp_path):
    root = _repo(
        tmp_path,
        """\
ARG TOOL_VERSION=1.2.3
FROM registry.example.com/team/tool:${TOOL_VERSION}-minimal AS tool
# FROM commented/out:1
FROM python:3.12-slim-bookworm
COPY --from=tool /bin/tool /bin/tool
COPY --from=ghcr.io/example/helper:2 /bin/helper /bin/helper
RUN apt-get update \\
    && apt-get install -y --no-install-recommends openssh-client git=1:2.39 \\
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt \\
        "Ansible_Core==2.19.13" "netaddr[nicer]>=1" \\
    && ansible-galaxy collection install --collections-path /opt/c \\
        cisco.ios:>=9 ansible.utils
RUN apk add --no-cache --virtual .build gcc
""",
    )
    assert _found(root) == {
        ("image", "registry.example.com/team/tool"),
        ("image", "python"),
        ("image", "ghcr.io/example/helper"),
        ("os", "openssh-client"),
        ("os", "git"),
        ("os", "gcc"),
        ("python", "ansible-core"),
        ("python", "netaddr"),
        ("collection", "cisco.ios"),
        ("collection", "ansible.utils"),
        # What a requirements file lists is out of the gate's sight.
        ("unreviewable", "python: -r requirements.txt"),
    }


@pytest.mark.parametrize(
    ("install", "option"),
    [
        ("pip install -r requirements.txt", "python: -r requirements.txt"),
        ("pip3 install --requirement=reqs.txt ansible-core", "python: --requirement=reqs.txt"),
        ("pip install -rreqs.txt", "python: -rreqs.txt"),
        (
            "ansible-galaxy collection install --requirements-file req.yml",
            "collection: --requirements-file req.yml",
        ),
    ],
)
def test_an_install_from_a_requirements_file_fails_the_gate(tmp_path, capsys, install, option):
    root = _repo(tmp_path, f"FROM python:3.12\nRUN {install}\n")
    _allow(root, "images", "python | PSF-2.0 | base-image | Base.")
    _allow(root, "python-packages", "ansible-core | GPL-3.0-or-later | exec | A program.")
    assert gate.main(["--root", str(root)]) == 1
    err = capsys.readouterr().err
    assert f"images/runner/Dockerfile installs from a file ({option})" in err
    assert "name every package on the install command" in err


def test_step_defaults_are_read_without_importing_the_plugin(tmp_path):
    root = _repo(tmp_path, "FROM python:3.12\n")
    module = root / "plugins" / "steps_x" / "src" / "steps_x"
    module.mkdir(parents=True)
    (module / "defaults.py").write_text(
        "import does_not_exist\n"
        'DEFAULT_IMAGE = "ghcr.io/example/one:1.0"\n'
        'DEFAULT_IMAGES: dict[str, str] = {"a": "docker.io/library/two:2@sha256:abc", "b": "three"}\n'
        'OTHER_IMAGE = "ignored:1"\n'
    )
    names = {f.name for f in gate.scan_step_defaults(root)}
    assert names == {"ghcr.io/example/one", "docker.io/library/two", "three"}


def test_an_unlisted_component_fails_the_gate(tmp_path, capsys):
    root = _repo(tmp_path, "FROM python:3.12\nRUN apt-get install -y git\n")
    _allow(root, "images", "python | PSF-2.0 | base-image | Base.")
    assert gate.main(["--root", str(root)]) == 1
    assert "os 'git' is not in images/.os-packages-allowed.txt" in capsys.readouterr().err


def test_copyleft_linked_into_hegemony_fails_and_review_licences_warn(tmp_path, capsys):
    root = _repo(tmp_path, "FROM python:3.12\nRUN apt-get install -y libfoo\n")
    root.joinpath("plugins", "steps_x", "src").mkdir(parents=True)
    root.joinpath("plugins", "steps_x", "src", "d.py").write_text(
        'DEFAULT_IMAGE = "vendor/tool:1"\n'
    )
    _allow(
        root,
        "images",
        "python | PSF-2.0 | base-image | Base.",
        "vendor/tool | BUSL-1.1 | step-default | Pulled by the operator.",
    )
    _allow(root, "os-packages", "libfoo | GPL-2.0-only | linked | Linked into the worker.")
    assert gate.main(["--root", str(root)]) == 1
    err = capsys.readouterr().err
    assert "os 'libfoo' is GPL-2.0-only and marked 'linked'" in err
    assert "warning: image 'vendor/tool' is BUSL-1.1" in err

    _allow(root, "os-packages", "libfoo | GPL-2.0-only | exec | A separate program.")
    assert gate.main(["--root", str(root)]) == 0
    assert gate.main(["--root", str(root), "--strict"]) == 1


def test_agpl_compatible_copyleft_may_be_linked(tmp_path, capsys):
    # The rule is AGPL compatibility, not the absence of copyleft: AGPL-3.0
    # section 13 permits combining with GPL-3.0 work.
    root = _repo(tmp_path, "FROM python:3.12\nRUN apt-get install -y libfoo\n")
    _allow(root, "images", "python | PSF-2.0 | base-image | Base.")
    _allow(root, "os-packages", "libfoo | GPL-3.0-or-later | linked | Linked into the worker.")
    assert gate.main(["--root", str(root)]) == 0
    assert "marked 'linked'" not in capsys.readouterr().err


def test_affero_gpl_version_1_only_may_not_be_linked(tmp_path, capsys):
    # AGPL-1.0 without "or later" is GPL-2.0-based and cannot be combined with
    # AGPL-3.0; the deprecated bare identifier means the same.
    for licence in ("AGPL-1.0-only", "AGPL-1.0"):
        root = _repo(tmp_path / licence, "FROM python:3.12\nRUN apt-get install -y libfoo\n")
        _allow(root, "images", "python | PSF-2.0 | base-image | Base.")
        _allow(root, "os-packages", f"libfoo | {licence} | linked | Linked into the worker.")
        assert gate.main(["--root", str(root)]) == 1
        assert f"os 'libfoo' is {licence} and marked 'linked'" in capsys.readouterr().err


@pytest.mark.parametrize("licence", ["APSL-2.0", "CPAL-1.0", "MS-PL", "NASA-1.3"])
def test_a_linked_licence_not_known_to_be_compatible_fails(tmp_path, capsys, licence):
    # The linked tier fails closed. Each of these is GPL-incompatible, and none
    # is on a short list of forbidden licences, so a denylist would pass it.
    root = _repo(tmp_path, "FROM python:3.12\nRUN apt-get install -y libfoo\n")
    _allow(root, "images", "python | PSF-2.0 | base-image | Base.")
    _allow(root, "os-packages", f"libfoo | {licence} | linked | Linked into the worker.")
    assert gate.main(["--root", str(root)]) == 1
    err = capsys.readouterr().err
    assert f"os 'libfoo' is {licence} and marked 'linked'" in err
    assert "COMPATIBLE_WHEN_LINKED" in err


def test_an_exception_does_not_fail_a_compatible_linked_licence(tmp_path):
    root = _repo(tmp_path, "FROM python:3.12\nRUN apt-get install -y libfoo\n")
    _allow(root, "images", "python | PSF-2.0 | base-image | Base.")
    _allow(
        root,
        "os-packages",
        "libfoo | GPL-3.0-or-later WITH GCC-exception-3.1 | linked | Linked into the worker.",
    )
    assert gate.main(["--root", str(root)]) == 0
    assert gate.license_identifiers("(MIT OR GPL-2.0-only WITH Classpath-exception-2.0)") == {
        "MIT",
        "GPL-2.0-only",
    }


def test_a_published_image_needs_notices_naming_what_it_installs(tmp_path, capsys):
    root = _repo(tmp_path, "FROM python:3.12\nRUN apt-get install -y git sshpass\n", published=True)
    _allow(root, "images", "python | PSF-2.0 | base-image | Base.")
    _allow(
        root,
        "os-packages",
        "git | GPL-2.0-only | exec | A program.",
        "sshpass | GPL-2.0-or-later | exec | A program.",
    )
    assert gate.main(["--root", str(root)]) == 1
    assert "images/runner is published but has no THIRD-PARTY-NOTICES.md" in (
        capsys.readouterr().err
    )

    notices = root / "images" / "runner" / "THIRD-PARTY-NOTICES.md"
    notices.write_text("`python` and `git`, with the written offer.\n")
    assert gate.main(["--root", str(root)]) == 1
    err = capsys.readouterr().err
    assert "does not copy THIRD-PARTY-NOTICES.md" in err
    assert "does not name `sshpass`" in err

    dockerfile = root / "images" / "runner" / "Dockerfile"
    dockerfile.write_text(
        dockerfile.read_text()
        + "COPY THIRD-PARTY-NOTICES.md /usr/share/doc/hegemony/THIRD-PARTY-NOTICES.md\n"
    )
    notices.write_text("`python`, `git` and `sshpass`, with the written offer.\n")
    assert gate.main(["--root", str(root)]) == 0


def test_published_images_are_read_from_a_literal_context_or_a_matrix(tmp_path):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "images.yml").write_text(
        "jobs:\n"
        "  image:\n"
        "    strategy:\n"
        "      matrix:\n"
        "        include:\n"
        "          - image: first-runner\n"
        "            description: The first\n"
        "          - image: second-runner\n"
        "    steps:\n"
        "      - with:\n"
        "          context: images/${{ matrix.image }}\n"
        "          image-ref: ${{ steps.ref.outputs.image }}\n"
        "      - with:\n"
        "          context: images/third\n"
    )
    assert gate.published_images(tmp_path) == ["first-runner", "second-runner", "third"]
    assert gate.published_images(REPO_ROOT) == ["ansible-runner", "opentofu-runner"]


@pytest.mark.parametrize(
    ("reference", "repository"),
    [
        ("python:3.12-slim", "python"),
        ("ghcr.io/opentofu/opentofu:1.12.6", "ghcr.io/opentofu/opentofu"),
        ("localhost:5000/team/img:tag", "localhost:5000/team/img"),
        ("registry/img@sha256:abc", "registry/img"),
    ],
)
def test_repository_of_strips_tag_and_digest(reference, repository):
    assert gate.repository_of(reference) == repository


def test_the_image_inventory_refuses_a_review_tier_licence():
    """The build-time inventory fails when an installed distribution is refused.

    This environment holds the workspace's own AGPL distributions, which the
    image never does, so refusing AGPL here must fail and refusing SSPL pass.
    """
    import subprocess

    script = REPO_ROOT / "images" / "ansible-runner" / "inventory.py"
    refused = subprocess.run(
        [sys.executable, str(script), "--fail-on", "AGPL"], capture_output=True, text=True
    )
    assert refused.returncode == 1
    assert "refused licences: " in refused.stderr and "hegemony-step-sdk" in refused.stderr

    accepted = subprocess.run(
        [sys.executable, str(script), "--fail-on", "SSPL", "BUSL"], capture_output=True, text=True
    )
    assert accepted.returncode == 0, accepted.stderr
    assert any(line.startswith("pytest | ") for line in accepted.stdout.splitlines())
