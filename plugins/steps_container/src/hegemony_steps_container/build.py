# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""``container.build``: build an image on the sandbox and push it to a registry, or keep it there.

The build context is a folder among the flow's attachments, the files
``tf.plan`` and ``ansible.playbook`` read their sources from too (a flow
synced from git brings them from the repository). The worker writes that
folder into a private directory and runs ``docker buildx build`` against the
sandbox daemon (BuildKit, Docker driver) with the step's Docker configuration,
which holds the organization's registry logins and, with a platform registry,
the step's registry token. Where the image goes depends on its name and on
the platform (:class:`~hegemony_step_sdk.ImageBuild`):

- a name without a registry host (``tools/netbox-sync``) lands at
  ``<registry>/orgs/<slug>/<name>``: pushed to the platform registry when the
  platform runs one, and otherwise built into the sandbox daemon only, under
  that same name;
- a name with its own registry host (``ghcr.io/acme/netbox-sync``) is pushed
  there, with the organization's login for that host when one is saved, and
  only when the host allows the step to push outside the platform. Its name
  is then dropped from the sandbox daemon, which every organization shares.

Every image is tagged ``run-<short run id>`` plus the step's extra tags, and
carries the labels ``org.opencontainers.image.created``, ``sh.hegemony.run``
and ``sh.hegemony.step``.

What a build may reach and use is decided here, never by the Dockerfile:

- ``RUN`` instructions get the sandbox's default network only when the host
  says the step's egress policy is open; otherwise ``--network=none``.
- Build secrets reach ``RUN --mount=type=secret`` through BuildKit
  (``--secret``), read from private files: never build arguments, never a
  layer, never the command line.
- Base images are always pulled with the step's own logins (``--pull``) and
  no build reads the daemon's build cache (``--no-cache``): the sandbox is
  shared by every organization, and an image or a cached step another
  organization left there must not stand in for one this step is entitled to.
  With a platform registry they are pulled from the organization's copies
  (``cache_base_images``, :meth:`BuildImageHandler._base_images`): BuildKit
  gets each as a named context, by digest, pulled with the step's token like
  any other image.
  Cache mounts (``RUN --mount=type=cache``) also get a name unique to the
  build (``BUILDKIT_CACHE_MOUNT_NS``), so none is shared with another build
  even if BuildKit kept one across ``--no-cache`` builds.
- Only the official Dockerfile frontend runs: a ``# syntax`` directive naming
  another image is refused, and so are ``BUILDKIT_*`` build arguments, which
  steer BuildKit itself.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hegemony_step_sdk import (
    BUILD_NETWORK_DEFAULT,
    BUILD_NETWORK_NONE,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    ImageBuild,
    ImageCache,
    StepKind,
)

from . import run as _run
from .base_images import base_image_references
from .image_cache import (
    CachePlan,
    RegistryClient,
    RegistryDenied,
    RegistryUnavailable,
    cache_key_tag,
    login_for,
    parse_reference,
    pin_reference,
    plan_cache,
    upstream_api_url,
)
from .pull_progress import require_docker_host
from .run import RunContainerHandler, _docker_env, repo_digest_for
from .runner import container_config_from, resolve_secret_values, secret_map_errors
from .streams import (
    KILL_WAIT_SECONDS,
    MAX_LIVE_OUTPUT_BYTES,
    LiveOutput,
    read_lines,
    size_text,
)

logger = logging.getLogger(__name__)

HANDLER_ID = "container.build"

#: Built-in step timeout: a build installs packages and pushes layers.
DEFAULT_BUILD_TIMEOUT_SECONDS = 1800
#: The build log kept as evidence; the live log stops at MAX_LIVE_OUTPUT_BYTES.
MAX_LOG_BYTES = 5 * 1024 * 1024
#: Live output is sent in batches of about this many characters, or every
#: :data:`_FLUSH_SECONDS`, whichever comes first.
_EVENT_BATCH_CHARS = 2048
_FLUSH_SECONDS = 0.25
#: The ``docker buildx version`` check and the digest lookup are quick; a
#: wedged worker or daemon must not hold the step for longer than this.
_PROBE_TIMEOUT_SECONDS = 15.0
#: The build argument that prefixes every cache mount's id (Dockerfile frontend).
CACHE_MOUNT_NS_ARG = "BUILDKIT_CACHE_MOUNT_NS"

#: The tag every build gets: ``run-`` and the run id's first eight characters,
#: the short id the run pages show.
RUN_TAG_PREFIX = "run-"
#: Labels the step sets on every image; a step's own labels may not use them.
CREATED_LABEL = "org.opencontainers.image.created"
RUN_LABEL = "sh.hegemony.run"
STEP_LABEL = "sh.hegemony.step"
RESERVED_LABEL_PREFIX = "sh.hegemony."

#: An OCI repository name: lowercase components separated by slashes (the
#: platform registry's own rule).
_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_IMAGE_NAME_RE = re.compile(rf"^{_NAME_COMPONENT}(?:/{_NAME_COMPONENT})*$")
#: A registry host in an image reference: DNS labels joined by dots, and an
#: optional port (the reference grammar Docker follows).
_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_REGISTRY_HOST_RE = re.compile(rf"^{_HOST_LABEL}(?:\.{_HOST_LABEL})*(?::[0-9]{{1,5}})?$")
MAX_IMAGE_NAME_LENGTH = 200
#: A full reference (registry, namespace, name and tag) Docker accepts.
MAX_REFERENCE_LENGTH = 255
_TAG_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
#: ``sha256_<hex>`` is the platform cache's key tag and ``sha256-<hex>`` the
#: OCI referrers fallback tag, which zot keeps out of its index entirely.
_DIGEST_SHAPED_TAG_RE = re.compile(r"^sha256[_-][0-9a-f]{64}$")
_ARG_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LABEL_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_STAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
_PLATFORM_RE = re.compile(r"^[a-z0-9]+/[a-z0-9_]+(?:/[a-z0-9]+)?$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TEMPLATE_RE = re.compile(r"\{\{|\{%")
#: A parser directive line at the top of a Dockerfile (``# syntax=...``).
_DIRECTIVE_RE = re.compile(r"^#\s*([A-Za-z_]+)\s*=\s*(.*?)\s*$")
#: The official Dockerfile frontends, by tag and/or digest.
_OFFICIAL_FRONTEND_RE = re.compile(
    r"^(?:docker\.io/)?docker/dockerfile(?:-upstream)?"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[0-9a-f]{64})?$"
)
#: Placeholder image for validating the step's egress fields with
#: ``container.run``'s own rules: a build pulls no image of its own.
_EGRESS_CHECK_IMAGE = "scratch"


def looks_like_host(segment: str) -> bool:
    """Whether a name's first segment has the shape of a registry host.

    The platform registry's rule (``looks_like_host`` in the platform's
    ``registry_tokens``): a dot, or ``localhost`` with or without a port
    after an underscore. Such names are the cache's copies of upstream
    images (``orgs/<slug>/<host>/<repository>``), so a built image never
    takes one, and the registry refuses the push.
    """
    return "." in segment or segment == "localhost" or segment.startswith("localhost_")


def _templated(value: object) -> bool:
    """Whether ``value`` still holds template syntax, which the host renders before a run."""
    return isinstance(value, str) and bool(_TEMPLATE_RE.search(value))


def registry_host_of(name: str) -> str | None:
    """The registry host ``name`` starts with, read the way Docker reads a reference, or None.

    A first segment with a dot or a colon, or ``localhost``, is a registry
    host when another segment follows it: ``ghcr.io/acme/x`` and
    ``registry.example.com:5000/x`` name one, ``tools/x`` and ``x`` do not.
    """
    first, separator, _rest = name.partition("/")
    if separator and ("." in first or ":" in first or first == "localhost"):
        return first
    return None


def image_name_error(name: object, *, allow_template: bool = False) -> str | None:
    """Why ``name`` cannot name a built image, or None.

    Either a name under the organization's namespace (``tools/netbox-sync``)
    or one with its own registry host in front (``ghcr.io/acme/netbox-sync``);
    never a tag, which the step's tags give.
    """
    if not isinstance(name, str) or not name.strip():
        return (
            "'image' is required: a name such as tools/netbox, or one with its registry in "
            "front, such as ghcr.io/acme/netbox"
        )
    if allow_template and _templated(name):
        return None
    name = name.strip()
    if len(name) > MAX_IMAGE_NAME_LENGTH:
        return f"'image' must be at most {MAX_IMAGE_NAME_LENGTH} characters"
    host = registry_host_of(name)
    if host is not None:
        if not _REGISTRY_HOST_RE.match(host):
            return f"'image' {name!r} starts with {host!r}, which is not a valid registry host"
        if host.partition(":")[0].lower() == "localhost":
            return (
                f"'image' {name!r} names localhost, which is the sandbox itself, not a registry "
                "to push to"
            )
        if not _IMAGE_NAME_RE.match(name.partition("/")[2]):
            return (
                f"'image' {name!r} is not a valid image name: after the registry host, "
                "lowercase letters and digits, separated by '.', '_', '__' or '-', in segments "
                "joined by '/' (ghcr.io/acme/netbox-sync), without a tag"
            )
        return None
    if not _IMAGE_NAME_RE.match(name):
        return (
            f"'image' {name!r} is not a valid image name: lowercase letters and digits, "
            "separated by '.', '_', '__' or '-', in segments joined by '/' (tools/netbox-sync), "
            "without a tag"
        )
    first = name.split("/", 1)[0]
    if looks_like_host(first):
        return (
            f"'image' {name!r} starts with {first!r}, which has the shape of a registry host "
            "(a dot, or localhost): such names are reserved for the platform's cached copies "
            "of upstream images. Name the image without one, e.g. tools/netbox-sync, or put "
            "its registry in front, e.g. ghcr.io/acme/netbox-sync"
        )
    return None


def tag_error(field: str, tag: object, *, allow_template: bool = False) -> str | None:
    """Why ``tag`` cannot tag a built image, or None."""
    if not isinstance(tag, str) or not tag.strip():
        return f"'{field}' must be a non-empty tag"
    if allow_template and _templated(tag):
        return None
    tag = tag.strip()
    if not _TAG_RE.match(tag):
        return (
            f"'{field}' {tag!r} is not a valid tag: up to 128 letters, digits, '_', '.' or '-', "
            "not starting with '.' or '-'"
        )
    if _DIGEST_SHAPED_TAG_RE.match(tag):
        return (
            f"'{field}' {tag!r} has the shape of a digest tag, which the platform registry "
            "reserves for cached copies and referrers"
        )
    return None


def relative_path_error(field: str, value: object, *, allow_empty: bool) -> str | None:
    """Why ``value`` is not a relative path among the flow attachments, or None."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None if allow_empty else f"'{field}' is required"
    if not isinstance(value, str):
        return f"'{field}' must be a relative path among the flow attachments"
    path = value.strip()
    if path.startswith("/") or "\\" in path or "\0" in path:
        return f"'{field}' must be a relative path among the flow attachments"
    if ".." in path.split("/"):
        return f"'{field}' must not contain '..'"
    return None


def frontend_error(dockerfile: str) -> str | None:
    """Why the Dockerfile's ``# syntax`` directive is refused, or None.

    BuildKit reads parser directives in the comment lines at the top of the
    file. A ``syntax`` directive runs the named image as the build's
    frontend, which builds whatever it likes and ignores this step's rules
    (it could read the sandbox's shared build cache), so only the official
    ``docker/dockerfile`` frontends are taken. Conservative on purpose: every
    directive-shaped comment before the first instruction is checked, even
    one BuildKit would read as a plain comment.
    """
    for raw in dockerfile.lstrip("﻿").splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("#"):
            return None
        match = _DIRECTIVE_RE.match(line)
        if match is None or match.group(1).lower() != "syntax":
            continue
        frontend = match.group(2)
        if not _OFFICIAL_FRONTEND_RE.match(frontend):
            return (
                f"the Dockerfile's syntax directive names the frontend {frontend!r}; only the "
                "official docker/dockerfile frontend may build here (or none: the built-in "
                "one takes every current Dockerfile)"
            )
    return None


def run_tag(run_id: str) -> str:
    """The tag every build of a run gets: ``run-`` and the run's short id."""
    short = re.sub(r"[^A-Za-z0-9_.-]", "", run_id)[:8]
    return f"{RUN_TAG_PREFIX}{short or 'unknown'}"


#: Where a build's image goes (``output.destination``): the platform registry,
#: the sandbox daemon only, or another registry.
DESTINATION_PLATFORM = "platform"
DESTINATION_LOCAL = "local"
DESTINATION_REMOTE = "remote"


@dataclass(frozen=True, slots=True)
class BaseImage:
    """Where the build took one of its Dockerfile's base images from."""

    # The reference as the Dockerfile names it (variables expanded).
    image: str
    # The platform registry's copy it was built on (``…@sha256:…``), or "" when
    # BuildKit pulled it from its own registry.
    served: str = ""
    # True when this step saved that copy.
    cached: bool = False

    def as_record(self) -> dict[str, Any]:
        return {
            "image": self.image,
            "served": self.served,
            "source": "cache" if self.served else "upstream",
            "cached": self.cached,
        }


@dataclass(frozen=True, slots=True)
class BuildDestination:
    """Where one build's image goes: its repository, and the registry it is pushed to."""

    kind: str
    repository: str
    # The registry host the push goes to; empty for an image the step keeps
    # in the sandbox.
    host: str = ""

    @property
    def push(self) -> bool:
        return self.kind != DESTINATION_LOCAL


class BuildRefused(Exception):
    """The image cannot go where its name says: the step's error and summary."""

    def __init__(self, error: str, summary: str) -> None:
        super().__init__(error)
        self.error = error
        self.summary = summary


#: Ports a registry host may carry that still name the same registry: Docker
#: reaches a registry on 443 (or 80 when it is insecure) when none is given.
_DEFAULT_REGISTRY_PORTS = (":443", ":80")


def same_registry_host(host: str, registry: str) -> bool:
    """Whether ``host`` names ``registry``, in any case and with or without a default port.

    ``registry.hegemony.internal:80`` and ``REGISTRY.hegemony.internal`` are
    the platform registry; ``registry.hegemony.internal:5000`` is another one.
    """

    def bare(value: str) -> str:
        value = value.lower()
        for port in _DEFAULT_REGISTRY_PORTS:
            if value.endswith(port):
                return value[: -len(port)]
        return value

    return bare(host) == bare(registry)


def build_destination(name: str, target: ImageBuild) -> BuildDestination:
    """Where the image named ``name`` goes, by its name and what the host allows.

    Pure, for testing; ``name`` has passed :func:`image_name_error`. A name
    without a registry host goes under the organization's namespace, pushed
    when the platform registry takes it and kept in the sandbox otherwise. A
    name with its own host is pushed there, when the host lets the step push
    outside the platform; the platform registry's own host is refused, since
    its names are the namespace's to give. Raises :class:`BuildRefused`.
    """
    host = registry_host_of(name)
    if host is None:
        if not target.registry or not target.namespace:
            raise BuildRefused(
                "The platform gave this step no image namespace to build under",
                "Image build unavailable",
            )
        repository = f"{target.registry}/{target.namespace}/{name}"
        if target.push:
            return BuildDestination(DESTINATION_PLATFORM, repository, target.registry)
        return BuildDestination(DESTINATION_LOCAL, repository)
    if target.registry and same_registry_host(host, target.registry):
        raise BuildRefused(
            f"'image' {name!r} names the platform registry itself: give the name without "
            "it, and the step puts the image under this organization's namespace",
            "Config validation failed",
        )
    if not target.external_push:
        raise BuildRefused(
            f"This step may not push to {host}: the sandbox daemon pushes to registries "
            "other than the platform's outside the egress policy the step's containers are "
            "held to, so the platform allows it only when the step's egress policy is open "
            "(open mode, no Deny rules)",
            "Push not allowed",
        )
    # Host names know no case, and Docker looks a login up by the host as
    # written: the lowercase spelling is the one logins are saved under.
    host = host.lower()
    return BuildDestination(DESTINATION_REMOTE, f"{host}/{name.partition('/')[2]}", host)


class BuildImageConfig(BaseModel):
    """Config for ``container.build``.

    The semantic checks (name and tag shapes, paths, reserved names) live in
    :meth:`BuildImageHandler.validate_config`.
    """

    model_config = ConfigDict(extra="allow")

    image: str = Field(
        min_length=1,
        title="Image name",
        description=(
            "A name such as tools/netbox-sync goes under this organization's namespace "
            "(registry.hegemony.internal/orgs/ORG/tools/netbox-sync): pushed to the platform "
            "registry when the platform runs one, otherwise built into the sandbox only. A "
            "name with its registry in front, such as ghcr.io/acme/netbox-sync, is pushed "
            "there with the organization's saved login for that registry. Lowercase, "
            "without a tag."
        ),
        json_schema_extra={"x_placeholder": "tools/netbox-sync"},
    )
    tags: list[str] = Field(
        default_factory=list,
        title="Extra tags",
        description=(
            "Tags to give the image besides run-SHORT_RUN_ID, which every build gets; one per "
            "line, e.g. latest or {{ inputs.version }}."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "latest\n{{ inputs.version }}",
            "x_rows": 2,
        },
    )
    context_dir: str = Field(
        default="",
        title="Build context folder",
        description=(
            "Folder among the flow attachments to build from, e.g. images/netbox-sync. Leave "
            "empty for the attachments root. Only the files under it are sent to the build."
        ),
        json_schema_extra={"x_placeholder": "images/netbox-sync"},
    )
    dockerfile: str = Field(
        default="Dockerfile",
        title="Dockerfile",
        description="Path of the Dockerfile inside the build context folder.",
        json_schema_extra={"x_placeholder": "Dockerfile"},
    )
    cache_base_images: bool = Field(
        default=True,
        title="Cache base images",
        description=(
            "Build on copies of the Dockerfile's base images (FROM and COPY --from) kept in "
            "the platform registry under this organization, saving a copy on first use, as "
            "Cache image does for a container step. A tag is still checked against the "
            "image's registry by digest, and the copy serves when that registry is "
            "unreachable. Turn off for base images that must come straight from their "
            "registries every time. No effect when the platform runs no registry, or when "
            "the build targets another platform."
        ),
    )
    build_args: dict[str, str] = Field(
        default_factory=dict,
        title="Build arguments",
        description=(
            "NAME=value, one per line, for the Dockerfile's ARG instructions. Values may use "
            "templates such as {{ inputs.version }}. Build arguments are recorded in the "
            "image's history: put credentials in Build secrets instead."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "VERSION={{ inputs.version }}",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    secrets: dict[str, str] = Field(
        default_factory=dict,
        title="Build secrets",
        description=(
            "ID=secret reference, one per line (a {{ secret('...') }} template or a bare "
            "reference such as vault://orgs/acme/secrets/pypi/token). A RUN instruction reads "
            "one with --mount=type=secret,id=ID (at /run/secrets/ID); it never lands in a "
            "layer, the image's history or the build's command line, and is redacted from "
            "the log."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "pypi_token=vault://orgs/acme/secrets/pypi/token",
            "x_rows": 2,
            "x_col_span": 2,
        },
    )
    target: str = Field(
        default="",
        title="Target stage",
        description="Build only up to this stage of a multi-stage Dockerfile (--target).",
        json_schema_extra={"x_placeholder": "runtime", "x_advanced": True},
    )
    platform: str = Field(
        default="",
        title="Platform",
        description=(
            "Platform to build for, e.g. linux/arm64. Leave empty for the sandbox's own. "
            "Another architecture needs emulation (QEMU) registered on the sandbox host."
        ),
        json_schema_extra={"x_placeholder": "linux/amd64", "x_advanced": True},
    )
    labels: dict[str, str] = Field(
        default_factory=dict,
        title="Labels",
        description=(
            "KEY=value image labels, one per line, e.g. "
            "org.opencontainers.image.source=https://git.example.com/netbox-sync. The step "
            "always sets org.opencontainers.image.created, sh.hegemony.run and "
            "sh.hegemony.step; keys starting with sh.hegemony. are reserved."
        ),
        json_schema_extra={
            "x_widget": "env-vars",
            "x_placeholder": "org.opencontainers.image.source=https://git.example.com/netbox-sync",
            "x_rows": 2,
            "x_col_span": 2,
            "x_advanced": True,
        },
    )
    egress_mode: str = Field(
        default="",
        title="Egress policy mode",
        description=(
            "Network for the build's RUN instructions: they reach the network only when the "
            "effective policy is 'open' with no Deny rules, and build without any network "
            "otherwise ('allow-listed', 'deny-all', or Deny rules). Leave empty to inherit the "
            "flow's network policy."
        ),
        json_schema_extra={
            "x_placeholder": "open | allow-listed | deny-all",
            "x_advanced": True,
            "x_col_span": 2,
        },
    )
    egress_allow: list[str] = Field(
        default_factory=list,
        title="Egress allow rules",
        description=(
            "One rule per line, used with allow-listed mode: CIDR[:port[-port]][/tcp|udp] or "
            "service:port. A build cannot be held to them, so it gets no network at all."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "0.0.0.0/0:443/tcp",
            "x_rows": 2,
            "x_advanced": True,
            "x_col_span": 2,
        },
    )
    egress_deny: list[str] = Field(
        default_factory=list,
        title="Egress deny rules",
        description=(
            "One rule per line, same format as Allow rules. Any Deny rule takes the build's "
            "network away entirely."
        ),
        json_schema_extra={
            "x_widget": "commands",
            "x_placeholder": "169.254.169.254/32",
            "x_rows": 2,
            "x_advanced": True,
            "x_col_span": 2,
        },
    )


def buildx_argv(
    *,
    context: str,
    dockerfile: str,
    references: list[str],
    network: str,
    metadata_file: str,
    build_args: dict[str, str] | None = None,
    labels: dict[str, str] | None = None,
    secret_files: dict[str, str] | None = None,
    target: str = "",
    platform: str = "",
    cache_namespace: str = "",
    push: bool = True,
    build_contexts: dict[str, str] | None = None,
) -> list[str]:
    """The ``docker`` arguments of one build (without the docker binary itself).

    Pure, for testing. ``secret_files`` maps a secret id to the private file
    holding its value; the value itself never reaches the argument list.
    ``cache_namespace`` prefixes the id of every cache mount the Dockerfile
    declares. ``push`` pushes the references; without it the image is loaded
    into the sandbox daemon under them, and goes nowhere else.
    ``build_contexts`` maps an image reference the Dockerfile uses to the
    ``docker-image://`` reference BuildKit takes it from instead.
    """
    args = [
        "buildx",
        "build",
        "--progress=plain",
        # Base images come from their registries with this step's logins, and
        # nothing is read from the build cache the sandbox shares with every
        # other organization (cache mounts start empty as well; the namespace
        # below keeps them apart even if they did not).
        "--pull",
        "--no-cache",
        # A plain image: no attestation manifests beside it.
        "--provenance=false",
        "--sbom=false",
        f"--network={network}",
        "--file",
        dockerfile,
        "--metadata-file",
        metadata_file,
    ]
    if target:
        args += ["--target", target]
    if platform:
        args += ["--platform", platform]
    for name, value in sorted((build_args or {}).items()):
        args += ["--build-arg", f"{name}={value}"]
    if cache_namespace:
        # The step's own build arguments never start with BUILDKIT_, so this
        # one cannot be overridden.
        args += ["--build-arg", f"{CACHE_MOUNT_NS_ARG}={cache_namespace}"]
    for key, value in sorted((labels or {}).items()):
        args += ["--label", f"{key}={value}"]
    for secret_id, path in sorted((secret_files or {}).items()):
        args += ["--secret", f"id={secret_id},src={path}"]
    for name, source in sorted((build_contexts or {}).items()):
        args += ["--build-context", f"{name}={source}"]
    for reference in references:
        args += ["--tag", reference]
    args += ["--push" if push else "--load", context]
    return args


def build_environment(docker_host: str, docker_config_dir: str) -> dict[str, str]:
    """The environment of every docker call a build makes.

    The sandbox daemon and the step's Docker configuration, as for
    ``container.run``; buildx settings inherited from the worker are dropped,
    and the ones a build needs are set: no default attestations, and a
    metadata file without the provenance record (it would carry the build
    arguments).
    """
    env = {
        key: value
        for key, value in _docker_env(docker_host, docker_config_dir).items()
        if not key.startswith(("BUILDX_", "BUILDKIT_"))
    }
    env["BUILDX_NO_DEFAULT_ATTESTATIONS"] = "1"
    env["BUILDX_METADATA_PROVENANCE"] = "disabled"
    env["BUILDX_METADATA_WARNINGS"] = "false"
    return env


def _failure(error: str, summary: str, **extra: Any) -> HandlerResult:
    return HandlerResult(success=False, error=error, summary=summary, **extra)


def _error_line(lines: deque[str]) -> str:
    """The build's own explanation of a failure: its last ``ERROR:`` line."""
    for line in reversed(lines):
        if line.startswith("ERROR:"):
            return line[len("ERROR:") :].strip()[:500]
    for line in reversed(lines):
        if "ERROR" in line:
            return line.strip()[:500]
    return ""


class _BuildLog:
    """The build's output: streamed to the live log in batches, up to a limit; kept for evidence."""

    def __init__(self, emit: Callable[..., Awaitable[Any]]) -> None:
        self._emit = emit
        # One emission at a time, so batches reach the log in order.
        self._lock = asyncio.Lock()
        self._pending: list[str] = []
        self._pending_chars = 0
        self._last_flush = time.monotonic()
        self.captured = bytearray()
        self.truncated = False
        self.tail: deque[str] = deque(maxlen=40)
        self._live = LiveOutput(
            f"[Live output stops here, at its {size_text(MAX_LIVE_OUTPUT_BYTES)} limit; the "
            f"build goes on. Its build_output evidence keeps the first "
            f"{size_text(MAX_LOG_BYTES)} of the log.]"
        )

    async def add(self, raw: bytes) -> None:
        text = raw.decode("utf-8", errors="replace")
        if len(self.captured) < MAX_LOG_BYTES:
            room = MAX_LOG_BYTES - len(self.captured)
            self.captured.extend(raw[:room])
            if len(raw) > room:
                self.truncated = True
        else:
            self.truncated = True
        self.tail.append(text.rstrip("\n"))
        live = self._live.admit(text)
        if not live:
            return
        self._pending.append(live)
        self._pending_chars += len(live)
        if (
            self._pending_chars >= _EVENT_BATCH_CHARS
            or time.monotonic() - self._last_flush >= _FLUSH_SECONDS
        ):
            await self.flush()

    async def flush(self) -> None:
        async with self._lock:
            self._last_flush = time.monotonic()
            if not self._pending:
                return
            chunk = "".join(self._pending)
            self._pending.clear()
            self._pending_chars = 0
            try:
                await self._emit(chunk, attrs={"milestone": "output", "stream": "stdout"})
            except Exception as exc:  # noqa: BLE001 - the live log must never fail the build
                logger.debug("Build output event failed: %s", exc)

    def text(self) -> str:
        output = self.captured.decode("utf-8", errors="replace")
        if self.truncated:
            output += f"\n[TRUNCATED after {MAX_LOG_BYTES} bytes]"
        return output


class BuildImageHandler(BaseHandler):
    """Build an image from flow attachments; push it to a registry, or keep it in the sandbox."""

    handler_id = HANDLER_ID
    supported_kinds = [StepKind.ACTION, StepKind.EXECUTE]
    display_name = "Build Image"
    description = (
        "Build a container image from the flow's attachments on the Docker-in-Docker "
        "sandbox and push it to the organization's namespace of the platform registry, or "
        "to another registry; without a platform registry, keep it in the sandbox."
    )
    category = "Actions"
    targeting = HandlerTargeting(roles=False, ips=False)
    container_backed = True
    builds_images = True
    # Secret references reach the handler as written (see resolve_secret_values).
    raw_config_keys = frozenset({"secrets"})
    config_model = BuildImageConfig
    default_config = {"dockerfile": "Dockerfile"}
    default_timeout_seconds = DEFAULT_BUILD_TIMEOUT_SECONDS

    def validate_config(self, config: dict[str, Any]) -> list[str]:
        """Validate the step's fields; templated values are checked again once rendered."""
        errors = super().validate_config(config)
        if errors:
            return errors
        return self._semantic_errors(config, allow_templates=True)

    def _semantic_errors(self, config: dict[str, Any], *, allow_templates: bool) -> list[str]:
        errors: list[str] = []
        error = image_name_error(config.get("image"), allow_template=allow_templates)
        if error:
            errors.append(error)
        for index, tag in enumerate(config.get("tags") or []):
            error = tag_error(f"tags[{index}]", tag, allow_template=allow_templates)
            if error:
                errors.append(error)
        for field, allow_empty in (("context_dir", True), ("dockerfile", True)):
            error = relative_path_error(field, config.get(field), allow_empty=allow_empty)
            if error:
                errors.append(error)
        for name in config.get("build_args") or {}:
            if not isinstance(name, str) or not _ARG_NAME_RE.match(name):
                errors.append(f"'build_args' name {name!r} is not a valid ARG name")
            elif name.upper().startswith("BUILDKIT_"):
                errors.append(
                    f"'build_args' name {name!r} is reserved: BUILDKIT_ arguments steer BuildKit "
                    "itself"
                )
        errors.extend(secret_map_errors("secrets", config.get("secrets")))
        for key in config.get("labels") or {}:
            if not isinstance(key, str) or not _LABEL_KEY_RE.match(key):
                errors.append(f"'labels' key {key!r} is not a valid label key")
            elif key.startswith(RESERVED_LABEL_PREFIX) or key == CREATED_LABEL:
                errors.append(f"'labels' key {key!r} is set by the step itself")
        for field, pattern, example in (
            ("target", _STAGE_RE, "a stage name such as runtime"),
            ("platform", _PLATFORM_RE, "os/arch[/variant], e.g. linux/arm64"),
        ):
            value = config.get(field)
            if value is None or (isinstance(value, str) and not value.strip()):
                continue
            if allow_templates and _templated(value):
                continue
            if not isinstance(value, str) or not pattern.match(value.strip()):
                errors.append(f"'{field}' must be {example}")
        # The egress fields, by container.run's own rules (one vocabulary).
        errors.extend(
            RunContainerHandler().validate_config(
                container_config_from(config, image=_EGRESS_CHECK_IMAGE, command=[])
            )
        )
        return errors

    async def execute(self, ctx: HandlerContext) -> HandlerResult:
        """Build the image, push it, and report the pushed references and digest."""
        errors = self.validate_config(ctx.config)
        if not errors:
            # Rendered now: a templated name or tag must hold up as well.
            errors = self._semantic_errors(ctx.config, allow_templates=False)
        if errors:
            return _failure(
                f"Invalid build config: {'; '.join(errors)}", "Config validation failed"
            )
        config = BuildImageConfig.model_validate(ctx.config)

        services = ctx.require_services()
        runtime = services.container_runtime()
        target = runtime.image_build
        if target is None:
            return _failure(
                "This step cannot build here: the platform gave it no build settings (it could "
                "not grant the step access to its registry, see the step's events, or it is "
                "older than this step)",
                "Image build unavailable",
            )
        try:
            docker_host = require_docker_host(runtime.docker_host or "")
        except ValueError as exc:
            return _failure(str(exc), "Container sandbox not configured")
        try:
            destination = build_destination(config.image.strip(), target)
        except BuildRefused as exc:
            return _failure(exc.error, exc.summary)

        network = (
            BUILD_NETWORK_DEFAULT if target.network == BUILD_NETWORK_DEFAULT else BUILD_NETWORK_NONE
        )
        repository = destination.repository
        tags = list(dict.fromkeys([run_tag(ctx.run_id), *(t.strip() for t in config.tags)]))
        references = [f"{repository}:{tag}" for tag in tags]
        too_long = [ref for ref in references if len(ref) > MAX_REFERENCE_LENGTH]
        if too_long:
            return _failure(
                f"Image reference {too_long[0]!r} is longer than {MAX_REFERENCE_LENGTH} "
                "characters; shorten the image name or the tag",
                "Config validation failed",
            )
        # "images/x/", "./images/x" and "images//x" name one folder; "." the root.
        context_dir = posixpath.normpath(config.context_dir.strip() or ".").strip("/")
        if context_dir == ".":
            context_dir = ""
        dockerfile = config.dockerfile.strip() or "Dockerfile"

        try:
            secrets = await resolve_secret_values(
                ctx, config.secrets, source=f"{HANDLER_ID}.secrets"
            )
        except ValueError as exc:
            return _failure(f"Invalid build config: {exc}", "Config validation failed")

        async def emit(message: str, attrs: dict[str, Any] | None = None) -> None:
            try:
                await ctx.emit_progress(message, attrs=attrs)
            except Exception as exc:  # noqa: BLE001 - events never fail the build
                logger.debug("Build progress event failed: %s", exc)

        docker_bin = runtime.docker_bin
        env = build_environment(docker_host, getattr(runtime, "docker_config_dir", "") or "")
        # Whether the organization saved a login for the registry the image
        # goes to: the push reads it from the step's Docker configuration.
        saved_login = destination.kind == DESTINATION_REMOTE and (
            login_for(parse_reference(repository).host, env) is not None
        )
        started = time.monotonic()
        deadline = started + max(int(ctx.timeout_seconds or 0), 1)
        workdir = tempfile.mkdtemp(prefix="hegemony-build-")
        built = False
        names_dropped = False
        try:
            context_root = os.path.join(workdir, "context")
            os.mkdir(context_root)
            try:
                staged = await self._stage_context(ctx, context_root, context_dir, dockerfile)
            except _ContextError as exc:
                return _failure(str(exc), "Build context unavailable")
            dockerfile_path = os.path.join(context_root, *dockerfile.split("/"))
            with open(dockerfile_path, encoding="utf-8", errors="replace") as handle:
                dockerfile_text = handle.read()
            problem = frontend_error(dockerfile_text)
            if problem:
                return _failure(f"Invalid Dockerfile: {problem}", "Config validation failed")

            secret_files = self._write_secrets(workdir, secrets)
            metadata_file = os.path.join(workdir, "metadata.json")

            probe = await self._probe_buildx(docker_bin, env)
            if probe is not None:
                return probe

            # The Dockerfile's base images, from the platform registry's copies.
            base_images: list[BaseImage] = []
            cache = getattr(runtime, "image_cache", None)
            if cache is not None and config.cache_base_images:
                base_references = base_image_references(
                    dockerfile_text, config.build_args, config.target.strip()
                )
                if base_references and config.platform.strip():
                    await emit(
                        "Base images come from their registries: the build targets "
                        f"{config.platform.strip()}, and a copy in the platform registry holds "
                        "only the sandbox's own platform",
                        attrs={
                            "milestone": "base_image_cache_skip",
                            "platform": config.platform.strip(),
                        },
                    )
                    base_images = [BaseImage(reference) for reference in base_references]
                elif base_references:
                    base_images = await self._base_images(
                        references=base_references,
                        cache=cache,
                        docker_bin=docker_bin,
                        docker_host=docker_host,
                        env=env,
                        deadline=deadline,
                        emit=emit,
                    )
            build_contexts = {
                base.image: f"docker-image://{base.served}" for base in base_images if base.served
            }

            created = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            labels = {
                **config.labels,
                CREATED_LABEL: created,
                RUN_LABEL: ctx.run_id,
                STEP_LABEL: ctx.step_id,
            }
            argv = buildx_argv(
                context=context_root,
                dockerfile=dockerfile_path,
                references=references,
                network=network,
                metadata_file=metadata_file,
                build_args=dict(config.build_args),
                labels=labels,
                secret_files=secret_files,
                target=config.target.strip(),
                platform=config.platform.strip(),
                cache_namespace=f"hegemony-build-{uuid.uuid4().hex}",
                push=destination.push,
                build_contexts=build_contexts,
            )
            source = f"attachments/{context_dir}" if context_dir else "the attachments root"
            network_note = (
                "RUN instructions may reach the network"
                if network == BUILD_NETWORK_DEFAULT
                else "RUN instructions have no network (the step's egress policy is not open)"
            )
            if destination.kind == DESTINATION_PLATFORM:
                destination_note = "pushing to the platform registry"
            elif destination.kind == DESTINATION_LOCAL:
                destination_note = (
                    "keeping it in the sandbox, unpushed (the platform runs no registry)"
                )
            elif saved_login:
                destination_note = (
                    f"pushing to {destination.host} with the organization's saved login for it"
                )
            else:
                destination_note = (
                    f"pushing to {destination.host} without a login: the organization saved "
                    "none for it"
                )
            await emit(
                f"Building {repository} from {source} ({staged} file(s), {dockerfile}), "
                f"{destination_note}; {network_note}",
                attrs={
                    "milestone": "build_start",
                    "image": repository,
                    "tags": tags,
                    "network": network,
                    "destination": destination.kind,
                    **(
                        {"saved_login": saved_login}
                        if destination.kind == DESTINATION_REMOTE
                        else {}
                    ),
                },
            )

            log = _BuildLog(ctx.emit_progress)
            built = True
            exit_code = await self._run_build(docker_bin, argv, env, log, deadline)
            # The digest first (the daemon's fallback reads it through the
            # names), then an image pushed to another registry loses its names
            # on the shared sandbox at once: nothing below needs them.
            digest = ""
            if exit_code == 0 and destination.push:
                digest = self._metadata_digest(metadata_file) or await self._daemon_digest(
                    docker_bin, env, references[0]
                )
            cleanup_problem = None
            if destination.kind == DESTINATION_REMOTE:
                names_dropped = True
                cleanup_problem = await self._drop_names(docker_bin, env, references)
            await log.flush()
            if cleanup_problem:
                await self._report_names_left(emit, references, cleanup_problem)
            duration = round(time.monotonic() - started, 2)
            if exit_code is None:
                timeout = int(ctx.timeout_seconds or 0)
                await emit(
                    f"Image build timed out after {timeout}s",
                    attrs={"milestone": "build_failed", "image": repository},
                )
                return _failure(
                    f"Image build timed out after {timeout}s",
                    "Build timed out",
                    evidence=[self._log_artifact(ctx, log, -1, repository, "", duration)],
                    metrics={"duration_seconds": duration, "image": repository},
                )

            if exit_code != 0:
                reason = (
                    _error_line(log.tail) or f"docker buildx build exited with code {exit_code}"
                )
                await emit(
                    f"Image build failed: {reason}",
                    attrs={
                        "milestone": "build_failed",
                        "image": repository,
                        "exit_code": exit_code,
                    },
                )
                return _failure(
                    reason,
                    "Image build failed",
                    evidence=[self._log_artifact(ctx, log, exit_code, repository, "", duration)],
                    metrics={
                        "exit_code": exit_code,
                        "duration_seconds": duration,
                        "image": repository,
                    },
                )

            if destination.push:
                if not digest:
                    # Later steps run output.reference; a tag in its place could
                    # move to another image after this step reported success.
                    reason = (
                        f"The image was pushed as {', '.join(tags)}, but its digest could not "
                        "be read (neither from the build's metadata nor from the sandbox "
                        "daemon), so the step cannot report the exact image it built"
                    )
                    await emit(
                        reason,
                        attrs={
                            "milestone": "build_failed",
                            "image": repository,
                            "references": references,
                        },
                    )
                    return _failure(
                        reason,
                        "Image digest unavailable",
                        evidence=[self._log_artifact(ctx, log, 0, repository, "", duration)],
                        metrics={
                            "exit_code": 0,
                            "duration_seconds": duration,
                            "image": repository,
                        },
                    )
                reference = f"{repository}@{digest}"
                await emit(
                    f"Pushed {reference} as {', '.join(tags)} in {duration:.1f}s",
                    attrs={
                        "milestone": "image_pushed",
                        "image": repository,
                        "digest": digest,
                        "references": references,
                        "destination": destination.kind,
                        "duration_seconds": duration,
                    },
                )
            else:
                # No registry holds the image, so no manifest digest names it:
                # the run tag does. No other run's build takes that tag (only
                # another build of the same name in this run would).
                digest = ""
                reference = references[0]
                await emit(
                    f"Built {reference} in {duration:.1f}s and kept it in the sandbox, "
                    "unpushed (the platform runs no registry)",
                    attrs={
                        "milestone": "image_built",
                        "image": repository,
                        "references": references,
                        "destination": destination.kind,
                        "duration_seconds": duration,
                    },
                )
            details = {
                "repository": repository,
                "digest": digest,
                "reference": reference,
                "tags": tags,
                "references": references,
                "destination": destination.kind,
                "pushed": destination.push,
                **({"saved_login": saved_login} if destination.kind == DESTINATION_REMOTE else {}),
                "context": source,
                "dockerfile": dockerfile,
                "target": config.target.strip(),
                "platform": config.platform.strip(),
                "network": network,
                "labels": labels,
                # Names only: values may be sensitive, and secrets stay with their backend.
                "build_args": sorted(config.build_args),
                "secrets": sorted(secrets),
                # What each base image was built on: a copy in the platform
                # registry by digest, or its own registry's pull.
                "base_images": [base.as_record() for base in base_images],
            }
            base_lines = [
                f"Base image: {base.image} from {base.served}"
                for base in base_images
                if base.served
            ]
            if destination.push:
                summary_lines = [
                    f"Image: {repository}",
                    f"Digest: {digest}",
                    *(f"Pushed: {ref}" for ref in references),
                    *base_lines,
                ]
                summary = f"Built and pushed {repository} ({', '.join(tags)})"
            else:
                summary_lines = [
                    f"Image: {repository}",
                    *(f"Kept in the sandbox: {ref}" for ref in references),
                    *base_lines,
                ]
                summary = f"Built {repository} ({', '.join(tags)}), kept in the sandbox"
            return HandlerResult(
                success=True,
                summary=summary,
                metrics={
                    "exit_code": 0,
                    "duration_seconds": duration,
                    "image": repository,
                    "image_digest": digest,
                    "tag_count": len(tags),
                },
                evidence=[
                    self._log_artifact(ctx, log, 0, reference, digest, duration),
                    {
                        "kind": "step_result",
                        "name": f"image_build_{ctx.step_id}",
                        "content_text": "\n".join(summary_lines) + "\n",
                        "content_json": details,
                    },
                ],
                output={
                    "image": repository,
                    "digest": digest,
                    "reference": reference,
                    "tags": tags,
                    "references": references,
                    "destination": destination.kind,
                    "pushed": destination.push,
                },
            )
        finally:
            try:
                # A build cut short by cancellation or an error still loses them.
                if built and destination.kind == DESTINATION_REMOTE and not names_dropped:
                    problem = await self._drop_names(docker_bin, env, references)
                    if problem:
                        await self._report_names_left(emit, references, problem)
            finally:
                shutil.rmtree(workdir, ignore_errors=True)

    async def _stage_context(
        self, ctx: HandlerContext, context_root: str, context_dir: str, dockerfile: str
    ) -> int:
        """Write the attachments under ``context_dir`` into ``context_root``; returns how many."""
        try:
            attachments = await ctx.require_services().fetch_run_attachments(ctx.run_id)
        except Exception as exc:  # noqa: BLE001 - reported as the step's failure
            raise _ContextError(f"Could not fetch the flow's attachments: {exc}") from exc
        prefix = f"{context_dir}/" if context_dir else ""
        staged = 0
        for attachment in attachments:
            filename = str(attachment.get("filename") or "").replace("\\", "/")
            if not filename.startswith(prefix) or filename.endswith("/"):
                continue
            relative = posixpath.normpath(filename[len(prefix) :])
            if relative.startswith(("../", "/")) or relative in ("..", "."):
                logger.warning("Skipping attachment outside the build context: %s", filename)
                continue
            path = os.path.join(context_root, *relative.split("/"))
            content = attachment.get("content")
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8", newline="") as handle:
                    handle.write("" if content is None else str(content))
            except OSError as exc:
                raise _ContextError(
                    f"Could not write attachment {filename} into the build context: {exc}"
                ) from exc
            staged += 1
        dockerfile_path = os.path.join(context_root, *dockerfile.split("/"))
        if not os.path.isfile(dockerfile_path):
            where = f"{context_dir}/{dockerfile}" if context_dir else dockerfile
            raise _ContextError(
                f"The Dockerfile {where} is not among the flow's attachments"
                + ("" if staged else f" (no attachment lies under {context_dir or 'the root'})")
            )
        return staged

    @staticmethod
    def _write_secrets(workdir: str, secrets: dict[str, str]) -> dict[str, str]:
        """Each secret in a file only this process can read; returns id -> path."""
        if not secrets:
            return {}
        directory = os.path.join(workdir, "secrets")
        os.mkdir(directory, 0o700)
        files: dict[str, str] = {}
        for index, (secret_id, value) in enumerate(sorted(secrets.items())):
            # Numbered, not named after the id: the path is in the argument list.
            path = os.path.join(directory, f"secret-{index}")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(value)
            files[secret_id] = path
        return files

    @staticmethod
    async def _probe_buildx(docker_bin: str, env: dict[str, str]) -> HandlerResult | None:
        """A failed result when the worker's Docker CLI cannot build, else None."""
        try:
            proc = await RunContainerHandler._run_docker(
                docker_bin, ["buildx", "version"], env=env, timeout=_PROBE_TIMEOUT_SECONDS
            )
        except FileNotFoundError:
            return _failure(f"Docker binary not found at '{docker_bin}'", "Docker not available")
        except (subprocess.SubprocessError, OSError) as exc:
            return _failure(f"docker buildx version failed: {exc}", "BuildKit not available")
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "").strip()[:300]
            return _failure(
                "The worker's Docker CLI has no working buildx plugin, which builds need"
                + (f": {detail}" if detail else ""),
                "BuildKit not available",
            )
        return None

    async def _base_images(
        self,
        *,
        references: list[str],
        cache: ImageCache,
        docker_bin: str,
        docker_host: str,
        env: dict[str, str],
        deadline: float,
        emit: Callable[..., Awaitable[None]],
    ) -> list[BaseImage]:
        """Serve the Dockerfile's base images from the platform registry's cache.

        Each one the way ``container.run`` serves its image: the digest its
        tag names upstream today (a digest-qualified reference already says),
        a copy of that digest in the organization's namespace and then the
        read-only ones, and without one a pull of that digest from upstream
        and a copy saved (:meth:`RunContainerHandler._store_copy`). With
        upstream unreachable, the last copy under the tag serves. Anything
        else (a refused check, an unreachable platform registry, a failed
        pull or copy) leaves the image to BuildKit's own pull, as without a
        cache. Never fails the step; out of time, the rest are left alone.
        """
        runner = RunContainerHandler()
        registry = RegistryClient(
            cache.api_url,
            login_for(cache.registry, env),
            trust_env=False,
            transport=_run._registry_transport(cache.api_url),
        )
        served: list[BaseImage] = []
        for image in references:
            plan = plan_cache(image, cache)
            if plan is None:
                # In the platform registry already, or a registry the cache
                # cannot name: BuildKit pulls it with the step's logins.
                served.append(BaseImage(image))
                continue
            try:
                served.append(
                    await self._base_image(
                        runner,
                        registry,
                        plan,
                        docker_bin=docker_bin,
                        docker_host=docker_host,
                        env=env,
                        deadline=deadline,
                        emit=emit,
                    )
                )
            except subprocess.TimeoutExpired:
                await emit(
                    "No time left to serve the remaining base images from the platform "
                    "registry; the build pulls them from their registries",
                    attrs={"milestone": "base_image_cache_skip", "image": image},
                )
                served.extend(BaseImage(rest) for rest in references[len(served) :])
                break
        return served

    async def _base_image(
        self,
        runner: RunContainerHandler,
        registry: RegistryClient,
        plan: CachePlan,
        *,
        docker_bin: str,
        docker_host: str,
        env: dict[str, str],
        deadline: float,
        emit: Callable[..., Awaitable[None]],
    ) -> BaseImage:
        """One base image through the cache (see :meth:`_base_images`)."""
        image = plan.requested
        reference = plan.reference

        async def skip(reason: str) -> BaseImage:
            await emit(
                f"Base image {image} comes from its registry: {reason}",
                attrs={"milestone": "base_image_cache_skip", "image": image, "reason": reason},
            )
            return BaseImage(image)

        upstream_url = upstream_api_url(reference.host)
        upstream = RegistryClient(
            upstream_url,
            login_for(reference.host, env),
            trust_env=True,
            transport=_run._registry_transport(upstream_url),
        )
        upstream_digest = reference.digest
        upstream_problem = ""
        if upstream_digest is None:
            try:
                upstream_digest = await runner._lookup(
                    upstream,
                    reference.repo,
                    reference.manifest_reference,
                    docker_bin=docker_bin,
                    image=image,
                    deadline=deadline,
                )
            except RegistryUnavailable as exc:
                upstream_problem = str(exc)
            except RegistryDenied as exc:
                # Access may have been withdrawn: no copy stands in for it.
                return await skip(f"{reference.host} refused the manifest check ({exc})")
            if upstream_digest is None and not upstream_problem:
                return await skip(f"{reference.host} does not have it")
        key_tag = cache_key_tag(upstream_digest) if upstream_digest else ""
        lookup_tag = key_tag or (reference.tag or "" if upstream_problem else "")

        for repo in plan.read_repos if lookup_tag else ():
            try:
                found = await runner._lookup(
                    registry,
                    repo,
                    lookup_tag,
                    docker_bin=docker_bin,
                    image=image,
                    deadline=deadline,
                )
            except (RegistryUnavailable, RegistryDenied) as exc:
                return await skip(f"the platform registry is unavailable ({exc})")
            if found is None:
                continue
            copy = pin_reference(plan.copy_reference(repo, lookup_tag), found)
            if upstream_problem:
                await emit(
                    f"{reference.host} is unreachable ({upstream_problem}); base image {image} "
                    f"comes from its last copy in the platform registry, {copy}",
                    attrs={
                        "milestone": "base_image_cache_stale",
                        "image": image,
                        "copy": copy,
                        "reason": upstream_problem,
                    },
                )
            else:
                await emit(
                    f"Base image {image} comes from its copy in the platform registry, {copy}",
                    attrs={"milestone": "base_image_cache_hit", "image": image, "copy": copy},
                )
            return BaseImage(image, served=copy)

        if upstream_problem or not upstream_digest:
            return await skip(
                f"{reference.host} is unreachable ({upstream_problem}) and the platform "
                "registry has no copy of it"
            )
        # No copy yet: pull exactly the digest the check named and save it, so
        # this build and later ones are built on the copy.
        target = image if reference.digest else pin_reference(image, upstream_digest)
        pulled = await runner._pull_image(
            docker_bin=docker_bin,
            image=target,
            docker_env=env,
            docker_host=docker_host,
            deadline=deadline,
            emit=emit,
        )
        if isinstance(pulled, HandlerResult):
            return await skip(f"it could not be pulled to save a copy ({pulled.error})")
        tags = [key_tag, *([reference.tag] if reference.tag else [])]
        stored = await runner._store_copy(
            image=target,
            plan=plan,
            tags=tags,
            docker_bin=docker_bin,
            docker_env=env,
            deadline=deadline,
            emit=emit,
        )
        if not stored:
            return await skip("no copy could be saved")
        try:
            found = await runner._lookup(
                registry,
                plan.write_repo,
                key_tag,
                docker_bin=docker_bin,
                image=image,
                deadline=deadline,
            )
        except (RegistryUnavailable, RegistryDenied) as exc:
            return await skip(f"the copy just saved cannot be found ({exc})")
        if found is None:
            return await skip("the copy just saved cannot be found")
        copy = pin_reference(plan.copy_reference(plan.write_repo, key_tag), found)
        await emit(
            f"Base image {image} comes from the copy just saved to the platform registry, {copy}",
            attrs={"milestone": "base_image_cached", "image": image, "copy": copy},
        )
        return BaseImage(image, served=copy, cached=True)

    @staticmethod
    async def _run_build(
        docker_bin: str,
        argv: list[str],
        env: dict[str, str],
        log: _BuildLog,
        deadline: float,
    ) -> int | None:
        """Run the build, streaming its output; the exit code, or None at the deadline."""
        proc = await asyncio.create_subprocess_exec(
            docker_bin,
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=env,
        )
        stream = proc.stdout
        if stream is None:  # pragma: no cover - PIPE always gives a stream
            raise RuntimeError("subprocess pipe not available")

        async def pump() -> int:
            async def ticker() -> None:
                while True:
                    await asyncio.sleep(_FLUSH_SECONDS)
                    await log.flush()

            flusher = asyncio.create_task(ticker())
            try:
                async for line in read_lines(stream):
                    await log.add(line)
            finally:
                flusher.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await flusher
            return await proc.wait()

        try:
            return await asyncio.wait_for(pump(), timeout=max(deadline - time.monotonic(), 1))
        except TimeoutError:
            # The client is BuildKit's session: ending it cancels the build.
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), timeout=KILL_WAIT_SECONDS)
            return None
        except asyncio.CancelledError:
            # A cancelled step must not leave its build running: kill the client
            # without waiting on it (the event loop reaps it).
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            raise
        except Exception:
            # Nor may a failure while reading its output.
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), timeout=KILL_WAIT_SECONDS)
            raise

    @staticmethod
    async def _drop_names(
        docker_bin: str, env: dict[str, str], references: list[str]
    ) -> str | None:
        """Take the names of an image pushed to another registry off the sandbox daemon.

        Every organization's steps share the sandbox daemon, and a step that
        runs an image already there (``docker run`` or containerlab inside a
        step) would take one left under a name outside this organization's
        namespace in place of the image that name stands for elsewhere. Run
        whatever the build got to, so a failed push leaves no name behind
        either. The names still exist from the build's export to the end of
        its push, which a step running one in that window could see; the
        caller drops them as soon as the build ends. Removing a name only
        untags an image another name or a container still holds; ``--force``
        keeps a container from blocking it. Returns what went wrong, or None.
        """
        try:
            proc = await RunContainerHandler._run_docker(
                docker_bin,
                ["image", "rm", "--force", *references],
                env=env,
                timeout=_PROBE_TIMEOUT_SECONDS,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            problem = str(exc)
        else:
            output = (proc.stderr or "").strip()
            # A name the build never set (it failed before tagging) is fine.
            leftover = [
                line
                for line in output.splitlines()
                if line.strip() and "no such image" not in line.lower()
            ]
            if proc.returncode == 0 or not leftover:
                return None
            problem = "; ".join(leftover)[:300]
        logger.warning("Could not remove built image names from the sandbox: %s", problem)
        return problem

    @staticmethod
    async def _report_names_left(
        emit: Callable[..., Awaitable[None]], references: list[str], problem: str
    ) -> None:
        """Say in the step's log that names :meth:`_drop_names` could not remove remain."""
        await emit(
            f"Could not remove {', '.join(references)} from the sandbox after the build: {problem}",
            attrs={"milestone": "build_cleanup_failed", "references": references},
        )

    @staticmethod
    def _metadata_digest(path: str) -> str:
        """The pushed manifest's digest from buildx's metadata file, or ""."""
        try:
            with open(path, encoding="utf-8") as handle:
                metadata = json.load(handle)
        except (OSError, ValueError):
            return ""
        digest = metadata.get("containerimage.digest") if isinstance(metadata, dict) else None
        return digest if isinstance(digest, str) and _DIGEST_RE.match(digest) else ""

    @staticmethod
    async def _daemon_digest(docker_bin: str, env: dict[str, str], reference: str) -> str:
        """The pushed digest as the sandbox daemon recorded it (RepoDigests), or ""."""
        try:
            proc = await RunContainerHandler._run_docker(
                docker_bin,
                ["image", "inspect", "--format", "{{json .RepoDigests}}", reference],
                env=env,
                timeout=_PROBE_TIMEOUT_SECONDS,
            )
            entries = json.loads(proc.stdout.strip() or "null") if proc.returncode == 0 else []
        except (subprocess.SubprocessError, OSError, ValueError):
            return ""
        pinned = repo_digest_for(reference, [str(entry) for entry in entries or []])
        return pinned.partition("@")[2]

    @staticmethod
    def _log_artifact(
        ctx: HandlerContext,
        log: _BuildLog,
        exit_code: int,
        image: str,
        digest: str,
        duration: float,
    ) -> dict[str, Any]:
        """The build log as ``container_output`` evidence, shaped like container.run's."""
        output = log.text()
        return {
            "kind": "container_output",
            "name": f"build_output_{ctx.step_id}",
            "content_text": output,
            "content_json": {
                "exit_code": exit_code,
                "image": image,
                "image_digest": digest,
                "duration_seconds": duration,
                "truncated": log.truncated,
                "stdout": output,
                "stderr": "",
            },
        }


class _ContextError(Exception):
    """The build context could not be put together from the attachments."""


__all__ = [
    "CREATED_LABEL",
    "DESTINATION_LOCAL",
    "DESTINATION_PLATFORM",
    "DESTINATION_REMOTE",
    "HANDLER_ID",
    "RUN_LABEL",
    "STEP_LABEL",
    "BuildDestination",
    "BuildImageConfig",
    "BuildImageHandler",
    "BuildRefused",
    "build_destination",
    "build_environment",
    "buildx_argv",
    "frontend_error",
    "image_name_error",
    "looks_like_host",
    "registry_host_of",
    "run_tag",
    "same_registry_host",
    "tag_error",
]
