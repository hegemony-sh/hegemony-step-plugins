# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Copies of pulled images in the platform registry (the "Cache image" option).

When the host serves an :class:`~hegemony_step_sdk.ImageCache`, a step whose
``cache_image`` option is on keeps a copy of the image it pulls in the
platform registry, under its organization's namespace, and later runs pull
that copy instead of going back to the image's own registry. The copy is
named after the upstream reference — ``<namespace>/<host>/<repository>`` —
and tagged twice: with the upstream tag, for people and for the offline
fallback, and with ``sha256-<upstream digest>``, the key a later run looks up
after asking upstream which digest the tag points at today. A copy is a
single-platform image with a digest of its own, so the upstream digest can
only be found by that tag, never by ``@digest``.

This module holds the pure parts: reference parsing and copy naming, the
registry HTTP calls (one ``HEAD`` per manifest, with the anonymous, Basic and
Bearer-token flows registries use), and the plan the runner executes. The
docker calls — pulling, tagging, pushing — stay in :mod:`.run`, on the same
daemon environment as every other docker invocation.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass

import httpx

from hegemony_step_sdk import ImageCache

from .pull_progress import DOCKER_HUB_AUTH_KEYS, RegistryLogin, registry_login

DOCKER_HUB_HOST = "docker.io"
DOCKER_HUB_API_URL = "https://registry-1.docker.io"
_DOCKER_HUB_ALIASES = frozenset({"docker.io", "index.docker.io", "registry-1.docker.io"})

#: Every manifest kind a registry may answer with, so the digest covers the
#: same document the daemon resolves (an index for a multi-platform image).
MANIFEST_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)

_HTTP_TIMEOUT = httpx.Timeout(connect=5.0, read=20.0, write=10.0, pool=5.0)
_CHALLENGE_PARAM = re.compile(r'(\w+)="([^"]*)"')
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class RegistryUnavailable(Exception):
    """The registry gave no usable answer: connection failure, timeout, 5xx."""


class RegistryDenied(Exception):
    """The registry refused the request after the login it was offered."""


@dataclass(frozen=True, slots=True)
class ImageReference:
    """An image reference split the way registries address it."""

    # ``docker.io`` for Docker Hub (whatever alias or no host the reference
    # used), otherwise the host as written, port included.
    host: str
    # Repository path inside the registry: ``library/alpine`` on Docker Hub
    # for a one-segment name, otherwise the path as written.
    repo: str
    tag: str | None
    digest: str | None

    @property
    def manifest_reference(self) -> str:
        """What to ask the upstream registry for: the digest when given, else the tag."""
        return self.digest or self.tag or "latest"


def parse_reference(image: str) -> ImageReference:
    """Split ``image`` into host, repository, tag and digest.

    Mirrors the docker CLI's normalization: no host means Docker Hub, a bare
    name on Docker Hub lives under ``library/``, a colon before the last slash
    is a registry port, and a digest wins over a tag when both are present
    (the tag is kept, for naming the copy).
    """
    name, _, digest = image.partition("@")
    first, sep, rest = name.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        host, path = first, rest
    else:
        host, path = DOCKER_HUB_HOST, name
    if host in _DOCKER_HUB_ALIASES:
        host = DOCKER_HUB_HOST
    tag: str | None = None
    slash = path.rfind("/")
    colon = path.rfind(":")
    if colon > slash:
        path, tag = path[:colon], path[colon + 1 :]
    if host == DOCKER_HUB_HOST and "/" not in path:
        path = f"library/{path}"
    if not digest and tag is None:
        tag = "latest"
    return ImageReference(host=host, repo=path, tag=tag or None, digest=digest or None)


def cache_key_tag(digest: str) -> str:
    """The tag a copy carries for the upstream digest it was made from.

    ``sha256:<hex>`` becomes ``sha256-<hex>``: a tag may not contain a colon,
    and the hex alone is 64 characters, well inside the 128 a tag allows.
    """
    algorithm, _, hexdigest = digest.partition(":")
    return f"{algorithm}-{hexdigest}"


@dataclass(frozen=True, slots=True)
class CachePlan:
    """Where a step's image may have a copy, and where its own copy goes."""

    requested: str
    reference: ImageReference
    registry: str
    # Repository of the copy this step writes (``orgs/acme/ghcr.io/x/tool``).
    write_repo: str
    # Repositories to look for a copy in, the writable one first.
    read_repos: tuple[str, ...]

    def copy_reference(self, repo: str, tag: str) -> str:
        """The pullable reference of a copy in ``repo`` under ``tag``."""
        return f"{self.registry}/{repo}:{tag}"


@dataclass(frozen=True, slots=True)
class AcquiredImage:
    """How the step's image got onto the sandbox daemon."""

    # The reference the container runs by: the requested one, or a copy's.
    served: str
    # ``upstream``: pulled from the image's own registry; ``cache``: a copy in
    # the platform registry; ``platform``: an image that lives in the platform
    # registry under its own name (a built image, or a copy named outright).
    source: str
    # True when this step saved a copy to the platform registry.
    cached: bool


def plan_cache(image: str, cache: ImageCache) -> CachePlan | None:
    """How ``image`` maps onto ``cache``, or None when the cache does not apply.

    An image that already lives in the platform registry (its host is the
    cache's registry) is pulled as it is: a copy of a copy would add nothing,
    and ``tf.apply`` reaches its plan's image by exactly such a reference.
    The copy's repository is ``<namespace>/<host>/<repository>``, the host
    with any port written after an underscore.
    """
    reference = parse_reference(image)
    if reference.host == cache.registry:
        return None
    # A repository path component may not contain a colon, so a registry port
    # is written with an underscore (``registry.example.com_5000``); host names
    # never contain underscores, so the spelling cannot clash with a host.
    path = f"{reference.host.replace(':', '_')}/{reference.repo}"
    write_repo = f"{cache.namespace}/{path}"
    read_repos = (write_repo, *(f"{namespace}/{path}" for namespace in cache.read_namespaces))
    return CachePlan(
        requested=image,
        reference=reference,
        registry=cache.registry,
        write_repo=write_repo,
        read_repos=read_repos,
    )


def upstream_api_url(host: str) -> str:
    """Base URL of the registry API for ``host`` (Docker Hub has its own)."""
    if host == DOCKER_HUB_HOST:
        return DOCKER_HUB_API_URL
    return f"https://{host}"


def login_for(host: str, env: Mapping[str, str]) -> RegistryLogin | None:
    """The step's login for ``host`` from its Docker configuration, if any."""
    return registry_login(None if host == DOCKER_HUB_HOST else host, env)


class RegistryClient:
    """One registry's manifest lookups, with the auth flows registries use.

    ``trust_env`` is True for upstream registries, which a worker may only
    reach through its proxy settings, and False for the platform registry on
    the compose network, which a proxy must never intercept. ``transport`` is
    the test seam.
    """

    def __init__(
        self,
        base_url: str,
        login: RegistryLogin | None,
        *,
        trust_env: bool,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._login = login
        self._trust_env = trust_env
        self._transport = transport

    async def manifest_digest(self, repo: str, reference: str) -> str | None:
        """Digest of ``repo:reference`` as the registry serves it, None when absent.

        Answers with one ``HEAD`` (plus the token round trip a Bearer challenge
        asks for); Docker Hub does not count ``HEAD`` requests against its pull
        limits. A registry that omits ``Docker-Content-Digest`` on ``HEAD`` is
        asked with ``GET`` and the digest is computed over the body, which is
        how the digest is defined. Raises :class:`RegistryUnavailable` when the
        registry cannot be used and :class:`RegistryDenied` when it refuses
        the login it was offered.
        """
        url = f"{self._base_url}/v2/{repo}/manifests/{reference}"
        headers = {"Accept": MANIFEST_ACCEPT}
        try:
            async with httpx.AsyncClient(
                timeout=_HTTP_TIMEOUT, trust_env=self._trust_env, transport=self._transport
            ) as client:
                response = await client.head(url, headers=headers)
                if response.status_code == 401:
                    authorization = await self._authorize(
                        client, response.headers.get("www-authenticate", ""), repo
                    )
                    if authorization is None:
                        raise RegistryDenied(f"{self._base_url} refused the login for {repo}")
                    headers["Authorization"] = authorization
                    response = await client.head(url, headers=headers)
                if response.status_code == 404:
                    return None
                if response.status_code in (401, 403):
                    raise RegistryDenied(f"{self._base_url} refused access to {repo}")
                if response.status_code != 200:
                    raise RegistryUnavailable(
                        f"{self._base_url} answered HTTP {response.status_code} for {repo}"
                    )
                digest = response.headers.get("docker-content-digest", "").strip()
                if _DIGEST.match(digest):
                    return digest
                response = await client.get(url, headers=headers)
                if response.status_code != 200:
                    raise RegistryUnavailable(
                        f"{self._base_url} answered HTTP {response.status_code} for {repo}"
                    )
                return "sha256:" + hashlib.sha256(response.content).hexdigest()
        except httpx.HTTPError as exc:
            raise RegistryUnavailable(f"{self._base_url}: {exc}"[:200]) from exc

    async def _authorize(self, client: httpx.AsyncClient, challenge: str, repo: str) -> str | None:
        """The ``Authorization`` value that answers ``challenge``, or None."""
        scheme, _, params_text = challenge.strip().partition(" ")
        params = dict(_CHALLENGE_PARAM.findall(params_text))
        scheme = scheme.lower()
        if scheme == "basic":
            return self._basic()
        if scheme != "bearer" or not params.get("realm"):
            return None
        query = {}
        if params.get("service"):
            query["service"] = params["service"]
        query["scope"] = params.get("scope") or f"repository:{repo}:pull"
        token_headers = {}
        basic = self._basic()
        if basic:
            token_headers["Authorization"] = basic
        response = await client.get(params["realm"], params=query, headers=token_headers)
        if response.status_code != 200:
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        token = body.get("token") or body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            return None
        return f"Bearer {token}"

    def _basic(self) -> str | None:
        if self._login is None:
            return None
        raw = f"{self._login.username}:{self._login.password}".encode()
        return "Basic " + base64.b64encode(raw).decode("ascii")


__all__ = [
    "DOCKER_HUB_AUTH_KEYS",
    "AcquiredImage",
    "CachePlan",
    "ImageReference",
    "RegistryClient",
    "RegistryDenied",
    "RegistryUnavailable",
    "cache_key_tag",
    "login_for",
    "parse_reference",
    "plan_cache",
    "upstream_api_url",
]
