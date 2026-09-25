# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Docker Engine API streaming pull with byte-accurate progress.

``docker pull`` on a non-TTY pipe suppresses byte progress entirely, so the
only way to report download percentages is the daemon's own
``POST /images/create`` JSON stream (``status`` / ``id`` /
``progressDetail.current|total`` objects). This module consumes that stream
and turns it into throttled ``pull_progress`` run events.

The API path is strictly best-effort: every failure — unsupported
``DOCKER_HOST`` shape, connection problems, HTTP errors, in-band pull errors —
raises :class:`EnginePullError`, and the caller
(:meth:`RunContainerHandler._pull_image`) falls back to the plain ``docker
pull`` CLI, which stays the authoritative pull mechanism (registry credential
helpers, exotic daemon transports). Layers fetched before a mid-stream failure
are reused by the daemon, so the fallback only finishes the remainder.

The one exception is a ``docker_host`` that names no daemon at all
(:func:`require_docker_host`): that raises :class:`ValueError` and fails the
step, because the CLI fallback would pull on the default socket, which inside
the worker is the worker's own Docker daemon rather than the sandbox.

Pure logic (reference parsing, endpoint resolution, auth-header construction,
progress aggregation) is module-level so it unit-tests without I/O.
"""

from __future__ import annotations

import base64
import json
import os
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

# Sentinel for PullOutcome.bytes_downloaded: the pull fetched something but
# never said how much. Distinct from 0, which asserts nothing was fetched.
BYTES_UNKNOWN = -1

# Docker Hub credentials live under the legacy index key in config.json; the
# other aliases show up from tooling that writes the modern hostnames.
DOCKER_HUB_AUTH_KEYS = (
    "https://index.docker.io/v1/",
    "index.docker.io",
    "docker.io",
    "registry-1.docker.io",
)

# Every emitted progress event is one `run_events` row behind a per-run
# `FOR UPDATE` seq allocation on the API side — the throttle is the only rate
# limit in the pipeline. 2s cadence for the first ~3 minutes of a pull, then
# 10s so a pathologically slow registry cannot flood the run's event log.
PULL_PROGRESS_INTERVAL_SECONDS = 2.0
PULL_PROGRESS_SLOW_INTERVAL_SECONDS = 10.0
PULL_PROGRESS_FAST_BUDGET = 90

# Percent is weighted download+extract over the same byte denominator:
# bytes-only would park the bar at 100% for the tens of seconds large images
# spend extracting, which reads as hung — the exact symptom this exists to fix.
DOWNLOAD_WEIGHT = 0.8
EXTRACT_WEIGHT = 0.2

# `read` is per-chunk, not per-request: a healthy pull delivers progress lines
# continuously, so 30s of silence means a stalled daemon/registry and the CLI
# fallback should take over. The overall step deadline is enforced by the
# caller via asyncio.wait_for.
_HTTP_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)


class EnginePullError(Exception):
    """API-path pull failed; the caller should fall back to the docker CLI."""


class EnginePullUnsupported(EnginePullError):
    """A daemon endpoint shape this module deliberately does not speak."""


@dataclass(frozen=True)
class EngineEndpoint:
    """Resolved daemon endpoint for httpx."""

    kind: str  # "uds" | "tcp"
    uds_path: str | None
    base_url: str


def require_docker_host(docker_host: str) -> str:
    """Return the sandbox daemon endpoint, refusing a value that names none.

    Every flow container runs on the Docker-in-Docker sandbox daemon that
    ``ContainerRuntime.docker_host`` names. An empty value, or a bare
    ``unix://`` without a socket path, leaves the docker CLI on its default
    socket, which inside the worker is the worker's own Docker daemon. A
    ``tcp://`` endpoint without a host names no daemon either: the CLI reads
    it as ``localhost:2375``. All of them raise :class:`ValueError`. Never an
    :class:`EnginePullError`: the pull path answers those by retrying with
    the CLI, which would reach the very daemon the value failed to name.
    """
    host = docker_host.strip()
    if not host or host == "unix://" or (host.startswith("tcp://") and not urlsplit(host).hostname):
        raise ValueError(
            "container.run needs the sandbox Docker daemon endpoint in "
            f"ContainerRuntime.docker_host, got {docker_host!r}; it never falls back "
            "to the worker's own Docker daemon"
        )
    return host


def resolve_engine_endpoint(docker_host: str, env: Mapping[str, str]) -> EngineEndpoint:
    """Map a ``DOCKER_HOST`` value onto an httpx-reachable endpoint.

    Supported shapes are the two the sandbox daemon is reached by (see
    ``ContainerRuntime.docker_host``): plain-TCP ``tcp://`` and a unix socket
    named by path (``unix:///var/run/dind/docker.sock``). An empty value or a
    bare ``unix://`` names no daemon and raises :class:`ValueError` (see
    :func:`require_docker_host`) instead of resolving to the default socket.
    Everything else — ``ssh://``, ``npipe://``, ``fd://``, or a TLS daemon
    (``DOCKER_TLS_VERIFY`` in the effective subprocess environment) — raises
    :class:`EnginePullUnsupported` so the CLI keeps handling it.
    """
    docker_host = require_docker_host(docker_host)
    if docker_host.startswith("unix://"):
        path = docker_host[len("unix://") :]
        return EngineEndpoint(kind="uds", uds_path=path, base_url="http://docker")
    if docker_host.startswith("tcp://"):
        if env.get("DOCKER_TLS_VERIFY"):
            raise EnginePullUnsupported("TLS daemon (DOCKER_TLS_VERIFY set)")
        netloc = docker_host[len("tcp://") :].strip("/")
        if not netloc:
            raise EnginePullUnsupported(f"malformed DOCKER_HOST: {docker_host!r}")
        return EngineEndpoint(kind="tcp", uds_path=None, base_url=f"http://{netloc}")
    raise EnginePullUnsupported(f"unsupported DOCKER_HOST scheme: {docker_host!r}")


def parse_image_reference(image: str) -> tuple[str, str]:
    """Split an image reference into the ``fromImage``/``tag`` query params.

    ``tag`` must always be sent: ``/images/create`` without one pulls every
    tag of the repository, unlike the CLI's implicit ``latest``. A digest
    reference travels in the ``tag`` param (that is what the docker CLI itself
    sends), and wins over a tag when both are present, mirroring
    ``docker pull name:tag@sha256:...``.

    Input shapes are already constrained by the handler's image validation
    (``_IMAGE_PATTERN`` plus scheme rejections), so no scheme handling here.
    """
    if "@" in image:
        name, digest = image.split("@", 1)
        slash = name.rfind("/")
        colon = name.rfind(":")
        if colon > slash:
            name = name[:colon]
        return name, digest
    slash = image.rfind("/")
    colon = image.rfind(":")
    # A colon before the last slash is a registry port (localhost:5000/repo),
    # not a tag separator.
    if colon > slash:
        return image[:colon], image[colon + 1 :]
    return image, "latest"


def _registry_host(image: str) -> str | None:
    """First path component when it names a registry host, else None (Docker Hub)."""
    name = image.split("@", 1)[0]
    first, sep, _rest = name.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        return first
    return None


def _load_docker_config(env: Mapping[str, str]) -> dict[str, Any]:
    config_dir = env.get("DOCKER_CONFIG") or os.path.join(os.path.expanduser("~"), ".docker")
    path = os.path.join(config_dir, "config.json")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def build_registry_auth_header(image: str, env: Mapping[str, str]) -> dict[str, str]:
    """Static-``auths`` credential parity with the docker CLI.

    Reads ``$DOCKER_CONFIG/config.json`` (default ``~/.docker``) and builds the
    ``X-Registry-Auth`` header the Engine API expects (URL-safe base64 of a
    JSON AuthConfig). Credential helpers (``credsStore``/``credHelpers``) and
    ``identitytoken``-only entries are out of scope: those return ``{}`` so the
    pull is attempted anonymously — a daemon-side auth failure then lands in
    the CLI fallback, which resolves helpers itself.
    """
    auths = _load_docker_config(env).get("auths")
    if not isinstance(auths, dict):
        return {}
    host = _registry_host(image)
    candidates = [host] if host else list(DOCKER_HUB_AUTH_KEYS)
    entry: dict[str, Any] | None = None
    serveraddress = ""
    for key in candidates:
        if not key:
            continue
        for variant in (key, f"https://{key}", f"http://{key}"):
            found = auths.get(variant)
            if isinstance(found, dict):
                entry = found
                serveraddress = key
                break
        if entry is not None:
            break
    if entry is None:
        return {}
    username = entry.get("username")
    password = entry.get("password")
    packed = entry.get("auth")
    if (not username or not password) and isinstance(packed, str) and packed:
        try:
            decoded = base64.b64decode(packed).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return {}
        username, _, password = decoded.partition(":")
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not username
        or not password
    ):
        return {}
    payload = json.dumps(
        {"username": username, "password": password, "serveraddress": serveraddress}
    )
    header = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")
    return {"X-Registry-Auth": header}


def _progress_detail(obj: Mapping[str, Any]) -> tuple[int | None, int | None]:
    detail = obj.get("progressDetail")
    if not isinstance(detail, dict):
        return None, None
    current = detail.get("current")
    total = detail.get("total")
    return (
        current if isinstance(current, int) and current >= 0 else None,
        total if isinstance(total, int) and total > 0 else None,
    )


@dataclass
class _LayerState:
    dl_current: int = 0
    dl_total: int = 0
    ex_current: int = 0
    ex_total: int = 0
    download_done: bool = False
    done: bool = False
    already_exists: bool = False


@dataclass(frozen=True)
class PullOutcome:
    """What a finished pull actually did, for the completion event.

    ``up_to_date`` comes from the daemon's own closing status line rather
    than from byte math: a pull that moved no bytes is not proof the image
    was already complete (a daemon may report no layer objects at all), and
    the daemon states it outright.

    ``bytes_downloaded`` is ``BYTES_UNKNOWN`` when the pull moved data but
    never reported how much — a daemon whose statuses this module does not
    interpret, or the CLI fallback, where a piped ``docker pull`` prints no
    progress at all. Callers must not treat that as zero: "we did not
    measure" and "nothing was fetched" are opposite facts about a pull.
    """

    up_to_date: bool
    bytes_downloaded: int


@dataclass(frozen=True)
class PullSnapshot:
    """One aggregated view of the pull, ready for an event emission."""

    progress_pct: float | None
    bytes_current: int
    bytes_total: int
    layers_complete: int
    layers_total: int
    phase: str  # "downloading" | "extracting"


class PullProgressAggregator:
    """Pure state machine over ``/images/create`` stream objects.

    Only the layer statuses the classic daemon emits are interpreted; unknown
    statuses (e.g. from containerd-image-store daemons) are ignored, so
    progress degrades to sparse rather than wrong. A top-level ``error`` object
    raises :class:`EnginePullError` — that is how the daemon reports auth
    failures and unknown images mid-stream.
    """

    def __init__(self) -> None:
        self._layers: dict[str, _LayerState] = {}
        self._saw_unknown_status = False

    def _layer(self, layer_id: str) -> _LayerState:
        state = self._layers.get(layer_id)
        if state is None:
            state = _LayerState()
            self._layers[layer_id] = state
        return state

    def feed(self, obj: Mapping[str, Any]) -> None:
        error = obj.get("error")
        if error:
            detail = obj.get("errorDetail")
            message = ""
            if isinstance(detail, dict):
                message = str(detail.get("message") or "")
            raise EnginePullError(message or str(error))

        layer_id = obj.get("id")
        status = obj.get("status")
        if not isinstance(layer_id, str) or not layer_id or not isinstance(status, str):
            # Top-level lines ("Pulling from ...", "Digest: ...", "Status: ...")
            # carry no per-layer math; stream end is the success signal.
            return

        if status in ("Pulling fs layer", "Waiting", "Verifying Checksum"):
            self._layer(layer_id)
        elif status == "Downloading":
            state = self._layer(layer_id)
            current, total = _progress_detail(obj)
            if current is not None:
                state.dl_current = current
            if total is not None:
                state.dl_total = max(state.dl_total, total)
        elif status == "Download complete":
            state = self._layer(layer_id)
            state.download_done = True
            if state.dl_total:
                state.dl_current = state.dl_total
        elif status == "Extracting":
            state = self._layer(layer_id)
            state.download_done = True
            if state.dl_total:
                state.dl_current = state.dl_total
            current, total = _progress_detail(obj)
            if current is not None:
                state.ex_current = current
            if total is not None:
                state.ex_total = max(state.ex_total, total)
        elif status == "Pull complete":
            state = self._layer(layer_id)
            state.done = True
            state.download_done = True
            if state.dl_total:
                state.dl_current = state.dl_total
            if state.ex_total:
                state.ex_current = state.ex_total
        elif status == "Already exists":
            state = self._layer(layer_id)
            state.done = True
            state.download_done = True
            state.already_exists = True
        else:
            # Ignored for progress (forward compatibility), but remembered:
            # a layer this module cannot read may still be moving bytes, and
            # the total is only honest if every layer was accounted for.
            self._saw_unknown_status = True

    @property
    def fully_measured(self) -> bool:
        """True when every layer's download size is known.

        A total assembled from *some* of the layers is not a smaller truth,
        it is a wrong number: it silently attributes the whole pull the size
        of the part this module happened to understand. Callers report
        :data:`BYTES_UNKNOWN` instead of publishing one.
        """
        if self._saw_unknown_status:
            return False
        return all(s.already_exists or s.dl_total > 0 for s in self._layers.values())

    def snapshot(self) -> PullSnapshot:
        layers = self._layers.values()
        layers_total = len(self._layers)
        layers_complete = sum(1 for state in layers if state.done)

        # Byte math covers layers with a known download size; cached
        # ("Already exists") layers never report totals and are excluded from
        # the denominator while still counting as complete layers.
        sized = [s for s in layers if s.dl_total > 0 and not s.already_exists]
        bytes_total = sum(s.dl_total for s in sized)
        bytes_current = sum(min(s.dl_current, s.dl_total) for s in sized)

        progress_pct: float | None = None
        if bytes_total > 0:
            dl_frac = bytes_current / bytes_total
            ex_weighted = 0.0
            for state in sized:
                if state.done or (state.ex_total and state.ex_current >= state.ex_total):
                    ex_frac = 1.0
                elif state.ex_total:
                    ex_frac = min(state.ex_current / state.ex_total, 1.0)
                else:
                    ex_frac = 0.0
                ex_weighted += state.dl_total * ex_frac
            ex_frac_total = ex_weighted / bytes_total
            progress_pct = round(
                100.0 * (DOWNLOAD_WEIGHT * dl_frac + EXTRACT_WEIGHT * ex_frac_total), 1
            )

        active = [s for s in layers if not s.already_exists]
        phase = "downloading"
        if active and all(s.download_done for s in active):
            phase = "extracting"

        return PullSnapshot(
            progress_pct=progress_pct,
            bytes_current=bytes_current,
            bytes_total=bytes_total,
            layers_complete=layers_complete,
            layers_total=layers_total,
            phase=phase,
        )


def _is_terminal_status(obj: Mapping[str, Any]) -> bool:
    """True for the top-level line that closes a successful pull.

    The daemon ends a pull with layer-less ``Digest: sha256:...`` and
    ``Status: Downloaded newer image for ...`` / ``Status: Image is up to date
    for ...`` objects. Their absence means the stream stopped early, which
    :func:`stream_pull` treats as a failure. (The opening
    ``Pulling from <repo>`` banner carries the tag in ``id``, so it is not
    mistaken for a completion line.)
    """
    if obj.get("id"):
        return False
    status = obj.get("status")
    return isinstance(status, str) and status.startswith(("Status:", "Digest:"))


def _says_up_to_date(obj: Mapping[str, Any]) -> bool:
    """True for the daemon's "nothing to fetch" closing line.

    A pull that finds every layer present ends with ``Status: Image is up to
    date for <ref>`` instead of ``Status: Downloaded newer image for <ref>``.
    The docker CLI prints the same sentence, so both pull paths recognise a
    cached image the same way.
    """
    status = obj.get("status")
    return isinstance(status, str) and "image is up to date" in status.lower()


def format_size(num_bytes: int) -> str:
    """Render a byte count the way ``docker images`` does — SI units, not binary.

    Matching docker's own display matters more than binary correctness here:
    the number is there to be recognised next to the one the reader gets from
    `docker images`, and 1.02 GB vs 972 MiB for the same image invites a
    bug report.
    """
    if num_bytes >= 1_000_000_000:
        return f"{num_bytes / 1e9:.1f} GB"
    if num_bytes >= 1_000_000:
        return f"{num_bytes / 1e6:.0f} MB"
    if num_bytes >= 1_000:
        return f"{num_bytes / 1e3:.0f} kB"
    return f"{num_bytes} B"


def _format_progress_message(image: str, snap: PullSnapshot, pct: float | None) -> str:
    mb = 1e6
    if pct is not None and snap.phase == "extracting":
        return (
            f"Pulling {image}: {pct:.0f}% "
            f"(extracting, {snap.layers_complete}/{snap.layers_total} layers)"
        )
    if pct is not None and snap.bytes_total > 0:
        return (
            f"Pulling {image}: {pct:.0f}% "
            f"({snap.bytes_current / mb:.1f}/{snap.bytes_total / mb:.1f} MB, "
            f"{snap.layers_complete}/{snap.layers_total} layers)"
        )
    return (
        f"Pulling {image}: {snap.bytes_current / mb:.1f} MB downloaded "
        f"({snap.layers_complete}/{snap.layers_total} layers)"
    )


async def stream_pull(
    *,
    image: str,
    docker_host: str,
    env: Mapping[str, str],
    emit: Callable[..., Awaitable[None]],
    transport: httpx.AsyncBaseTransport | None = None,
    now: Callable[[], float] = time.monotonic,
) -> PullOutcome:
    """Pull ``image`` via the Engine API, emitting throttled progress events.

    ``emit`` is the handler's ``_safe_emit_progress`` (``message, attrs=...``).
    ``transport`` and ``now`` are test seams (``httpx.MockTransport`` and a
    scripted clock). Returns a :class:`PullOutcome` on success; raises
    :class:`EnginePullError` when the caller should fall back to the CLI pull.
    ``asyncio.CancelledError`` passes through untouched for step cancellation.
    A ``docker_host`` that names no daemon raises :class:`ValueError` before
    anything else (see :func:`require_docker_host`), which is not a fallback.
    """
    # The one failure that must not degrade: with no sandbox daemon named, the
    # CLI fallback would pull on the default socket, the worker's own daemon.
    # So it is refused here, ahead of the EnginePullError boundary below.
    docker_host = require_docker_host(docker_host)

    # Pre-flight sits inside the EnginePullError boundary as well: this
    # module's contract is that every other failure degrades to the CLI pull, and
    # an unexpected error while parsing the reference, reading credentials, or
    # building the transport would otherwise fail the step outright instead of
    # falling back. (CancelledError derives from BaseException, so step
    # cancellation still propagates untouched.)
    try:
        from_image, tag = parse_image_reference(image)
        headers = build_registry_auth_header(image, env)

        base_url = "http://docker"
        if transport is None:
            endpoint = resolve_engine_endpoint(docker_host, env)
            base_url = endpoint.base_url
            if endpoint.kind == "uds":
                transport = httpx.AsyncHTTPTransport(uds=endpoint.uds_path)
    except EnginePullError:
        raise
    except Exception as e:
        raise EnginePullError(f"pull pre-flight failed ({type(e).__name__}): {e}"[:200]) from e

    aggregator = PullProgressAggregator()
    last_emit = now()
    last_phase = "downloading"
    last_pct = 0.0
    emitted = 0
    saw_terminal = False
    up_to_date = False

    try:
        # trust_env=False is load-bearing: worker environments carry proxy
        # variables (HTTPS_PROXY etc.) that must never intercept daemon
        # traffic — the docker CLI does not route through them either.
        async with (
            httpx.AsyncClient(
                transport=transport, base_url=base_url, timeout=_HTTP_TIMEOUT, trust_env=False
            ) as client,
            client.stream(
                "POST",
                "/images/create",
                params={"fromImage": from_image, "tag": tag},
                headers=headers,
            ) as response,
        ):
            if response.status_code // 100 != 2:
                body = await response.aread()
                text = body.decode("utf-8", errors="replace").strip()
                try:
                    data = json.loads(text)
                    if isinstance(data, dict) and data.get("message"):
                        text = str(data["message"])
                except ValueError:
                    pass
                raise EnginePullError(f"HTTP {response.status_code}: {text[:200]}")

            async for line in response.aiter_lines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(obj, dict):
                    continue
                aggregator.feed(obj)
                if _is_terminal_status(obj):
                    saw_terminal = True
                    up_to_date = up_to_date or _says_up_to_date(obj)

                snap = aggregator.snapshot()
                if snap.layers_total == 0:
                    continue
                # The downloading->extracting hand-off is always worth one
                # event, even inside the throttle window.
                force = snap.phase == "extracting" and last_phase != "extracting"
                interval = (
                    PULL_PROGRESS_INTERVAL_SECONDS
                    if emitted < PULL_PROGRESS_FAST_BUDGET
                    else PULL_PROGRESS_SLOW_INTERVAL_SECONDS
                )
                ts = now()
                if not force and ts - last_emit < interval:
                    continue

                pct = snap.progress_pct
                if pct is not None:
                    # Late layer totals can shrink the honest percentage;
                    # the displayed value never moves backwards (bytes
                    # stay truthful).
                    pct = max(pct, last_pct)
                    last_pct = pct
                attrs: dict[str, object] = {
                    "milestone": "pull_progress",
                    "image": image,
                    "phase": snap.phase,
                    "bytes_current": snap.bytes_current,
                    "layers_complete": snap.layers_complete,
                    "layers_total": snap.layers_total,
                }
                if pct is not None:
                    attrs["progress_pct"] = pct
                if snap.bytes_total > 0:
                    attrs["bytes_total"] = snap.bytes_total
                await emit(_format_progress_message(image, snap, pct), attrs=attrs)
                last_emit = ts
                last_phase = snap.phase
                emitted += 1

            if not saw_terminal:
                # A cleanly closed stream that never announced completion has
                # not necessarily produced the image; returning here would
                # skip the fallback and leave `docker create` to fail with
                # "No such image". Falling back costs one mostly-cached
                # `docker pull`; a false success costs the step.
                raise EnginePullError("pull stream ended without a completion status")
    except EnginePullError:
        raise
    except (httpx.HTTPError, httpx.StreamError, OSError) as e:
        raise EnginePullError(str(e)[:200] or type(e).__name__) from e

    # A daemon that fetched a newer image while reporting no layer totals —
    # or only some of them — leaves us with nothing honest to say. Reporting
    # the aggregator's figure would claim a byte count for the whole pull
    # that describes only the part this module could read.
    snap = aggregator.snapshot()
    measured = up_to_date or (snap.bytes_total > 0 and aggregator.fully_measured)
    return PullOutcome(
        up_to_date=up_to_date,
        bytes_downloaded=snap.bytes_current if measured else BYTES_UNKNOWN,
    )
