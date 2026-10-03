# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Public SDK for Hegemony step-handler plugins.

Dependency-light (pydantic only). Out-of-tree plugin wheels depend on this package
and never import Hegemony app internals. A plugin exposes a ``register(registry)``
callable under the ``hegemony.step_handlers`` entry-point group and registers
:class:`BaseHandler` subclasses; handlers reach every platform facility through
``ctx.services`` (:class:`HandlerServices`).
"""

from __future__ import annotations

from ._version import SDK_ABI_VERSION, __version__
from .concurrency import (
    MAX_PARALLEL_DEVICES_LIMIT,
    for_each_target_device,
    max_parallel_from_config,
)
from .contract import (
    DEFAULT_DEVICE_PLATFORM,
    MAX_CHAIN_OUTPUT_CHARS,
    OUTPUT_EVENT_CHUNK_CHARS,
    OUTPUT_EVENT_MAX_CHARS,
    OUTPUT_MILESTONE,
    OUTPUT_TRUNCATION_NOTICE,
    BaseHandler,
    HandlerContext,
    HandlerResult,
    HandlerTargeting,
    command_label,
    resolve_target_devices_for_roles,
)
from .enums import StepKind
from .probes import (
    PROBE_ENTRY_POINT_GROUP,
    BaseProbe,
    ProbeRegistry,
    ProbeResult,
)
from .registry import StepHandlerRegistry
from .services import (
    BUILD_NETWORK_DEFAULT,
    BUILD_NETWORK_NONE,
    CommandResult,
    ContainerRuntime,
    HandlerServices,
    ImageBuild,
    ImageCache,
    ShellResult,
    ShellTransport,
    StateBackendAccess,
    Transport,
)
from .transports import (
    DEFAULT_DEVICE_MGMT_PORT,
    TRANSPORT_ENTRY_POINT_GROUP,
    ConnectionCancellationRegistry,
    DeviceConnectionSpec,
    DeviceCredentials,
    JumpHostSpec,
    TransportOutputSink,
    TransportRegistry,
)

#: The entry-point group out-of-tree step-handler plugins register under.
STEP_HANDLER_ENTRY_POINT_GROUP = "hegemony.step_handlers"

__all__ = [
    "BUILD_NETWORK_DEFAULT",
    "BUILD_NETWORK_NONE",
    "DEFAULT_DEVICE_MGMT_PORT",
    "DEFAULT_DEVICE_PLATFORM",
    "MAX_CHAIN_OUTPUT_CHARS",
    "MAX_PARALLEL_DEVICES_LIMIT",
    "OUTPUT_EVENT_CHUNK_CHARS",
    "OUTPUT_EVENT_MAX_CHARS",
    "OUTPUT_MILESTONE",
    "OUTPUT_TRUNCATION_NOTICE",
    "PROBE_ENTRY_POINT_GROUP",
    "SDK_ABI_VERSION",
    "STEP_HANDLER_ENTRY_POINT_GROUP",
    "TRANSPORT_ENTRY_POINT_GROUP",
    "BaseHandler",
    "command_label",
    "BaseProbe",
    "CommandResult",
    "ConnectionCancellationRegistry",
    "ContainerRuntime",
    "ImageBuild",
    "ImageCache",
    "DeviceConnectionSpec",
    "DeviceCredentials",
    "HandlerContext",
    "HandlerResult",
    "HandlerServices",
    "HandlerTargeting",
    "JumpHostSpec",
    "ProbeRegistry",
    "ProbeResult",
    "ShellResult",
    "ShellTransport",
    "StateBackendAccess",
    "StepHandlerRegistry",
    "StepKind",
    "Transport",
    "TransportOutputSink",
    "TransportRegistry",
    "__version__",
    "for_each_target_device",
    "max_parallel_from_config",
    "resolve_target_devices_for_roles",
]
