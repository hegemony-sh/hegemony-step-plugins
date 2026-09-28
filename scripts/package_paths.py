# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from __future__ import annotations

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
    ROOT / "probes" / "probe_net",
    ROOT / "transports" / "transport_netmiko",
    ROOT / "transports" / "transport_scrapli",
    ROOT / "transports" / "transport_asyncssh",
)

# Everything except the SDK (index 0) pins hegemony-step-sdk and is version-locked to it.
PLUGIN_DIRS = PACKAGE_DIRS[1:]
SDK_VERSION_FILE = ROOT / "packages" / "step_sdk" / "src" / "hegemony_step_sdk" / "_version.py"
