# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Upgrade module for firmware/software upgrades.

This module provides:
1. Driver abstraction for multi-platform upgrades (driver.py)
2. Platform-specific drivers (cisco/iosxe_install.py, cisco/iosxe_bundle.py)
3. Modular handlers for upgrade workflow stages (handlers/)

Handlers:
- cisco.iosxe.upgrade.preflight: Pre-upgrade checks
- cisco.iosxe.upgrade.stage: File transfer and verification
- cisco.iosxe.upgrade.install: Execute upgrade (triggers reboot)
- cisco.iosxe.upgrade.verify: Post-reboot verification
- cisco.iosxe.upgrade.cleanup: Remove inactive packages/files

Supported platforms:
- IOS-XE (install mode): Catalyst 9000, ISR 4000 series with install mode
- IOS-XE (bundle mode): Legacy IOS-XE devices using boot system commands

Planned (not yet implemented):
- NX-OS: Nexus 9000/7000/5000 series
- IOS-XR: ASR 9000, NCS series
"""

# Import drivers to register them
from .cisco import iosxe_bundle, iosxe_install  # noqa: F401
from .driver import (
    CleanupResult,
    InstallResult,
    PreflightResult,
    StageResult,
    TransferCapabilities,
    UpgradeDriver,
    UpgradeMode,
    VerifyResult,
    get_driver,
    register_driver,
)
from .handlers import (
    UpgradeCleanupHandler,
    UpgradeInstallHandler,
    UpgradePreflightHandler,
    UpgradeStageHandler,
    UpgradeVerifyHandler,
)

__all__ = [
    # Driver abstraction
    "UpgradeDriver",
    "UpgradeMode",
    "TransferCapabilities",
    "PreflightResult",
    "StageResult",
    "InstallResult",
    "VerifyResult",
    "CleanupResult",
    "register_driver",
    "get_driver",
    # Handlers
    "UpgradePreflightHandler",
    "UpgradeStageHandler",
    "UpgradeInstallHandler",
    "UpgradeVerifyHandler",
    "UpgradeCleanupHandler",
]
