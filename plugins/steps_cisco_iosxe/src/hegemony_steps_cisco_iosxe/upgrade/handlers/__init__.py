# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Upgrade handlers package.

This package contains modular handlers for each stage of the upgrade workflow:
- preflight: Pre-upgrade checks (version, disk space, file exists)
- stage: File transfer and verification
- install: Execute upgrade (install command or boot system config)
- verify: Post-reboot verification
- cleanup: Remove old packages/files

Each handler can be used independently in flows for maximum flexibility.
"""

from .cleanup import UpgradeCleanupHandler
from .install import UpgradeInstallHandler
from .preflight import UpgradePreflightHandler
from .stage import UpgradeStageHandler
from .verify import UpgradeVerifyHandler

__all__ = [
    "UpgradePreflightHandler",
    "UpgradeStageHandler",
    "UpgradeInstallHandler",
    "UpgradeVerifyHandler",
    "UpgradeCleanupHandler",
]
