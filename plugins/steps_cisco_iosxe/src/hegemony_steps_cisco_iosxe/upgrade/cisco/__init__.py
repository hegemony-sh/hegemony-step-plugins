# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Cisco IOS-XE upgrade drivers.

This package contains:
- iosxe_install: IOS-XE Install Mode driver (modern Catalyst 3K/9K, ISR 4K+)
- iosxe_bundle: IOS-XE Bundle Mode driver (legacy ISR routers)
- iosxe_common: Shared utilities for both drivers

Usage:
    from hegemony_steps_cisco_iosxe.upgrade import get_driver, UpgradeMode

    driver = get_driver(UpgradeMode.INSTALL)  # or UpgradeMode.BUNDLE
"""

# Modular drivers
from .iosxe_bundle import IOSXEBundleDriver

# Common utilities
from .iosxe_common import (
    check_file_exists_in_dir,
    normalize_filesystem,
    parse_boot_statements,
    parse_file_size_from_dir,
    parse_free_bytes,
    parse_version_from_show_version,
)
from .iosxe_install import IOSXEInstallDriver

__all__ = [
    # Drivers
    "IOSXEInstallDriver",
    "IOSXEBundleDriver",
    # Common utilities
    "parse_free_bytes",
    "parse_version_from_show_version",
    "normalize_filesystem",
    "check_file_exists_in_dir",
    "parse_file_size_from_dir",
    "parse_boot_statements",
]
