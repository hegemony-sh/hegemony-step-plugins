# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Base upgrade driver interface for multi-vendor support.

This module defines the abstract interface that all upgrade drivers must implement.
Drivers are platform-specific implementations that handle the details of:
- Preflight checks (version, disk space, compatibility)
- File staging (transfer + verification)
- Software installation (activation, commit)
- Post-upgrade verification
- Cleanup of old software

The modular handler architecture uses these drivers to provide consistent
behavior across different vendors and platforms while allowing platform-specific
optimizations.

Supported upgrade modes:
- Install mode: Modern IOS-XE (Catalyst 3K/9K, ISR 4K with install mode)
- Bundle mode: Legacy IOS-XE (older ISR, some ASR) using boot system commands
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from hegemony_step_sdk import Transport

logger = logging.getLogger(__name__)


# ==============================================================================
# Transfer capabilities
# ==============================================================================


@dataclass
class TransferCapabilities:
    """What file transfer methods this platform supports.

    Used by handlers to select the best transfer method based on
    device capabilities and network topology.
    """

    http: bool = False  # Device can pull via HTTP (copy http://...)
    https: bool = False  # Device can pull via HTTPS
    scp: bool = False  # SCP push is not implemented at any level yet
    tftp: bool = False  # No TFTP implementation exists anywhere in the stage path
    ftp: bool = False  # Device can pull via FTP


# ==============================================================================
# Result dataclasses for each operation
# ==============================================================================


@dataclass
class PreflightResult:
    """Result from preflight checks.

    Contains all information gathered during pre-upgrade validation:
    - Current software version
    - Available storage space
    - Whether target file already exists
    - Whether upgrade mode is supported
    - Any blocking errors
    """

    success: bool
    current_version: str = ""
    free_bytes: int | None = None
    filesystem: str = ""
    image_exists: bool | None = None  # None if not checked
    target_version_installed: bool = False  # Already running target version
    install_mode_supported: bool = True  # False for bundle-mode only devices
    config_saved: bool | None = None  # Running config saved to startup; None: not checked
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    cli_outputs: dict[str, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)  # Driver-specific extra data


@dataclass
class StageResult:
    """Result from file staging (transfer + verify).

    Staging involves:
    1. Transferring the file to device storage
    2. Verifying file integrity (size, hash)
    """

    success: bool
    staged: bool = False  # File now on device and verified
    skipped: bool = False  # True if file already existed
    transferred_bytes: int | None = None
    transfer_method: str = ""  # "http", "https"
    transfer_elapsed_sec: float = 0.0
    hash_verified: bool = False
    verified_hash: str | None = None  # MD5 (the only on-device check IOS-XE offers here)
    computed_hash: str | None = None  # MD5 the device reported, whether it matched or not
    hash_type: str = ""  # "md5"
    filesystem: str = ""
    full_path: str = ""  # e.g., "flash:cat9k_iosxe.17.09.01.SPA.bin"
    error: str | None = None
    cli_output: str = ""


@dataclass
class InstallResult:
    """Result from software installation.

    Installation may trigger a device reboot. The handler must
    wait for reconnection if reboot_triggered is True.
    """

    success: bool
    reboot_triggered: bool = False
    activated: bool = False  # Software activated but may not be committed
    committed: bool = False  # Software committed (won't auto-rollback)
    error: str | None = None
    cli_output: str = ""
    note: str | None = None  # Optional note (e.g., "Already at target version")
    # The step changed the boot setting in the running configuration, or could
    # not undo a failed change. Not proof of a save: "write memory" comes later
    # and can still fail, which the error then says.
    boot_config_changed: bool = False
    previous_boot: list[str] = field(default_factory=list)  # Boot entries before the step


@dataclass
class VerifyResult:
    """Result from post-upgrade verification.

    Confirms the upgrade was successful by checking:
    - Running version matches expected
    - Software is committed (for install-mode)
    - Boot configuration is correct
    """

    success: bool
    current_version: str = ""
    version_match: bool = False  # Running version is target_version (same release)
    version_changed: bool = False  # Version different from preflight
    committed: bool = False  # Install-mode: software committed
    boot_config_correct: bool = True  # Boot system points to new image
    error: str | None = None
    cli_outputs: dict[str, str] = field(default_factory=dict)


@dataclass
class CleanupResult:
    """Result from cleanup operations.

    Cleanup removes old software to reclaim storage space.
    """

    success: bool
    removed_packages: list[str] = field(default_factory=list)
    bytes_reclaimed: int | None = None
    error: str | None = None
    cli_output: str = ""


# ==============================================================================
# Upgrade mode enum
# ==============================================================================


class UpgradeMode(str, Enum):  # noqa: UP042 - (str, Enum) keeps str() parity with platform enums
    """IOS-XE upgrade modes.

    INSTALL: Modern install-mode using 'install add file ... activate commit'
             Supported on Catalyst 3K/9K, ISR 4K (16.x+), ASR 1K
             Uses packages.conf, supports hitless upgrades on some platforms

    BUNDLE: Legacy bundle-mode using 'copy + boot system'
            Used on older ISR routers, some ASR platforms
            Requires manual boot system configuration
    """

    INSTALL = "install"
    BUNDLE = "bundle"


# ==============================================================================
# Abstract driver interface
# ==============================================================================


class UpgradeDriver(ABC):
    """Abstract base class for platform-specific upgrade drivers.

    Each platform (IOS-XE, NX-OS, EOS, etc.) has its own driver implementation
    that handles the platform-specific details of software upgrades.

    Drivers are stateless - all state is passed via method parameters.
    This allows handlers to use drivers without managing driver lifecycle.

    Implementations:
    - IOSXEInstallDriver: IOS-XE install mode (modern)
    - IOSXEBundleDriver: IOS-XE bundle mode (legacy)
    - (Future) NXOSDriver, EOSDriver, JunosDriver
    """

    # Platform identifier (matches Device.platform value)
    platform: str = ""

    # Human-readable name
    display_name: str = ""

    # Default filesystem for this platform
    default_fs: str = "flash:"

    # Upgrade mode (for IOS-XE variants)
    upgrade_mode: UpgradeMode | None = None

    # Transfer capabilities - initialized in __init__ for ABC compatibility
    transfer_capabilities: TransferCapabilities

    def __init__(self) -> None:
        """Initialize driver with default transfer capabilities."""
        if not hasattr(self, "transfer_capabilities") or self.transfer_capabilities is None:
            self.transfer_capabilities = TransferCapabilities()

    @abstractmethod
    async def preflight(
        self,
        ssh: Transport,
        *,
        image_name: str | None = None,
        dest_fs: str | None = None,
        min_free_bytes: int | None = None,
        target_version: str | None = None,
    ) -> PreflightResult:
        """Run preflight checks before upgrade.

        Validates that the device is ready for upgrade:
        - Current version detection
        - Disk space availability
        - File existence check
        - Upgrade mode support verification

        This operation is non-disruptive and safe to run at any time.

        Args:
            ssh: Connected SSH transport
            image_name: Expected file filename (optional, for existence check)
            dest_fs: Destination filesystem (uses driver default if not specified)
            min_free_bytes: Minimum required free space in bytes
            target_version: Target version string (to check if already installed)

        Returns:
            PreflightResult with validation status and device info
        """
        ...

    @abstractmethod
    async def stage(
        self,
        ssh: Transport,
        *,
        source_url: str,
        dest_fs: str,
        dest_filename: str,
        transfer_method: str = "auto",
        expected_md5: str | None = None,
        expected_size: int | None = None,
        overwrite: bool = False,
    ) -> StageResult:
        """Stage (transfer + verify) file to device.

        Transfers the software file to device storage and verifies
        its integrity. This operation is idempotent - if the file
        already exists and is verified, it will be skipped.

        This operation is non-disruptive (no reboot), but may take
        a long time for large files over slow links.

        Args:
            ssh: Connected SSH transport
            source_url: URL to download file from (for HTTP/HTTPS transfer)
            dest_fs: Destination filesystem (e.g., "flash:")
            dest_filename: Filename on device
            transfer_method: "auto", "http", "https"
            expected_md5: Expected MD5 hash for verification
            expected_size: Expected file size in bytes
            overwrite: Overwrite if file already exists

        Returns:
            StageResult with transfer and verification status
        """
        ...

    @abstractmethod
    async def install(
        self,
        ssh: Transport,
        *,
        image_name: str,
        dest_fs: str,
        activate: bool = True,
        commit: bool = True,
        fix_boot_config: bool = False,
    ) -> InstallResult:
        """Execute software installation.

        Activates the staged software file. This operation typically
        triggers a device reboot.

        WARNING: This operation is disruptive and causes a service outage
        until the device completes rebooting.

        Args:
            ssh: Connected SSH transport
            image_name: File filename on device
            dest_fs: Filesystem where file is stored
            activate: Activate the software (usually True)
            commit: Commit the software to prevent auto-rollback
            fix_boot_config: Install mode: set and save the boot variable when
                it does not point at packages.conf, instead of failing

        Returns:
            InstallResult with installation status and reboot indication
        """
        ...

    @abstractmethod
    async def verify(
        self,
        ssh: Transport,
        *,
        target_version: str | None = None,
        preflight_version: str | None = None,
        auto_commit: bool = True,
    ) -> VerifyResult:
        """Verify upgrade was successful.

        Checks that the device is running the expected software version
        and that the upgrade is properly committed (for install-mode).

        Should be called after the device has rebooted and is reachable.

        Args:
            ssh: Connected SSH transport
            target_version: Expected version, compared as a release (17.9.4a
                is 17.09.04a; 17.09.04 is not)
            preflight_version: Version before upgrade (to detect unchanged)
            auto_commit: Automatically commit if not committed

        Returns:
            VerifyResult with version and commit status
        """
        ...

    @abstractmethod
    async def cleanup(
        self,
        ssh: Transport,
        *,
        remove_inactive: bool = True,
        keep_versions: int = 1,
    ) -> CleanupResult:
        """Remove old software packages to reclaim space.

        Cleans up inactive software packages and old files.
        Safe to run after verify confirms the upgrade was successful.

        Args:
            ssh: Connected SSH transport
            remove_inactive: Remove inactive packages (install-mode)
            keep_versions: Number of old versions to keep

        Returns:
            CleanupResult with removed packages list
        """
        ...

    def select_transfer_method(
        self,
        preferred: str = "auto",
        http_url_available: bool = False,
        scp_available: bool = True,
    ) -> str:
        """Select the best transfer method based on capabilities.

        Args:
            preferred: Preferred method ("auto" for automatic selection)
            http_url_available: Whether an HTTP/HTTPS URL is available
            scp_available: Whether SCP can be used

        Returns:
            Selected transfer method: "http", "https", or the unimplemented
            "scp" fallback (fails downstream with an explicit error)
        """
        if preferred != "auto":
            return preferred

        # Prefer HTTP (device pulls) over SCP (worker pushes)
        # HTTP is generally faster and doesn't require worker to have file locally
        if http_url_available:
            if self.transfer_capabilities.https:
                return "https"
            if self.transfer_capabilities.http:
                return "http"

        if scp_available and self.transfer_capabilities.scp:
            return "scp"

        # Fallback
        return "scp"


# ==============================================================================
# Driver registry
# ==============================================================================

_drivers: dict[str, type[UpgradeDriver]] = {}


def register_driver(platform: str, mode: UpgradeMode | None = None):
    """Decorator to register an upgrade driver.

    Args:
        platform: Platform identifier (e.g., "ios-xe", "nxos")
        mode: Upgrade mode (for platforms with multiple modes)

    Usage:
        @register_driver("ios-xe", UpgradeMode.INSTALL)
        class IOSXEInstallDriver(UpgradeDriver):
            ...
    """

    def decorator(cls: type[UpgradeDriver]) -> type[UpgradeDriver]:
        key = f"{platform.lower()}"
        if mode:
            key = f"{platform.lower()}:{mode.value}"
        _drivers[key] = cls
        logger.debug(f"Registered upgrade driver: {key} -> {cls.__name__}")
        return cls

    return decorator


def get_driver(
    platform: str,
    mode: UpgradeMode | str | None = None,
) -> UpgradeDriver:
    """Get an upgrade driver instance for the specified platform.

    Args:
        platform: Platform identifier (e.g., "ios-xe", "nxos", "eos")
        mode: Upgrade mode (for platforms with multiple modes like IOS-XE)

    Returns:
        Configured driver instance

    Raises:
        ValueError: If no driver found for platform/mode combination
    """
    platform_lower = platform.lower().replace("_", "-")

    # Normalize common aliases
    aliases = {
        "cisco-ios-xe": "ios-xe",
        "iosxe": "ios-xe",
        "cisco-nxos": "nxos",
        "nx-os": "nxos",
        "cisco-xr": "ios-xr",
        "iosxr": "ios-xr",
        "arista-eos": "eos",
        "juniper-junos": "junos",
    }
    platform_key = aliases.get(platform_lower, platform_lower)

    # Handle mode
    if isinstance(mode, str):
        mode = UpgradeMode(mode.lower())

    # Try platform:mode first, then platform only
    if mode:
        key = f"{platform_key}:{mode.value}"
        if key in _drivers:
            return _drivers[key]()

    # Try platform without mode
    if platform_key in _drivers:
        return _drivers[platform_key]()

    # For IOS-XE, default to install mode if no mode specified
    if platform_key == "ios-xe":
        install_key = f"ios-xe:{UpgradeMode.INSTALL.value}"
        if install_key in _drivers:
            return _drivers[install_key]()

    available = list(_drivers.keys())
    raise ValueError(
        f"No upgrade driver for platform '{platform}'"
        + (f" with mode '{mode.value}'" if mode else "")
        + f". Available: {available}"
    )


def list_drivers() -> list[dict[str, str | None]]:
    """List all registered upgrade drivers.

    Returns:
        List of dicts with 'key', 'platform', 'mode', 'class_name'
    """
    result: list[dict[str, str | None]] = []
    for key, cls in _drivers.items():
        parts = key.split(":")
        result.append(
            {
                "key": key,
                "platform": parts[0],
                "mode": parts[1] if len(parts) > 1 else None,
                "class_name": cls.__name__,
            }
        )
    return result
