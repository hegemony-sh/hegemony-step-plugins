# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SDK version and ABI marker.

The SDK has its own version, separate from the plugin wheels' release version; it
changes only when the SDK changes (scripts/sdk_version.py checks the bump).
``SDK_ABI_VERSION`` is bumped only when the plugin-facing contract changes
incompatibly, and it is always the major of ``__version__``. The core platform compares
it against the version it was built for and can refuse to load plugins from a newer,
incompatible ABI.
"""

from __future__ import annotations

__version__ = "1.0.1"
SDK_ABI_VERSION = 1
