# SPDX-FileCopyrightText: 2025-2026 Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""SDK version and ABI marker.

``SDK_ABI_VERSION`` is bumped only when the plugin-facing registration contract changes
incompatibly. The core platform compares it against the version it was built for and can
refuse to load plugins from a newer, incompatible ABI.
"""

from __future__ import annotations

__version__ = "0.27.1"
SDK_ABI_VERSION = 1
