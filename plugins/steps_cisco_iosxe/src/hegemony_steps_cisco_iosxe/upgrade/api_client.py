# SPDX-FileCopyrightText: 2025-2026 Rexonix s.r.o.
# SPDX-FileContributor: Jakub Trávník <jakub.travnik@gmail.com>
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Internal-API helpers for upgrade handlers.

Uses the scoped API client from ``HandlerServices`` — this package never
reads platform settings or auth material directly.
"""

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FileDownloadUrlResponse:
    """Typed response for file download URL endpoints."""

    url: str
    expires_at: str
    filename: str


async def get_file_device_download_url(services: Any, file_id: str) -> FileDownloadUrlResponse:
    """Get presigned download URL for a file, using external URL for device access.

    This returns a URL that network devices can reach (not internal Docker network).
    Requires HEGEMONY_S3_EXTERNAL_URL to be configured.

    Args:
        services: ``HandlerServices`` providing the scoped API client
        file_id: UUID of the StoredFile

    Returns:
        Typed response with url, expires_at, filename

    Raises:
        ValueError: If file not found, external URL not configured, or API error
    """
    async with services.open_api_client(timeout=30) as client:
        response = await client.post(f"/files/{file_id}/device-download-url")

        if response.status_code == 404:
            raise ValueError(f"File not found: {file_id}")

        if response.status_code == 503:
            raise ValueError(
                "External S3 URL not configured. Set HEGEMONY_S3_EXTERNAL_URL so devices can reach repository files"
            )

        if response.status_code != 200:
            raise ValueError(
                f"API error getting device download URL for {file_id}: {response.status_code}"
            )

        payload = response.json()
        try:
            return FileDownloadUrlResponse(
                url=str(payload["url"]),
                expires_at=str(payload["expires_at"]),
                filename=str(payload["filename"]),
            )
        except KeyError as e:
            raise ValueError(f"Missing expected field in API response: {e}") from e
