"""Google Drive export client for Fortis Intelligence Hub report uploads.

Uploads generated reports (PDF, Markdown, STIX, CSV, JSON) to a shared
Google Drive folder using a GCP service account. Gracefully degrades
when google-api-python-client is not installed or Drive is not configured.
"""

import io
import os
from typing import Optional

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaIoBaseUpload
    HAS_GDRIVE = True
except ImportError:
    HAS_GDRIVE = False


MIME_TYPES = {
    "pdf": "application/pdf",
    "markdown": "text/markdown",
    "stix": "application/json",
    "csv": "text/csv",
    "json": "application/json",
}

SCOPES = ["https://www.googleapis.com/auth/drive.file"]

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


class GDriveClient:

    def __init__(self):
        self._key_file = os.getenv("GDRIVE_SERVICE_ACCOUNT_KEY_FILE", "")
        self._folder_id = os.getenv("GDRIVE_FOLDER_ID", "")
        self._service = None

    @property
    def is_configured(self) -> bool:
        if not HAS_GDRIVE:
            return False
        if not self._key_file or not self._folder_id:
            return False
        if ".." in self._key_file:
            return False
        return os.path.isfile(self._key_file)

    def _get_service(self):
        if self._service is None:
            if ".." in self._key_file:
                raise ValueError("Invalid key file path")
            credentials = service_account.Credentials.from_service_account_file(
                self._key_file, scopes=SCOPES
            )
            self._service = build("drive", "v3", credentials=credentials)
        return self._service

    def upload_file(self, file_bytes: bytes, filename: str, mime_type: str) -> dict:
        """Upload a file to the configured Google Drive folder.

        Args:
            file_bytes: Raw file content.
            filename: Target filename in Drive.
            mime_type: MIME type string.

        Returns:
            Dict with ``success``, and on success ``file_id`` and
            ``web_view_link``; on failure ``error``.
        """
        if not self.is_configured:
            return {"success": False, "error": "Google Drive not configured"}

        if len(file_bytes) > MAX_UPLOAD_BYTES:
            return {"success": False, "error": f"File exceeds {MAX_UPLOAD_BYTES // (1024*1024)}MB limit"}

        try:
            service = self._get_service()
            file_metadata = {
                "name": filename,
                "parents": [self._folder_id],
            }
            media = MediaIoBaseUpload(
                io.BytesIO(file_bytes),
                mimetype=mime_type,
                resumable=False,
            )
            result = service.files().create(
                body=file_metadata,
                media_body=media,
                fields="id, webViewLink",
            ).execute()

            return {
                "success": True,
                "file_id": result.get("id"),
                "web_view_link": result.get("webViewLink"),
            }
        except Exception as exc:
            print(f"[WARN] Google Drive upload failed: {exc}")
            return {"success": False, "error": str(exc)}

    def test_connection(self) -> dict:
        """Test Drive connectivity and folder access.

        Returns:
            Dict with ``configured``, ``connected``, optional ``folder_name``,
            ``folder_id``, and ``error`` keys.
        """
        if not self.is_configured:
            return {
                "configured": False,
                "connected": False,
                "error": "Google Drive not configured -- set GDRIVE_SERVICE_ACCOUNT_KEY_FILE and GDRIVE_FOLDER_ID"
                         + ("" if HAS_GDRIVE else " (google-api-python-client not installed)"),
            }
        try:
            service = self._get_service()
            folder = service.files().get(
                fileId=self._folder_id,
                fields="id, name",
            ).execute()
            return {
                "configured": True,
                "connected": True,
                "folder_name": folder.get("name"),
                "folder_id": folder.get("id"),
                "error": None,
            }
        except Exception as exc:
            print(f"[WARN] Google Drive connection test failed: {exc}")
            return {
                "configured": True,
                "connected": False,
                "error": str(exc),
            }


_gdrive_client: Optional[GDriveClient] = None


def get_gdrive_client() -> GDriveClient:
    """Return a module-level singleton ``GDriveClient``."""
    global _gdrive_client
    if _gdrive_client is None:
        _gdrive_client = GDriveClient()
    return _gdrive_client
