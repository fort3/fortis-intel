"""Safe upload path and session ID helpers for Fortis Intelligence Hub."""

import re
import uuid
from pathlib import Path
from typing import Tuple

SESSION_ID_PATTERN = re.compile(r"^[a-f0-9]{12}_[\w.\-]+$")

MAX_FILE_SIZE_MB = 50

ALLOWED_EXTENSIONS = {".pdf", ".md", ".csv", ".json"}


def _sanitize_filename(filename: str) -> str:
    """Return a basename with only safe characters."""
    basename = filename.replace("\\", "/").split("/")[-1]
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "_", basename)
    sanitized = re.sub(r"\.{2,}", "_", sanitized)
    return sanitized or "upload"


def create_session_id(original_filename: str) -> str:
    """Return a non-guessable session ID derived from a sanitized filename."""
    safe_name = _sanitize_filename(original_filename)
    return f"{uuid.uuid4().hex[:12]}_{safe_name}"


def validate_session_id(session_id: str) -> bool:
    """Reject path traversal and malformed session IDs."""
    if not session_id:
        return False
    if ".." in session_id or "/" in session_id or "\\" in session_id:
        return False
    return bool(SESSION_ID_PATTERN.match(session_id))


def safe_storage_path(base_dir: str, session_id: str, suffix: str = "") -> Path:
    """Resolve a storage path that must stay inside base_dir."""
    if not validate_session_id(session_id):
        raise ValueError("Invalid session ID")

    base = Path(base_dir).resolve()
    filename = f"{session_id}{suffix}"
    path = (base / filename).resolve()

    if base not in path.parents and path != base:
        raise ValueError("Path traversal detected")

    return path


def validate_upload_file(file, *, max_size_mb: int | None = None) -> Tuple[bool, str]:
    """
    Validate uploaded file is an allowed type and within size limits.

    Supports PDF, Markdown, CSV, and JSON files with format-specific validation.
    """
    if not file or not file.filename:
        return False, "No file provided"

    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Unsupported file type. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"

    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)

    if file_size == 0:
        return False, "File is empty"

    effective_limit = max_size_mb or MAX_FILE_SIZE_MB
    max_size = effective_limit * 1024 * 1024
    if file_size > max_size:
        return False, f"File size exceeds {effective_limit}MB limit"

    if ext == ".pdf":
        header = file.read(4)
        file.seek(0)
        if header != b'%PDF':
            return False, "File is not a valid PDF (invalid magic bytes)"

    elif ext in (".md", ".csv", ".json"):
        sample = file.read(8192)
        file.seek(0)
        if b'\x00' in sample:
            return False, f"File contains binary content and is not a valid {ext} file"
        try:
            sample.decode("utf-8")
        except UnicodeDecodeError:
            return False, "File is not valid UTF-8 text"

    return True, ""
