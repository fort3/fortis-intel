"""Audit logging for security events and user activities."""

import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional


class AuditLogger:
    """Logs security events and user activities to file."""

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Setup Python logger
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)

        # Add file handler (avoid duplicate handlers on repeated init)
        if not self.logger.handlers:
            log_file = self.log_dir / "audit.log"
            handler = logging.FileHandler(log_file, encoding="utf-8")
            handler.setFormatter(logging.Formatter(
                '%(asctime)s | %(levelname)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            ))
            self.logger.addHandler(handler)

    def _sanitize_email(self, email: str) -> str:
        """
        Hash email for privacy while maintaining uniqueness for auditing.

        SECURITY: This protects user privacy by hashing email addresses in logs
        while still allowing correlation of events from the same user.

        Returns: First 16 characters of SHA-256 hash
        """
        if not email:
            return "unknown"
        return hashlib.sha256(email.encode()).hexdigest()[:16]

    def _log_event(self, event_type: str, email: Optional[str], details: dict):
        """
        Internal method to log structured event.

        SECURITY: Email addresses are hashed for privacy protection.
        """
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_hash": self._sanitize_email(email) if email else None,
            **details
        }
        self.logger.info(json.dumps(event))

    # --- Authentication events ---

    def log_login_attempt(self, email: str, success: bool, reason: str = ""):
        """Log login attempt."""
        self._log_event("LOGIN_ATTEMPT", email, {
            "success": success,
            "reason": reason
        })

    def log_login_success(self, email: str):
        """Log successful login."""
        self._log_event("LOGIN_SUCCESS", email, {})

    def log_logout(self, email: str):
        """Log user logout."""
        self._log_event("LOGOUT", email, {})

    def log_session_expired(self, email: str):
        """Log session expiration."""
        self._log_event("SESSION_EXPIRED", email, {})

    def log_permission_denied(self, email: str, endpoint: str, reason: Optional[str] = None):
        """Log permission denial."""
        self._log_event("PERMISSION_DENIED", email, {
            "endpoint": endpoint,
            "reason": reason
        })

    # --- Document events ---

    def log_upload(self, email: str, filename: str, session_id: str):
        """
        Log PDF upload.

        SECURITY: Filename is not logged to prevent sensitive data leakage.
        Only session ID is logged for debugging purposes.
        """
        self._log_event("UPLOAD_PDF", email, {
            "session_id": session_id
            # Note: filename intentionally not logged for privacy
        })

    def log_query(self, email: str, session_id: str, endpoint: str):
        """Log AI query."""
        self._log_event("AI_QUERY", email, {
            "session_id": session_id,
            "endpoint": endpoint
        })

    # --- OSINT events ---

    def log_investigation(self, email: str, indicator_type: str, session_id: str = ""):
        """Log an OSINT investigation (single indicator lookup)."""
        self._log_event("INVESTIGATION", email, {
            "indicator_type": indicator_type,
            "session_id": session_id
        })

    def log_triangulation(self, email: str, indicator_count: int, session_id: str = ""):
        """Log a triangulation (cross-referencing multiple indicators)."""
        self._log_event("TRIANGULATION", email, {
            "indicator_count": indicator_count,
            "session_id": session_id
        })

    def log_batch_investigation(self, email: str, indicator_count: int, session_id: str = ""):
        """Log a batch investigation (bulk indicator lookup)."""
        self._log_event("BATCH_INVESTIGATION", email, {
            "indicator_count": indicator_count,
            "session_id": session_id
        })

    def log_enrichment(self, email: str, indicator_type: str, source: str, session_id: str = ""):
        """Log an enrichment action (augmenting indicator data from an external source)."""
        self._log_event("ENRICHMENT", email, {
            "indicator_type": indicator_type,
            "source": source,
            "session_id": session_id
        })

    def log_monitor_create(self, email: str, monitor_type: str, session_id: str = ""):
        """Log creation of a monitoring rule or alert."""
        self._log_event("MONITOR_CREATE", email, {
            "monitor_type": monitor_type,
            "session_id": session_id
        })

    def log_export(self, email: str, export_format: str, record_count: int = 0, session_id: str = ""):
        """Log data export."""
        self._log_event("EXPORT", email, {
            "format": export_format,
            "record_count": record_count,
            "session_id": session_id
        })

    # --- Generic ---

    def log_security_event(self, event_type: str, details: dict):
        """Log generic security event."""
        self._log_event(f"SECURITY_{event_type}", None, details)


# Global singleton
_audit_logger = None


def get_audit_logger() -> AuditLogger:
    """Get singleton audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger
