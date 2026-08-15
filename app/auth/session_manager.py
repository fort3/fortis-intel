"""In-memory session store and management."""

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Optional


@dataclass
class UserSession:
    """Represents an authenticated user session."""
    email: str
    name: str
    picture: str
    created_at: datetime
    last_activity: datetime


_MAX_SESSIONS = 10_000


class SessionManager:
    """Manages user sessions in memory."""

    def __init__(self, timeout_minutes: int = 30):
        self.sessions: Dict[str, UserSession] = {}
        self.email_to_token: Dict[str, str] = {}  # Reverse lookup
        self.timeout_minutes = timeout_minutes
        self._request_count = 0

    def create_session(
        self,
        email: str,
        name: str = "",
        picture: str = "",
    ) -> str:
        """
        Create new session and return session token.

        Args:
            email: User's email address
            name: User's display name
            picture: URL to user's profile picture

        Returns:
            Session token (256-bit random string)
        """
        # Invalidate any existing session for this email
        if email in self.email_to_token:
            old_token = self.email_to_token[email]
            self.sessions.pop(old_token, None)

        # Generate new token
        token = secrets.token_urlsafe(32)

        # Create session
        now = datetime.utcnow()
        session = UserSession(
            email=email,
            name=name,
            picture=picture,
            created_at=now,
            last_activity=now,
        )

        if len(self.sessions) >= _MAX_SESSIONS:
            self.cleanup_expired_sessions()

        self.sessions[token] = session
        self.email_to_token[email] = token

        return token

    def get_session(self, token: str) -> Optional[UserSession]:
        """
        Retrieve active session or None if expired/invalid.

        Args:
            token: Session token

        Returns:
            UserSession if valid and not expired, None otherwise
        """
        if not token or token not in self.sessions:
            return None

        self._request_count += 1
        if self._request_count % 100 == 0:
            self.cleanup_expired_sessions()

        session = self.sessions[token]

        # Check expiration
        timeout_delta = timedelta(minutes=self.timeout_minutes)
        if datetime.utcnow() - session.last_activity > timeout_delta:
            # Session expired
            self.invalidate_session(token)
            return None

        # Update last activity
        session.last_activity = datetime.utcnow()
        return session

    def invalidate_session(self, token: str) -> None:
        """
        Remove session (logout).

        Args:
            token: Session token to invalidate
        """
        if token in self.sessions:
            session = self.sessions[token]
            # Remove from both mappings
            self.sessions.pop(token)
            self.email_to_token.pop(session.email, None)

    def cleanup_expired_sessions(self) -> int:
        """
        Remove all expired sessions.

        Returns:
            Number of sessions cleaned up
        """
        now = datetime.utcnow()
        timeout_delta = timedelta(minutes=self.timeout_minutes)

        expired_tokens = [
            token for token, session in self.sessions.items()
            if now - session.last_activity > timeout_delta
        ]

        for token in expired_tokens:
            self.invalidate_session(token)

        return len(expired_tokens)


# Global singleton instance
from app.auth.config import SESSION_TIMEOUT_MINUTES
session_manager = SessionManager(timeout_minutes=SESSION_TIMEOUT_MINUTES)
