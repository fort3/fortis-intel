"""Authentication package for Fortis Intelligence Hub."""

from app.auth.config import validate_auth_config, ADMIN_EMAILS
from app.auth.decorators import login_required, admin_required, is_current_request_admin
from app.auth.oauth_client import OAuthError, get_oauth_client
from app.auth.session_manager import SessionManager, UserSession, session_manager
from app.auth.audit_logger import get_audit_logger

__all__ = [
    "validate_auth_config",
    "login_required",
    "admin_required",
    "is_current_request_admin",
    "ADMIN_EMAILS",
    "get_oauth_client",
    "OAuthError",
    "SessionManager",
    "UserSession",
    "session_manager",
    "get_audit_logger",
]
