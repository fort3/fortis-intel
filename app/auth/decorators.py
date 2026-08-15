"""Flask route decorators for authentication and authorization."""

from functools import wraps
from flask import request, jsonify, session, g

from app.auth.config import AUTH_ENABLED
from app.auth.session_manager import session_manager


def login_required(f):
    """
    Require valid session for route access.

    Sets g.user_session for use in route handler.
    Returns 401 if not authenticated.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not AUTH_ENABLED:
            from app.auth.session_manager import UserSession
            from datetime import datetime
            g.user_session = UserSession(
                email="test@localhost",
                name="Test User",
                picture="",
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow(),
                is_admin=True,
            )
            return f(*args, **kwargs)

        token = session.get("auth_token")

        if not token:
            return jsonify({"error": "Authentication required"}), 401

        user_session = session_manager.get_session(token)

        if not user_session:
            return jsonify({"error": "Session expired or invalid"}), 401

        g.user_session = user_session
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    """
    Require admin privileges for route access.

    Must be placed AFTER @login_required in decorator stack.
    Returns 403 if user is not an admin.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_session = getattr(g, "user_session", None)
        if not user_session or not user_session.is_admin:
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)

    return decorated_function


def is_current_request_admin() -> bool:
    """Check if the current request comes from an admin user.

    Works before g.user_session is set (reads session token directly).
    Used by the rate-limiter request_filter so admins bypass all limits.
    """
    if not AUTH_ENABLED:
        return True

    from flask import session as flask_session
    token = flask_session.get("auth_token")
    if not token:
        return False
    user_session = session_manager.get_session(token)
    if not user_session:
        return False
    return user_session.is_admin
