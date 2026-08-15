"""Flask route decorators for authentication."""

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
        # Feature flag bypass - create dummy session when auth disabled
        if not AUTH_ENABLED:
            from app.auth.session_manager import UserSession
            from datetime import datetime
            # Create a dummy admin session for development/testing
            g.user_session = UserSession(
                email="test@localhost",
                name="Test User",
                picture="",
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow(),
            )
            return f(*args, **kwargs)

        # Get session token from Flask session
        token = session.get("auth_token")

        if not token:
            return jsonify({"error": "Authentication required"}), 401

        # Validate session
        user_session = session_manager.get_session(token)

        if not user_session:
            return jsonify({"error": "Session expired or invalid"}), 401

        # Store in Flask g for route access
        g.user_session = user_session
        return f(*args, **kwargs)

    return decorated_function
