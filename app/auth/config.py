"""Authentication configuration from environment variables."""

import os
from dotenv import load_dotenv

load_dotenv()

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI_DEV = os.getenv("GOOGLE_REDIRECT_URI_DEV", "http://localhost:5000/oauth/callback")
GOOGLE_REDIRECT_URI_PROD = os.getenv("GOOGLE_REDIRECT_URI_PROD")

# Determine redirect URI based on environment
FLASK_ENV = os.getenv("FLASK_ENV", "development")
GOOGLE_REDIRECT_URI = (
    GOOGLE_REDIRECT_URI_PROD if FLASK_ENV == "production"
    else GOOGLE_REDIRECT_URI_DEV
)

# Session Configuration
SESSION_TIMEOUT_MINUTES = int(os.getenv("SESSION_TIMEOUT_MINUTES", "30"))
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY")

# Feature Flag
AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").lower() == "true"


def validate_auth_config() -> None:
    """Ensure required auth environment variables are set."""
    if not GOOGLE_CLIENT_ID:
        raise ValueError(
            "GOOGLE_CLIENT_ID not set. Get from Google Cloud Console OAuth 2.0 credentials."
        )
    if not GOOGLE_CLIENT_SECRET:
        raise ValueError(
            "GOOGLE_CLIENT_SECRET not set. Get from Google Cloud Console."
        )
    if FLASK_ENV == "production" and not GOOGLE_REDIRECT_URI_PROD:
        raise ValueError(
            "GOOGLE_REDIRECT_URI_PROD required in production. Example: https://your-domain.com/oauth/callback"
        )
    if not SESSION_SECRET_KEY:
        raise ValueError(
            "SESSION_SECRET_KEY not set. Generate with: "
            "python -c 'import secrets; print(secrets.token_hex(32))'"
        )
