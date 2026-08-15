"""Google OAuth 2.0 client for authentication."""

from typing import Dict, Tuple
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow


class OAuthError(Exception):
    """Raised when OAuth authentication fails."""
    pass


class GoogleOAuthClient:
    """Client for Google OAuth 2.0 authentication flow."""

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        # Use full Google scope URLs to avoid mismatch
        self.scopes = [
            "openid",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile"
        ]

    def get_authorization_url(self) -> Tuple[str, str]:
        """
        Generate OAuth authorization URL and state token.

        Returns:
            Tuple of (authorization_url, state_token)
        """
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            },
            scopes=self.scopes,
            redirect_uri=self.redirect_uri
        )

        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="select_account"
        )

        return authorization_url, state

    def exchange_code_for_token(self, authorization_code: str, state: str) -> Dict:
        """
        Exchange authorization code for access token.

        Args:
            authorization_code: Code from OAuth callback
            state: State token for CSRF validation

        Returns:
            Dict with user info: {email, name, email_verified, picture}

        Raises:
            OAuthError: If token exchange fails
        """
        try:
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": self.client_id,
                        "client_secret": self.client_secret,
                        "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                    }
                },
                scopes=self.scopes,
                redirect_uri=self.redirect_uri,
                state=state
            )

            flow.fetch_token(code=authorization_code)

            # Verify ID token
            credentials = flow.credentials
            id_info = id_token.verify_oauth2_token(
                credentials.id_token,
                google_requests.Request(),
                self.client_id
            )

            if not id_info.get("email_verified"):
                raise OAuthError("Email not verified")

            return {
                "email": id_info["email"],
                "name": id_info.get("name", ""),
                "picture": id_info.get("picture", ""),
                "email_verified": id_info.get("email_verified", False)
            }

        except Exception as exc:
            raise OAuthError(f"OAuth token exchange failed: {exc}")


# Singleton instance
_oauth_client = None


def get_oauth_client() -> GoogleOAuthClient:
    """Get singleton OAuth client instance."""
    global _oauth_client
    if _oauth_client is None:
        from app.auth.config import GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI
        _oauth_client = GoogleOAuthClient(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI)
    return _oauth_client
