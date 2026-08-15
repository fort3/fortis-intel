"""Input sanitization utilities for OSINT identifiers.

Provides validation and normalization helpers that run *before* identifiers
are passed to external API queries, stored in the database, or rendered
in the UI.
"""

import ipaddress
import re
from html.parser import HTMLParser
from io import StringIO
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class _HTMLStripper(HTMLParser):
    """Minimal HTML-to-plain-text converter."""

    def __init__(self):
        super().__init__()
        self._parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self._parts.append(data)

    def get_text(self) -> str:
        return "".join(self._parts)


_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)

_DOMAIN_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}$"
)

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,64}$")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def sanitize_identifier(identifier: str, id_type: str) -> str:
    """Strip and normalize an identifier before using it in API queries.

    Args:
        identifier: Raw user-supplied value.
        id_type: One of ``"username"``, ``"email"``, ``"domain"``,
            ``"ip"``, ``"url"``, or ``"generic"``.

    Returns:
        Cleaned identifier string.

    Raises:
        ValueError: If *identifier* is empty or *id_type* is unknown.
    """
    if not identifier or not identifier.strip():
        raise ValueError("Identifier must not be empty")

    cleaned = identifier.strip()

    dispatch = {
        "username": lambda v: normalize_username(v),
        "email": lambda v: v.lower().strip(),
        "domain": lambda v: v.lower().strip().rstrip("."),
        "ip": lambda v: str(ipaddress.ip_address(v.strip())),
        "url": lambda v: v.strip(),
        "generic": lambda v: v.strip(),
    }

    handler = dispatch.get(id_type)
    if handler is None:
        raise ValueError(f"Unknown identifier type: {id_type}")

    return handler(cleaned)


def sanitize_html(text: str) -> str:
    """Strip HTML tags and return plain text for safe display.

    Args:
        text: Possibly-HTML string.

    Returns:
        Plain text with all HTML markup removed.
    """
    if not text:
        return ""
    stripper = _HTMLStripper()
    stripper.feed(text)
    return stripper.get_text()


def normalize_username(username: str) -> str:
    """Normalize a social-media / platform username.

    Strips leading ``@`` characters, collapses whitespace, and lowercases.

    Args:
        username: Raw username (e.g. ``"@JohnDoe"``).

    Returns:
        Normalized form (e.g. ``"johndoe"``).

    Raises:
        ValueError: If the result is empty or contains illegal characters.
    """
    if not username or not username.strip():
        raise ValueError("Username must not be empty")

    cleaned = username.strip().lstrip("@").lower()

    if not cleaned:
        raise ValueError("Username must not be empty after normalization")

    if not _USERNAME_RE.match(cleaned):
        raise ValueError(
            f"Username contains invalid characters: {cleaned!r}"
        )

    return cleaned


def validate_url(url: str) -> bool:
    """Return ``True`` if *url* looks like a valid HTTP(S) URL.

    Checks scheme (``http`` / ``https``) and presence of a network location.
    Does **not** attempt DNS resolution.
    """
    if not url or not url.strip():
        return False
    try:
        result = urlparse(url.strip())
        return result.scheme in ("http", "https") and bool(result.netloc)
    except Exception:
        return False


def validate_ip(ip: str) -> bool:
    """Return ``True`` if *ip* is a valid IPv4 or IPv6 address."""
    if not ip or not ip.strip():
        return False
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_email(email: str) -> bool:
    """Return ``True`` if *email* matches a basic email format.

    This is intentionally lenient -- it catches obviously-wrong input
    without attempting full RFC 5322 compliance.
    """
    if not email or not email.strip():
        return False
    return bool(_EMAIL_RE.match(email.strip()))


def validate_domain(domain: str) -> bool:
    """Return ``True`` if *domain* looks like a valid domain name.

    Checks label lengths and overall structure.  Does **not** perform
    DNS resolution.
    """
    if not domain or not domain.strip():
        return False
    cleaned = domain.strip().rstrip(".")
    if len(cleaned) > 253:
        return False
    return bool(_DOMAIN_RE.match(cleaned))
