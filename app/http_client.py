"""Stealth HTTP session factory for Fortis Intelligence Hub.

Provides browser-like TLS fingerprinting via curl_cffi when available,
falling back to standard requests.Session otherwise.
"""

import logging

log = logging.getLogger(__name__)

HAS_CURL_CFFI = False
try:
    from curl_cffi.requests import Session as _CffiSession
    HAS_CURL_CFFI = True
except ImportError:
    _CffiSession = None  # type: ignore[assignment,misc]

_DEFAULT_IMPERSONATE = "chrome"


def create_session(
    *,
    impersonate: str | None = _DEFAULT_IMPERSONATE,
    user_agent: str = "FortisIntelHub/1.0",
    pool_connections: int = 6,
    pool_maxsize: int = 10,
    max_retries: int = 1,
    timeout: float = 30.0,
) -> object:
    """Return a stealth HTTP session (curl_cffi) or standard requests.Session.

    The returned object supports ``.get()``, ``.post()``, ``.head()``, etc.
    with the same API as ``requests.Session``.
    """
    if HAS_CURL_CFFI and impersonate:
        session = _CffiSession(impersonate=impersonate, timeout=timeout)
        session.headers.update({"User-Agent": user_agent})
        log.info(
            "Stealth HTTP session created (curl_cffi, impersonate=%s)",
            impersonate,
        )
        return session

    import requests
    from requests.adapters import HTTPAdapter

    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    adapter = HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        max_retries=max_retries,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    log.info("Standard HTTP session created (requests, no TLS impersonation)")
    return session
