"""Stealth HTTP session factory for Fortis Intelligence Hub.

Provides browser-like TLS fingerprinting via curl_cffi when available,
falling back to standard requests.Session otherwise.

Sessions are wrapped in a thread-local proxy so each thread gets its own
underlying handle — curl_cffi uses libcurl which binds to Windows COM on
the creating thread and is NOT safe to share across threads.
"""

import logging
import threading

log = logging.getLogger(__name__)

HAS_CURL_CFFI = False
try:
    from curl_cffi.requests import Session as _CffiSession
    HAS_CURL_CFFI = True
except ImportError:
    _CffiSession = None  # type: ignore[assignment,misc]

_DEFAULT_IMPERSONATE = "chrome"


class _ThreadLocalSession:
    """Proxy that gives each thread its own HTTP session.

    Attribute access (`.get`, `.post`, `.headers`, etc.) is forwarded to
    a per-thread real session created lazily on first use.
    """

    def __init__(self, factory):
        object.__setattr__(self, "_factory", factory)
        object.__setattr__(self, "_local", threading.local())

    def _session(self):
        local = object.__getattribute__(self, "_local")
        try:
            return local.session
        except AttributeError:
            factory = object.__getattribute__(self, "_factory")
            local.session = factory()
            return local.session

    def __getattr__(self, name):
        return getattr(self._session(), name)

    def __setattr__(self, name, value):
        setattr(self._session(), name, value)


def create_session(
    *,
    impersonate: str | None = _DEFAULT_IMPERSONATE,
    user_agent: str = "FortisIntelHub/1.0",
    pool_connections: int = 6,
    pool_maxsize: int = 10,
    max_retries: int = 1,
    timeout: float = 30.0,
) -> object:
    """Return a thread-safe HTTP session proxy.

    Each thread that touches the returned object gets its own underlying
    session (curl_cffi with Chrome TLS impersonation, or requests.Session
    fallback).  The proxy is transparent — callers use ``.get()``,
    ``.post()``, ``.headers``, etc. as normal.
    """
    def _build():
        if HAS_CURL_CFFI and impersonate:
            session = _CffiSession(impersonate=impersonate, timeout=timeout)
            session.headers.update({"User-Agent": user_agent})
            log.debug(
                "Stealth HTTP session created (curl_cffi, impersonate=%s) [tid=%s]",
                impersonate, threading.current_thread().name,
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
        log.debug(
            "Standard HTTP session created (requests) [tid=%s]",
            threading.current_thread().name,
        )
        return session

    log.info(
        "HTTP session factory ready (backend=%s)",
        "curl_cffi" if (HAS_CURL_CFFI and impersonate) else "requests",
    )
    return _ThreadLocalSession(_build)
