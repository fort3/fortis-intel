"""Multi-backend web search engine for Fortis Intelligence Hub.

Uses the ``ddgs`` package (or legacy ``duckduckgo-search``) to query
DuckDuckGo, Google, Bing, Brave and others — no API key required.
Rate-limited globally to avoid upstream throttling.
"""

import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

DORK_MAX_QUERIES = int(os.environ.get("DORK_MAX_QUERIES", "20"))
DORK_RATE_PER_MINUTE = int(os.environ.get("DORK_RATE_PER_MINUTE", "20"))
DORK_RATE_PER_HOUR = int(os.environ.get("DORK_RATE_PER_HOUR", "60"))
DORK_SEARCH_REGION = os.environ.get("DORK_SEARCH_REGION", "wt-wt")
DORK_SEARCH_BACKEND = os.environ.get("DORK_SEARCH_BACKEND", "auto")
DORK_SEARCH_TIMEOUT = int(os.environ.get("DORK_SEARCH_TIMEOUT", "30"))

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DorkQuery:
    query: str
    purpose: str
    finding_ref: str
    query_type: str  # "gap_fill" or "validation"


@dataclass
class DorkResult:
    title: str
    url: str
    snippet: str
    source_engine: str = "duckduckgo"


# ---------------------------------------------------------------------------
# Parser — extracts structured dork queries from LLM output
# ---------------------------------------------------------------------------

_DORK_LINE_RE = re.compile(
    r"DORK:\s*(?P<query>.+?)\s*\|\s*PURPOSE:\s*(?P<purpose>.+?)\s*\|\s*(?:FINDING|GAP|TARGET):\s*(?P<ref>.+)",
    re.IGNORECASE,
)


def parse_dork_queries(llm_output: str, query_type: str) -> list[DorkQuery]:
    queries: list[DorkQuery] = []
    for line in llm_output.splitlines():
        m = _DORK_LINE_RE.match(line.strip())
        if m:
            queries.append(DorkQuery(
                query=m.group("query").strip(),
                purpose=m.group("purpose").strip(),
                finding_ref=m.group("ref").strip(),
                query_type=query_type,
            ))
    return queries


# ---------------------------------------------------------------------------
# Scrape-URL parser — extracts URLs flagged for deep scraping by synthesis
# ---------------------------------------------------------------------------

_SCRAPE_LINE_RE = re.compile(
    r"SCRAPE:\s*(?P<url>https?://\S+)\s*\|\s*CONFIDENCE:\s*(?P<conf>HIGH|MODERATE)",
    re.IGNORECASE,
)


@dataclass
class ScrapeCandidate:
    url: str
    confidence: str  # "HIGH" or "MODERATE"


def parse_scrape_candidates(synthesis_output: str) -> list[ScrapeCandidate]:
    candidates: list[ScrapeCandidate] = []
    for line in synthesis_output.splitlines():
        m = _SCRAPE_LINE_RE.match(line.strip())
        if m:
            candidates.append(ScrapeCandidate(
                url=m.group("url").strip(),
                confidence=m.group("conf").strip().upper(),
            ))
    return candidates


# ---------------------------------------------------------------------------
# Sliding-window rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    def __init__(self, per_minute: int, per_hour: int):
        self._per_minute = per_minute
        self._per_hour = per_hour
        self._lock = threading.Lock()
        self._timestamps: list[float] = []

    def acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < 3600]
                recent_minute = sum(1 for t in self._timestamps if now - t < 60)
                if recent_minute < self._per_minute and len(self._timestamps) < self._per_hour:
                    self._timestamps.append(now)
                    return True
            time.sleep(0.5)
        return False


# ---------------------------------------------------------------------------
# DorkSearchClient
# ---------------------------------------------------------------------------

class DorkSearchClient:
    def __init__(self):
        self._limiter = _RateLimiter(DORK_RATE_PER_MINUTE, DORK_RATE_PER_HOUR)

    def search(self, query: str, max_results: int = 10) -> list[DorkResult]:
        if not self._limiter.acquire():
            log.warning("Dork search rate limit exceeded, skipping query: %s", query[:80])
            return []

        try:
            try:
                from ddgs import DDGS
            except ImportError:
                from duckduckgo_search import DDGS

            results: list[DorkResult] = []
            search_kwargs: dict = {
                "keywords": query,
                "region": DORK_SEARCH_REGION,
                "max_results": max_results,
            }
            if DORK_SEARCH_BACKEND != "auto":
                search_kwargs["backend"] = DORK_SEARCH_BACKEND

            ddgs = DDGS(timeout=DORK_SEARCH_TIMEOUT)
            for r in ddgs.text(**search_kwargs):
                results.append(DorkResult(
                    title=r.get("title", ""),
                    url=r.get("href", ""),
                    snippet=r.get("body", ""),
                ))
            log.info("Dork search returned %d results for: %s", len(results), query[:80])
            return results

        except ImportError:
            log.error("ddgs / duckduckgo-search package not installed")
            return []
        except TypeError:
            # Older package version may not support backend/keywords kwargs —
            # fall back to positional call.
            try:
                try:
                    from ddgs import DDGS
                except ImportError:
                    from duckduckgo_search import DDGS
                results = []
                ddgs = DDGS(timeout=DORK_SEARCH_TIMEOUT)
                for r in ddgs.text(query, max_results=max_results):
                    results.append(DorkResult(
                        title=r.get("title", ""),
                        url=r.get("href", ""),
                        snippet=r.get("body", ""),
                    ))
                return results
            except Exception as exc2:
                log.error("Dork search fallback failed for %r: %s", query[:80], exc2)
                return []
        except Exception as exc:
            log.error("Dork search failed for %r: %s", query[:80], exc)
            return []

    def search_batch(
        self,
        queries: list[DorkQuery],
        max_per_query: int = 10,
        delay: float = 0.2,
    ) -> dict[str, list[DorkResult]]:
        capped = queries[:DORK_MAX_QUERIES]
        results: dict[str, list[DorkResult]] = {}
        for i, dq in enumerate(capped):
            results[dq.query] = self.search(dq.query, max_results=max_per_query)
            if i < len(capped) - 1:
                time.sleep(delay)
        return results
