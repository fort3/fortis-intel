"""Wayback Machine CDX API client for Fortis Intelligence Hub.

Provides domain enrichment via archive.org's free CDX Server API:
- Historical snapshots timeline
- Subdomain discovery from archived URLs
- Deleted/changed page detection via digest comparison
- robots.txt history

Rate limit: 1 request per 2 seconds (archive.org policy).
No API key required.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from app.http_client import create_session

log = logging.getLogger(__name__)

CDX_BASE = "https://web.archive.org/cdx/search/cdx"
WAYBACK_URL = "https://web.archive.org/web"
_RATE_LIMIT_INTERVAL = 2.0
_DEFAULT_TIMEOUT = 20.0
_MAX_RESULTS = 500


@dataclass
class WaybackSnapshot:
    url: str
    timestamp: str
    status_code: str
    digest: str
    mime_type: str
    original_url: str
    archive_url: str = ""

    @property
    def datetime(self) -> datetime | None:
        try:
            return datetime.strptime(self.timestamp, "%Y%m%d%H%M%S")
        except (ValueError, TypeError):
            return None

    @property
    def date_str(self) -> str:
        dt = self.datetime
        return dt.strftime("%Y-%m-%d") if dt else self.timestamp[:8]


@dataclass
class WaybackDomainReport:
    domain: str
    total_snapshots: int = 0
    first_seen: str = ""
    last_seen: str = ""
    subdomains: list[str] = field(default_factory=list)
    snapshots: list[WaybackSnapshot] = field(default_factory=list)
    content_changes: list[dict] = field(default_factory=list)
    robots_history: list[WaybackSnapshot] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class WaybackClient:
    """Client for the Wayback Machine CDX Server API."""

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT):
        self._session = create_session(
            impersonate=None,
            user_agent="FortisIntelHub/1.0 (OSINT research)",
            timeout=timeout,
        )
        self._last_request_time = 0.0

    def _rate_limit(self):
        elapsed = time.time() - self._last_request_time
        if elapsed < _RATE_LIMIT_INTERVAL:
            time.sleep(_RATE_LIMIT_INTERVAL - elapsed)
        self._last_request_time = time.time()

    def _cdx_query(self, **params) -> list[list[str]]:
        """Execute a CDX API query and return parsed rows."""
        params.setdefault("output", "json")
        params.setdefault("limit", _MAX_RESULTS)

        self._rate_limit()
        try:
            resp = self._session.get(CDX_BASE, params=params, timeout=_DEFAULT_TIMEOUT)
            if resp.status_code == 429:
                log.warning("Wayback CDX rate limited, backing off 5s")
                time.sleep(5)
                resp = self._session.get(CDX_BASE, params=params, timeout=_DEFAULT_TIMEOUT)

            if resp.status_code != 200:
                log.warning("Wayback CDX returned %d", resp.status_code)
                return []

            data = resp.json()
            if not data or len(data) < 2:
                return []
            return data[1:]
        except Exception as exc:
            log.warning("Wayback CDX query failed: %s", exc)
            return []

    def get_domain_snapshots(self, domain: str, limit: int = 100) -> list[WaybackSnapshot]:
        """Get historical snapshots for a domain's main page."""
        domain = domain.strip().lower()
        rows = self._cdx_query(
            url=domain,
            matchType="domain",
            fl="timestamp,original,statuscode,digest,mimetype",
            collapse="timestamp:8",
            limit=min(limit, _MAX_RESULTS),
            filter="statuscode:200",
        )

        snapshots = []
        for row in rows:
            if len(row) < 5:
                continue
            ts, original, status, digest, mime = row[:5]
            snapshots.append(WaybackSnapshot(
                url=original,
                timestamp=ts,
                status_code=status,
                digest=digest,
                mime_type=mime,
                original_url=original,
                archive_url=f"{WAYBACK_URL}/{ts}/{original}",
            ))
        return snapshots

    def discover_subdomains(self, domain: str) -> list[str]:
        """Discover subdomains via archived URL patterns."""
        domain = domain.strip().lower()
        rows = self._cdx_query(
            url=f"*.{domain}",
            matchType="domain",
            fl="original",
            collapse="urlkey",
            limit=_MAX_RESULTS,
            filter="statuscode:200",
        )

        subdomains = set()
        for row in rows:
            if not row:
                continue
            url = row[0] if isinstance(row, list) else str(row)
            try:
                parsed = urlparse(url if "://" in url else f"https://{url}")
                host = parsed.hostname or ""
                if host and host.endswith(f".{domain}") and host != domain:
                    subdomains.add(host)
            except Exception:
                continue

        return sorted(subdomains)

    def detect_content_changes(self, url: str, limit: int = 50) -> list[dict]:
        """Detect content changes by comparing digests across snapshots."""
        rows = self._cdx_query(
            url=url,
            fl="timestamp,digest,statuscode",
            limit=min(limit, _MAX_RESULTS),
            filter="statuscode:200",
        )

        changes = []
        prev_digest = None
        for row in rows:
            if len(row) < 3:
                continue
            ts, digest, status = row[:3]
            if prev_digest and digest != prev_digest:
                snap_dt = None
                try:
                    snap_dt = datetime.strptime(ts, "%Y%m%d%H%M%S")
                except ValueError:
                    pass
                changes.append({
                    "timestamp": ts,
                    "date": snap_dt.strftime("%Y-%m-%d") if snap_dt else ts[:8],
                    "old_digest": prev_digest,
                    "new_digest": digest,
                    "archive_url": f"{WAYBACK_URL}/{ts}/{url}",
                })
            prev_digest = digest

        return changes

    def get_robots_history(self, domain: str) -> list[WaybackSnapshot]:
        """Get historical robots.txt snapshots for a domain."""
        domain = domain.strip().lower()
        robots_url = f"{domain}/robots.txt"
        rows = self._cdx_query(
            url=robots_url,
            fl="timestamp,original,statuscode,digest,mimetype",
            collapse="digest",
            limit=50,
            filter="statuscode:200",
        )

        snapshots = []
        for row in rows:
            if len(row) < 5:
                continue
            ts, original, status, digest, mime = row[:5]
            snapshots.append(WaybackSnapshot(
                url=original,
                timestamp=ts,
                status_code=status,
                digest=digest,
                mime_type=mime,
                original_url=original,
                archive_url=f"{WAYBACK_URL}/{ts}/{original}",
            ))
        return snapshots

    def enrich_domain(self, domain: str) -> WaybackDomainReport:
        """Full domain enrichment via Wayback Machine.

        Runs all enrichment queries with rate limiting between each.
        Returns a structured report with snapshots, subdomains, changes,
        and robots.txt history.
        """
        report = WaybackDomainReport(domain=domain)

        try:
            snapshots = self.get_domain_snapshots(domain, limit=100)
            report.snapshots = snapshots
            report.total_snapshots = len(snapshots)
            if snapshots:
                report.first_seen = snapshots[0].date_str
                report.last_seen = snapshots[-1].date_str
        except Exception as exc:
            report.errors.append(f"Snapshot query failed: {exc}")

        try:
            report.subdomains = self.discover_subdomains(domain)
        except Exception as exc:
            report.errors.append(f"Subdomain discovery failed: {exc}")

        try:
            main_url = f"https://{domain}/"
            report.content_changes = self.detect_content_changes(main_url, limit=30)
        except Exception as exc:
            report.errors.append(f"Content change detection failed: {exc}")

        try:
            report.robots_history = self.get_robots_history(domain)
        except Exception as exc:
            report.errors.append(f"Robots.txt history failed: {exc}")

        return report

    def to_osint_findings(self, report: WaybackDomainReport) -> list[dict]:
        """Convert a WaybackDomainReport into OSINT findings dicts."""
        findings = []

        if report.total_snapshots > 0:
            findings.append({
                "platform": "Wayback Machine",
                "source": "archive.org",
                "type": "domain_history",
                "title": f"Domain Archive: {report.domain}",
                "description": (
                    f"Found {report.total_snapshots} archived snapshots. "
                    f"First seen: {report.first_seen}. "
                    f"Last seen: {report.last_seen}."
                ),
                "confidence": 0.9,
                "data": {
                    "total_snapshots": report.total_snapshots,
                    "first_seen": report.first_seen,
                    "last_seen": report.last_seen,
                    "sample_urls": [
                        s.archive_url for s in report.snapshots[:5]
                    ],
                },
            })

        if report.subdomains:
            findings.append({
                "platform": "Wayback Machine",
                "source": "archive.org",
                "type": "subdomain_discovery",
                "title": f"Archived Subdomains: {report.domain}",
                "description": (
                    f"Discovered {len(report.subdomains)} subdomains via "
                    f"archived URLs: {', '.join(report.subdomains[:10])}"
                    + (f" (+{len(report.subdomains) - 10} more)"
                       if len(report.subdomains) > 10 else "")
                ),
                "confidence": 0.85,
                "data": {"subdomains": report.subdomains},
            })

        if report.content_changes:
            findings.append({
                "platform": "Wayback Machine",
                "source": "archive.org",
                "type": "content_changes",
                "title": f"Content Changes: {report.domain}",
                "description": (
                    f"Detected {len(report.content_changes)} content changes. "
                    f"Most recent change: {report.content_changes[-1]['date']}."
                ),
                "confidence": 0.8,
                "data": {
                    "changes": report.content_changes[:10],
                    "total_changes": len(report.content_changes),
                },
            })

        if report.robots_history:
            findings.append({
                "platform": "Wayback Machine",
                "source": "archive.org",
                "type": "robots_history",
                "title": f"Robots.txt History: {report.domain}",
                "description": (
                    f"Found {len(report.robots_history)} distinct robots.txt "
                    f"versions. May reveal hidden paths or policy changes."
                ),
                "confidence": 0.75,
                "data": {
                    "versions": len(report.robots_history),
                    "archive_urls": [
                        s.archive_url for s in report.robots_history[:5]
                    ],
                },
            })

        return findings


_client: WaybackClient | None = None


def get_wayback_client() -> WaybackClient:
    global _client
    if _client is None:
        _client = WaybackClient()
    return _client
