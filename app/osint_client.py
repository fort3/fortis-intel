"""Main OSINT aggregator client for Fortis Intelligence Hub."""

import logging
import os
import re as _re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

_IS_WIN32 = sys.platform == "win32"


def _win32_thread_init():
    """Initialize COM on Windows worker threads so libcurl/Schannel TLS cleanup works."""
    if _IS_WIN32:
        try:
            import ctypes
            ctypes.windll.ole32.CoInitializeEx(0, 0x2)  # COINIT_MULTITHREADED
        except Exception:
            pass

from app.constants import SOCIAL_PLATFORMS
from app.http_client import create_session
from app.source_reliability import (
    tag_profile_reliability,
    tag_post_reliability,
    tag_web_mention_reliability,
    tag_entity_reliability,
    get_source_reliability,
)

log = logging.getLogger(__name__)


@dataclass
class SocialProfile:
    platform: str = ""
    user_id: str = ""
    username: str = ""
    display_name: str = ""
    bio: str = ""
    url: str = ""
    followers: int = 0
    following: int = 0
    post_count: int = 0
    created_at: str | None = None
    last_active: str | None = None
    verified: bool = False
    profile_image_url: str = ""
    geo_data: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    source_reliability: dict[str, Any] = field(default_factory=dict)


@dataclass
class SocialPost:
    platform: str = ""
    post_id: str = ""
    author_id: str = ""
    author_username: str = ""
    content: str = ""
    url: str = ""
    timestamp: str = ""
    likes: int = 0
    shares: int = 0
    replies: int = 0
    media_urls: list[str] = field(default_factory=list)
    hashtags: list[str] = field(default_factory=list)
    mentions: list[str] = field(default_factory=list)
    geo_data: dict[str, Any] = field(default_factory=dict)
    language: str = ""
    sentiment: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    source_reliability: dict[str, Any] = field(default_factory=dict)


@dataclass
class WebMention:
    source_url: str = ""
    source_title: str = ""
    snippet: str = ""
    discovered_at: str = ""
    domain: str = ""
    mention_type: str = ""
    relevance_score: float = 0.0
    raw: dict[str, Any] = field(default_factory=dict)
    source_reliability: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnrichedEntity:
    entity_type: str = ""
    entity_value: str = ""
    original_context: str = ""
    profiles: list[SocialProfile] = field(default_factory=list)
    posts: list[SocialPost] = field(default_factory=list)
    web_mentions: list[WebMention] = field(default_factory=list)
    geo_points: list[dict[str, Any]] = field(default_factory=list)
    risk_indicators: list[str] = field(default_factory=list)
    confidence: float = 0.0
    enrichment_sources: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    source_reliability: dict[str, Any] = field(default_factory=dict)


@dataclass
class OSINTFindings:
    identifier: str = ""
    identifier_type: str = ""
    subject_id: str = ""
    depth: str = "standard"
    timestamp: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    collection_timestamp: str = field(default_factory=lambda: datetime.now(tz=timezone.utc).isoformat())
    profiles: list[SocialProfile] = field(default_factory=list)
    posts: list[SocialPost] = field(default_factory=list)
    web_mentions: list[WebMention] = field(default_factory=list)
    geo_points: list[dict[str, Any]] = field(default_factory=list)
    entities: list[EnrichedEntity] = field(default_factory=list)
    entity_graph: dict[str, Any] = field(default_factory=dict)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    platforms_queried: list[str] = field(default_factory=list)
    source_count: int = 0
    errors: list[str] = field(default_factory=list)
    sensitivity_level: str = "INTERNAL"


class OSINTClient:
    """Main OSINT aggregator that orchestrates social, geo, and web modules."""

    def __init__(self):
        self._platform_config = SOCIAL_PLATFORMS

        from app.social_client import SocialClient
        from app.web_scraper import WebScraper
        from app.metadata_extractor import MetadataExtractor

        self._social = SocialClient()
        self._scraper = WebScraper()
        self._extractor = MetadataExtractor()

        self._video_geo = None
        try:
            from app.video_geo import VideoGeoExtractor, HAS_CV2
            if HAS_CV2:
                self._video_geo = VideoGeoExtractor()
                log.info("VideoGeoExtractor loaded (OpenCV available)")
            else:
                log.info("VideoGeoExtractor skipped — OpenCV not installed")
        except ImportError:
            log.info("VideoGeoExtractor not available")

        self._geo_client = None
        try:
            from app.geo_client import GeoClient
            self._geo_client = GeoClient()
        except ImportError:
            log.info("GeoClient not available for NLP geocoding")

        self._http = create_session(pool_connections=4, pool_maxsize=6)

        log.info("OSINTClient initialised — social, web, metadata modules loaded")

    _DOMAIN_RE = _re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    _IP_RE = _re.compile(
        r"^(?:\d{1,3}\.){3}\d{1,3}$"
        r"|^[0-9a-fA-F:]{3,39}$"
    )

    def _classify_identifier(self, identifier: str) -> str:
        stripped = identifier.strip()
        if self._IP_RE.match(stripped):
            return "ip"
        if self._DOMAIN_RE.match(stripped):
            return "domain"
        if stripped.startswith("http://") or stripped.startswith("https://"):
            return "url"
        return "username"

    def investigate(
        self,
        identifier: str,
        platforms: list[str] | None = None,
        depth: str = "standard",
    ) -> OSINTFindings:
        """Run a full-spectrum OSINT investigation on *identifier*."""
        resolved_platforms = platforms or list(self._platform_config.keys())
        id_type = self._classify_identifier(identifier)
        findings = OSINTFindings(
            identifier=identifier,
            identifier_type=id_type,
            subject_id=identifier,
            depth=depth,
            platforms_queried=resolved_platforms,
        )

        tasks = {}
        workers = 2 if _IS_WIN32 else 4
        with ThreadPoolExecutor(
            max_workers=workers,
            initializer=_win32_thread_init if _IS_WIN32 else None,
        ) as executor:
            tasks["profiles"] = executor.submit(
                self._collect_profiles, identifier, resolved_platforms
            )
            tasks["content"] = executor.submit(
                self._collect_content, identifier, resolved_platforms
            )
            if depth in ("standard", "deep"):
                tasks["web"] = executor.submit(
                    self._collect_web_mentions, identifier
                )
            if depth == "deep":
                tasks["news"] = executor.submit(
                    self._collect_news, identifier
                )

            for key, future in tasks.items():
                try:
                    result = future.result(timeout=90)
                    if key == "profiles":
                        findings.profiles = result
                    elif key == "content":
                        findings.posts = result
                    elif key == "web":
                        findings.web_mentions.extend(result)
                    elif key == "news":
                        findings.web_mentions.extend(result)
                except Exception as exc:
                    log.error("OSINT task %s failed: %s", key, exc)
                    findings.errors.append(f"{key}: {str(exc)[:200]}")

        if id_type in ("domain", "url"):
            domain = identifier
            if id_type == "url":
                from urllib.parse import urlparse
                domain = urlparse(identifier).netloc or identifier
            try:
                whois_data = self._scraper.whois_lookup(domain)
                dns_data = self._scraper.dns_lookup(domain)
                dnsdumpster = self._scraper.dnsdumpster_lookup(domain)
                http_headers = self._scraper.http_headers_lookup(domain)
                findings.metadata["domain_intel"] = {
                    "domain": domain,
                    "whois": whois_data,
                    "dns": dns_data,
                    "dnsdumpster": dnsdumpster,
                    "http_headers": http_headers,
                }
                enrichment_sources = ["whois", "dns", "dnsdumpster"]
                findings.entities.append(EnrichedEntity(
                    entity_type="domain",
                    entity_value=domain,
                    confidence=0.95,
                    enrichment_sources=enrichment_sources,
                    raw={"whois": whois_data, "dns": dns_data, "dnsdumpster": dnsdumpster},
                ))
                for sub in dnsdumpster.get("subdomains", []):
                    sub_host = sub.get("hostname", "")
                    if sub_host and sub_host != domain:
                        findings.entities.append(EnrichedEntity(
                            entity_type="subdomain",
                            entity_value=sub_host,
                            confidence=0.85,
                            enrichment_sources=["dnsdumpster"],
                            raw={"ip": sub.get("ip", "")},
                        ))
                a_records = dns_data.get("A", [])
                all_ips = set(a_records)
                for sub in dnsdumpster.get("subdomains", []):
                    sub_ip = sub.get("ip", "")
                    if sub_ip:
                        all_ips.add(sub_ip)
                if self._geo_client:
                    for ip in list(all_ips)[:6]:
                        geo_pt = self._geo_client.ip_geolocate(ip)
                        if geo_pt:
                            label_host = domain
                            for sub in dnsdumpster.get("subdomains", []):
                                if sub.get("ip") == ip:
                                    label_host = sub.get("hostname", domain)
                                    break
                            findings.geo_points.append({
                                "lat": geo_pt.lat,
                                "lon": geo_pt.lon,
                                "label": f"{label_host} → {ip} ({geo_pt.label})",
                                "source": "domain_ip_geolocation",
                                "confidence": 0.65,
                            })
                log.info("Domain intel collected for %r: registrar=%s, A=%s, subdomains=%d",
                         domain, whois_data.get("registrar", "?"), a_records,
                         len(dnsdumpster.get("subdomains", [])))
            except Exception as exc:
                log.error("Domain/IP intel failed for %r: %s", domain, exc)
                findings.errors.append(f"domain_intel: {str(exc)[:200]}")

        if id_type == "ip":
            try:
                if self._geo_client:
                    geo_pt = self._geo_client.ip_geolocate(identifier)
                    if geo_pt:
                        findings.geo_points.append({
                            "lat": geo_pt.lat,
                            "lon": geo_pt.lon,
                            "label": f"IP {identifier} ({geo_pt.label})",
                            "source": "ip_geolocation",
                            "confidence": geo_pt.confidence,
                        })
                        findings.metadata["ip_geolocation"] = geo_pt.raw
                reverse_dns = self._scraper.reverse_dns_lookup(identifier)
                co_hosted = self._scraper.reverse_ip_lookup(identifier)
                findings.metadata["ip_intel"] = {
                    "ip": identifier,
                    "reverse_dns": reverse_dns,
                    "co_hosted_domains": co_hosted[:50],
                    "co_hosted_count": len(co_hosted),
                }
                if reverse_dns:
                    findings.entities.append(EnrichedEntity(
                        entity_type="hostname",
                        entity_value=reverse_dns,
                        confidence=0.9,
                        enrichment_sources=["reverse_dns"],
                    ))
                for d in co_hosted[:10]:
                    findings.entities.append(EnrichedEntity(
                        entity_type="co_hosted_domain",
                        entity_value=d,
                        confidence=0.8,
                        enrichment_sources=["reverse_ip"],
                    ))
                hostname = reverse_dns or None
                if not hostname:
                    try:
                        import socket
                        hostname = socket.getfqdn(identifier)
                        if hostname == identifier:
                            hostname = None
                    except Exception:
                        pass
                if hostname:
                    whois_data = self._scraper.whois_lookup(hostname)
                    dns_data = self._scraper.dns_lookup(hostname)
                    dnsdumpster = self._scraper.dnsdumpster_lookup(hostname)
                    findings.metadata["ip_reverse"] = {
                        "hostname": hostname,
                        "whois": whois_data,
                        "dns": dns_data,
                        "dnsdumpster": dnsdumpster,
                    }
                findings.entities.append(EnrichedEntity(
                    entity_type="ip",
                    entity_value=identifier,
                    confidence=0.95,
                    enrichment_sources=["ip_geolocation", "reverse_dns", "reverse_ip"],
                ))
                log.info("IP intel collected for %r: reverse_dns=%s, co_hosted=%d",
                         identifier, reverse_dns or "none", len(co_hosted))
            except Exception as exc:
                log.error("IP intel failed for %r: %s", identifier, exc)
                findings.errors.append(f"ip_intel: {str(exc)[:200]}")

        findings.geo_points.extend(self._extract_geo(findings.posts))
        findings.geo_points.extend(self._extract_media_geo(findings.posts))
        findings.geo_points.extend(self._extract_video_geo(findings.posts))

        if findings.posts:
            posting_times = [
                p.timestamp for p in findings.posts if p.timestamp
            ]
            if posting_times:
                tz_info = self._extractor.infer_timezone(posting_times)
                findings.metadata["inferred_timezone"] = tz_info

        all_text = self._gather_text(findings)
        if all_text:
            lang_info = self._extractor.detect_language_region([all_text[:5000]])
            findings.metadata["language"] = lang_info

            detected_lang = lang_info.get("language", "") if lang_info else ""
            entities_raw = self._extractor.extract_entities_nlp(
                all_text[:10000], detected_language=detected_lang,
            )
            seen = set()
            for ent in entities_raw:
                key = (ent.get("type", ""), ent.get("value", ""))
                if key not in seen and ent.get("type") in (
                    "PERSON", "ORG", "GPE", "LOC", "NORP", "FAC", "EVENT"
                ):
                    seen.add(key)
                    findings.entities.append(
                        EnrichedEntity(
                            entity_type=ent["type"],
                            entity_value=ent["value"],
                            confidence=ent.get("confidence", 0.5),
                            enrichment_sources=["nlp"],
                        )
                    )

        findings.geo_points.extend(
            self._geocode_entity_locations(findings.entities)
        )

        findings.timeline = self._build_timeline(findings)
        findings.sensitivity_level = self._assess_sensitivity(findings)

        findings.source_count = sum(1 for p in resolved_platforms
                                    if any(pr.platform == p for pr in findings.profiles)
                                    or any(po.platform == p for po in findings.posts))

        # ── Source reliability tagging (NATO Admiralty system) ─────
        self._tag_reliability(findings)

        try:
            from app.intel_graph import build_entity_graph, graph_to_cytoscape_json
            entities_data = [asdict(e) for e in findings.entities]
            normalized = []
            for e in entities_data:
                ne = dict(e)
                if "entity_type" in ne and "type" not in ne:
                    ne["type"] = ne["entity_type"]
                if "entity_value" in ne and "name" not in ne:
                    ne["name"] = ne["entity_value"]
                normalized.append(ne)
            if normalized:
                g = build_entity_graph(normalized)
                findings.entity_graph = graph_to_cytoscape_json(g)
        except Exception as exc:
            log.error("Entity graph construction failed: %s", exc)

        return findings

    def enrich_entities(
        self,
        entities: list[dict[str, Any]],
    ) -> list[EnrichedEntity]:
        """Enrich extracted entities with OSINT data."""
        results: list[EnrichedEntity] = []
        for entity in entities:
            etype = entity.get("entity_type", "unknown")
            evalue = entity.get("entity_value", "")
            enriched = EnrichedEntity(
                entity_type=etype,
                entity_value=evalue,
                original_context=entity.get("context", ""),
            )

            try:
                if etype in ("PERSON", "username"):
                    profiles = self._social.search_username(evalue)
                    enriched.profiles = [self._dict_to_profile(p) for p in profiles]
                    enriched.enrichment_sources.append("social_search")

                if etype in ("ORG", "PERSON", "GPE", "keyword"):
                    news = self._scraper.fetch_news(evalue)
                    enriched.web_mentions = [
                        WebMention(
                            source_url=a.get("url", ""),
                            source_title=a.get("title", ""),
                            snippet=a.get("snippet", ""),
                            published=a.get("published", ""),
                            domain=a.get("source", ""),
                            mention_type="news",
                        )
                        for a in news[:10]
                    ]
                    enriched.enrichment_sources.append("news")

                if etype == "domain":
                    whois_data = self._scraper.whois_lookup(evalue)
                    dns_data = self._scraper.dns_lookup(evalue)
                    dnsdumpster = self._scraper.dnsdumpster_lookup(evalue)
                    enriched.raw = {
                        "whois": whois_data,
                        "dns": dns_data,
                        "dnsdumpster": dnsdumpster,
                    }
                    enriched.enrichment_sources.append("domain_intel")
                    enriched.enrichment_sources.append("dnsdumpster")

                if etype == "ip":
                    reverse_dns = self._scraper.reverse_dns_lookup(evalue)
                    co_hosted = self._scraper.reverse_ip_lookup(evalue)
                    enriched.raw = {
                        "reverse_dns": reverse_dns,
                        "co_hosted_domains": co_hosted[:20],
                    }
                    if self._geo_client:
                        geo_pt = self._geo_client.ip_geolocate(evalue)
                        if geo_pt:
                            enriched.geo_points.append({
                                "lat": geo_pt.lat,
                                "lon": geo_pt.lon,
                                "label": f"{evalue} ({geo_pt.label})",
                                "source": "ip_geolocation",
                                "confidence": geo_pt.confidence,
                            })
                    enriched.enrichment_sources.append("ip_intel")

                enriched.confidence = 0.5 + 0.1 * len(enriched.enrichment_sources)

            except Exception as exc:
                log.error("Entity enrichment failed for %s=%s: %s", etype, evalue, exc)

            results.append(enriched)
        return results

    def search(
        self,
        query: str,
        sources: list[str] | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        """General OSINT search across configured sources."""
        results: list[dict[str, Any]] = []
        search_sources = sources or ["social", "news"]

        if "social" in search_sources:
            try:
                posts = self._social.search_content(
                    query, date_from=date_from, date_to=date_to
                )
                for post in posts:
                    results.append({
                        "type": "social_post",
                        "source": post.get("platform", "unknown"),
                        **post,
                    })
            except Exception as exc:
                log.error("Social search failed: %s", exc)

        if "news" in search_sources:
            try:
                articles = self._scraper.fetch_news(
                    query, date_from=date_from, date_to=date_to
                )
                for article in articles:
                    results.append({
                        "type": "news_article",
                        "source": article.get("source", "unknown"),
                        **article,
                    })
            except Exception as exc:
                log.error("News search failed: %s", exc)

        return results

    def is_configured(self) -> dict[str, bool]:
        """Check which platforms have the required environment variables set."""
        status: dict[str, bool] = {}
        for platform_key, cfg in self._platform_config.items():
            if "env_key" in cfg:
                status[platform_key] = bool(os.getenv(cfg["env_key"], "").strip())
            elif "env_keys" in cfg:
                status[platform_key] = all(
                    bool(os.getenv(k, "").strip()) for k in cfg["env_keys"]
                )
            else:
                status[platform_key] = False
        return status

    def _collect_profiles(
        self, identifier: str, platforms: list[str]
    ) -> list[SocialProfile]:
        raw_profiles = self._social.search_username(identifier, platforms=platforms)
        return [self._dict_to_profile(p) for p in raw_profiles]

    def _collect_content(
        self, identifier: str, platforms: list[str]
    ) -> list[SocialPost]:
        raw_posts = self._social.search_content(identifier, platforms=platforms)
        return [self._dict_to_post(p) for p in raw_posts]

    def _collect_web_mentions(self, identifier: str) -> list[WebMention]:
        mentions: list[WebMention] = []
        try:
            news = self._scraper.fetch_news(identifier)
            for article in news[:20]:
                mentions.append(WebMention(
                    source_url=article.get("url", ""),
                    source_title=article.get("title", ""),
                    snippet=article.get("snippet", ""),
                    discovered_at=article.get("published", ""),
                    domain=article.get("source", ""),
                    mention_type="news",
                ))
        except Exception as exc:
            log.error("Web mention collection failed: %s", exc)
        return mentions

    def _collect_news(self, identifier: str) -> list[WebMention]:
        try:
            news = self._scraper.fetch_news(identifier)
            return [
                WebMention(
                    source_url=a.get("url", ""),
                    source_title=a.get("title", ""),
                    snippet=a.get("snippet", ""),
                    discovered_at=a.get("published", ""),
                    domain=a.get("source", ""),
                    mention_type="news_deep",
                )
                for a in news[20:40]
            ]
        except Exception as exc:
            log.error("Deep news collection failed: %s", exc)
            return []

    def _extract_geo(self, posts: list[SocialPost]) -> list[dict[str, Any]]:
        geo_points: list[dict[str, Any]] = []
        post_dicts = []
        for p in posts:
            if not p.geo_data:
                continue
            d = asdict(p)
            d["geo"] = d.pop("geo_data", None)
            post_dicts.append(d)
        extracted = self._social.extract_geotags(post_dicts)
        for gp in extracted:
            if gp.get("lat") is not None and gp.get("lon") is not None:
                geo_points.append(gp)
        return geo_points

    _IMAGE_EXT_RE = _re.compile(r"\.(jpe?g|png|tiff?|webp|heic)(\?.*)?$", _re.I)
    _MAX_MEDIA_DOWNLOAD = 50
    _MEDIA_DOWNLOAD_TIMEOUT = 10

    # Platforms that strip EXIF/GPS metadata on upload — downloading their
    # images for EXIF extraction is wasteful.  Only attempt EXIF on media
    # from non-platform sources (blogs, forums, paste sites, dork results).
    _EXIF_STRIP_PLATFORMS = {
        "twitter", "reddit", "instagram", "facebook",
        "tiktok", "youtube", "mastodon", "telegram",
    }

    def _extract_media_geo(self, posts: list[SocialPost]) -> list[dict[str, Any]]:
        """Download images from posts' media_urls and extract EXIF GPS.

        Skips images from major social platforms (they strip EXIF metadata).
        Only attempts extraction on media from non-platform sources like
        blogs, forums, and web mentions where EXIF may still be intact.
        """
        image_urls: list[tuple[str, str]] = []
        skipped_platform = 0
        for p in posts:
            for url in (p.media_urls or []):
                if not url or not url.startswith("http"):
                    continue
                if p.platform.lower() in self._EXIF_STRIP_PLATFORMS:
                    skipped_platform += 1
                    continue
                if self._IMAGE_EXT_RE.search(url) or "/photo/" in url:
                    image_urls.append((url, p.platform))
                if len(image_urls) >= self._MAX_MEDIA_DOWNLOAD:
                    break
            if len(image_urls) >= self._MAX_MEDIA_DOWNLOAD:
                break

        if skipped_platform:
            log.info(
                "Skipped %d platform-hosted images (EXIF stripped by platform)",
                skipped_platform,
            )

        if not image_urls:
            return []

        log.info("Downloading %d media URLs for EXIF geo extraction", len(image_urls))
        image_bytes_list: list[bytes] = []
        url_metadata: list[dict[str, str]] = []

        for url, platform in image_urls:
            try:
                resp = self._http.get(url, timeout=self._MEDIA_DOWNLOAD_TIMEOUT, stream=True)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("Content-Type", "")
                if "image" not in ct and "octet-stream" not in ct:
                    continue
                data = resp.content
                if len(data) < 100:
                    continue
                # Cap at 20 MB per image
                if len(data) > 20 * 1024 * 1024:
                    continue
                image_bytes_list.append(data)
                url_metadata.append({"url": url, "platform": platform})
            except Exception as exc:
                log.debug("Failed to download media %s: %s", url[:80], exc)

        if not image_bytes_list:
            return []

        geo_results = self._extractor.extract_geo_from_images(image_bytes_list)

        for i, gp in enumerate(geo_results):
            if i < len(url_metadata):
                gp["media_url"] = url_metadata[i]["url"]
                gp["platform"] = url_metadata[i]["platform"]
                gp["source"] = "exif"
                gp.setdefault("confidence", 0.95)

        log.info("Extracted %d EXIF geo points from %d downloaded images",
                 len(geo_results), len(image_bytes_list))
        return geo_results

    _VIDEO_EXT_RE = _re.compile(
        r"\.(mp4|avi|mov|mkv|webm|flv|wmv|m4v|3gp)(\?.*)?$", _re.I
    )
    _VIDEO_URL_HINTS = ("/video/", "/videos/", ".mp4", ".webm")

    def _extract_video_geo(self, posts: list[SocialPost]) -> list[dict[str, Any]]:
        """Extract geo signals from video URLs in posts.

        Skips videos from major social platforms (they strip metadata
        and transcode uploads). Only processes non-platform video sources.
        """
        if self._video_geo is None:
            return []

        video_urls: list[tuple[str, str]] = []
        for p in posts:
            if p.platform.lower() in self._EXIF_STRIP_PLATFORMS:
                continue
            for url in (p.media_urls or []):
                if not url or not url.startswith("http"):
                    continue
                if self._VIDEO_EXT_RE.search(url) or any(
                    h in url.lower() for h in self._VIDEO_URL_HINTS
                ):
                    video_urls.append((url, p.platform))
                if len(video_urls) >= 10:
                    break
            if len(video_urls) >= 10:
                break

        if not video_urls:
            return []

        log.info("Processing %d video URLs for geo extraction", len(video_urls))
        try:
            return self._video_geo.extract_from_urls(video_urls)
        except Exception as exc:
            log.error("Video geo extraction failed: %s", exc)
            return []

    def extract_geo_from_uploaded_media(
        self, file_bytes_list: list[tuple[bytes, str]],
    ) -> list[dict[str, Any]]:
        """Extract EXIF GPS from user-uploaded media files.

        Unlike platform-hosted media, user uploads may still contain
        original EXIF metadata including GPS coordinates.

        Args:
            file_bytes_list: List of (file_bytes, filename) tuples.

        Returns:
            List of geo point dicts with source='exif_upload'.
        """
        image_bytes = []
        video_paths: list[tuple[str, str]] = []
        filenames: list[str] = []

        for data, filename in file_bytes_list:
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext in ("jpg", "jpeg", "png", "tiff", "tif", "webp", "heic"):
                image_bytes.append(data)
                filenames.append(filename)
            elif ext in ("mp4", "avi", "mov", "mkv", "webm", "flv", "m4v"):
                if self._video_geo is not None:
                    import tempfile
                    tmp = tempfile.NamedTemporaryFile(
                        suffix=f".{ext}", delete=False,
                    )
                    tmp.write(data)
                    tmp.close()
                    video_paths.append((tmp.name, filename))

        geo_points: list[dict[str, Any]] = []

        if image_bytes:
            results = self._extractor.extract_geo_from_images(image_bytes)
            for i, gp in enumerate(results):
                gp["source"] = "exif_upload"
                gp["media_url"] = filenames[i] if i < len(filenames) else "upload"
                gp["platform"] = "user_upload"
                gp.setdefault("confidence", 0.95)
                geo_points.append(gp)
            log.info(
                "Extracted %d EXIF geo points from %d uploaded images",
                len(results), len(image_bytes),
            )

        if video_paths and self._video_geo is not None:
            try:
                video_results = self._video_geo.extract_from_urls(video_paths)
                for vp in video_results:
                    vp["platform"] = "user_upload"
                geo_points.extend(video_results)
            except Exception as exc:
                log.error("Uploaded video geo extraction failed: %s", exc)
            finally:
                import os as _os
                for path, _ in video_paths:
                    try:
                        _os.unlink(path)
                    except OSError:
                        pass

        return geo_points

    def _geocode_entity_locations(
        self, entities: list[EnrichedEntity]
    ) -> list[dict[str, Any]]:
        """Geocode GPE/LOC entities from NLP extraction into geo points."""
        if self._geo_client is None:
            return []

        location_ents: list[tuple[str, float]] = []
        for ent in entities:
            if ent.entity_type in ("GPE", "LOC") and ent.entity_value:
                location_ents.append((ent.entity_value, ent.confidence))

        if not location_ents:
            return []

        log.info("Geocoding %d NLP-extracted location entities", len(location_ents))
        geo_points: list[dict[str, Any]] = []
        seen: set[str] = set()

        for loc_name, nlp_conf in location_ents[:20]:
            try:
                point = self._geo_client.geocode(loc_name)
                if point is None:
                    continue
                loc_key = f"{point.lat:.4f},{point.lon:.4f}"
                if loc_key in seen:
                    continue
                seen.add(loc_key)
                geo_points.append({
                    "lat": point.lat,
                    "lon": point.lon,
                    "label": loc_name,
                    "source": "nlp_mention",
                    "confidence": round(nlp_conf * 0.85, 2),
                    "method": "nlp_entity_geocode",
                })
            except Exception as exc:
                log.debug("Failed to geocode entity %r: %s", loc_name, exc)

        log.info("Geocoded %d/%d location entities", len(geo_points), len(location_ents))
        return geo_points

    def _tag_reliability(self, findings: OSINTFindings) -> None:
        """Tag all findings with NATO Admiralty reliability grades."""
        # Build a lookup of verified status & followers per platform/username
        profile_meta: dict[str, dict] = {}
        for p in findings.profiles:
            key = f"{p.platform}:{p.username}".lower()
            profile_meta[key] = {
                "verified": p.verified,
                "followers": p.followers,
                "created_at": p.created_at,
            }

        # Tag profiles
        for p in findings.profiles:
            p.source_reliability = tag_profile_reliability(
                platform=p.platform,
                verified=p.verified,
                followers=p.followers,
                created_at=p.created_at,
            )

        # Tag posts (check if author has a known profile for verification status)
        for post in findings.posts:
            author_key = f"{post.platform}:{post.author_username}".lower()
            author_meta = profile_meta.get(author_key, {})
            post.source_reliability = tag_post_reliability(
                platform=post.platform,
                author_verified=author_meta.get("verified", False),
                author_followers=author_meta.get("followers", 0),
            )

        # Tag web mentions
        for wm in findings.web_mentions:
            wm.source_reliability = tag_web_mention_reliability(
                mention_type=wm.mention_type,
                domain=wm.domain,
            )

        # Tag entities
        for ent in findings.entities:
            ent.source_reliability = tag_entity_reliability(
                enrichment_sources=ent.enrichment_sources,
            )

        # Tag domain/IP intel metadata
        domain_intel = findings.metadata.get("domain_intel", {})
        if domain_intel:
            findings.metadata.setdefault("domain_intel_reliability", {})
            for key in ("whois", "dns"):
                if domain_intel.get(key):
                    findings.metadata["domain_intel_reliability"][key] = (
                        get_source_reliability(key)
                    )

        ip_intel = findings.metadata.get("ip_intel", {})
        if ip_intel:
            findings.metadata["ip_intel_reliability"] = get_source_reliability("dns")

        log.info(
            "Reliability tagged: %d profiles, %d posts, %d web mentions, %d entities",
            len(findings.profiles), len(findings.posts),
            len(findings.web_mentions), len(findings.entities),
        )

    def _gather_text(self, findings: OSINTFindings) -> str:
        parts: list[str] = []
        for p in findings.profiles:
            if p.bio:
                parts.append(p.bio)
        for post in findings.posts[:50]:
            if post.content:
                parts.append(post.content)
        for wm in findings.web_mentions[:20]:
            if wm.snippet:
                parts.append(wm.snippet)
        return "\n".join(parts)

    def _build_timeline(self, findings: OSINTFindings) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for post in findings.posts:
            if post.timestamp:
                events.append({
                    "timestamp": post.timestamp,
                    "type": "post",
                    "platform": post.platform,
                    "content": post.content[:100],
                    "url": post.url,
                })
        for wm in findings.web_mentions:
            if wm.discovered_at:
                events.append({
                    "timestamp": wm.discovered_at,
                    "type": "web_mention",
                    "platform": wm.domain,
                    "content": wm.snippet[:100],
                    "url": wm.source_url,
                })
        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return events[:100]

    def _assess_sensitivity(self, findings: OSINTFindings) -> str:
        has_geo = len(findings.geo_points) > 0
        has_pii = any(
            e.entity_type in ("PERSON", "GPE", "LOC")
            for e in findings.entities
        )
        profile_count = len(findings.profiles)

        if has_geo and has_pii:
            return "RESTRICTED"
        if has_pii or profile_count > 3:
            return "INTERNAL"
        if profile_count == 0 and not findings.posts:
            return "PUBLIC"
        return "INTERNAL"

    @staticmethod
    def _dict_to_profile(d: dict[str, Any]) -> SocialProfile:
        return SocialProfile(
            platform=d.get("platform", ""),
            user_id=str(d.get("user_id", "")),
            username=d.get("username", ""),
            display_name=d.get("display_name", ""),
            bio=d.get("bio", ""),
            url=d.get("url", ""),
            followers=d.get("followers", 0) or 0,
            following=d.get("following", 0) or 0,
            post_count=d.get("post_count", 0) or 0,
            created_at=d.get("created_at"),
            verified=d.get("verified", False),
            profile_image_url=d.get("profile_image_url", ""),
        )

    @staticmethod
    def _dict_to_post(d: dict[str, Any]) -> SocialPost:
        return SocialPost(
            platform=d.get("platform", ""),
            post_id=str(d.get("post_id", "")),
            author_id=str(d.get("author_id", "")),
            author_username=d.get("author_username", ""),
            content=d.get("content", ""),
            url=d.get("url", ""),
            timestamp=d.get("timestamp", ""),
            likes=d.get("likes", 0) or 0,
            shares=d.get("shares", 0) or 0,
            replies=d.get("replies", 0) or 0,
            hashtags=d.get("hashtags", []),
            mentions=d.get("mentions", []),
            media_urls=d.get("media_urls", []),
            geo_data=d.get("geo") or d.get("geo_data") or {},
        )
