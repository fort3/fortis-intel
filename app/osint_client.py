"""Main OSINT aggregator client for Fortis Intelligence Hub."""

import logging
import os
import re as _re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

import requests as _requests

from app.constants import SOCIAL_PLATFORMS

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
        log.info("OSINTClient initialised — social, web, metadata modules loaded")

    def investigate(
        self,
        identifier: str,
        platforms: list[str] | None = None,
        depth: str = "standard",
    ) -> OSINTFindings:
        """Run a full-spectrum OSINT investigation on *identifier*."""
        resolved_platforms = platforms or list(self._platform_config.keys())
        findings = OSINTFindings(
            identifier=identifier,
            subject_id=identifier,
            depth=depth,
            platforms_queried=resolved_platforms,
        )

        tasks = {}
        with ThreadPoolExecutor(max_workers=4) as executor:
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
                    result = future.result(timeout=30)
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

        findings.geo_points = self._extract_geo(findings.posts)
        findings.geo_points.extend(self._extract_media_geo(findings.posts))

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

            entities_raw = self._extractor.extract_entities_nlp(all_text[:10000])
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
                            confidence=0.7,
                            enrichment_sources=["nlp"],
                        )
                    )

        findings.timeline = self._build_timeline(findings)
        findings.sensitivity_level = self._assess_sensitivity(findings)

        findings.source_count = sum(1 for p in resolved_platforms
                                    if any(pr.platform == p for pr in findings.profiles)
                                    or any(po.platform == p for po in findings.posts))

        try:
            from app.intel_graph import build_investigation_graph, graph_to_cytoscape_json
            entities_data = [asdict(e) for e in findings.entities]
            if entities_data:
                g = build_investigation_graph(entities_data)
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
                    enriched.raw = {"whois": whois_data, "dns": dns_data}
                    enriched.enrichment_sources.append("domain_intel")

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

    def _extract_media_geo(self, posts: list[SocialPost]) -> list[dict[str, Any]]:
        """Download images from posts' media_urls and extract EXIF GPS."""
        image_urls: list[tuple[str, str]] = []
        for p in posts:
            for url in (p.media_urls or []):
                if not url or not url.startswith("http"):
                    continue
                if self._IMAGE_EXT_RE.search(url) or "/photo/" in url:
                    image_urls.append((url, p.platform))
                if len(image_urls) >= self._MAX_MEDIA_DOWNLOAD:
                    break
            if len(image_urls) >= self._MAX_MEDIA_DOWNLOAD:
                break

        if not image_urls:
            return []

        log.info("Downloading %d media URLs for EXIF geo extraction", len(image_urls))
        image_bytes_list: list[bytes] = []
        url_metadata: list[dict[str, str]] = []

        for url, platform in image_urls:
            try:
                resp = _requests.get(url, timeout=self._MEDIA_DOWNLOAD_TIMEOUT, stream=True)
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
