"""Fortis Intelligence Hub -- Flask application factory.

OSINT analysis platform with ForgeChain governance, FAISS knowledge base,
and multi-source intelligence aggregation.
"""

import base64
import hashlib
import hmac as hmac_mod
import json as _json
import os
import re
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

_IS_WIN32 = sys.platform == "win32"

# Windows fixes
if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

from dotenv import load_dotenv
from flask import (
    Flask, jsonify, make_response, render_template,
    request, session, g, redirect, url_for,
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── App imports ────────────────────────────────────────────────────
from app.auth import (
    login_required,
    admin_required,
    get_oauth_client,
    OAuthError,
    session_manager,
    get_audit_logger,
    validate_auth_config,
    ADMIN_EMAILS,
)
from app.auth.config import AUTH_ENABLED, SESSION_SECRET_KEY, SESSION_TIMEOUT_MINUTES
from app.chains import (
    get_chat_intent_chain,
    get_rag_chain,
    get_investigation_chain,
    get_enrichment_chain,
    get_geolocation_chain,
    get_batch_item_chain,
    get_batch_synthesis_chain,
    get_scenario_chain,
    get_dork_collection_chain,
    get_dork_gap_analysis_chain,
    get_dork_validation_chain,
    get_dork_synthesis_chain,
    get_dork_deep_synthesis_chain,
    get_report_consolidation_chain,
    get_competing_hypotheses_chain,
    get_report_refinement_chain,
)
from app.bias_audit import run_bias_audit
from app.self_consistency import (
    run_self_consistency_check,
    SELF_CONSISTENCY_ENABLED,
)
from app.provenance import ProvenanceTrail
from app.rag_store import (
    build_vectorstore,
    load_vectorstore,
    add_to_knowledge_base,
    query_knowledge_base,
    knowledge_base_exists,
    rebuild_knowledge_base,
    verify_kb_on_startup,
)
from app.report_store import AnalysisReport, get_report_store
from app.export import generate_pdf, generate_markdown
from app.export_ioc import convert_to_stix21, convert_to_csv, convert_to_json
from app.charts import generate_investigation_charts
from app.intel_graph import (
    build_investigation_graph,
    build_entity_graph,
    graph_to_cytoscape_json,
    graph_context,
    cache_graph,
    persist_relationships,
    query_shared_connections,
    query_location_clusters,
    query_activity_overlap,
)
from app.forge import gated_invoke
from app.forge.config import FORGE_ENABLED
from app.forge.grounding_verifier import verify_grounding
from app.forge.chain_store import get_chain_store
from app.forge.replay import get_session_replay
from app.osint_client import OSINTClient
from app.geo_client import GeoClient
from app.feed_monitor import FeedMonitor
from app.civilian_harm import get_civilian_harm_classifier, CIVILIAN_HARM_ENABLED
from app.gdrive_client import get_gdrive_client
from app.image_search import reverse_image_search, IMAGE_SEARCH_ENABLED
from app.image_forensics import analyze_image_forensics, IMAGE_FORENSICS_ENABLED
from app.image_stego import detect_steganography, IMAGE_STEGO_ENABLED
from app.image_vision import analyze_image as clip_analyze_image, IMAGE_VISION_ENABLED
from app.image_deepseek_vision import describe_image as deepseek_describe_image, DEEPSEEK_VISION_ENABLED
from app.utils import create_session_id, safe_storage_path, validate_session_id
from app.utils.pdf_reader import extract_pdf_text
from app.utils.uploads import validate_upload_file
from app.utils.sanitizer import sanitize_identifier
from app.constants import (
    SOCIAL_PLATFORMS,
    SENSITIVITY_LEVELS,
    IDENTIFIER_TYPES,
    INVESTIGATION_DEPTHS,
    SCENARIO_TYPES,
)

# ── Constants ──────────────────────────────────────────────────────

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"
VECTORSTORE_DIR = BASE_DIR / "vectorstores"
LOG_DIR = BASE_DIR / "logs"

stored_reports: dict = {}
_MAX_STORED_REPORTS = 500
_KB_CONTEXT_MAX_CHARS = 2000

_shared_osint_client: OSINTClient | None = None
_shared_geo_client: GeoClient | None = None
_shared_feed_monitor: FeedMonitor | None = None


def _get_osint_client() -> OSINTClient:
    global _shared_osint_client
    if _shared_osint_client is None:
        _shared_osint_client = OSINTClient()
    return _shared_osint_client


def _get_geo_client() -> GeoClient:
    global _shared_geo_client
    if _shared_geo_client is None:
        _shared_geo_client = GeoClient()
    return _shared_geo_client


def _get_feed_monitor() -> FeedMonitor:
    global _shared_feed_monitor
    if _shared_feed_monitor is None:
        _shared_feed_monitor = FeedMonitor()
    return _shared_feed_monitor

# ── Helper functions ───────────────────────────────────────────────


def _get_user_hash() -> str:
    """SHA-256 hash prefix of the current user's email for audit logs."""
    if hasattr(g, "user_session"):
        return hashlib.sha256(g.user_session.email.encode()).hexdigest()[:16]
    return "unknown"


def _is_admin() -> bool:
    """Check if the current request user is an admin."""
    return getattr(getattr(g, "user_session", None), "is_admin", False)



def _save_to_kb(
    source_route: str,
    report_type: str,
    analysis_text: str,
    subject_identifier: str | None = None,
    identifier_type: str | None = None,
    sensitivity_level: str = "INTERNAL",
    platforms_queried: list[str] | None = None,
    entity_count: int = 0,
    source_count: int = 0,
    tags: list[str] | None = None,
    source_type: str = "llm_analysis",
) -> str | None:
    """Save a report to the ReportStore and index it in the FAISS knowledge base.

    Args:
        source_type: Provenance tag for the RAG contamination guard.
            "llm_analysis" (default) for LLM-generated reports,
            "uploaded_document" for user-uploaded documents,
            "primary_source" for raw OSINT data.
    """
    try:
        report_id = uuid.uuid4().hex
        user_hash = _get_user_hash()

        chunk_count = 0
        try:
            chunk_count = add_to_knowledge_base(
                analysis_text, report_id, source_type=source_type,
            )
        except Exception as exc:
            print(f"[WARN] KB vectorstore update failed (non-fatal): {exc}")

        report = AnalysisReport(
            report_id=report_id,
            source_route=source_route,
            report_type=report_type,
            analysis_text=analysis_text,
            subject_identifier=subject_identifier,
            identifier_type=identifier_type,
            sensitivity_level=sensitivity_level,
            platforms_queried=_json.dumps(platforms_queried) if platforms_queried else None,
            entity_count=entity_count,
            source_count=source_count,
            created_at=datetime.now(tz=timezone.utc).isoformat(),
            created_by=user_hash,
            in_knowledge_base=chunk_count > 0,
            kb_chunk_count=chunk_count,
            tags=_json.dumps(tags) if tags else None,
        )
        get_report_store().save(report)
        subject_short = (subject_identifier or "")[:50]
        print(f"[KB] Saved report {report_id[:8]} ({report_type}: {subject_short}) -- {chunk_count} chunks")
        return report_id
    except Exception as exc:
        print(f"[ERROR] _save_to_kb failed (non-fatal): {exc}")
        return None


def _get_kb_context(query: str) -> str:
    """Query the global FAISS knowledge base for supplemental context.

    Chunks tagged as LLM-generated are automatically labelled with
    ``[PRIOR ANALYSIS - not a primary source]`` by the RAG contamination
    guard in ``query_knowledge_base`` so the downstream LLM can
    distinguish primary evidence from derived analysis.
    """
    try:
        results = query_knowledge_base(query, k=3)
        if not results:
            return ""
        # results is a list of dicts with 'content', 'source_type', 'score'
        kb_text = "\n\n".join(r["content"] for r in results)
        if len(kb_text) > _KB_CONTEXT_MAX_CHARS:
            kb_text = kb_text[:_KB_CONTEXT_MAX_CHARS] + "..."
        return f"\n\n=== Prior Intelligence (Knowledge Base) ===\n{kb_text}"
    except Exception as exc:
        print(f"[WARN] KB query failed (non-fatal): {exc}")
        return ""


def _report_type_to_source_type(report_type: str) -> str:
    """Map a ReportStore report_type to a RAG contamination guard source_type."""
    if report_type == "ingestion":
        return "uploaded_document"
    return "llm_analysis"


def _rebuild_kb_from_store() -> int:
    """Rebuild the FAISS knowledge base from all in-KB reports."""
    try:
        store = get_report_store()
        reports = store.get_all_in_kb()
        texts = [
            (r.report_id, r.analysis_text, _report_type_to_source_type(r.report_type))
            for r in reports
        ]
        count = rebuild_knowledge_base(texts)
        print(f"[KB] Rebuilt with {count} chunks from {len(texts)} reports")
        return count
    except Exception as exc:
        print(f"[ERROR] KB rebuild failed: {exc}")
        return 0


def _run_civilian_harm_analysis(findings_dict: dict) -> dict | None:
    """Score posts and web mentions for civilian harm likelihood.

    Returns a summary dict or None if disabled / no scoreable content.
    """
    if not CIVILIAN_HARM_ENABLED:
        return None

    posts = findings_dict.get("posts", [])
    mentions = findings_dict.get("web_mentions", [])

    scoreable = []
    for p in posts:
        text = p.get("content", "") or ""
        if len(text.strip()) >= 20:
            scoreable.append({
                "content": text,
                "platform": p.get("platform", ""),
                "url": p.get("url", ""),
                "author": p.get("author_username", ""),
                "timestamp": p.get("timestamp", ""),
                "language": p.get("language", ""),
                "item_type": "post",
            })
    for m in mentions:
        text = m.get("snippet", "") or m.get("description", "") or ""
        if len(text.strip()) >= 20:
            scoreable.append({
                "content": text,
                "platform": m.get("platform", m.get("source", "")),
                "url": m.get("source_url", m.get("url", "")),
                "author": m.get("domain", ""),
                "timestamp": m.get("discovered_at", ""),
                "language": "",
                "item_type": "web_mention",
            })

    if not scoreable:
        return None

    try:
        classifier = get_civilian_harm_classifier()
        scored = classifier.score_batch(scoreable)
        summary = classifier.summarize(scored)
        print(
            f"[HARM] Scored {summary['total_scored']} items: "
            f"{summary.get('flagged_count', 0)} flagged, "
            f"max={summary.get('max_score', 0):.2f}"
        )
        return summary
    except Exception as exc:
        print(f"[WARN] Civilian harm analysis failed (non-fatal): {exc}")
        return None


def _score_text_for_harm(text: str) -> dict | None:
    """Score a single text block for civilian harm (used by Q&A, scenario)."""
    if not CIVILIAN_HARM_ENABLED or not text or len(text.strip()) < 30:
        return None
    try:
        classifier = get_civilian_harm_classifier()
        result = classifier.score_text(text)
        if result.score < 0.15:
            return None
        return {
            "score": result.score,
            "classification": result.classification,
            "matched_concepts": result.matched_concepts[:3],
            "matched_keywords": result.matched_keywords[:5],
        }
    except Exception:
        return None


def _findings_to_context(findings_dict: dict) -> str:
    """Convert serialized OSINTFindings to a text context for chain input."""
    parts: list[str] = []

    profiles = findings_dict.get("profiles", [])
    if profiles:
        parts.append(f"=== Social Profiles ({len(profiles)}) ===")
        for p in profiles[:20]:
            rel = p.get("source_reliability", {})
            rel_tag = f", Reliability: {rel['grade']}" if rel.get("grade") else ""
            line = f"  [{p.get('platform', '?')}{rel_tag}] @{p.get('username', '?')} - {p.get('display_name', '')}"
            parts.append(line)
            bio = p.get("bio", "")
            if bio:
                parts.append(f"    Bio: {bio[:200]}")
            followers = p.get("followers")
            if followers:
                parts.append(f"    Followers: {followers}")

    posts = findings_dict.get("posts", [])
    if posts:
        parts.append(f"\n=== Recent Posts ({len(posts)}) ===")
        for post in posts[:15]:
            ts = post.get("timestamp", "")
            content = post.get("content", "")[:200]
            rel = post.get("source_reliability", {})
            rel_tag = f", Reliability: {rel['grade']}" if rel.get("grade") else ""
            parts.append(f"  [{post.get('platform', '?')}{rel_tag}] {ts}: {content}")

    web_mentions = findings_dict.get("web_mentions", [])
    if web_mentions:
        parts.append(f"\n=== Web Mentions ({len(web_mentions)}) ===")
        for wm in web_mentions[:10]:
            rel = wm.get("source_reliability", {})
            rel_tag = f", Reliability: {rel['grade']}" if rel.get("grade") else ""
            parts.append(
                f"  [{wm.get('domain', '?')}{rel_tag}] {wm.get('source_title', '')}: "
                f"{wm.get('snippet', '')[:200]}"
            )

    geo_points = findings_dict.get("geo_points", [])
    if geo_points:
        credible_geo = [
            gp for gp in geo_points
            if isinstance(gp.get("confidence", 0), (int, float))
            and gp.get("confidence", 0) >= GEO_CONFIDENCE_FLOOR
        ]
        parts.append(f"\n=== Geo Points ({len(credible_geo)} accepted / {len(geo_points)} total) ===")
        for gp in credible_geo[:10]:
            conf = gp.get("confidence", 0)
            conf_str = f"{conf:.0%}" if isinstance(conf, float) else str(conf)
            parts.append(
                f"  ({gp.get('lat', '?')}, {gp.get('lon', '?')}) "
                f"- {gp.get('source', '')} [{conf_str}]"
            )

    entities = findings_dict.get("entities", [])
    if entities:
        parts.append(f"\n=== Extracted Entities ({len(entities)}) ===")
        for e in entities[:20]:
            conf = e.get("confidence", 0)
            conf_str = f"{conf:.0%}" if isinstance(conf, float) else str(conf)
            rel = e.get("source_reliability", {})
            rel_tag = f", Reliability: {rel['grade']}" if rel.get("grade") else ""
            parts.append(f"  [{e.get('entity_type', '?')}{rel_tag}] {e.get('entity_value', '?')} (confidence: {conf_str})")

    timeline = findings_dict.get("timeline", [])
    if timeline:
        parts.append(f"\n=== Timeline Events ({len(timeline)}) ===")
        for evt in timeline[:10]:
            parts.append(f"  {evt}")

    metadata = findings_dict.get("metadata", {})
    domain_intel = metadata.get("domain_intel", {})
    if domain_intel:
        domain_rel = metadata.get("domain_intel_reliability", {})
        whois_rel = domain_rel.get("whois", {})
        whois_grade = f" [Reliability: {whois_rel['grade']}]" if whois_rel.get("grade") else ""
        parts.append(f"\n=== Domain Intelligence{whois_grade}: {domain_intel.get('domain', '?')} ===")
        whois = domain_intel.get("whois", {})
        if whois.get("registrar"):
            parts.append(f"  Registrar: {whois['registrar']}")
        if whois.get("registrant"):
            parts.append(f"  Registrant: {whois['registrant']}")
        if whois.get("creation_date"):
            parts.append(f"  Created: {whois['creation_date']}")
        if whois.get("expiration_date"):
            parts.append(f"  Expires: {whois['expiration_date']}")
        dns = domain_intel.get("dns", {})
        for rtype in ("A", "AAAA", "MX", "NS", "CNAME", "SOA"):
            records = dns.get(rtype, [])
            if records:
                parts.append(f"  {rtype}: {', '.join(str(r) for r in records)}")
        dd = domain_intel.get("dnsdumpster", {})
        subs = dd.get("subdomains", [])
        if subs:
            parts.append(f"  Subdomains (DNSdumpster): {len(subs)} found")
            for s in subs[:15]:
                parts.append(f"    {s.get('hostname', '?')} -> {s.get('ip', '?')}")
            if len(subs) > 15:
                parts.append(f"    ... and {len(subs) - 15} more")
        headers = domain_intel.get("http_headers", {})
        if headers.get("Server"):
            parts.append(f"  Server: {headers['Server']}")
        if headers.get("X-Powered-By"):
            parts.append(f"  Powered-By: {headers['X-Powered-By']}")
        url_fuzz = domain_intel.get("url_fuzz", {})
        if url_fuzz.get("findings"):
            fuzz_findings = url_fuzz["findings"]
            by_sev = url_fuzz.get("by_severity", {})
            sev_summary = ", ".join(f"{k}: {v}" for k, v in sorted(by_sev.items()))
            parts.append(f"\n  === Exposed Endpoints (URL Fuzzing) === [{sev_summary}]")
            parts.append(f"  {url_fuzz['endpoints_found']} endpoints discovered out of {url_fuzz.get('total_probed', '?')} probed")
            for ef in fuzz_findings[:30]:
                status_tag = f"HTTP {ef['status']}"
                sev_tag = ef.get("severity", "INFO")
                redir = f" -> {ef['redirect_to']}" if ef.get("redirect_to") else ""
                ctype = f" [{ef['content_type']}]" if ef.get("content_type") else ""
                parts.append(f"    [{sev_tag}] {ef['path']} — {status_tag}{ctype}{redir}")
            if len(fuzz_findings) > 30:
                parts.append(f"    ... and {len(fuzz_findings) - 30} more")

    ip_intel = metadata.get("ip_intel", {})
    if ip_intel:
        ip_rel = metadata.get("ip_intel_reliability", {})
        ip_grade = f" [Reliability: {ip_rel['grade']}]" if ip_rel.get("grade") else ""
        parts.append(f"\n=== IP Intelligence{ip_grade}: {ip_intel.get('ip', '?')} ===")
        if ip_intel.get("reverse_dns"):
            parts.append(f"  Reverse DNS: {ip_intel['reverse_dns']}")
        co = ip_intel.get("co_hosted_domains", [])
        if co:
            parts.append(f"  Co-hosted domains: {ip_intel.get('co_hosted_count', len(co))}")
            for d in co[:10]:
                parts.append(f"    {d}")

    ip_geo = metadata.get("ip_geolocation", {})
    if ip_geo:
        parts.append(f"\n=== IP Geolocation ===")
        for k in ("ip", "city", "country", "isp", "region"):
            if ip_geo.get(k):
                parts.append(f"  {k.title()}: {ip_geo[k]}")

    errors = findings_dict.get("errors", [])
    if errors:
        parts.append(f"\n=== Collection Errors ({len(errors)}) ===")
        for err in errors:
            parts.append(f"  - {err}")

    if not parts:
        return "No OSINT data collected. OSINT sources are in Phase 0 (stub mode)."

    return "\n".join(parts)


GEO_CONFIDENCE_FLOOR = float(os.environ.get("GEO_CONFIDENCE_FLOOR", "0.6"))
MAX_UPLOAD_SIZE_MB = int(os.environ.get("MAX_UPLOAD_SIZE_MB", "50"))


def _filter_geo_points(geo_points: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split geo points into accepted (above confidence floor) and rejected.

    Returns ``(accepted, rejected)`` — only accepted points should appear
    on the map and in the LLM report context.
    """
    accepted, rejected = [], []
    for gp in geo_points:
        conf = gp.get("confidence", 0)
        if isinstance(conf, (int, float)) and conf >= GEO_CONFIDENCE_FLOOR:
            accepted.append(gp)
        else:
            rejected.append(gp)
    return accepted, rejected


def _geo_points_to_text(geo_points: list[dict]) -> str:
    """Convert geo data points to text context for chain input.

    Only points that passed the confidence floor should be passed here.
    """
    if not geo_points:
        return "No geolocation data available."
    parts = []
    for gp in geo_points[:20]:
        conf = gp.get("confidence", 0)
        conf_str = f"{conf:.0%}" if isinstance(conf, float) else str(conf)
        parts.append(
            f"- ({gp.get('lat', '?')}, {gp.get('lon', '?')}) "
            f"source={gp.get('source', '?')} confidence={conf_str} "
            f"type={gp.get('point_type', '?')} ts={gp.get('timestamp', '?')}"
        )
    return "\n".join(parts)


DORK_VALIDATION_ENABLED = os.environ.get("DORK_VALIDATION_ENABLED", "true").lower() in ("1", "true", "yes")
DORK_MAX_SCRAPE_URLS = int(os.environ.get("DORK_MAX_SCRAPE_URLS", "5"))


def _run_initial_dorking(
    subject_identifier: str,
    identifier_type: str,
    platforms: list[str],
    session_id: str,
    user_hash: str,
    purpose: str = "Initial web collection for OSINT investigation",
) -> dict:
    """Phase 1 dorking: generate and execute collection dork queries BEFORE OSINT collection.

    Returns a dict with ``text`` (formatted results), ``data`` (structured results),
    and ``suggested_platforms`` (list of platforms the LLM recommends checking).
    Non-fatal: callers should wrap this in try/except.
    """
    from app.dork_search import DorkQuery, DorkSearchClient, parse_dork_queries
    from app.dork_sanitizer import sanitize_dork_query, sanitize_search_results, sanitize_scraped_content

    result: dict = {"text": "", "data": {}, "queries_run": 0, "suggested_platforms": []}

    platforms_str = ", ".join(platforms) if platforms else "none"

    collection_chain = get_dork_collection_chain()
    collection_input = {
        "subject_identifier": subject_identifier,
        "identifier_type": identifier_type,
        "platforms": platforms_str,
        "investigation_purpose": purpose,
        "purpose": purpose,
    }
    collection_result = gated_invoke(
        collection_chain, collection_input,
        chain_name="dork_collection_chain",
        endpoint="/investigate",
        mode="osint",
        session_id=session_id,
        user_hash=user_hash,
        trusted_keys={"subject_identifier", "identifier_type", "platforms", "investigation_purpose"},
    )
    if not collection_result.success:
        print(f"[DORK] Initial collection blocked: {collection_result.reason}")
        return result

    collection_queries = parse_dork_queries(collection_result.content, "collection")

    # Deterministic queries: baseline + hardcoded platform-specific queries
    # that always run regardless of what the LLM generates.  Search engines
    # don't personalise API results, so we compensate by targeting the
    # platforms most likely to have data for each identifier type.
    PLATFORM_QUERIES = {
        "name": [
            ("site:linkedin.com", "LinkedIn professional profile"),
            ("site:facebook.com", "Facebook profile"),
            ("site:twitter.com OR site:x.com", "Twitter/X profile"),
            ("site:instagram.com", "Instagram profile"),
            ("site:github.com", "GitHub profile"),
            ("site:medium.com OR site:substack.com", "Blog/publication profile"),
        ],
        "username": [
            ("site:github.com", "GitHub account"),
            ("site:reddit.com", "Reddit account"),
            ("site:twitter.com OR site:x.com", "Twitter/X account"),
            ("site:instagram.com", "Instagram account"),
            ("site:tiktok.com", "TikTok account"),
            ("site:linkedin.com", "LinkedIn profile"),
            ("site:medium.com", "Blog posts"),
        ],
        "email": [
            ("site:linkedin.com", "LinkedIn profile linked to email"),
            ("site:facebook.com", "Facebook profile linked to email"),
            ("forum OR registration OR profile", "Forum/service registrations"),
            ("site:github.com", "GitHub account linked to email"),
            ("site:gravatar.com", "Gravatar profile (passive)"),
            ("site:keyserver.ubuntu.com OR site:keys.openpgp.org", "PGP key publication (passive)"),
            ("site:haveibeenpwned.com", "Breach exposure check (passive)"),
            ("site:hunter.io OR site:emailrep.io", "Email reputation and verification (passive)"),
            ("site:pastebin.com OR site:paste.ee", "Paste site mentions (passive)"),
        ],
        "phone": [
            ("site:truecaller.com", "Truecaller caller ID"),
            ("site:facebook.com", "Facebook profile linked to phone"),
            ("site:whocalledme.com OR site:whocallsme.com", "Caller reports"),
            ("directory OR lookup OR owner", "Phone directory/lookup"),
        ],
        "domain": [
            # General OSINT
            ("-site:{id}", "Mentions outside the domain itself"),
            ("site:linkedin.com", "Organisation LinkedIn page"),
            ("site:github.com", "Associated code repositories"),
            ("site:crunchbase.com OR site:dnb.com", "Business intelligence"),
            # Passive recon — exposed documents
            ("site:{id} filetype:pdf", "Indexed PDF documents (passive)"),
            ("site:{id} filetype:doc OR filetype:xlsx", "Indexed Office documents (passive)"),
            ("site:{id} filetype:xml OR filetype:json", "Exposed configuration files (passive)"),
            ("site:{id} filetype:log OR filetype:sql OR filetype:bak", "Exposed logs/backups (passive)"),
            ("site:{id} filetype:env OR filetype:cfg", "Exposed environment/config files (passive)"),
            # Passive recon — API surface
            ("site:{id} inurl:api", "Indexed API endpoints (passive)"),
            ("site:{id} intitle:swagger OR intitle:\"api docs\"", "Exposed API documentation (passive)"),
            ("site:{id} inurl:graphql", "GraphQL endpoint exposure (passive)"),
            # Passive recon — subdomains & DNS via passive aggregators
            ("site:crt.sh", "Certificate transparency — subdomain enumeration (passive)"),
            ("site:dnsdumpster.com", "DNS records and subdomains (passive)"),
            ("site:securitytrails.com", "Historical DNS and subdomain data (passive)"),
            ("site:{id} -www", "Non-www subdomains via search index (passive)"),
            # Passive recon — infrastructure exposure
            ("site:{id} intitle:\"index of\"", "Exposed directory listings (passive)"),
            ("site:{id} intitle:login OR intitle:admin", "Login and admin panels (passive)"),
            ("site:{id} inurl:wp-content", "WordPress installation detection (passive)"),
            ("site:{id} inurl:.git", "Exposed Git repository (passive)"),
            # Passive recon — cloud storage exposure
            ("site:s3.amazonaws.com \"{id}\"", "AWS S3 bucket references (passive)"),
            ("site:blob.core.windows.net \"{id}\"", "Azure Blob storage references (passive)"),
            ("site:storage.googleapis.com \"{id}\"", "GCS bucket references (passive)"),
            # Passive recon — error & debug disclosure
            ("site:{id} intitle:\"error\" OR intitle:\"exception\"", "Error pages with stack traces (passive)"),
            ("site:{id} inurl:debug OR inurl:phpinfo", "Debug/phpinfo exposure (passive)"),
            # Passive recon — technology fingerprinting
            ("site:builtwith.com", "Technology stack analysis (passive)"),
            ("site:web.archive.org", "Wayback Machine historical snapshots (passive)"),
            # Leak/paste references
            ("site:pastebin.com OR site:paste.ee", "Paste site references (passive)"),
            ("site:haveibeenpwned.com", "Breach exposure check (passive)"),
        ],
        "ip": [
            # General threat intel
            ("site:shodan.io", "Shodan device intelligence (passive)"),
            ("site:abuseipdb.com", "Abuse reports"),
            ("site:virustotal.com", "Security analysis"),
            ("abuse OR blocklist OR security", "Security references"),
            # Passive recon — host & certificate intel
            ("site:censys.io", "Censys certificate and host data (passive)"),
            ("site:greynoise.io", "Internet noise classification (passive)"),
            ("site:urlscan.io", "URL scan results and hosted content (passive)"),
            ("site:threatcrowd.org", "ThreatCrowd IP intel (passive)"),
            # Passive recon — DNS & network
            ("site:securitytrails.com", "Historical DNS and hosting data (passive)"),
            ("site:viewdns.info", "Reverse DNS and hosting lookup (passive)"),
            ("\"reverse dns\" OR \"ptr record\"", "Reverse DNS / PTR records (passive)"),
            ("site:crt.sh", "Certificate transparency logs (passive)"),
            ("site:dnslytics.com", "DNS analytics and hosting history (passive)"),
            # Passive recon — reputation & ASN
            ("site:ipinfo.io OR site:bgp.he.net", "Network and ASN intelligence (passive)"),
            ("blacklist OR reputation OR malicious", "IP reputation references"),
            ("site:talosintelligence.com", "Cisco Talos IP reputation (passive)"),
            # Passive recon — geolocation & hosting
            ("site:iplocation.net OR site:ip-api.com", "IP geolocation data (passive)"),
            ("\"hosted by\" OR \"hosting provider\"", "Hosting provider identification (passive)"),
        ],
        "keyword": [
            ("site:reddit.com", "Reddit discussions"),
            ("site:twitter.com OR site:x.com", "Twitter/X mentions"),
            ("site:news.ycombinator.com", "Hacker News discussions"),
            ("news OR article OR report", "News coverage"),
        ],
    }

    baseline_query = f'"{subject_identifier}"'
    baseline_dq = DorkQuery(
        query=baseline_query,
        purpose=f"Direct search for {identifier_type} identifier",
        finding_ref="baseline",
        query_type="collection",
    )

    all_queries = [baseline_dq]
    seen_queries = {baseline_query.lower()}

    # Add hardcoded platform-specific queries for this identifier type
    id_type_lower = identifier_type.lower()
    for suffix, purpose_text in PLATFORM_QUERIES.get(id_type_lower, []):
        if "{id}" in suffix:
            suffix = suffix.replace("{id}", subject_identifier)
        pq = f'"{subject_identifier}" {suffix}'
        if pq.lower() not in seen_queries:
            all_queries.append(DorkQuery(
                query=pq, purpose=purpose_text,
                finding_ref="platform_target", query_type="collection",
            ))
            seen_queries.add(pq.lower())

    # Add LLM-generated queries (deduped against the deterministic set)
    for dq in collection_queries:
        cleaned, warnings = sanitize_dork_query(dq.query)
        if warnings:
            print(f"[DORK] Collection query sanitisation warnings for '{dq.query[:60]}': {warnings}")
        if cleaned and cleaned.lower() not in seen_queries:
            dq.query = cleaned
            all_queries.append(dq)
            seen_queries.add(cleaned.lower())

    if not all_queries:
        print("[DORK] No valid collection queries after sanitisation")
        return result

    client = DorkSearchClient()
    search_results = client.search_batch(all_queries, max_per_query=10)

    collection_raw = []
    for dq in all_queries:
        for dr in search_results.get(dq.query, []):
            collection_raw.append({
                "title": dr.title, "url": dr.url, "snippet": dr.snippet,
                "query": dq.query, "purpose": dq.purpose, "ref": dq.finding_ref,
            })

    collection_text = sanitize_search_results(collection_raw) if collection_raw else "No initial collection results."

    # Deep-scrape the top initial results — these are typically the highest-
    # quality hits (LinkedIn profiles, news articles, company pages) that the
    # hardcoded SOCIAL_PLATFORMS would never reach.  Search position correlates
    # with relevance so we scrape the first N unique URLs across all queries.
    scraped_enrichments = []
    if collection_raw:
        from app.http_client import create_session
        scrape_http = create_session(timeout=15.0)
        seen_urls: set[str] = set()
        scrape_cap = min(DORK_MAX_SCRAPE_URLS, len(collection_raw))

        for item in collection_raw:
            if len(scraped_enrichments) >= scrape_cap:
                break
            url = item.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                resp = scrape_http.get(url, timeout=15)
                if hasattr(resp, "status_code") and resp.status_code == 200:
                    raw_html = resp.text if hasattr(resp, "text") else str(resp.content)
                    clean = sanitize_scraped_content(raw_html, max_chars=2000)
                    if clean and len(clean) > 50:
                        scraped_enrichments.append({
                            "url": url,
                            "title": item.get("title", ""),
                            "content": clean,
                        })
                        print(f"[DORK] Initial scrape enriched: {url} ({len(clean)} chars)")
            except Exception as exc:
                print(f"[DORK] Initial scrape skipped {url}: {exc}")

    # Build enriched text that includes both snippets AND scraped full-page content
    enriched_text = collection_text
    if scraped_enrichments:
        enriched_text += "\n\n--- ENRICHED PAGE CONTENT (top web results) ---\n"
        for se in scraped_enrichments:
            enriched_text += f"\n[Source: {se['title']}]\nURL: {se['url']}\n{se['content']}\n"

    result["queries_run"] = len(all_queries)
    result["text"] = enriched_text
    result["data"]["queries"] = [
        {"query": dq.query, "type": "collection", "purpose": dq.purpose, "ref": dq.finding_ref}
        for dq in all_queries
    ]
    result["data"]["collection_results"] = collection_raw
    if scraped_enrichments:
        result["data"]["scraped_pages"] = [
            {"url": se["url"], "title": se["title"]} for se in scraped_enrichments
        ]

    # Parse platform recommendations from LLM output (if no platforms were specified)
    if not platforms or platforms_str == "none":
        import re
        rec_match = re.search(
            r"PLATFORM RECOMMENDATIONS?:?\s*(.+?)(?:\n\n|\Z)",
            collection_result.content, re.DOTALL | re.IGNORECASE,
        )
        if rec_match:
            result["suggested_platforms"] = [
                line.strip().lstrip("- ").strip()
                for line in rec_match.group(1).splitlines()
                if line.strip() and line.strip() != "-"
            ]

    print(f"[DORK] Initial collection: {len(all_queries)} queries, {len(collection_raw)} results, {len(scraped_enrichments)} pages scraped")
    return result


def _run_final_dorking(
    analysis_text: str,
    osint_summary: str,
    entities_summary: str,
    session_id: str,
    user_hash: str,
    purpose: str = "OSINT investigation — final validation and gap analysis",
) -> dict:
    """Run the 4-phase dork search pipeline (gap-fill + validate + synthesise + deep scrape).

    Returns a dict with ``text`` (markdown section) and ``data`` (structured results).
    Non-fatal: callers should wrap this in try/except.
    """
    from app.dork_search import DorkSearchClient, parse_dork_queries, parse_scrape_candidates
    from app.dork_sanitizer import sanitize_dork_query, sanitize_search_results, sanitize_scraped_content

    result: dict = {"text": "", "data": {}, "queries_run": 0}

    # Phase 1: Gap analysis — identify missing intel
    gap_chain = get_dork_gap_analysis_chain()
    gap_input = {
        "analysis_text": analysis_text,
        "osint_summary": osint_summary,
        "entities_summary": entities_summary,
        "investigation_purpose": purpose,
        "purpose": purpose,
    }
    gap_result = gated_invoke(
        gap_chain, gap_input,
        chain_name="dork_gap_analysis_chain",
        endpoint="/investigate",
        mode="osint",
        session_id=session_id,
        user_hash=user_hash,
        trusted_keys={"analysis_text", "osint_summary", "entities_summary", "investigation_purpose"},
    )
    if not gap_result.success:
        print(f"[DORK] Gap analysis blocked: {gap_result.reason}")
        return result

    gap_queries = parse_dork_queries(gap_result.content, "gap_fill")

    # Phase 2: Validation — cross-reference findings
    val_chain = get_dork_validation_chain()
    val_input = {
        "analysis_text": analysis_text,
        "entities_summary": entities_summary,
        "investigation_purpose": purpose,
        "purpose": purpose,
    }
    val_result = gated_invoke(
        val_chain, val_input,
        chain_name="dork_validation_chain",
        endpoint="/investigate",
        mode="osint",
        session_id=session_id,
        user_hash=user_hash,
        trusted_keys={"analysis_text", "entities_summary", "investigation_purpose"},
    )
    if not val_result.success:
        print(f"[DORK] Validation generation blocked: {val_result.reason}")
        return result

    val_queries = parse_dork_queries(val_result.content, "validation")

    # Sanitise all queries
    all_queries = []
    for dq in gap_queries + val_queries:
        cleaned, warnings = sanitize_dork_query(dq.query)
        if warnings:
            print(f"[DORK] Query sanitisation warnings for '{dq.query[:60]}': {warnings}")
        if cleaned:
            dq.query = cleaned
            all_queries.append(dq)

    if not all_queries:
        print("[DORK] No valid queries after sanitisation")
        return result

    # Execute searches
    client = DorkSearchClient()
    search_results = client.search_batch(all_queries, max_per_query=5)

    gap_fill_raw = []
    validation_raw = []
    for dq in all_queries:
        for dr in search_results.get(dq.query, []):
            entry = {"title": dr.title, "url": dr.url, "snippet": dr.snippet,
                     "query": dq.query, "purpose": dq.purpose, "ref": dq.finding_ref}
            if dq.query_type == "gap_fill":
                gap_fill_raw.append(entry)
            else:
                validation_raw.append(entry)

    gap_fill_text = sanitize_search_results(gap_fill_raw) if gap_fill_raw else "No gap-fill results."
    validation_text = sanitize_search_results(validation_raw) if validation_raw else "No validation results."

    result["queries_run"] = len(all_queries)
    result["data"]["queries"] = [
        {"query": dq.query, "type": dq.query_type, "purpose": dq.purpose, "ref": dq.finding_ref}
        for dq in all_queries
    ]
    result["data"]["gap_fill_results"] = gap_fill_raw
    result["data"]["validation_results"] = validation_raw

    # Phase 3: Synthesis
    synth_chain = get_dork_synthesis_chain()
    synth_input = {
        "analysis_text": analysis_text,
        "gap_fill_results": gap_fill_text,
        "validation_results": validation_text,
        "purpose": purpose,
    }
    synth_result = gated_invoke(
        synth_chain, synth_input,
        chain_name="dork_synthesis_chain",
        endpoint="/investigate",
        mode="osint",
        session_id=session_id,
        user_hash=user_hash,
        trusted_keys={"analysis_text"},
    )
    if not synth_result.success:
        print(f"[DORK] Synthesis blocked: {synth_result.reason}")
        return result

    synthesis_text = synth_result.content
    result["text"] = synthesis_text

    # Phase 4: Deep scrape (confidence-gated)
    scrape_candidates = parse_scrape_candidates(synthesis_text)
    scrape_candidates = scrape_candidates[:DORK_MAX_SCRAPE_URLS]

    if scrape_candidates:
        scraped_parts = []
        from app.http_client import create_session
        scrape_http = create_session(timeout=15.0)

        for sc in scrape_candidates:
            try:
                resp = scrape_http.get(sc.url, timeout=15)
                if hasattr(resp, "status_code") and resp.status_code == 200:
                    raw_html = resp.text if hasattr(resp, "text") else str(resp.content)
                    clean = sanitize_scraped_content(raw_html, max_chars=2000)
                    if clean and len(clean) > 50:
                        scraped_parts.append(
                            f"--- Source: {sc.url} (Confidence: {sc.confidence}) ---\n{clean}"
                        )
                        print(f"[DORK] Deep scraped: {sc.url} ({len(clean)} chars)")
                    else:
                        print(f"[DORK] Scraped content too short, skipping: {sc.url}")
                else:
                    status = getattr(resp, "status_code", "?")
                    print(f"[DORK] Scrape failed HTTP {status}: {sc.url}")
            except Exception as exc:
                print(f"[DORK] Scrape error for {sc.url}: {exc}")

        if scraped_parts:
            scraped_content = "\n\n".join(scraped_parts)

            deep_chain = get_dork_deep_synthesis_chain()
            deep_input = {
                "analysis_text": analysis_text,
                "initial_synthesis": synthesis_text,
                "scraped_content": scraped_content,
                "purpose": purpose,
            }
            deep_result = gated_invoke(
                deep_chain, deep_input,
                chain_name="dork_deep_synthesis_chain",
                endpoint="/investigate",
                mode="osint",
                session_id=session_id,
                user_hash=user_hash,
                trusted_keys={"analysis_text", "initial_synthesis"},
            )
            if deep_result.success:
                result["text"] = deep_result.content
                result["data"]["deep_scraped"] = [
                    {"url": sc.url, "confidence": sc.confidence} for sc in scrape_candidates
                ]
                print(f"[DORK] Deep synthesis complete ({len(scraped_parts)} pages)")
            else:
                print(f"[DORK] Deep synthesis blocked: {deep_result.reason}")

    return result


def _process_single_identifier(identifier, identifier_type, platforms, depth,
                               osint_client, geo_client, session_id, user_hash,
                               elevated=False):
    """Process a single identifier for batch investigation."""
    try:
        clean_id = sanitize_identifier(identifier, identifier_type)
    except Exception:
        clean_id = identifier

    # Initial dorking for batch item
    initial_dork_context = ""
    if DORK_VALIDATION_ENABLED:
        try:
            dork_data = _run_initial_dorking(
                subject_identifier=clean_id,
                identifier_type=identifier_type,
                platforms=platforms,
                session_id=session_id or f"batch_{clean_id}",
                user_hash=user_hash,
                purpose="Batch OSINT investigation — initial web collection",
            )
            if dork_data and dork_data.get("text"):
                initial_dork_context = dork_data["text"]
        except Exception:
            pass

    try:
        findings = osint_client.investigate(clean_id, platforms=platforms, depth=depth)
        findings_dict = asdict(findings)
    except Exception as exc:
        return {
            "success": False,
            "identifier": identifier,
            "identifier_type": identifier_type,
            "error": f"OSINT collection failed: {str(exc)[:200]}",
        }

    osint_context = _findings_to_context(findings_dict)
    if initial_dork_context:
        osint_context += "\n\n--- INITIAL WEB COLLECTION ---\n" + initial_dork_context
    batch_accepted_geo, _ = _filter_geo_points(findings_dict.get("geo_points", []))
    geo_context = _geo_points_to_text(batch_accepted_geo)

    chain = get_batch_item_chain()
    chain_input = {
        "osint_data": osint_context,
        "geo_data": geo_context,
        "subject_identifier": clean_id,
        "identifier_type": identifier_type,
        "elevated_authorization": elevated,
        "purpose": "OSINT batch investigation",
    }

    analysis = ""
    try:
        result = gated_invoke(
            chain=chain,
            chain_input=chain_input,
            chain_name="batch_item_chain",
            endpoint="/batch-investigate",
            session_id=session_id or f"batch_{clean_id}",
            mode="osint",
            user_hash=user_hash,
            trusted_keys={"osint_data", "geo_data"},
        )
        if result.success:
            analysis = result.content
        else:
            analysis = f"[Governance blocked: {result.reason}]"
    except Exception as exc:
        analysis = f"[LLM analysis failed: {str(exc)[:150]}]"

    return {
        "success": True,
        "identifier": clean_id,
        "identifier_type": identifier_type,
        "analysis": analysis,
        "entity_count": len(findings_dict.get("entities", [])),
        "source_count": len(findings_dict.get("platforms_queried", [])),
        "sensitivity_level": findings_dict.get("sensitivity_level", "INTERNAL"),
        "error": None,
    }


# ── Application factory ───────────────────────────────────────────


def create_app():
    load_dotenv()

    # Validate auth config if authentication is enabled
    if AUTH_ENABLED:
        try:
            validate_auth_config()
        except ValueError as exc:
            print(f"[ERROR] Authentication configuration invalid: {exc}")

    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    # ── Session configuration ──────────────────────────────────────
    app.config.update(
        SECRET_KEY=SESSION_SECRET_KEY,
        MAX_CONTENT_LENGTH=50 * 1024 * 1024,  # 50 MB upload limit
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_NAME="__Host-fortis-session",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_TIMEOUT_MINUTES),
    )

    # ── CORS ───────────────────────────────────────────────────────
    allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5000").split(",")
    CORS(
        app,
        origins=allowed_origins,
        supports_credentials=True,
        max_age=3600,
    )

    # ── Rate limiting ──────────────────────────────────────────────
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["1000 per day", "200 per hour"],
        storage_uri=os.getenv("REDIS_URL", "memory://"),
    )

    # ── Security headers ───────────────────────────────────────────
    @app.after_request
    def set_security_headers(response):
        """Apply security headers to every response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        if os.getenv("FLASK_ENV") == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
            "https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: https://*.basemaps.cartocdn.com "
            "https://*.tile.openstreetmap.org https://server.arcgisonline.com; "
            "connect-src 'self' https://*.basemaps.cartocdn.com "
            "https://*.tile.openstreetmap.org https://server.arcgisonline.com; "
            "form-action 'self'; "
            "base-uri 'self'"
        )

        return response

    # ── Initialize directories ─────────────────────────────────────
    for directory in (UPLOAD_DIR, DATA_DIR, VECTORSTORE_DIR, LOG_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    # ── Initialize databases ───────────────────────────────────────
    try:
        get_report_store()
        print("[STARTUP] ReportStore initialized")
    except Exception as exc:
        print(f"[ERROR] ReportStore init failed: {exc}")

    try:
        get_chain_store()
        print("[STARTUP] ForgeChain store initialized")
    except Exception as exc:
        print(f"[ERROR] ForgeChain store init failed: {exc}")

    # ================================================================
    #  AUTH ROUTES
    # ================================================================

    @app.route("/")
    def welcome():
        """Serve welcome page. Redirect to app if already authenticated."""
        auth_on = os.getenv("AUTH_ENABLED", "true").lower() == "true"
        if auth_on:
            token = session.get("auth_token")
            if token and session_manager.get_session(token):
                return redirect(url_for("app_page"))
        return render_template("welcome.html", auth_enabled=auth_on)

    @app.route("/oauth/login", methods=["GET"])
    def oauth_login():
        """Initiate Google OAuth flow."""
        try:
            oauth_client = get_oauth_client()
            authorization_url, state = oauth_client.get_authorization_url()

            session["oauth_state"] = state
            session.permanent = True

            return redirect(authorization_url)
        except Exception as exc:
            print(f"[ERROR] OAuth initialization failed: {exc}")
            return redirect(url_for("welcome", error="oauth_init_failed"))

    @app.route("/oauth/callback", methods=["GET"])
    @limiter.limit("10 per minute")
    def oauth_callback():
        """Handle OAuth callback from Google."""
        audit_logger = get_audit_logger()

        error = request.args.get("error")
        if error:
            print(f"[ERROR] OAuth error: {error}")
            return redirect(url_for("welcome", error="oauth_denied"))

        code = request.args.get("code")
        state = request.args.get("state")

        # Verify state token (CSRF protection)
        stored_state = session.get("oauth_state")
        if not state or not stored_state or not hmac_mod.compare_digest(state, stored_state):
            print("[ERROR] OAuth state mismatch (CSRF attempt)")
            audit_logger._log_event("CSRF_ATTEMPT", {"state": state})
            session.pop("oauth_state", None)
            return redirect(url_for("welcome", error="csrf_detected"))

        try:
            oauth_client = get_oauth_client()
            user_info = oauth_client.exchange_code_for_token(code, state)
            email = user_info["email"]

            # Log successful login
            audit_logger.log_login_success(email)

            # Create session
            session_token = session_manager.create_session(
                email=email,
                name=user_info.get("name", email),
                picture=user_info.get("picture", ""),
            )

            # Set session cookie
            session["auth_token"] = session_token
            session["user_name"] = user_info.get("name", email)
            session["user_picture"] = user_info.get("picture", "")
            session.permanent = True

            # Clear OAuth state
            session.pop("oauth_state", None)

            return redirect(url_for("app_page"))

        except OAuthError as exc:
            audit_logger.log_login_attempt("unknown", False, f"OAuth error: {str(exc)}")
            print(f"[ERROR] OAuth exchange failed: {exc}")
            return redirect(url_for("welcome", error="oauth_failed"))
        except Exception as exc:
            email_local = email if "email" in dir() else "unknown"
            audit_logger.log_login_attempt(email_local, False, f"Server error: {str(exc)}")
            print(f"[ERROR] Login failed: {exc}")
            return redirect(url_for("welcome", error="server_error"))

    @app.route("/app")
    @login_required
    def app_page():
        """Serve the main SPA."""
        return render_template("index.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        """Destroy the current session."""
        audit_logger = get_audit_logger()
        audit_logger.log_logout(g.user_session.email)

        token = session.get("auth_token")
        if token:
            session_manager.invalidate_session(token)
        session.clear()
        return jsonify({"success": True})

    @app.route("/me", methods=["GET"])
    @login_required
    def get_current_user():
        """Return current user info."""
        user_session = g.user_session
        return jsonify({
            "email": user_session.email,
            "name": session.get("user_name", user_session.email),
            "picture": session.get("user_picture", ""),
            "is_admin": user_session.is_admin,
        })

    # ================================================================
    #  CORE ANALYSIS ROUTES
    # ================================================================

    @app.route("/upload", methods=["POST"])
    @login_required
    @limiter.limit("20 per hour")
    def upload():
        """Upload a PDF or Markdown file, extract text, and build vectorstore."""
        try:
            file = request.files.get("file") or request.files.get("pdf")
            if not file or not file.filename:
                return jsonify({"error": "No file uploaded"}), 400

            # Validate file type and size
            is_valid, error_msg = validate_upload_file(file)
            if not is_valid:
                print(f"  File validation failed: {error_msg}")
                return jsonify({"error": error_msg}), 400

            ext = Path(file.filename).suffix.lower()
            try:
                session_id = create_session_id(file.filename)
                path = safe_storage_path(str(UPLOAD_DIR), session_id, suffix=ext)
            except ValueError as ve:
                return jsonify({"error": f"Invalid session ID: {ve}"}), 400

            file.save(path)

            print(f"\nDocument Upload ({ext}):")
            print(f"  Original filename: {file.filename}")
            print(f"  Session ID: {session_id}")

            if ext == ".md":
                text = path.read_text(encoding="utf-8")
            else:
                text = extract_pdf_text(str(path))

            if not text or len(text.strip()) < 50:
                error_msg = (
                    f"Document appears to be empty or unreadable. "
                    f"Extracted {len(text)} characters."
                )
                print(f"  Error: {error_msg}")
                return jsonify({"error": error_msg}), 400

            # Enforce TTL + size limits on in-memory report cache
            from app.compliance import evict_expired_cache
            evict_expired_cache(stored_reports)
            if len(stored_reports) >= _MAX_STORED_REPORTS:
                oldest_key = min(
                    stored_reports,
                    key=lambda k: stored_reports[k].get("created_at", datetime.min),
                )
                stored_reports.pop(oldest_key, None)

            stored_reports[session_id] = {
                "text": text,
                "user_email": g.user_session.email if hasattr(g, "user_session") else "unknown",
                "created_at": datetime.now(tz=timezone.utc),
            }

            # Build vectorstore for RAG queries
            try:
                build_vectorstore(text, session_id)
            except Exception as exc:
                print(f"  Warning: Could not build vectorstore: {exc}")

            # Save to KB so it appears in the Knowledge Base panel
            report_id = _save_to_kb(
                source_route="/upload",
                report_type="ingestion",
                analysis_text=text,
                subject_identifier=file.filename,
                sensitivity_level="INTERNAL",
                source_type="uploaded_document",
            )

            # MITRE technique extraction
            mitre_techniques = []
            try:
                from app.mitre import extract_mitre_techniques
                mitre_techniques = extract_mitre_techniques(text[:10000])
            except Exception:
                pass

            pages = None
            chunks = None
            try:
                vs_path = os.path.join(str(VECTORSTORE_DIR), session_id)
                if os.path.isdir(vs_path):
                    import glob as _glob
                    chunk_files = _glob.glob(os.path.join(vs_path, "*.pkl"))
                    if chunk_files:
                        chunks = len(chunk_files)
            except Exception:
                pass

            return jsonify({
                "session_id": session_id,
                "message": "Document ingested successfully",
                "char_count": len(text),
                "report_id": report_id,
                "mitre_techniques": mitre_techniques,
                "pages": pages,
                "chunks": chunks,
            })

        except Exception as exc:
            print(f"Error during document upload: {exc}")
            return jsonify({"error": "Failed to process document. Please try again."}), 500

    @app.route("/ask", methods=["POST"])
    @login_required
    @limiter.limit("60 per hour")
    def ask():
        """Smart chat — routes questions to RAG and action requests to the appropriate pipeline."""
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id")
        question = data.get("question")

        if not question:
            return jsonify({"error": "Question is required"}), 400

        # ── Intent classification ────────────────────────────────
        intent_data = None
        try:
            intent_chain = get_chat_intent_chain()
            raw_intent = intent_chain.invoke({"question": question})
            import json as _json
            clean = raw_intent.strip()
            if clean.startswith("```"):
                clean = "\n".join(clean.split("\n")[1:])
                clean = clean.rsplit("```", 1)[0]
            intent_data = _json.loads(clean)
        except Exception:
            intent_data = {"intent": "question"}

        intent = intent_data.get("intent", "question")

        # ── Action intents: return routing payload for frontend ──
        if intent == "investigate":
            identifier = intent_data.get("identifier", "").strip()
            if not identifier:
                intent = "question"
            else:
                id_type = intent_data.get("identifier_type", "username")
                if id_type not in IDENTIFIER_TYPES:
                    id_type = "username"
                return jsonify({
                    "action": "investigate",
                    "params": {
                        "identifier": identifier,
                        "identifier_type": id_type,
                        "depth": intent_data.get("depth", "standard"),
                        "investigation_purpose": intent_data.get("purpose", "OSINT investigation"),
                    },
                    "message": f"Starting investigation on **{identifier}** ({id_type})...",
                    "session_id": session_id or "",
                })

        if intent == "scenario":
            scenario_type = intent_data.get("scenario_type", "")
            subject = intent_data.get("subject", "")
            if scenario_type in SCENARIO_TYPES and (session_id or subject):
                return jsonify({
                    "action": "scenario",
                    "params": {
                        "scenario_type": scenario_type,
                        "subject_context": subject,
                        "session_id": session_id or "",
                    },
                    "message": f"Running **{scenario_type.replace('_', ' ')}** analysis"
                               + (f" for {subject}" if subject else "") + "...",
                    "session_id": session_id or "",
                })
            elif not session_id:
                intent = "question"

        if intent == "batch":
            identifiers = intent_data.get("identifiers", [])
            id_types = intent_data.get("identifier_types", [])
            if identifiers and len(identifiers) > 1:
                batch_items = []
                for i, ident in enumerate(identifiers):
                    it = id_types[i] if i < len(id_types) else "username"
                    batch_items.append({"identifier": ident.strip(), "identifier_type": it})
                return jsonify({
                    "action": "batch",
                    "params": {"identifiers": batch_items},
                    "message": f"Starting batch investigation on **{len(batch_items)} subjects**...",
                    "session_id": session_id or "",
                })
            intent = "question"

        if intent == "monitor":
            monitor_type = intent_data.get("monitor_type", "keyword")
            query = intent_data.get("query", "")
            if query:
                return jsonify({
                    "action": "monitor",
                    "params": {
                        "monitor_type": monitor_type,
                        "query": query,
                    },
                    "message": f"Setting up **{monitor_type}** monitor for \"{query}\"...",
                    "session_id": session_id or "",
                })
            intent = "question"

        # ── Question intent: RAG pipeline ────────────────────────
        context = ""
        kb_context = ""

        if session_id and validate_session_id(session_id) and session_id in stored_reports:
            try:
                vs = load_vectorstore(session_id)
                docs = vs.similarity_search(question, k=5)
                context = "\n\n".join(doc.page_content for doc in docs)
            except Exception:
                context = stored_reports[session_id]["text"]
            kb_context = _get_kb_context(question)
        else:
            kb_context = _get_kb_context(question)
            if not kb_context:
                return jsonify({
                    "error": "No context available. Upload a document or run an investigation first."
                }), 400
            session_id = session_id or f"kb_{uuid.uuid4().hex[:16]}"

        chain = get_rag_chain()
        chain_input = {
            "context": context,
            "kb_context": kb_context,
            "question": question,
        }

        user_hash = _get_user_hash()
        result = gated_invoke(
            chain,
            chain_input,
            chain_name="rag_chain",
            endpoint="/ask",
            mode="osint",
            session_id=session_id,
            user_hash=user_hash,
            trusted_keys={"context", "kb_context"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        answer = result.content

        _save_to_kb(
            source_route="/ask",
            report_type="qa_answer",
            analysis_text=f"Q: {question}\n\nA: {answer}",
            subject_identifier=question[:100],
            sensitivity_level="INTERNAL",
            source_type="llm_analysis",
        )

        if session_id and session_id in stored_reports:
            prev = stored_reports[session_id].get("text", "")
            stored_reports[session_id]["text"] = (
                prev + f"\n\nQ: {question}\n\nA: {answer}"
            ).strip()
        elif session_id:
            stored_reports[session_id] = {
                "text": f"Q: {question}\n\nA: {answer}",
                "user_email": g.user_session.email if hasattr(g, "user_session") else "unknown",
                "created_at": datetime.now(tz=timezone.utc),
            }

        qa_resp = {
            "answer": answer,
            "session_id": session_id,
            "kb_context": bool(kb_context),
        }
        qa_harm = _score_text_for_harm(context or kb_context)
        if qa_harm:
            qa_resp["civilian_harm"] = qa_harm
        return jsonify(qa_resp)

    # ================================================================
    #  OSINT INVESTIGATION ROUTES (Phase 0)
    # ================================================================

    @app.route("/investigate", methods=["POST"])
    @login_required
    @limiter.limit("20 per hour")
    def investigate():
        """Full OSINT investigation for a subject identifier."""
        # Support both JSON and multipart form data (for media uploads)
        media_files: list[tuple[bytes, str]] = []
        if request.content_type and "multipart/form-data" in request.content_type:
            identifier = request.form.get("identifier", "").strip()
            identifier_type = request.form.get("identifier_type", "").strip().lower()
            platforms_raw = request.form.get("platforms", "")
            try:
                import json as _json
                platforms = _json.loads(platforms_raw) if platforms_raw else list(SOCIAL_PLATFORMS.keys())
            except (ValueError, TypeError):
                platforms = list(SOCIAL_PLATFORMS.keys())
            depth = request.form.get("depth", "standard").strip().lower()
            investigation_purpose = request.form.get("investigation_purpose", "").strip()
            # Collect uploaded media files for EXIF extraction
            for f in request.files.getlist("media_files"):
                if f and f.filename:
                    file_bytes = f.read()
                    if len(file_bytes) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
                        continue
                    media_files.append((file_bytes, f.filename))
            if media_files:
                print(f"[GEO] {len(media_files)} media files uploaded for EXIF extraction")
        else:
            data = request.get_json(silent=True) or {}
            identifier = data.get("identifier", "").strip()
            identifier_type = data.get("identifier_type", "").strip().lower()
            platforms = data.get("platforms", list(SOCIAL_PLATFORMS.keys()))
            depth = data.get("depth", "standard").strip().lower()
            investigation_purpose = data.get("investigation_purpose", "").strip()

        # Input validation
        if not identifier:
            return jsonify({"error": "Identifier is required"}), 400
        if identifier_type not in IDENTIFIER_TYPES:
            return jsonify({
                "error": f"Invalid identifier_type. Must be one of: {', '.join(IDENTIFIER_TYPES)}"
            }), 400
        if depth not in INVESTIGATION_DEPTHS:
            return jsonify({
                "error": f"Invalid depth. Must be one of: {', '.join(INVESTIGATION_DEPTHS.keys())}"
            }), 400

        # Validate and filter platforms
        if isinstance(platforms, list):
            platforms = [p for p in platforms if p in SOCIAL_PLATFORMS]

        # Sanitize identifier
        try:
            clean_id = sanitize_identifier(identifier, identifier_type)
        except Exception:
            clean_id = identifier

        session_id = f"inv_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()
        provenance = ProvenanceTrail(clean_id, identifier_type)

        # ── Phase 1: Initial Dorking (Collection) ─────────────────────
        # Runs BEFORE platform backfill so the LLM sees the user's actual
        # platform selection (empty = broad web sweep with recommendations).
        if request.content_type and "multipart/form-data" in request.content_type:
            web_search_enabled = request.form.get("web_search", "true").lower() in ("true", "1", "yes")
        else:
            web_search_enabled = data.get("web_search", DORK_VALIDATION_ENABLED)
        initial_dork_data = None
        initial_dork_context = ""
        if web_search_enabled and DORK_VALIDATION_ENABLED:
            try:
                initial_dork_data = _run_initial_dorking(
                    subject_identifier=clean_id,
                    identifier_type=identifier_type,
                    platforms=platforms,
                    session_id=session_id,
                    user_hash=user_hash,
                    purpose=investigation_purpose or "OSINT investigation — initial web collection",
                )
                if initial_dork_data and initial_dork_data.get("text"):
                    initial_dork_context = initial_dork_data["text"]
                    print(f"[DORK] Initial collection: {initial_dork_data['queries_run']} queries executed")
            except Exception as exc:
                print(f"[WARN] Initial dorking failed (non-fatal): {exc}")

        # Backfill platforms for OSINT collection if none were selected
        if not platforms:
            platforms = list(SOCIAL_PLATFORMS.keys())

        # ── Phase 2: OSINT Collection ─────────────────────────────────
        osint_client = _get_osint_client()
        geo_client = _get_geo_client()

        try:
            findings = osint_client.investigate(
                clean_id, platforms=platforms, depth=depth,
                elevated_authorization=_is_admin(),
            )
            findings_dict = asdict(findings)
        except Exception as exc:
            print(f"[ERROR] OSINT investigation failed: {exc}")
            return jsonify({"error": "OSINT collection failed. Please try again."}), 500

        provenance.record_collection(
            platforms=findings_dict.get("platforms_queried", platforms),
            findings_summary={
                "profiles": len(findings_dict.get("profiles", [])),
                "posts": len(findings_dict.get("posts", [])),
                "web_mentions": len(findings_dict.get("web_mentions", [])),
                "entities": len(findings_dict.get("entities", [])),
                "geo_points": len(findings_dict.get("geo_points", [])),
            },
        )

        # ── Phase 2b: Process uploaded media for EXIF geo ─────────────
        if media_files:
            try:
                upload_geo = osint_client.extract_geo_from_uploaded_media(media_files)
                if upload_geo:
                    existing_geo = findings_dict.get("geo_points", [])
                    existing_geo.extend(upload_geo)
                    findings_dict["geo_points"] = existing_geo
                    print(f"[GEO] Added {len(upload_geo)} geo points from uploaded media")
            except Exception as exc:
                print(f"[WARN] Uploaded media geo extraction failed (non-fatal): {exc}")

        # ── Phase 2b-ii: Image OSINT analysis ─────────────────────────
        image_analysis_results = []
        if media_files:
            for file_bytes, fname in media_files:
                try:
                    img_result = {"filename": fname}
                    if IMAGE_SEARCH_ENABLED:
                        img_result["reverse_search"] = reverse_image_search(file_bytes, fname)
                    if IMAGE_FORENSICS_ENABLED:
                        img_result["forensics"] = analyze_image_forensics(file_bytes, fname)
                    if IMAGE_STEGO_ENABLED:
                        img_result["steganography"] = detect_steganography(file_bytes, fname)
                    if IMAGE_VISION_ENABLED:
                        img_result["vision"] = clip_analyze_image(file_bytes, fname)
                    if DEEPSEEK_VISION_ENABLED:
                        img_result["deepseek_vision"] = deepseek_describe_image(file_bytes, fname)

                        # Build reverse search context for vision geo
                        rs_context = None
                        rs = img_result.get("reverse_search")
                        if rs:
                            rs_parts = []
                            for eng in ("yandex_results", "google_lens_results", "bing_results"):
                                eng_data = rs.get(eng)
                                if eng_data and eng_data.get("matches"):
                                    for match in eng_data["matches"][:3]:
                                        title = match.get("title", "")
                                        if title:
                                            rs_parts.append(title)
                            if rs_parts:
                                rs_context = "; ".join(rs_parts[:8])

                        try:
                            from app.vision_geolocation import extract_geo_clues
                            vgeo = extract_geo_clues(file_bytes, fname, reverse_search_context=rs_context)
                            img_result["vision_geo"] = vgeo
                            if vgeo.get("geo_points"):
                                existing_geo = findings_dict.get("geo_points", [])
                                for vgp in vgeo["geo_points"]:
                                    vgp["media_url"] = fname
                                    vgp["platform"] = "user_upload"
                                existing_geo.extend(vgeo["geo_points"])
                                findings_dict["geo_points"] = existing_geo
                                print(f"[VISION GEO] {fname}: {len(vgeo['geo_points'])} location(s) from visual clues")
                        except Exception as vge:
                            print(f"[WARN] Vision geo failed for {fname} (non-fatal): {vge}")

                    # GeoCLIP local model geolocation
                    try:
                        from app.geoclip_locator import predict_location, GEOCLIP_ENABLED
                        if GEOCLIP_ENABLED:
                            gc_result = predict_location(file_bytes, filename=fname)
                            img_result["geoclip"] = gc_result
                            if gc_result.get("geo_points"):
                                existing_geo = findings_dict.get("geo_points", [])
                                for gcp in gc_result["geo_points"]:
                                    gcp["media_url"] = fname
                                    gcp["platform"] = "user_upload"
                                existing_geo.extend(gc_result["geo_points"])
                                findings_dict["geo_points"] = existing_geo
                                print(f"[GEOCLIP] {fname}: {len(gc_result['geo_points'])} location(s)")
                    except Exception as gce:
                        print(f"[WARN] GeoCLIP failed for {fname} (non-fatal): {gce}")
                    image_analysis_results.append(img_result)
                except Exception as exc:
                    print(f"[WARN] Image analysis failed for {fname} (non-fatal): {exc}")
            if image_analysis_results:
                print(f"[IMAGE] Analysed {len(image_analysis_results)} images")

        # ── Phase 2c: Wayback Machine enrichment (domains only) ───────
        if identifier_type.lower() == "domain":
            try:
                from app.wayback_client import get_wayback_client
                wb_client = get_wayback_client()
                wb_report = wb_client.enrich_domain(clean_id)
                wb_findings = wb_client.to_osint_findings(wb_report)
                if wb_findings:
                    existing_web = findings_dict.get("web_mentions", [])
                    existing_web.extend(wb_findings)
                    findings_dict["web_mentions"] = existing_web
                    if "Wayback Machine" not in findings_dict.get("platforms_queried", []):
                        findings_dict.setdefault("platforms_queried", []).append("Wayback Machine")
                    print(f"[WAYBACK] Enriched {clean_id}: {len(wb_findings)} findings, "
                          f"{wb_report.total_snapshots} snapshots, "
                          f"{len(wb_report.subdomains)} subdomains")
            except Exception as exc:
                print(f"[WARN] Wayback Machine enrichment failed (non-fatal): {exc}")

        # ── Phase 2d: Civilian harm scoring (Bellingcat methodology) ──
        civilian_harm_data = None
        try:
            civilian_harm_data = _run_civilian_harm_analysis(findings_dict)
        except Exception as exc:
            print(f"[WARN] Civilian harm scoring failed (non-fatal): {exc}")

        # ── Phase 3: Context Preparation ──────────────────────────────
        osint_context = _findings_to_context(findings_dict)
        geo_data_raw = findings_dict.get("geo_points", [])

        # Filter geo points: only those above the confidence floor are
        # accepted.  Rejected points (NLP mentions, low-confidence OCR,
        # etc.) are excluded from the map AND the LLM report context.
        accepted_geo, rejected_geo = _filter_geo_points(geo_data_raw)
        if rejected_geo:
            print(
                f"[GEO] Rejected {len(rejected_geo)}/{len(geo_data_raw)} geo points "
                f"below {GEO_CONFIDENCE_FLOOR:.0%} confidence: "
                + ", ".join(
                    f"{gp.get('source','?')}({gp.get('confidence',0):.0%})"
                    for gp in rejected_geo[:10]
                )
            )
        geo_context = _geo_points_to_text(accepted_geo)

        # Build entity graph
        entities_data = findings_dict.get("entities", [])
        normalized_entities = []
        for e in entities_data:
            ne = dict(e)
            if "entity_type" in ne and "type" not in ne:
                ne["type"] = ne["entity_type"]
            if "entity_value" in ne and "name" not in ne:
                ne["name"] = ne["entity_value"]
            normalized_entities.append(ne)
        try:
            entity_graph = build_entity_graph(normalized_entities)
            # Add investigation subject as central hub node
            subject_nid = f"{identifier_type}:{clean_id.strip().lower().replace(' ', '_')[:80]}"
            if subject_nid not in entity_graph:
                entity_graph.add_node(subject_nid, type=identifier_type, label=clean_id)
            for nid in list(entity_graph.nodes()):
                if nid != subject_nid and not entity_graph.has_edge(subject_nid, nid):
                    entity_graph.add_edge(subject_nid, nid, relationship="associated_with")
            graph_json = graph_to_cytoscape_json(entity_graph)
            entity_graph_ctx = graph_context(entity_graph, max_chars=4000)
            graph_cache_key = cache_graph(entity_graph, session_id)
        except Exception as exc:
            print(f"[WARN] Graph construction failed (non-fatal): {exc}")
            entity_graph = None
            graph_json = {"nodes": [], "edges": []}
            entity_graph_ctx = "No entity graph available."
            graph_cache_key = ""

        # Persist entity relationships to SQLite for cross-investigation queries
        try:
            if entity_graph and entity_graph.number_of_edges() > 0:
                persisted = persist_relationships(entity_graph, get_report_store())
                print(f"[GRAPH] Persisted {persisted} relationships for {clean_id}")
        except Exception as exc:
            print(f"[WARN] Relationship persistence failed (non-fatal): {exc}")

        # Build map data — ONLY from accepted geo points.
        # Run triangulation first to identify spatial outliers via DBSCAN,
        # then build markers from the cluster points only.
        map_data = {}
        try:
            if accepted_geo:
                from app.geo_client import GeoDataPoint as GeoDP

                # Convert to GeoDataPoint objects for triangulation
                tri_points = []
                for gp in accepted_geo:
                    lat = gp.get("lat")
                    lon = gp.get("lon") or gp.get("lng")
                    if lat is None or lon is None:
                        continue
                    tri_points.append(GeoDP(
                        lat=float(lat), lon=float(lon),
                        label=gp.get("label") or gp.get("name", ""),
                        source=gp.get("source", "osint"),
                        confidence=gp.get("confidence", 0.5),
                        timestamp=gp.get("timestamp", ""),
                    ))

                # Run triangulation to cluster and reject spatial outliers
                tri_result = None
                outlier_coords: set[tuple[float, float]] = set()
                if len(tri_points) >= 2:
                    try:
                        tri_result = _get_geo_client().triangulate(tri_points)
                        if tri_result and tri_result.outliers:
                            outlier_coords = {
                                (round(o.lat, 6), round(o.lon, 6))
                                for o in tri_result.outliers
                            }
                            print(
                                f"[GEO] Triangulation rejected {len(tri_result.outliers)} "
                                f"spatial outliers via {tri_result.method}"
                            )
                    except Exception as tri_exc:
                        print(f"[DEBUG] Triangulation skipped: {tri_exc}")

                # Build markers from accepted + non-outlier points only
                markers = []
                for gp in accepted_geo:
                    lat = gp.get("lat")
                    lon = gp.get("lon") or gp.get("lng")
                    if lat is None or lon is None:
                        continue
                    coord_key = (round(float(lat), 6), round(float(lon), 6))
                    if coord_key in outlier_coords:
                        continue
                    desc_parts = []
                    if gp.get("method"):
                        desc_parts.append(gp["method"].replace("_", " "))
                    if gp.get("platform"):
                        desc_parts.append(f"via {gp['platform']}")
                    if gp.get("detected_text"):
                        desc_parts.append(f'text: "{gp["detected_text"][:60]}"')
                    markers.append({
                        "lat": float(lat),
                        "lng": float(lon),
                        "label": gp.get("label") or gp.get("name", ""),
                        "source_type": gp.get("source", "osint"),
                        "confidence": gp.get("confidence", 0.5),
                        "description": " | ".join(desc_parts) if desc_parts else "",
                    })

                if markers:
                    lats = [m["lat"] for m in markers]
                    lngs = [m["lng"] for m in markers]
                    map_data = {
                        "markers": markers,
                        "center": [sum(lats) / len(lats), sum(lngs) / len(lngs)],
                        "zoom": GeoClient._auto_zoom(
                            [min(lats), min(lngs)],
                            [max(lats), max(lngs)],
                        ) if len(markers) > 1 else 10,
                        "points_rejected": len(rejected_geo) + len(outlier_coords),
                        "points_accepted": len(markers),
                    }
                    if tri_result and tri_result.center_lat:
                        map_data["triangulation"] = {
                            "center": {"lat": tri_result.center_lat, "lng": tri_result.center_lon},
                            "confidence_radius": tri_result.radius_m,
                            "source_points": [{"lat": m["lat"], "lng": m["lng"]} for m in markers],
                            "method": tri_result.method,
                            "confidence": tri_result.confidence,
                        }
                    print(
                        f"[GEO] Map: {len(markers)} markers rendered, "
                        f"{len(rejected_geo)} below confidence, "
                        f"{len(outlier_coords)} spatial outliers removed"
                    )
        except Exception as exc:
            print(f"[WARN] Map data construction failed (non-fatal): {exc}")

        # Generate charts
        charts = {}
        try:
            all_findings = (
                findings_dict.get("profiles", [])
                + findings_dict.get("posts", [])
                + findings_dict.get("web_mentions", [])
            )
            charts = generate_investigation_charts(all_findings, entities_data)
        except Exception as exc:
            print(f"[WARN] Chart generation failed (non-fatal): {exc}")

        # ── Phase 4: LLM Analysis ────────────────────────────────────
        # Include initial dork results in the OSINT data so the LLM can
        # reference web discoveries alongside platform findings.
        full_osint_context = osint_context
        if initial_dork_context:
            full_osint_context += (
                "\n\n--- INITIAL WEB COLLECTION (pre-OSINT dorking) ---\n"
                + initial_dork_context
            )
        if civilian_harm_data and civilian_harm_data.get("flagged_count", 0) > 0:
            harm_lines = [
                "\n\n--- CIVILIAN HARM ANALYSIS (Bellingcat methodology) ---",
                f"Scored {civilian_harm_data['total_scored']} items. "
                f"{civilian_harm_data['flagged_count']} flagged "
                f"(max score: {civilian_harm_data.get('max_score', 0):.2f}).",
                "Distribution: " + ", ".join(
                    f"{k}: {v}" for k, v in civilian_harm_data.get("distribution", {}).items()
                ),
            ]
            for item in civilian_harm_data.get("flagged", [])[:5]:
                hs = item.get("harm_score", {})
                harm_lines.append(
                    f"- [{hs.get('classification', '?')} {hs.get('score', 0):.2f}] "
                    f"({item.get('platform', '?')}) {item.get('content', '')[:200]}"
                )
            full_osint_context += "\n".join(harm_lines)

        if image_analysis_results:
            img_lines = ["\n\n--- IMAGE ANALYSIS ---"]
            for ir in image_analysis_results:
                img_lines.append(f"\n**{ir['filename']}**:")
                if ir.get("forensics", {}).get("overall_verdict"):
                    img_lines.append(f"  Forensics: {ir['forensics']['overall_verdict']} (confidence {ir['forensics'].get('confidence', 0):.0%})")
                    for flag in ir["forensics"].get("flags", []):
                        img_lines.append(f"    - {flag}")
                if ir.get("steganography", {}).get("overall_verdict"):
                    img_lines.append(f"  Steganography: {ir['steganography']['overall_verdict']} (confidence {ir['steganography'].get('confidence', 0):.0%})")
                if ir.get("vision", {}).get("classifications"):
                    top = ir["vision"]["classifications"][:3]
                    cls_parts = [c["category"] + " (" + f"{c['confidence']:.0%}" + ")" for c in top]
                    img_lines.append(f"  CLIP classification: {', '.join(cls_parts)}")
                if ir.get("vision", {}).get("landmarks"):
                    img_lines.append(f"  Landmarks: {', '.join(lm['name'] for lm in ir['vision']['landmarks'][:3])}")
                if ir.get("vision", {}).get("safety", {}).get("classification") not in (None, "safe"):
                    img_lines.append(f"  Safety: {ir['vision']['safety']['classification']} ({ir['vision']['safety'].get('score', 0):.0%})")
                if ir.get("deepseek_vision", {}).get("description"):
                    img_lines.append(f"  AI Scene Analysis: {ir['deepseek_vision']['description']}")
                if ir.get("vision_geo", {}).get("geo_points"):
                    vgps = ir["vision_geo"]["geo_points"]
                    img_lines.append(f"  Vision Geolocation: {len(vgps)} candidate location(s)")
                    for vgp in vgps[:3]:
                        img_lines.append(f"    - {vgp.get('label', '?')} ({vgp.get('lat', '?')}, {vgp.get('lon', '?')}) "
                                         f"conf={vgp.get('confidence', 0):.0%} — {vgp.get('vision_reasoning', '')}")
                if ir.get("reverse_search", {}).get("similar_cached"):
                    img_lines.append(f"  Similar images in cache: {len(ir['reverse_search']['similar_cached'])}")
                if ir.get("reverse_search", {}).get("tineye_results"):
                    img_lines.append(f"  TinEye matches: {len(ir['reverse_search']['tineye_results'])}")
            full_osint_context += "\n".join(img_lines)

        chain = get_investigation_chain()
        chain_input = {
            "osint_data": full_osint_context,
            "geo_data": geo_context,
            "entity_graph_context": entity_graph_ctx,
            "subject_identifier": clean_id,
            "identifier_type": identifier_type,
            "elevated_authorization": _is_admin(),
            "purpose": investigation_purpose or "OSINT investigation",
        }

        result = gated_invoke(
            chain,
            chain_input,
            chain_name="investigation_chain",
            endpoint="/investigate",
            mode="osint",
            session_id=session_id,
            user_hash=user_hash,
            trusted_keys={"osint_data", "geo_data", "entity_graph_context"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        analysis = result.content
        sensitivity = findings_dict.get("sensitivity_level", "INTERNAL")
        provenance.record_analysis(
            chain_name="investigation_chain",
            analysis_text=analysis,
            forgechain_block_id=result.block_id or "",
        )

        # ── Phase 5: Final Dorking + Report Consolidation ────────
        web_intelligence = None
        if web_search_enabled and DORK_VALIDATION_ENABLED:
            try:
                entities_text = "\n".join(
                    f"- {e.get('name', '')} ({e.get('type', '')})" for e in entities_data[:30]
                ) or "No entities extracted."

                web_intelligence = _run_final_dorking(
                    analysis_text=analysis,
                    osint_summary=osint_context[:4000],
                    entities_summary=entities_text,
                    session_id=session_id,
                    user_hash=user_hash,
                    purpose=investigation_purpose or "OSINT investigation — final validation",
                )
                if web_intelligence and web_intelligence.get("text"):
                    print(f"[DORK] Final dorking complete ({web_intelligence['queries_run']} queries), running consolidation...")
            except Exception as exc:
                print(f"[WARN] Final dorking failed (non-fatal): {exc}")

        # ── Phase 6: Report Consolidation ────────
        # Merge initial analysis + web intel + civilian harm into a single cohesive brief
        if web_intelligence and web_intelligence.get("text"):
            harm_summary = "No civilian harm data."
            if civilian_harm_data and civilian_harm_data.get("flagged_count", 0) > 0:
                harm_lines = [
                    f"Scored {civilian_harm_data['total_scored']} items. "
                    f"{civilian_harm_data['flagged_count']} flagged "
                    f"(max score: {civilian_harm_data.get('max_score', 0):.2f}).",
                    "Distribution: " + ", ".join(
                        f"{k}: {v}" for k, v in civilian_harm_data.get("distribution", {}).items()
                    ),
                ]
                for item in civilian_harm_data.get("flagged", [])[:5]:
                    hs = item.get("harm_score", {})
                    harm_lines.append(
                        f"- [{hs.get('classification', '?')} {hs.get('score', 0):.2f}] "
                        f"({item.get('platform', '?')}) {item.get('content', '')[:200]}"
                    )
                harm_summary = "\n".join(harm_lines)

            try:
                consolidation_chain = get_report_consolidation_chain()
                consolidation_input = {
                    "initial_analysis": analysis,
                    "web_intelligence": web_intelligence["text"],
                    "civilian_harm_summary": harm_summary,
                    "subject_identifier": clean_id,
                    "identifier_type": identifier_type,
                    "purpose": investigation_purpose or "OSINT investigation — report consolidation",
                }
                # All inputs are pre-verified: initial_analysis passed ForgeChain
                # in Phase 4, web_intelligence passed multiple ForgeChain gates in
                # Phase 5, and civilian_harm_summary is locally computed.  Running
                # another gate here is redundant and can false-positive on scraped
                # web content that already cleared sanitisation.
                consolidation_raw = consolidation_chain.invoke(consolidation_input)
                analysis = consolidation_raw.content if hasattr(consolidation_raw, "content") else str(consolidation_raw)
                print("[CONSOLIDATION] Report consolidated successfully")
            except Exception as exc:
                analysis += "\n\n---\n\n## Web Intelligence\n\n" + web_intelligence["text"]
                print(f"[WARN] Consolidation failed ({exc}), falling back to append")

        # ── Phase 7: Output Grounding Verification ────────
        grounding_result = None
        try:
            grounding_result = verify_grounding(analysis, full_osint_context)
            print(
                f"[GROUNDING] {grounding_result['verdict']}: "
                f"{grounding_result['grounded_ratio']:.0%} claims grounded "
                f"({grounding_result['total_claims']} total, "
                f"{grounding_result['ungrounded_claims']} ungrounded)"
            )
        except Exception as exc:
            print(f"[WARN] Grounding verification failed (non-fatal): {exc}")

        if grounding_result:
            provenance.record_verification(
                "Grounding Verification",
                grounding_result.get("verdict", ""),
                f"{grounding_result.get('grounded_ratio', 0):.0%} grounded",
            )

        # ── Phase 7b: Self-Consistency Check (optional) ────────
        self_consistency_result = None
        if SELF_CONSISTENCY_ENABLED:
            try:
                self_consistency_result = run_self_consistency_check(
                    chain=chain,
                    chain_input=chain_input,
                    primary_output=analysis,
                    gated_invoke_fn=gated_invoke,
                    gated_invoke_kwargs={
                        "chain_name": "investigation_chain",
                        "endpoint": "/investigate",
                        "mode": "osint",
                        "session_id": session_id,
                        "user_hash": user_hash,
                        "trusted_keys": {"osint_data", "geo_data", "entity_graph_context"},
                    },
                )
                print(
                    f"[CONSISTENCY] {self_consistency_result['verdict']}: "
                    f"{self_consistency_result['consistency_ratio']:.0%} stable "
                    f"({self_consistency_result['runs_completed']} runs)"
                )
            except Exception as exc:
                print(f"[WARN] Self-consistency check failed (non-fatal): {exc}")

        # ── Phase 8: Competing Hypotheses (ACH) ────────
        competing_hypotheses = None
        try:
            ach_chain = get_competing_hypotheses_chain()
            ach_input = {
                "analysis_text": analysis,
                "osint_summary": full_osint_context[:6000],
            }
            ach_raw = ach_chain.invoke(ach_input)
            competing_hypotheses = ach_raw.content if hasattr(ach_raw, "content") else str(ach_raw)
            print(f"[ACH] Competing hypotheses generated ({len(competing_hypotheses)} chars)")
        except Exception as exc:
            print(f"[WARN] Competing hypotheses generation failed (non-fatal): {exc}")

        # ── Phase 9: Bias Audit ────────
        bias_audit_result = None
        try:
            bias_audit_result = run_bias_audit(
                report_text=analysis,
                findings_dict=findings_dict,
                platforms_queried=findings_dict.get("platforms_queried", platforms),
            )
            print(
                f"[BIAS] Audit complete: {bias_audit_result['overall_risk']} "
                f"({len(bias_audit_result['warnings'])} warnings)"
            )
        except Exception as exc:
            print(f"[WARN] Bias audit failed (non-fatal): {exc}")

        if bias_audit_result:
            provenance.record_verification(
                "Bias Audit",
                bias_audit_result.get("overall_risk", ""),
                f"{len(bias_audit_result.get('warnings', []))} warnings",
            )

        # ── Phase 10: Report Refinement ────────
        # Use integrity results to produce a clean, high-confidence report.
        # All framework details stay in the background.
        try:
            grounding_summary = "No grounding data available."
            if grounding_result:
                ungrounded = grounding_result.get("ungrounded_details", [])
                ungrounded_list = "; ".join(
                    c.get("claim", "")[:120] for c in ungrounded[:10]
                ) if ungrounded else "none"
                grounding_summary = (
                    f"Verdict: {grounding_result['verdict']}. "
                    f"{grounding_result.get('grounded_ratio', 0):.0%} of claims grounded. "
                    f"Ungrounded claims: {ungrounded_list}"
                )

            bias_summary = "No bias audit data available."
            if bias_audit_result:
                warnings = bias_audit_result.get("warnings", [])
                bias_summary = (
                    f"Overall risk: {bias_audit_result['overall_risk']}. "
                    f"Warnings: {'; '.join(warnings[:5]) if warnings else 'none'}"
                )

            hypotheses_summary = competing_hypotheses or "No competing hypotheses generated."

            consistency_summary = "No consistency data available."
            if self_consistency_result:
                unstable = self_consistency_result.get("unstable_details", [])
                unstable_list = "; ".join(
                    c.get("claim", "")[:120] for c in unstable[:10]
                ) if unstable else "none"
                consistency_summary = (
                    f"Verdict: {self_consistency_result['verdict']}. "
                    f"{self_consistency_result.get('consistency_ratio', 0):.0%} stable. "
                    f"Unstable claims: {unstable_list}"
                )

            refinement_chain = get_report_refinement_chain()
            refinement_input = {
                "raw_report": analysis,
                "grounding_summary": grounding_summary,
                "bias_summary": bias_summary,
                "hypotheses_summary": hypotheses_summary[:6000],
                "consistency_summary": consistency_summary,
            }
            refinement_raw = gated_invoke(
                refinement_chain,
                refinement_input,
                chain_name="report_refinement_chain",
                endpoint="/investigate",
                mode="osint",
                session_id=session_id,
                user_hash=user_hash,
                trusted_keys={"raw_report", "grounding_summary", "bias_summary",
                              "hypotheses_summary", "consistency_summary"},
            )
            analysis = refinement_raw.content if hasattr(refinement_raw, "content") else str(refinement_raw)
            provenance.record_analysis("report_refinement_chain", analysis)
            print(f"[REFINEMENT] Final report produced ({len(analysis)} chars)")
        except Exception as exc:
            print(f"[WARN] Report refinement failed (non-fatal), using raw report: {exc}")

        # Save to knowledge base
        report_id = _save_to_kb(
            source_route="/investigate",
            report_type="investigation",
            analysis_text=analysis,
            subject_identifier=clean_id,
            identifier_type=identifier_type,
            sensitivity_level=sensitivity,
            platforms_queried=findings_dict.get("platforms_queried", platforms),
            entity_count=len(entities_data),
            source_count=len(findings_dict.get("platforms_queried", [])),
            source_type="llm_analysis",
        )

        # Cache in-memory for follow-up queries and export
        stored_reports[session_id] = {
            "text": analysis,
            "entities": entities_data,
            "sensitivity_level": sensitivity,
            "identifier": clean_id,
            "chart_data": charts,
            "map_data": map_data,
            "entity_graph": graph_json,
            "user_email": g.user_session.email if hasattr(g, "user_session") else "unknown",
            "created_at": datetime.now(tz=timezone.utc),
            "civilian_harm": civilian_harm_data,
            "image_analysis": image_analysis_results or None,
        }

        response = {
            "report_id": report_id,
            "session_id": session_id,
            "analysis": analysis,
            "map_data": map_data,
            "entity_graph": graph_json,
            "charts": charts,
            "sensitivity_level": sensitivity,
            "identifier": clean_id,
            "identifier_type": identifier_type,
            "entities": entities_data,
            "entity_count": len(entities_data),
            "source_count": len(findings_dict.get("platforms_queried", [])),
            "metadata": findings_dict.get("metadata", {}),
        }
        if image_analysis_results:
            safe_results = []
            for ir in image_analysis_results:
                safe_ir = {k: v for k, v in ir.items()}
                if "forensics" in safe_ir and "ela" in safe_ir.get("forensics", {}):
                    safe_ir["forensics"] = dict(safe_ir["forensics"])
                    safe_ir["forensics"].pop("ela_image_b64", None)
                    if "ela" in safe_ir["forensics"]:
                        safe_ir["forensics"]["ela"] = dict(safe_ir["forensics"]["ela"])
                        safe_ir["forensics"]["ela"].pop("ela_image_b64", None)
                if "steganography" in safe_ir and "lsb_analysis" in safe_ir.get("steganography", {}):
                    safe_ir["steganography"] = dict(safe_ir["steganography"])
                    if "lsb_analysis" in safe_ir["steganography"]:
                        safe_ir["steganography"]["lsb_analysis"] = dict(safe_ir["steganography"]["lsb_analysis"])
                        safe_ir["steganography"]["lsb_analysis"].pop("lsb_visual_b64", None)
                safe_results.append(safe_ir)
            response["image_analysis"] = safe_results
        if graph_cache_key:
            response["graph_cache_key"] = graph_cache_key

        # Combine initial + final dork data into unified web_intelligence
        wi_data = {}
        if initial_dork_data and initial_dork_data.get("data"):
            wi_data["initial_collection"] = initial_dork_data["data"]
            wi_data["initial_queries_run"] = initial_dork_data.get("queries_run", 0)
        if web_intelligence and web_intelligence.get("data"):
            wi_data["final_validation"] = web_intelligence["data"]
            wi_data["final_queries_run"] = web_intelligence.get("queries_run", 0)
        if wi_data:
            response["web_intelligence"] = wi_data
        if civilian_harm_data:
            response["civilian_harm"] = civilian_harm_data

        return jsonify(response)

    @app.route("/analyze-image", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def analyze_image_endpoint():
        """Standalone image analysis: forensics, reverse search, stego, CLIP, DeepSeek Vision."""
        if not request.files:
            return jsonify({"error": "No image files uploaded"}), 400

        run_forensics = IMAGE_FORENSICS_ENABLED and request.form.get("mod_forensics", "1") == "1"
        run_stego = IMAGE_STEGO_ENABLED and request.form.get("mod_stego", "1") == "1"
        run_search = IMAGE_SEARCH_ENABLED and request.form.get("mod_search", "1") == "1"
        run_vision = IMAGE_VISION_ENABLED and request.form.get("mod_vision", "1") == "1"
        run_deepseek = DEEPSEEK_VISION_ENABLED and request.form.get("mod_deepseek", "1") == "1"
        run_vision_geo = DEEPSEEK_VISION_ENABLED and request.form.get("mod_vision_geo", "1") == "1"

        results = []
        for f in request.files.getlist("images"):
            if not f or not f.filename:
                continue
            file_bytes = f.read()
            if len(file_bytes) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
                results.append({"filename": f.filename, "error": "File too large"})
                continue
            try:
                img_result = {"filename": f.filename}
                if run_search:
                    img_result["reverse_search"] = reverse_image_search(file_bytes, f.filename)
                if run_forensics:
                    img_result["forensics"] = analyze_image_forensics(file_bytes, f.filename)
                if run_stego:
                    img_result["steganography"] = detect_steganography(file_bytes, f.filename)
                if run_vision:
                    img_result["vision"] = clip_analyze_image(file_bytes, f.filename)
                if run_deepseek:
                    img_result["deepseek_vision"] = deepseek_describe_image(file_bytes, f.filename)
                if run_vision_geo:
                    rs_ctx = None
                    rs = img_result.get("reverse_search")
                    if rs:
                        rs_parts = []
                        for eng in ("yandex_results", "google_lens_results", "bing_results"):
                            eng_data = rs.get(eng)
                            if eng_data and eng_data.get("matches"):
                                for m in eng_data["matches"][:3]:
                                    if m.get("title"):
                                        rs_parts.append(m["title"])
                        if rs_parts:
                            rs_ctx = "; ".join(rs_parts[:8])
                    try:
                        from app.vision_geolocation import extract_geo_clues
                        img_result["vision_geo"] = extract_geo_clues(file_bytes, f.filename, reverse_search_context=rs_ctx)
                    except Exception as vge:
                        print(f"[WARN] Vision geo failed for {f.filename}: {vge}")
                    try:
                        from app.geoclip_locator import predict_location, GEOCLIP_ENABLED
                        if GEOCLIP_ENABLED:
                            img_result["geoclip"] = predict_location(file_bytes, filename=f.filename)
                    except Exception as gce:
                        print(f"[WARN] GeoCLIP failed for {f.filename}: {gce}")
                results.append(img_result)
            except Exception as exc:
                results.append({"filename": f.filename, "error": str(exc)})

        return jsonify({
            "results": results,
            "modules": {
                "reverse_search": run_search,
                "forensics": run_forensics,
                "steganography": run_stego,
                "vision": run_vision,
                "deepseek_vision": run_deepseek,
                "vision_geo": run_vision_geo,
            },
        })

    @app.route("/enrich", methods=["POST"])
    @login_required
    @limiter.limit("15 per hour")
    def enrich():
        """Enrich an existing document with OSINT data."""
        data = request.get_json(silent=True) or {}
        session_id = data.get("session_id")
        identifier = data.get("identifier", "").strip()
        identifier_type = data.get("identifier_type", "username").strip().lower()
        investigation_purpose = data.get("investigation_purpose", "").strip()

        # Need either a session (uploaded doc) or explicit text
        document_text = ""
        if session_id and validate_session_id(session_id) and session_id in stored_reports:
            document_text = stored_reports[session_id].get("text", "")
        else:
            document_text = data.get("document_text", "").strip()

        if not document_text:
            return jsonify({
                "error": "No document to enrich. Upload a document first or provide document_text."
            }), 400

        if not identifier:
            return jsonify({"error": "Identifier is required for enrichment"}), 400

        try:
            clean_id = sanitize_identifier(identifier, identifier_type)
        except Exception:
            clean_id = identifier

        enrich_session_id = f"enr_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()

        # Initial dorking for enrichment context
        web_search_enabled = data.get("web_search", DORK_VALIDATION_ENABLED)
        initial_dork_context = ""
        if web_search_enabled and DORK_VALIDATION_ENABLED:
            try:
                initial_dork_data = _run_initial_dorking(
                    subject_identifier=clean_id,
                    identifier_type=identifier_type,
                    platforms=[],
                    session_id=enrich_session_id,
                    user_hash=user_hash,
                    purpose=investigation_purpose or "Document enrichment — initial web collection",
                )
                if initial_dork_data and initial_dork_data.get("text"):
                    initial_dork_context = initial_dork_data["text"]
            except Exception as exc:
                print(f"[WARN] Initial dorking for /enrich failed (non-fatal): {exc}")

        # OSINT collection
        osint_client = _get_osint_client()
        try:
            findings = osint_client.investigate(clean_id, depth="standard")
            findings_dict = asdict(findings)
        except Exception as exc:
            print(f"[ERROR] OSINT enrichment collection failed: {exc}")
            return jsonify({"error": "OSINT collection failed."}), 500

        osint_context = _findings_to_context(findings_dict)
        if initial_dork_context:
            osint_context += "\n\n--- INITIAL WEB COLLECTION ---\n" + initial_dork_context
        enrich_accepted_geo, _ = _filter_geo_points(findings_dict.get("geo_points", []))
        geo_context = _geo_points_to_text(enrich_accepted_geo)

        # Extract entities from document for cross-referencing
        entities_data = findings_dict.get("entities", [])
        extracted_entities = "\n".join(
            f"[{e.get('entity_type', '?')}] {e.get('entity_value', '?')}"
            for e in entities_data[:30]
        ) or "No entities extracted."

        # Build entity graph for relationship context
        try:
            entity_graph = build_investigation_graph(entities_data)
            entity_graph_ctx = graph_context(entity_graph, max_chars=4000)
        except Exception as exc:
            print(f"[WARN] Graph construction failed in /enrich (non-fatal): {exc}")
            entity_graph_ctx = "No entity graph available."

        chain = get_enrichment_chain()
        chain_input = {
            "document_text": document_text[:8000],
            "extracted_entities": extracted_entities,
            "osint_data": osint_context,
            "geo_data": geo_context,
            "entity_graph_context": entity_graph_ctx,
        }

        result = gated_invoke(
            chain,
            chain_input,
            chain_name="enrichment_chain",
            endpoint="/enrich",
            mode="osint",
            session_id=enrich_session_id,
            user_hash=user_hash,
            trusted_keys={"document_text", "osint_data", "geo_data", "entity_graph_context"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        analysis = result.content
        sensitivity = findings_dict.get("sensitivity_level", "INTERNAL")

        # Output grounding verification
        enrich_grounding = None
        try:
            enrich_grounding = verify_grounding(analysis, osint_context)
            print(
                f"[GROUNDING] /enrich {enrich_grounding['verdict']}: "
                f"{enrich_grounding['grounded_ratio']:.0%} grounded"
            )
        except Exception as exc:
            print(f"[WARN] Grounding verification failed in /enrich (non-fatal): {exc}")

        report_id = _save_to_kb(
            source_route="/enrich",
            report_type="enrichment",
            analysis_text=analysis,
            subject_identifier=clean_id,
            identifier_type=identifier_type,
            sensitivity_level=sensitivity,
            entity_count=len(entities_data),
            source_type="llm_analysis",
        )

        enrich_resp = {
            "report_id": report_id,
            "session_id": enrich_session_id,
            "analysis": analysis,
            "sensitivity_level": sensitivity,
            "identifier": clean_id,
            "entity_count": len(entities_data),
            "metadata": findings_dict.get("metadata", {}),
        }
        return jsonify(enrich_resp)

    @app.route("/triangulate", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def triangulate():
        """Geolocation triangulation from multiple data points."""

        # Handle image uploads (multipart/form-data from the Images tab)
        uploaded_images = request.files.getlist("images")
        if uploaded_images:
            from app.metadata_extractor import MetadataExtractor
            from app.geo_client import GeoDataPoint as _GeoDP

            extractor = MetadataExtractor()
            image_bytes_list = []
            for f in uploaded_images:
                img_data = f.read()
                if img_data:
                    image_bytes_list.append(img_data)

            if not image_bytes_list:
                return jsonify({"error": "No valid image data received"}), 400

            geo_results = extractor.extract_geo_from_images(image_bytes_list)

            data_points = []
            for gp in geo_results:
                data_points.append({
                    "type": "coordinates",
                    "lat": gp["lat"],
                    "lon": gp["lon"],
                    "label": f"EXIF ({gp.get('gps_date', '')})".strip(),
                    "source": "exif",
                    "confidence": 0.95,
                })

            # Vision geolocation fallback when EXIF is absent
            vision_clues = None
            if not data_points:
                try:
                    from app.vision_geolocation import extract_geo_clues
                    from app.image_deepseek_vision import DEEPSEEK_VISION_ENABLED
                    if DEEPSEEK_VISION_ENABLED:
                        for img_data in image_bytes_list:
                            vr = extract_geo_clues(img_data)
                            print(f"[VISION GEO] Result: enabled={vr.get('enabled')}, "
                                  f"method={vr.get('method')}, "
                                  f"geo_points={len(vr.get('geo_points', []))}, "
                                  f"error={vr.get('error', 'none')}")
                            if vr.get("clues"):
                                vision_clues = vr["clues"]
                                locs = vr["clues"].get("locations", [])
                                if locs:
                                    print(f"[VISION GEO] Locations identified: "
                                          f"{[l.get('name','?')+' ('+str(l.get('confidence','?'))+')' for l in locs[:3]]}")
                            for vgp in vr.get("geo_points", []):
                                data_points.append({
                                    "type": "coordinates",
                                    "lat": vgp["lat"],
                                    "lon": vgp["lon"],
                                    "label": vgp.get("label", "AI Vision Geo"),
                                    "source": "vision_geolocation",
                                    "confidence": vgp.get("confidence", 0.5),
                                    "vision_reasoning": vgp.get("vision_reasoning", ""),
                                })
                        if data_points:
                            print(f"[VISION GEO] Found {len(data_points)} location(s) via AI vision analysis")
                    else:
                        print("[VISION GEO] Skipped — DEEPSEEK_VISION_ENABLED is False")
                except Exception as exc:
                    print(f"[WARN] Vision geolocation failed (non-fatal): {exc}")
                    import traceback
                    traceback.print_exc()

                # GeoCLIP local model fallback
                try:
                    from app.geoclip_locator import predict_location, GEOCLIP_ENABLED
                    if GEOCLIP_ENABLED:
                        for img_data in image_bytes_list:
                            gc = predict_location(img_data)
                            print(f"[GEOCLIP] Result: enabled={gc.get('enabled')}, "
                                  f"available={gc.get('available')}, "
                                  f"reason={gc.get('reason', 'ok')}, "
                                  f"predictions={len(gc.get('predictions', []))}, "
                                  f"geo_points={len(gc.get('geo_points', []))}, "
                                  f"error={gc.get('error', 'none')}")
                            for gcp in gc.get("geo_points", []):
                                data_points.append({
                                    "type": "coordinates",
                                    "lat": gcp["lat"],
                                    "lon": gcp["lon"],
                                    "label": gcp.get("label", "GeoCLIP Prediction"),
                                    "source": "geoclip",
                                    "confidence": gcp.get("confidence", 0.4),
                                })
                        if data_points:
                            print(f"[GEOCLIP] Found {len(data_points)} location(s) via GeoCLIP")
                    else:
                        print("[GEOCLIP] Skipped — GEOCLIP_ENABLED is False")
                except ImportError:
                    print("[GEOCLIP] Skipped — geoclip package not installed")
                except Exception as exc:
                    print(f"[WARN] GeoCLIP failed (non-fatal): {exc}")

            if not data_points:
                err_detail = "No location data found. Images contain no EXIF GPS data."
                if vision_clues and vision_clues.get("locations"):
                    loc_names = [l.get("name", "?") for l in vision_clues["locations"][:3]]
                    err_detail += (f" AI vision identified possible location(s): "
                                   f"{', '.join(loc_names)}, but geocoding to coordinates failed.")
                else:
                    err_detail += " AI vision analysis could not identify a location."
                return jsonify({"error": err_detail}), 400

            data = {"data_points": data_points}
            subject_context = ""
            investigation_purpose = ""
        else:
            data = request.get_json(silent=True) or {}
            data_points = data.get("data_points", [])
            subject_context = data.get("subject_context", "").strip()
            investigation_purpose = data.get("investigation_purpose", "").strip()

        if not data_points or not isinstance(data_points, list):
            return jsonify({"error": "data_points (list) is required"}), 400

        if len(data_points) > 100:
            return jsonify({"error": "Maximum 100 data points per request"}), 400

        session_id = f"tri_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()

        geo_client = _get_geo_client()

        from app.geo_client import GeoDataPoint as GeoDP
        geo_points = []
        for dp in data_points:
            try:
                dp_type = dp.get("type", "")
                value = dp.get("value", "").strip()

                if dp_type == "ip" and value:
                    resolved = geo_client.ip_geolocate(value)
                    if resolved:
                        geo_points.append(resolved)
                    try:
                        scraper = _get_osint_client()._scraper
                        reverse_dns = scraper.reverse_dns_lookup(value)
                        co_hosted = scraper.reverse_ip_lookup(value)
                        if not data.get("_ip_intel"):
                            data["_ip_intel"] = {}
                        data["_ip_intel"][value] = {
                            "reverse_dns": reverse_dns,
                            "co_hosted_domains": co_hosted[:20],
                            "co_hosted_count": len(co_hosted),
                        }
                    except Exception:
                        pass
                    continue

                if dp_type == "address" and value:
                    resolved = geo_client.geocode(value)
                    if resolved:
                        geo_points.append(resolved)
                    continue

                if dp_type == "social_post" and value:
                    resolved = geo_client.resolve_locations([value])
                    geo_points.extend(resolved)
                    continue

                lat = dp.get("lat", dp.get("latitude"))
                lon = dp.get("lon", dp.get("lng", dp.get("longitude")))
                if lat is not None and lon is not None:
                    geo_points.append(GeoDP(
                        lat=float(lat),
                        lon=float(lon),
                        label=dp.get("label", value or ""),
                        source=dp.get("source", "user_input"),
                        confidence=float(dp.get("confidence", 0.5)),
                        timestamp=dp.get("timestamp"),
                        radius_m=float(dp.get("radius_m", 0)) if dp.get("radius_m") else None,
                        raw=dp,
                    ))
            except (ValueError, TypeError):
                continue

        if not geo_points:
            return jsonify({"error": "No valid geographic data points provided"}), 400

        # Triangulate
        triangulation = None
        try:
            triangulation = geo_client.triangulate(geo_points)
        except Exception as exc:
            print(f"[WARN] Triangulation failed (non-fatal): {exc}")

        triangulation_text = "No triangulation result available."
        if triangulation:
            tri_dict = asdict(triangulation)
            triangulation_text = (
                f"Center: ({tri_dict.get('center_lat')}, {tri_dict.get('center_lon')})\n"
                f"Radius: {tri_dict.get('radius_m')}m\n"
                f"Confidence: {tri_dict.get('confidence')}\n"
                f"Method: {tri_dict.get('method')}\n"
                f"Point count: {tri_dict.get('point_count')}"
            )

        # Build map data — use only accepted (non-outlier) points from
        # the triangulation.  Outliers and low-confidence points are excluded.
        map_data = {}
        try:
            # Determine which points are accepted by the geolocation assessment
            if triangulation and triangulation.cluster_points:
                accepted_pts = triangulation.cluster_points
                outlier_count = len(triangulation.outliers) if triangulation.outliers else 0
            else:
                accepted_pts = [
                    gp for gp in geo_points
                    if gp.confidence >= GEO_CONFIDENCE_FLOOR
                ] or geo_points
                outlier_count = 0

            markers = []
            for gp in accepted_pts:
                markers.append({
                    "lat": gp.lat,
                    "lng": gp.lon,
                    "label": gp.label or "",
                    "source_type": gp.source or "user_input",
                    "confidence": gp.confidence,
                    "description": gp.raw.get("city", "") if isinstance(gp.raw, dict) else "",
                })

            if markers:
                lats = [m["lat"] for m in markers]
                lngs = [m["lng"] for m in markers]
                center = [sum(lats) / len(lats), sum(lngs) / len(lngs)]

                map_data = {
                    "markers": markers,
                    "center": center,
                    "zoom": geo_client._auto_zoom(
                        [min(lats), min(lngs)],
                        [max(lats), max(lngs)],
                    ) if len(markers) > 1 else 10,
                    "points_accepted": len(markers),
                    "points_rejected": len(geo_points) - len(accepted_pts),
                }

                if triangulation and triangulation.center_lat and triangulation.center_lon:
                    map_data["triangulation"] = {
                        "center": {
                            "lat": triangulation.center_lat,
                            "lng": triangulation.center_lon,
                        },
                        "confidence_radius": triangulation.radius_m or 500,
                        "source_points": [{"lat": m["lat"], "lng": m["lng"]} for m in markers],
                        "method": triangulation.method,
                        "confidence": triangulation.confidence,
                    }

                if outlier_count:
                    print(f"[GEO] Triangulate: {outlier_count} spatial outliers removed from map")
        except Exception as exc:
            print(f"[WARN] Map data construction failed (non-fatal): {exc}")

        # Metadata extraction
        metadata_summary = "No metadata analysis available."
        try:
            from app.metadata_extractor import MetadataExtractor
            extractor = MetadataExtractor()
            content_items = [{"type": "geo_point", **asdict(gp)} for gp in geo_points[:20]]
            meta_results = extractor.extract_all(content_items)
            if meta_results:
                metadata_summary = "\n".join(
                    f"Source {m.source_id}: tz={m.timezone}, region={m.region}"
                    for m in meta_results[:10]
                    if m
                )
        except Exception as exc:
            print(f"[WARN] Metadata extraction failed (non-fatal): {exc}")

        geo_points_text = _geo_points_to_text([asdict(gp) for gp in geo_points])

        chain = get_geolocation_chain()
        chain_input = {
            "geo_points": geo_points_text,
            "triangulation_result": triangulation_text,
            "metadata_summary": metadata_summary,
            "subject_context": subject_context or "No additional subject context provided.",
            "elevated_authorization": _is_admin(),
            "purpose": "OSINT geolocation triangulation",
        }

        result = gated_invoke(
            chain,
            chain_input,
            chain_name="geolocation_chain",
            endpoint="/triangulate",
            mode="osint",
            session_id=session_id,
            user_hash=user_hash,
            trusted_keys={"geo_points", "triangulation_result", "metadata_summary"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        analysis = result.content

        report_id = _save_to_kb(
            source_route="/triangulate",
            report_type="triangulation",
            analysis_text=analysis,
            sensitivity_level="RESTRICTED",
            tags=["geolocation", "triangulation"],
            source_type="llm_analysis",
        )

        response = {
            "report_id": report_id,
            "session_id": session_id,
            "analysis": analysis,
            "map_data": map_data,
            "point_count": len(geo_points),
            "sensitivity_level": "RESTRICTED",
        }
        if triangulation:
            response["triangulation"] = asdict(triangulation)
        if data.get("_ip_intel"):
            response["ip_intel"] = data["_ip_intel"]

        return jsonify(response)

    @app.route("/batch-investigate", methods=["POST"])
    @login_required
    @limiter.limit("5 per hour")
    def batch_investigate():
        """Batch OSINT investigation for multiple identifiers."""
        data = request.get_json(silent=True) or {}
        if not data and request.form:
            data = dict(request.form)
            if "platforms" in data and isinstance(data["platforms"], str):
                try:
                    data["platforms"] = json.loads(data["platforms"])
                except (json.JSONDecodeError, TypeError):
                    pass

        identifiers = data.get("identifiers", [])
        identifier_type = data.get("identifier_type", "auto")
        depth = data.get("depth", "quick").strip().lower()

        if isinstance(identifiers, str):
            lines = [l.strip() for l in identifiers.replace(",", "\n").split("\n") if l.strip()]
            identifiers = [{"identifier": l, "identifier_type": identifier_type} for l in lines]

        # Handle file upload (CSV)
        uploaded_file = request.files.get("file")
        if uploaded_file and not identifiers:
            try:
                import csv
                import io
                content = uploaded_file.read().decode("utf-8")
                uploaded_file.seek(0)
                reader = csv.reader(io.StringIO(content))
                for row in reader:
                    if row and row[0].strip():
                        ident = row[0].strip()
                        id_type = row[1].strip().lower() if len(row) > 1 and row[1].strip() else identifier_type
                        identifiers.append({"identifier": ident, "identifier_type": id_type})
            except Exception:
                return jsonify({"error": "Failed to parse uploaded file"}), 400

        if not identifiers or not isinstance(identifiers, list):
            return jsonify({"error": "identifiers list is required"}), 400

        batch_limit = 500 if _is_admin() else 50
        if len(identifiers) > batch_limit:
            return jsonify({"error": f"Maximum {batch_limit} identifiers per batch"}), 400

        if depth not in INVESTIGATION_DEPTHS:
            depth = "quick"

        session_id = f"batch_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()

        # Validate each identifier
        valid_items = []
        invalid_items = []
        for item in identifiers:
            if isinstance(item, dict):
                ident = item.get("identifier", "").strip()
                id_type = item.get("identifier_type", "username").strip().lower()
            elif isinstance(item, str):
                ident = item.strip()
                id_type = "username"
            else:
                continue

            if not ident:
                invalid_items.append({"identifier": ident, "error": "Empty identifier"})
                continue
            if id_type not in IDENTIFIER_TYPES:
                id_type = "username"

            valid_items.append({"identifier": ident, "identifier_type": id_type})

        if not valid_items:
            return jsonify({"error": "No valid identifiers provided"}), 400

        # Process in parallel
        osint_client = _get_osint_client()
        geo_client = _get_geo_client()
        platforms = list(SOCIAL_PLATFORMS.keys())

        elevated = _is_admin()
        max_batch_workers = min(3, len(valid_items)) if _IS_WIN32 else min(8, len(valid_items))
        with ThreadPoolExecutor(max_workers=max_batch_workers) as executor:
            futures = {
                executor.submit(
                    _process_single_identifier,
                    item["identifier"],
                    item["identifier_type"],
                    platforms,
                    depth,
                    osint_client,
                    geo_client,
                    session_id,
                    user_hash,
                    elevated,
                ): item
                for item in valid_items
            }
            item_results = []
            for future in as_completed(futures):
                item_results.append(future.result())

        # Maintain input order
        ident_order = [item["identifier"] for item in valid_items]
        item_results.sort(
            key=lambda r: ident_order.index(r.get("identifier", ""))
            if r.get("identifier", "") in ident_order else len(ident_order)
        )

        successful = [r for r in item_results if r.get("success")]
        failed = [r for r in item_results if not r.get("success")]

        # Cross-entity synthesis
        consolidated_analysis = ""
        if successful:
            per_entity_summaries = "\n---\n".join(
                f"### {r['identifier']} ({r['identifier_type']})\n{r['analysis']}"
                for r in successful
            )
            chain = get_batch_synthesis_chain()
            chain_input = {
                "per_entity_summaries": per_entity_summaries,
                "aggregate_osint": f"{len(successful)} entities analyzed in batch.",
                "cross_entity_relationships": "Cross-entity analysis pending (Phase 0).",
                "geo_aggregate": "Geographic aggregate data pending (Phase 0).",
                "elevated_authorization": _is_admin(),
                "purpose": "OSINT batch investigation synthesis",
            }

            try:
                synth_result = gated_invoke(
                    chain=chain,
                    chain_input=chain_input,
                    chain_name="batch_synthesis_chain",
                    endpoint="/batch-investigate",
                    session_id=session_id,
                    mode="osint",
                    user_hash=user_hash,
                    trusted_keys={"per_entity_summaries", "aggregate_osint"},
                )
                if synth_result.success:
                    consolidated_analysis = synth_result.content
                else:
                    consolidated_analysis = f"[Synthesis blocked: {synth_result.reason}]"
            except Exception as exc:
                consolidated_analysis = f"[Synthesis failed: {str(exc)[:200]}]"

        # Save consolidated analysis
        report_id = None
        if consolidated_analysis and not consolidated_analysis.startswith("["):
            report_id = _save_to_kb(
                source_route="/batch-investigate",
                report_type="batch",
                analysis_text=consolidated_analysis,
                subject_identifier=f"Batch: {len(successful)} entities",
                entity_count=sum(r.get("entity_count", 0) for r in successful),
                tags=["batch"],
                source_type="llm_analysis",
            )

        batch_harm = None
        if CIVILIAN_HARM_ENABLED and consolidated_analysis:
            batch_harm = _score_text_for_harm(consolidated_analysis)

        resp = {
            "report_id": report_id,
            "session_id": session_id,
            "consolidated_analysis": consolidated_analysis,
            "item_results": item_results,
            "summary": {
                "total": len(valid_items),
                "successful": len(successful),
                "failed": len(failed),
                "invalid": invalid_items,
            },
        }
        if batch_harm:
            resp["civilian_harm"] = batch_harm
        return jsonify(resp)

    @app.route("/scenario", methods=["POST"])
    @login_required
    @limiter.limit("20 per hour")
    def scenario():
        """Generate analytical scenarios from OSINT data."""
        data = request.get_json(silent=True) or {}
        scenario_type = data.get("scenario_type", "").strip().lower()
        osint_data = data.get("osint_data", "").strip()
        subject_context = data.get("subject_context", "").strip()
        investigation_purpose = data.get("investigation_purpose", "").strip()
        session_id = data.get("session_id")

        if scenario_type not in SCENARIO_TYPES:
            return jsonify({
                "error": f"Invalid scenario_type. Must be one of: {', '.join(SCENARIO_TYPES.keys())}"
            }), 400

        # Build OSINT context from session or provided data
        if not osint_data and session_id and validate_session_id(session_id) and session_id in stored_reports:
            osint_data = stored_reports[session_id].get("text", "")[:5000]

        if not osint_data:
            return jsonify({
                "error": "No OSINT data available. Run an investigation or provide osint_data."
            }), 400

        # Build entity graph from session entities if available
        entity_graph_ctx = "No entity graph available."
        if session_id and validate_session_id(session_id) and session_id in stored_reports:
            cached = stored_reports[session_id]
            entities_data = cached.get("entities", [])
            if entities_data:
                try:
                    entity_graph = build_investigation_graph(entities_data)
                    entity_graph_ctx = graph_context(entity_graph, max_chars=4000)
                except Exception as exc:
                    print(f"[WARN] Graph construction failed in /scenario (non-fatal): {exc}")

        scenario_session_id = session_id or f"scn_{uuid.uuid4().hex[:16]}"
        user_hash = _get_user_hash()

        chain = get_scenario_chain()
        chain_input = {
            "scenario_type": scenario_type,
            "osint_data": osint_data,
            "subject_context": subject_context or "No additional subject context provided.",
            "entity_graph_context": entity_graph_ctx,
        }

        result = gated_invoke(
            chain,
            chain_input,
            chain_name="scenario_chain",
            endpoint="/scenario",
            mode="osint",
            session_id=scenario_session_id,
            user_hash=user_hash,
            trusted_keys={"osint_data", "entity_graph_context"},
        )

        if not result.success:
            return jsonify({
                "error": "Request blocked by governance",
                "reason": result.reason,
                "block_id": result.block_id,
                "gate_outcome": result.gate_outcome,
            }), 403

        analysis = result.content

        # Output grounding verification
        scenario_grounding = None
        try:
            scenario_grounding = verify_grounding(analysis, osint_data)
            print(
                f"[GROUNDING] /scenario {scenario_grounding['verdict']}: "
                f"{scenario_grounding['grounded_ratio']:.0%} grounded"
            )
        except Exception as exc:
            print(f"[WARN] Grounding verification failed in /scenario (non-fatal): {exc}")

        report_id = _save_to_kb(
            source_route="/scenario",
            report_type="scenario",
            analysis_text=analysis,
            tags=[scenario_type, "scenario"],
            source_type="llm_analysis",
        )

        scenario_resp = {
            "report_id": report_id,
            "session_id": scenario_session_id,
            "scenario": analysis,
            "scenario_type": scenario_type,
        }
        scenario_harm = _score_text_for_harm(osint_data)
        if scenario_harm:
            scenario_resp["civilian_harm"] = scenario_harm
        return jsonify(scenario_resp)

    # ================================================================
    #  EXPORT ROUTES
    # ================================================================

    def _resolve_export_data(data: dict) -> dict:
        """Merge export request data with stored report data.

        When the frontend sends only a session_id, look up the cached
        analysis text, entities, and sensitivity from stored_reports so
        export routes have everything they need.
        """
        sid = data.get("session_id", "")
        if sid and validate_session_id(sid) and sid in stored_reports:
            cached = stored_reports[sid]
            if not data.get("content"):
                data["content"] = cached.get("text", "")
            if not data.get("entities"):
                data["entities"] = cached.get("entities", [])
            if not data.get("sensitivity_level"):
                data["sensitivity_level"] = cached.get("sensitivity_level", "INTERNAL")
            if not data.get("title"):
                identifier = cached.get("identifier", "")
                if identifier:
                    data["title"] = f"Fortis Report — {identifier}"
            if not data.get("chart_data"):
                data["chart_data"] = cached.get("chart_data")
            if not data.get("map_data"):
                data["map_data"] = cached.get("map_data")
            if not data.get("entity_graph"):
                data["entity_graph"] = cached.get("entity_graph")
            if not data.get("investigation"):
                data["investigation"] = {
                    "identifier": cached.get("identifier", ""),
                    "sensitivity_level": cached.get("sensitivity_level", "INTERNAL"),
                }
        return data

    @app.route("/export/pdf", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_pdf():
        """Generate a styled PDF from analysis text, charts, map, and graph."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        content = data.get("content", "")
        title = data.get("title", "Fortis Intelligence Report")
        export_session_id = data.get("session_id", "")
        sensitivity_level = data.get("sensitivity_level", "INTERNAL")
        map_snapshot_b64 = data.get("map_snapshot")
        map_data = data.get("map_data")
        entity_graph = data.get("entity_graph")

        if not content or not content.strip():
            return jsonify({"error": "No content provided"}), 400
        if len(content) > 500_000 and not _is_admin():
            return jsonify({"error": "Content too large for export"}), 400

        title = re.sub(r"[^\w\s\-]", "", title)[:100] or "Fortis Intelligence Report"

        charts = None
        chart_data = data.get("chart_data")
        if chart_data and isinstance(chart_data, dict):
            try:
                findings = chart_data.get("findings", [])
                entities = chart_data.get("entities", [])
                if findings or entities:
                    charts = generate_investigation_charts(findings, entities)
            except Exception as exc:
                print(f"[WARN] Chart generation for PDF failed (non-fatal): {exc}")

        graph_b64 = None
        if entity_graph and isinstance(entity_graph, dict):
            try:
                from app.charts import chart_entity_graph
                graph_b64 = chart_entity_graph(entity_graph)
            except Exception as exc:
                print(f"[WARN] Graph rendering for PDF failed (non-fatal): {exc}")

        try:
            pdf_bytes = generate_pdf(
                content, title, export_session_id,
                charts=charts,
                sensitivity_level=sensitivity_level,
                map_snapshot_b64=map_snapshot_b64,
                map_data=map_data,
                entity_graph_b64=graph_b64,
            )
        except Exception as exc:
            print(f"[ERROR] PDF export failed: {exc}")
            return jsonify({"error": "PDF generation failed"}), 500

        safe_filename = re.sub(r"\s+", "_", title)[:50] + ".pdf"
        response = make_response(pdf_bytes)
        response.headers["Content-Type"] = "application/pdf"
        response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
        response.headers["Content-Length"] = len(pdf_bytes)
        return response

    @app.route("/export/markdown", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_markdown():
        """Generate a Markdown export of analysis text."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        content = data.get("content", "")
        title = data.get("title", "Fortis Intelligence Report")
        export_session_id = data.get("session_id", "")
        sensitivity_level = data.get("sensitivity_level", "INTERNAL")

        if not content or not content.strip():
            return jsonify({"error": "No content provided"}), 400
        if len(content) > 500_000 and not _is_admin():
            return jsonify({"error": "Content too large for export"}), 400

        title = re.sub(r"[^\w\s\-]", "", title)[:100] or "Fortis Intelligence Report"

        try:
            md_bytes = generate_markdown(content, title, export_session_id,
                                         sensitivity_level=sensitivity_level)
        except Exception as exc:
            print(f"[ERROR] Markdown export failed: {exc}")
            return jsonify({"error": "Markdown generation failed"}), 500

        safe_filename = re.sub(r"\s+", "_", title)[:50] + ".md"
        response = make_response(md_bytes)
        response.headers["Content-Type"] = "text/markdown"
        response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
        return response

    @app.route("/export/stix", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_stix():
        """Export OSINT entities in STIX 2.1 format."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        entities = data.get("entities")
        investigation = data.get("investigation")

        if not entities or not isinstance(entities, list):
            return jsonify({"error": "No entity data provided"}), 400

        try:
            stix_bundle = convert_to_stix21(entities, investigation)
            stix_json = _json.dumps(stix_bundle, indent=2)

            subject = (investigation or {}).get("identifier", "export")
            safe_filename = re.sub(r"[^\w\-]", "_", str(subject))[:40] + ".stix.json"

            response = make_response(stix_json)
            response.headers["Content-Type"] = "application/json"
            response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"'
            return response
        except Exception as exc:
            print(f"[ERROR] STIX export failed: {exc}")
            return jsonify({"error": "STIX export failed"}), 500

    @app.route("/export/csv", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_csv():
        """Export OSINT entities in CSV format."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        entities = data.get("entities")

        if not entities or not isinstance(entities, list):
            return jsonify({"error": "No entity data provided"}), 400

        try:
            csv_data = convert_to_csv(entities)

            response = make_response(csv_data)
            response.headers["Content-Type"] = "text/csv"
            response.headers["Content-Disposition"] = 'attachment; filename="entities_export.csv"'
            return response
        except Exception as exc:
            print(f"[ERROR] CSV export failed: {exc}")
            return jsonify({"error": "CSV export failed"}), 500

    @app.route("/export/json", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_json_route():
        """Export OSINT entities in structured JSON format."""
        data = _resolve_export_data(request.get_json(silent=True) or {})
        entities = data.get("entities")
        investigation = data.get("investigation")

        if not entities or not isinstance(entities, list):
            return jsonify({"error": "No entity data provided"}), 400

        try:
            json_data = convert_to_json(entities, investigation)

            response = make_response(json_data)
            response.headers["Content-Type"] = "application/json"
            response.headers["Content-Disposition"] = 'attachment; filename="entities_export.json"'
            return response
        except Exception as exc:
            print(f"[ERROR] JSON export failed: {exc}")
            return jsonify({"error": "JSON export failed"}), 500

    # ── Google Drive export ────────────────────────────────────────

    def _drive_upload_or_503(file_bytes, filename, mime_type):
        """Upload bytes to Google Drive or return 503 if not configured."""
        client = get_gdrive_client()
        if not client.is_configured:
            return jsonify({
                "error": "Google Drive not configured. "
                         "Set GDRIVE_SERVICE_ACCOUNT_KEY_FILE and GDRIVE_FOLDER_ID in .env"
            }), 503
        result = client.upload_file(file_bytes, filename, mime_type)
        if result["success"]:
            user_hash = _get_user_hash()
            print(f"[AUDIT] Drive upload: user={user_hash} file={filename} id={result.get('file_id')}")
            return jsonify(result)
        return jsonify({"error": result.get("error", "Upload failed")}), 500

    @app.route("/export/drive/<format_type>", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_drive(format_type):
        """Upload an export to Google Drive."""
        if format_type not in ("pdf", "markdown", "stix", "csv", "json"):
            return jsonify({"error": "Invalid format. Use: pdf, markdown, stix, csv, json"}), 400

        data = _resolve_export_data(request.get_json(silent=True) or {})
        sensitivity = data.get("sensitivity_level", "INTERNAL")
        sens_tag = sensitivity.replace(" ", "_")

        if format_type == "pdf":
            content = data.get("content", "")
            title = data.get("title", "Fortis Intelligence Report")
            export_session_id = data.get("session_id", "")
            map_snapshot_b64 = data.get("map_snapshot")
            map_data = data.get("map_data")
            entity_graph = data.get("entity_graph")

            if not content or not content.strip():
                return jsonify({"error": "No content provided"}), 400
            if len(content) > 500_000:
                return jsonify({"error": "Content too large"}), 400

            title = re.sub(r"[^\w\s\-]", "", title)[:100] or "Fortis Report"

            charts = None
            chart_data = data.get("chart_data")
            if chart_data and isinstance(chart_data, dict):
                try:
                    charts = generate_investigation_charts(
                        chart_data.get("findings", []),
                        chart_data.get("entities", []),
                    )
                except Exception:
                    pass

            graph_b64 = None
            if entity_graph and isinstance(entity_graph, dict):
                try:
                    from app.charts import chart_entity_graph
                    graph_b64 = chart_entity_graph(entity_graph)
                except Exception:
                    pass

            try:
                file_bytes = generate_pdf(
                    content, title, export_session_id,
                    charts=charts,
                    sensitivity_level=sensitivity,
                    map_snapshot_b64=map_snapshot_b64,
                    map_data=map_data,
                    entity_graph_b64=graph_b64,
                )
            except Exception as exc:
                print(f"[ERROR] Drive PDF generation failed: {exc}")
                return jsonify({"error": "PDF generation failed"}), 500

            safe_filename = re.sub(r"\s+", "_", title)[:50] + f"_{sens_tag}.pdf"
            return _drive_upload_or_503(file_bytes, safe_filename, "application/pdf")

        elif format_type == "markdown":
            content = data.get("content", "")
            title = data.get("title", "Fortis Intelligence Report")
            export_session_id = data.get("session_id", "")

            if not content or not content.strip():
                return jsonify({"error": "No content provided"}), 400
            if len(content) > 500_000:
                return jsonify({"error": "Content too large"}), 400

            title = re.sub(r"[^\w\s\-]", "", title)[:100] or "Fortis Report"

            try:
                file_bytes = generate_markdown(content, title, export_session_id,
                                               sensitivity_level=sensitivity)
            except Exception as exc:
                print(f"[ERROR] Drive Markdown generation failed: {exc}")
                return jsonify({"error": "Markdown generation failed"}), 500

            safe_filename = re.sub(r"\s+", "_", title)[:50] + f"_{sens_tag}.md"
            return _drive_upload_or_503(file_bytes, safe_filename, "text/markdown")

        elif format_type == "stix":
            entities = data.get("entities")
            investigation = data.get("investigation")
            if not entities or not isinstance(entities, list):
                return jsonify({"error": "No entity data provided"}), 400
            try:
                stix_bundle = convert_to_stix21(entities, investigation)
                file_bytes = _json.dumps(stix_bundle, indent=2).encode("utf-8")
            except Exception as exc:
                print(f"[ERROR] Drive STIX generation failed: {exc}")
                return jsonify({"error": "STIX generation failed"}), 500

            subject = (investigation or {}).get("identifier", "export")
            safe_filename = re.sub(r"[^\w\-]", "_", str(subject))[:40] + f"_{sens_tag}.stix.json"
            return _drive_upload_or_503(file_bytes, safe_filename, "application/json")

        elif format_type == "csv":
            entities = data.get("entities")
            if not entities or not isinstance(entities, list):
                return jsonify({"error": "No entity data provided"}), 400
            try:
                csv_data = convert_to_csv(entities)
                file_bytes = csv_data.encode("utf-8") if isinstance(csv_data, str) else csv_data
            except Exception as exc:
                print(f"[ERROR] Drive CSV generation failed: {exc}")
                return jsonify({"error": "CSV generation failed"}), 500

            safe_filename = f"entities_{sens_tag}.csv"
            return _drive_upload_or_503(file_bytes, safe_filename, "text/csv")

        else:  # json
            entities = data.get("entities")
            investigation = data.get("investigation")
            if not entities or not isinstance(entities, list):
                return jsonify({"error": "No entity data provided"}), 400
            try:
                json_str = convert_to_json(entities, investigation)
                file_bytes = json_str.encode("utf-8") if isinstance(json_str, str) else json_str
            except Exception as exc:
                print(f"[ERROR] Drive JSON generation failed: {exc}")
                return jsonify({"error": "JSON generation failed"}), 500

            safe_filename = f"entities_{sens_tag}.json"
            return _drive_upload_or_503(file_bytes, safe_filename, "application/json")

    @app.route("/export/map-snapshot", methods=["POST"])
    @login_required
    @limiter.limit("30 per hour")
    def export_map_snapshot():
        """Save a map PNG from frontend base64 data."""
        data = request.get_json(silent=True) or {}
        image_b64 = data.get("image")
        snapshot_session_id = data.get("session_id", uuid.uuid4().hex[:16])

        if not image_b64:
            return jsonify({"error": "No image data provided"}), 400

        # Strip data URI prefix if present
        if "," in image_b64:
            image_b64 = image_b64.split(",", 1)[1]

        try:
            image_bytes = base64.b64decode(image_b64)
        except Exception:
            return jsonify({"error": "Invalid base64 image data"}), 400

        if len(image_bytes) > 10 * 1024 * 1024:  # 10 MB limit
            return jsonify({"error": "Image too large (max 10 MB)"}), 400

        snapshot_dir = DATA_DIR / "map_snapshots"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        filename = f"map_{snapshot_session_id}_{uuid.uuid4().hex[:8]}.png"
        filepath = snapshot_dir / filename

        filepath.write_bytes(image_bytes)

        return jsonify({
            "success": True,
            "filename": filename,
            "size_bytes": len(image_bytes),
        })

    # ================================================================
    #  KNOWLEDGE BASE ROUTES
    # ================================================================

    @app.route("/kb/reports", methods=["GET"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_list_reports():
        """List reports with pagination and filtering."""
        page = request.args.get("page", 1, type=int)
        per_page = min(request.args.get("per_page", 20, type=int), 100)
        report_type = request.args.get("type")
        in_kb = request.args.get("in_kb")
        sensitivity_level = request.args.get("sensitivity_level")
        identifier_type = request.args.get("identifier_type")

        if in_kb is not None:
            in_kb = in_kb.lower() == "true"

        store = get_report_store()
        offset = (page - 1) * per_page
        reports = store.list_reports(
            limit=per_page,
            offset=offset,
            report_type=report_type,
            in_kb=in_kb,
            sensitivity_level=sensitivity_level,
            identifier_type=identifier_type,
        )
        total = store.count()

        return jsonify({
            "reports": [
                {k: v for k, v in asdict(r).items() if k != "analysis_text"}
                for r in reports
            ],
            "total": total,
            "page": page,
            "per_page": per_page,
        })

    @app.route("/kb/reports/<report_id>", methods=["GET"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_get_report(report_id: str):
        """Get a specific report by ID."""
        store = get_report_store()
        report = store.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404
        return jsonify(asdict(report))

    @app.route("/kb/reports/<report_id>", methods=["DELETE"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_delete_report(report_id: str):
        """Delete a report and rebuild KB if it was indexed."""
        store = get_report_store()
        report = store.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404

        store.delete(report_id)
        if report.in_knowledge_base:
            _rebuild_kb_from_store()

        return jsonify({"message": "Report deleted"})

    @app.route("/kb/reports/<report_id>/toggle", methods=["POST"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_toggle_report(report_id: str):
        """Toggle a report in or out of the knowledge base."""
        store = get_report_store()
        report = store.get(report_id)
        if not report:
            return jsonify({"error": "Report not found"}), 404

        new_state = not report.in_knowledge_base
        store.toggle_kb(report_id, new_state)
        _rebuild_kb_from_store()

        return jsonify({"in_knowledge_base": new_state})

    @app.route("/kb/stats", methods=["GET"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_stats():
        """Return knowledge base statistics."""
        store = get_report_store()
        stats = store.get_stats()
        stats["kb_exists"] = knowledge_base_exists()
        stats["retention_days"] = int(os.getenv("KB_RETENTION_DAYS", "90"))
        return jsonify(stats)

    @app.route("/kb/rebuild", methods=["POST"])
    @login_required
    @limiter.limit("60 per hour")
    def kb_rebuild():
        """Force a full rebuild of the FAISS knowledge base."""
        store = get_report_store()
        archived = store.archive_stale()
        count = _rebuild_kb_from_store()
        return jsonify({
            "message": "KB rebuilt",
            "total_chunks": count,
            "stale_archived": archived,
        })

    # ================================================================
    #  FORGECHAIN ROUTES
    # ================================================================

    @app.route("/forge/session/<session_id>/replay", methods=["GET"])
    @login_required
    def forge_replay(session_id):
        """Return forensic replay data for a ForgeChain session."""
        if not validate_session_id(session_id):
            return jsonify({"error": "Invalid session ID"}), 400

        endpoint_filter = request.args.get("endpoint")
        outcome_filter = request.args.get("outcome")

        replay_data = get_session_replay(
            session_id=session_id,
            endpoint_filter=endpoint_filter,
            outcome_filter=outcome_filter,
        )

        if replay_data is None:
            return jsonify({"error": "Session not found in ForgeChain"}), 404

        return jsonify(replay_data)

    @app.route("/forge/session/<session_id>/verify", methods=["GET"])
    @login_required
    def forge_verify(session_id):
        """Verify the cryptographic integrity of a ForgeChain session."""
        if not validate_session_id(session_id):
            return jsonify({"error": "Invalid session ID"}), 400

        store = get_chain_store()
        chain_session = store.load_session(session_id)

        if chain_session is None:
            return jsonify({"error": "Session not found"}), 404

        is_valid, error = chain_session.verify_integrity()
        return jsonify({
            "session_id": session_id,
            "chain_valid": is_valid,
            "block_count": len(chain_session.blocks),
            "error": error,
        })

    @app.route("/forge/health", methods=["GET"])
    @login_required
    def forge_health():
        """Return ForgeChain health and statistics."""
        store = get_chain_store()
        stats = store.get_stats()
        return jsonify({
            "forge_enabled": FORGE_ENABLED,
            "total_sessions": stats["total_sessions"],
            "total_blocks": stats["total_blocks"],
            "last_activity": stats["last_block_timestamp"],
        })

    # ================================================================
    #  MONITOR ROUTES (Phase 0)
    # ================================================================

    @app.route("/monitor/create", methods=["POST"])
    @login_required
    @limiter.limit("10 per hour")
    def monitor_create():
        """Create a new feed monitor."""
        data = request.get_json(silent=True) or {}
        query = data.get("query", "").strip()
        monitor_type = data.get("monitor_type", "keyword").strip()
        platforms = data.get("platforms", [])
        interval_minutes = data.get("interval_minutes", 60)
        alert_threshold = data.get("alert_threshold", "all")

        if not query:
            return jsonify({"error": "Query is required"}), 400
        if len(query) > 500:
            return jsonify({"error": "Query too long (max 500 characters)"}), 400

        user_hash = _get_user_hash()

        config = {
            "query": query,
            "monitor_type": monitor_type,
            "platforms": platforms,
            "interval_minutes": interval_minutes,
            "alert_threshold": alert_threshold,
            "created_by": user_hash,
        }

        try:
            monitor = _get_feed_monitor()
            result = monitor.create_monitor(config)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Monitor creation failed: {exc}")
            return jsonify({"error": "Failed to create monitor"}), 500

    @app.route("/monitor/<monitor_id>/pause", methods=["POST"])
    @login_required
    def monitor_pause(monitor_id):
        """Pause a feed monitor."""
        try:
            monitor = _get_feed_monitor()
            result = monitor.pause_monitor(monitor_id)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Monitor pause failed: {exc}")
            return jsonify({"error": "Failed to pause monitor"}), 500

    @app.route("/monitor/<monitor_id>/resume", methods=["POST"])
    @login_required
    def monitor_resume(monitor_id):
        """Resume a paused feed monitor."""
        try:
            monitor = _get_feed_monitor()
            result = monitor.resume_monitor(monitor_id)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Monitor resume failed: {exc}")
            return jsonify({"error": "Failed to resume monitor"}), 500

    @app.route("/monitor/<monitor_id>/delete", methods=["DELETE"])
    @login_required
    def monitor_delete(monitor_id):
        """Delete a feed monitor."""
        try:
            monitor = _get_feed_monitor()
            result = monitor.delete_monitor(monitor_id)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Monitor deletion failed: {exc}")
            return jsonify({"error": "Failed to delete monitor"}), 500

    @app.route("/monitor/list", methods=["GET"])
    @login_required
    def monitor_list():
        """List all feed monitors."""
        try:
            monitor = _get_feed_monitor()
            monitors = monitor.list_monitors()
            return jsonify({"monitors": monitors})
        except Exception as exc:
            print(f"[ERROR] Monitor list failed: {exc}")
            return jsonify({"error": "Failed to list monitors"}), 500

    @app.route("/monitor/watch", methods=["GET"])
    @login_required
    def monitor_watch():
        """List pending findings from feed monitors."""
        try:
            monitor = _get_feed_monitor()
            findings = monitor.get_pending_findings()
            return jsonify({"findings": findings})
        except Exception as exc:
            print(f"[ERROR] Monitor watch failed: {exc}")
            return jsonify({"error": "Failed to fetch findings"}), 500

    @app.route("/monitor/<finding_id>/approve", methods=["POST"])
    @login_required
    def monitor_approve(finding_id):
        """Approve a monitor finding for further investigation."""
        try:
            monitor = _get_feed_monitor()
            result = monitor.approve_finding(finding_id)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Finding approval failed: {exc}")
            return jsonify({"error": "Failed to approve finding"}), 500

    @app.route("/monitor/<finding_id>/dismiss", methods=["POST"])
    @login_required
    def monitor_dismiss(finding_id):
        """Dismiss a monitor finding."""
        data = request.get_json(silent=True) or {}
        reason = data.get("reason")

        try:
            monitor = _get_feed_monitor()
            result = monitor.dismiss_finding(finding_id, reason=reason)
            return jsonify(result)
        except Exception as exc:
            print(f"[ERROR] Finding dismissal failed: {exc}")
            return jsonify({"error": "Failed to dismiss finding"}), 500

    # ================================================================
    #  UTILITY ROUTES
    # ================================================================

    @app.route("/osint-status", methods=["GET"])
    def osint_status():
        """Check OSINT source availability and return platform status."""
        configured = []
        unconfigured = []

        for platform, config in SOCIAL_PLATFORMS.items():
            env_keys = config.get("env_keys", [])
            if not env_keys:
                single_key = config.get("env_key", f"{platform.upper()}_API_KEY")
                env_keys = [single_key]
            name = config.get("name", platform)
            if all(bool(os.getenv(k)) for k in env_keys):
                configured.append(name)
            else:
                unconfigured.append(name)

        return jsonify({
            "configured": configured,
            "unconfigured": unconfigured,
        })

    # ================================================================
    #  COMPLIANCE / DATA PROTECTION ROUTES
    # ================================================================

    @app.route("/compliance/processing-record", methods=["GET"])
    @login_required
    @admin_required
    def compliance_processing_record():
        """GDPR Article 30 processing record."""
        from app.compliance import generate_processing_record
        record = generate_processing_record(get_report_store())
        return jsonify(record)

    @app.route("/compliance/retention", methods=["POST"])
    @login_required
    @admin_required
    def compliance_enforce_retention():
        """Enforce data retention policy — hard-delete reports past their retention period."""
        from app.compliance import enforce_retention, evict_expired_cache
        cache_evicted = evict_expired_cache(stored_reports)
        db_deleted = enforce_retention(get_report_store())

        if db_deleted > 0:
            try:
                rebuild_knowledge_base(get_report_store())
                print(f"[COMPLIANCE] KB rebuilt after retention enforcement")
            except Exception as exc:
                print(f"[WARN] KB rebuild after retention failed: {exc}")

        return jsonify({
            "cache_evicted": cache_evicted,
            "db_deleted": db_deleted,
            "message": f"Retention enforced: {db_deleted} DB records deleted, {cache_evicted} cache entries evicted",
        })

    @app.route("/data/subject-delete", methods=["POST"])
    @login_required
    @admin_required
    @limiter.limit("10 per hour")
    def data_subject_delete():
        """Right to erasure (GDPR Art. 17) — delete ALL data for a subject."""
        from app.compliance import erase_subject_data
        data = request.get_json(silent=True) or {}
        subject = data.get("subject_identifier", "").strip()

        if not subject:
            return jsonify({"error": "subject_identifier is required"}), 400

        summary = erase_subject_data(
            report_store=get_report_store(),
            subject_identifier=subject,
            stored_reports=stored_reports,
        )

        total_deleted = (
            summary["reports_deleted"]
            + summary["subjects_deleted"]
            + summary["geo_points_deleted"]
            + summary["relationships_deleted"]
            + summary["cache_entries_removed"]
        )

        if summary["reports_deleted"] > 0:
            try:
                rebuild_knowledge_base(get_report_store())
                print(f"[COMPLIANCE] KB rebuilt after subject erasure")
            except Exception as exc:
                print(f"[WARN] KB rebuild after erasure failed: {exc}")

        return jsonify({
            "erasure_summary": summary,
            "total_records_deleted": total_deleted,
            "message": f"All data for '{subject}' has been erased",
        })

    @app.route("/compliance/classification", methods=["GET"])
    @login_required
    def compliance_classification():
        """Return data classification levels and retention policies."""
        from app.compliance import CLASSIFICATION_LEVELS, NIST_CSF_MAPPING
        return jsonify({
            "classification_levels": CLASSIFICATION_LEVELS,
            "nist_csf_mapping": NIST_CSF_MAPPING,
        })

    # ================================================================
    #  ADMIN ROUTES
    # ================================================================

    @app.route("/admin/sessions", methods=["GET"])
    @login_required
    @admin_required
    def admin_sessions():
        """List all active sessions (admin only)."""
        sessions_list = []
        for token, user_sess in session_manager.sessions.items():
            sessions_list.append({
                "email": user_sess.email,
                "name": user_sess.name,
                "is_admin": user_sess.is_admin,
                "created_at": user_sess.created_at.isoformat(),
                "last_activity": user_sess.last_activity.isoformat(),
                "token_prefix": token[:8],
            })
        sessions_list.sort(key=lambda s: s["last_activity"], reverse=True)
        return jsonify({"sessions": sessions_list, "total": len(sessions_list)})

    @app.route("/admin/sessions/<token_prefix>", methods=["DELETE"])
    @login_required
    @admin_required
    def admin_kill_session(token_prefix):
        """Terminate a session by token prefix (admin only)."""
        if not token_prefix or len(token_prefix) < 8:
            return jsonify({"error": "Token prefix must be at least 8 characters"}), 400

        for token in list(session_manager.sessions.keys()):
            if token.startswith(token_prefix):
                target = session_manager.sessions[token]
                if target.email == g.user_session.email:
                    return jsonify({"error": "Cannot terminate your own session"}), 400
                session_manager.invalidate_session(token)
                audit_logger = get_audit_logger()
                audit_logger._log_event("ADMIN_SESSION_KILL", {
                    "admin": g.user_session.email,
                    "target_email": target.email,
                })
                return jsonify({"success": True, "killed_email": target.email})

        return jsonify({"error": "Session not found"}), 404

    @app.route("/admin/stats", methods=["GET"])
    @login_required
    @admin_required
    def admin_stats():
        """System statistics (admin only)."""
        report_store = get_report_store()
        reports = report_store.list_reports(limit=0)

        return jsonify({
            "active_sessions": len(session_manager.sessions),
            "cached_reports": len(stored_reports),
            "kb_reports": len(reports),
            "admin_emails": sorted(ADMIN_EMAILS),
            "forge_enabled": os.getenv("FORGE_ENABLED", "true").lower() == "true",
            "auth_enabled": AUTH_ENABLED,
            "vectorstore_exists": VECTORSTORE_DIR.is_dir() and any(VECTORSTORE_DIR.iterdir()) if VECTORSTORE_DIR.is_dir() else False,
        })

    @app.route("/admin/config", methods=["GET"])
    @login_required
    @admin_required
    def admin_config():
        """View non-secret configuration (admin only)."""
        return jsonify({
            "auth_enabled": AUTH_ENABLED,
            "forge_enabled": os.getenv("FORGE_ENABLED", "true").lower() == "true",
            "forge_healing_enabled": os.getenv("FORGE_HEALING_ENABLED", "true").lower() == "true",
            "session_timeout_minutes": SESSION_TIMEOUT_MINUTES,
            "max_upload_mb_regular": 50,
            "max_upload_mb_admin": 200,
            "max_batch_regular": 50,
            "max_batch_admin": 500,
            "admin_count": len(ADMIN_EMAILS),
            "redis_configured": bool(os.getenv("REDIS_URL")),
            "flask_env": os.getenv("FLASK_ENV", "development"),
        })

    @app.route("/admin/audit", methods=["GET"])
    @login_required
    @admin_required
    def admin_audit():
        """Read recent audit log entries (admin only)."""
        limit = min(int(request.args.get("limit", 100)), 500)
        log_path = LOG_DIR / "audit.log"
        if not log_path.exists():
            return jsonify({"entries": [], "total": 0})

        lines = log_path.read_text(encoding="utf-8", errors="replace").strip().split("\n")
        entries = []
        for line in lines[-limit:]:
            try:
                entries.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue
        entries.reverse()
        return jsonify({"entries": entries, "total": len(lines)})

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint for container orchestration and monitoring."""
        components = {}

        # LLM: check if DeepSeek API key is configured
        components["llm"] = bool(os.getenv("DEEPSEEK_API_KEY"))

        # Redis: try a ping
        try:
            import redis as _redis
            redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            r = _redis.from_url(redis_url, socket_connect_timeout=2)
            r.ping()
            components["redis"] = True
        except Exception:
            components["redis"] = False

        # Vectorstore: check if the KB directory exists and has content
        components["vectorstore"] = VECTORSTORE_DIR.is_dir() and any(VECTORSTORE_DIR.iterdir())

        overall = "healthy" if any(components.values()) else "degraded"
        return jsonify({
            "status": overall,
            "version": "1.0.0",
            "components": components,
        })

    @app.route("/gdrive-status", methods=["GET"])
    def gdrive_status():
        """Check Google Drive configuration status."""
        client = get_gdrive_client()
        return jsonify({"configured": client.is_configured})

    # ================================================================
    #  STARTUP TASKS
    # ================================================================

    # Verify KB integrity on startup
    if not verify_kb_on_startup():
        print("[STARTUP] Rebuilding KB from ReportStore...")
        try:
            _rebuild_kb_from_store()
        except Exception as exc:
            print(f"[STARTUP] KB rebuild failed: {exc}")

    # Archive stale KB reports + enforce retention policy
    try:
        store = get_report_store()
        archived = store.archive_stale()
        if archived > 0:
            print(f"[STARTUP] Archived {archived} stale reports, rebuilding KB...")
            _rebuild_kb_from_store()
    except Exception as exc:
        print(f"[STARTUP] KB retention cleanup failed: {exc}")

    try:
        from app.compliance import enforce_retention
        deleted = enforce_retention(get_report_store())
        if deleted > 0:
            print(f"[STARTUP] Retention: hard-deleted {deleted} expired reports")
            _rebuild_kb_from_store()
    except Exception as exc:
        print(f"[STARTUP] Retention enforcement failed (non-fatal): {exc}")

    # Check OSINT source availability
    try:
        available_count = 0
        for platform, config in SOCIAL_PLATFORMS.items():
            env_keys = config.get("env_keys", [])
            if not env_keys:
                single_key = config.get("env_key", f"{platform.upper()}_API_KEY")
                env_keys = [single_key]
            if all(bool(os.getenv(k)) for k in env_keys):
                available_count += 1
                print(f"[STARTUP] OSINT source available: {platform}")
        if available_count == 0:
            print("[STARTUP] No OSINT API keys configured (Phase 0 stub mode)")
        else:
            print(f"[STARTUP] {available_count}/{len(SOCIAL_PLATFORMS)} OSINT sources configured")
    except Exception as exc:
        print(f"[STARTUP] OSINT availability check failed: {exc}")

    return app
