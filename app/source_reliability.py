"""NATO Admiralty System source reliability tagging for OSINT findings.

Provides reliability grading (A-F) for each source platform and
information credibility assessment (1-6) for collected data.

Grades:
    A = Completely reliable
    B = Usually reliable
    C = Fairly reliable
    D = Not usually reliable
    E = Unreliable
    F = Cannot be judged

Information credibility:
    1 = Confirmed by other independent sources
    2 = Probably true (consistent with known facts)
    3 = Possibly true (not confirmed, not contradicted)
    4 = Doubtful (inconsistent with known facts)
    5 = Improbable (contradicted by known facts)
    6 = Cannot be judged
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Grade definitions
# ---------------------------------------------------------------------------

GRADE_LABELS: dict[str, str] = {
    "A": "Completely reliable",
    "B": "Usually reliable",
    "C": "Fairly reliable",
    "D": "Not usually reliable",
    "E": "Unreliable",
    "F": "Cannot be judged",
}

GRADE_ORDER = list(GRADE_LABELS.keys())  # A=0 .. F=5

CREDIBILITY_LABELS: dict[str, str] = {
    "1": "Confirmed by other independent sources",
    "2": "Probably true",
    "3": "Possibly true",
    "4": "Doubtful",
    "5": "Improbable",
    "6": "Cannot be judged",
}

# ---------------------------------------------------------------------------
# Platform -> base grade mapping
# ---------------------------------------------------------------------------

_PLATFORM_GRADES: dict[str, str] = {
    # A -- Official registry records, legally scrutinized
    "whois": "A",
    "dns": "A",
    "ssl_cert": "A",
    "crt.sh": "A",
    # B -- Structured scans / editorial oversight
    "shodan": "B",
    "news": "B",
    "newsapi": "B",
    "abuseipdb": "B",
    "otx": "B",
    "securitytrails": "A",
    "urlscan": "B",
    "fullcontact": "B",
    # C -- Platform-verified possible / published content
    "twitter": "C",
    "x": "C",
    "reddit": "C",
    "youtube": "C",
    "instagram": "C",
    "facebook": "C",
    "rss_feed": "C",
    "rss": "C",
    # D -- No identity verification / anonymous by default
    "telegram": "D",
    "mastodon": "D",
    "tiktok": "D",
    # E -- Unknown provenance / unvetted results
    "web_scrape": "E",
    "dork_search": "E",
    # F -- Cannot be judged
    "unknown": "F",
}


def _grade_index(grade: str) -> int:
    """Return numeric index for a grade (A=0, F=5)."""
    try:
        return GRADE_ORDER.index(grade.upper())
    except ValueError:
        return 5  # default to F


def _index_to_grade(index: int) -> str:
    """Clamp index to valid range and return grade letter."""
    clamped = max(0, min(index, len(GRADE_ORDER) - 1))
    return GRADE_ORDER[clamped]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_source_reliability(
    platform: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Return a reliability assessment for a given source platform.

    Args:
        platform: Source platform key (e.g. ``"twitter"``, ``"whois"``).
        metadata: Optional dict with keys such as ``verified``,
            ``account_age_days``, ``followers``, ``karma`` that can
            upgrade or downgrade the base grade.

    Returns:
        Dict with ``grade``, ``label``, ``credibility``, and ``rationale``.
    """
    platform_key = platform.strip().lower()
    base_grade = _PLATFORM_GRADES.get(platform_key, "F")
    rationale_parts: list[str] = []

    # Base rationale
    if base_grade == "A":
        rationale_parts.append("Official registry/technical records")
    elif base_grade == "B":
        rationale_parts.append("Structured scan data or editorially vetted")
    elif base_grade == "C":
        rationale_parts.append("Platform-verified possible; content unvetted")
    elif base_grade == "D":
        rationale_parts.append("No identity verification on platform")
    elif base_grade == "E":
        rationale_parts.append("Unknown provenance; unvetted content")
    else:
        rationale_parts.append("Source reliability cannot be judged")

    grade_idx = _grade_index(base_grade)

    # Metadata-based adjustments
    if metadata:
        # Verified account -> upgrade by 1 grade
        if metadata.get("verified"):
            grade_idx = max(grade_idx - 1, 0)
            rationale_parts.append("Verified account (+1)")

        # Account age > 2 years -> upgrade by 1 (cap at B)
        account_age_days = metadata.get("account_age_days")
        if account_age_days is None and metadata.get("created_at"):
            try:
                created = datetime.fromisoformat(
                    str(metadata["created_at"]).replace("Z", "+00:00")
                )
                now = datetime.now(tz=timezone.utc)
                account_age_days = (now - created).days
            except (ValueError, TypeError):
                account_age_days = None

        if account_age_days is not None and account_age_days > 730:
            new_idx = max(grade_idx - 1, 1)  # cap at B (index 1)
            if new_idx < grade_idx:
                grade_idx = new_idx
                rationale_parts.append("Account age >2 years (+1, cap B)")

        # Very few followers/karma -> downgrade by 1
        followers = metadata.get("followers")
        karma = metadata.get("karma")
        engagement = followers if followers is not None else karma
        if engagement is not None and engagement < 50:
            grade_idx = min(grade_idx + 1, 5)
            rationale_parts.append("Very low engagement (-1)")

    final_grade = _index_to_grade(grade_idx)

    # Default credibility based on grade
    credibility = _default_credibility(final_grade)

    return {
        "grade": final_grade,
        "label": GRADE_LABELS[final_grade],
        "credibility": credibility,
        "rationale": "; ".join(rationale_parts),
    }


def _default_credibility(grade: str) -> str:
    """Map a reliability grade to a default information credibility score."""
    return {
        "A": "2",  # Probably true
        "B": "2",  # Probably true
        "C": "3",  # Possibly true
        "D": "3",  # Possibly true
        "E": "6",  # Cannot be judged
        "F": "6",  # Cannot be judged
    }.get(grade, "6")


def get_information_credibility(data: dict[str, Any]) -> str:
    """Rate information credibility 1-6.

    1 = Confirmed by other independent sources
    2 = Probably true (consistent with known facts)
    3 = Possibly true (not confirmed, not contradicted)
    4 = Doubtful (inconsistent with known facts)
    5 = Improbable (contradicted by known facts)
    6 = Cannot be judged

    For now, uses heuristics based on the data dict. Full cross-referencing
    credibility assessment will be implemented in a future phase.
    """
    if not data:
        return "6"

    source_count = data.get("source_count", 0)
    confidence = data.get("confidence", 0)

    # Multiple corroborating sources -> confirmed
    if source_count >= 3 and confidence >= 0.8:
        return "1"

    # Two sources or high confidence -> probably true
    if source_count >= 2 or confidence >= 0.7:
        return "2"

    # Single source with moderate confidence -> possibly true
    if source_count >= 1 and confidence >= 0.4:
        return "3"

    # Low confidence -> doubtful
    if 0 < confidence < 0.3:
        return "4"

    # Default: cannot be judged
    return "6"


def tag_profile_reliability(
    platform: str,
    verified: bool = False,
    followers: int = 0,
    created_at: str | None = None,
) -> dict[str, str]:
    """Convenience wrapper to tag a social profile with reliability."""
    meta: dict[str, Any] = {
        "verified": verified,
        "followers": followers,
    }
    if created_at:
        meta["created_at"] = created_at
    return get_source_reliability(platform, metadata=meta)


def tag_post_reliability(
    platform: str,
    author_verified: bool = False,
    author_followers: int = 0,
) -> dict[str, str]:
    """Convenience wrapper to tag a social post with reliability."""
    meta: dict[str, Any] = {
        "verified": author_verified,
        "followers": author_followers,
    }
    return get_source_reliability(platform, metadata=meta)


def tag_web_mention_reliability(
    mention_type: str,
    domain: str = "",
) -> dict[str, str]:
    """Tag a web mention with reliability based on its type."""
    # Map mention types to platform keys
    type_map = {
        "news": "news",
        "news_deep": "news",
        "rss": "rss_feed",
        "web_scrape": "web_scrape",
        "dork": "dork_search",
    }
    platform_key = type_map.get(mention_type, "web_scrape")
    return get_source_reliability(platform_key)


def tag_entity_reliability(
    enrichment_sources: list[str],
) -> dict[str, str]:
    """Tag an enriched entity based on its enrichment sources.

    Uses the highest-reliability source as the base grade.
    """
    if not enrichment_sources:
        return get_source_reliability("unknown")

    # Find the best grade among all enrichment sources
    best_idx = 5  # start at F
    for src in enrichment_sources:
        src_lower = src.strip().lower()
        # Map enrichment source names to platform keys
        source_map = {
            "whois": "whois",
            "dns": "dns",
            "dnsdumpster": "dns",
            "reverse_dns": "dns",
            "reverse_ip": "dns",
            "ip_geolocation": "shodan",
            "ip_intel": "shodan",
            "domain_intel": "whois",
            "social_search": "twitter",
            "news": "news",
            "nlp": "web_scrape",
            "crt.sh": "crt.sh",
            "abuseipdb": "abuseipdb",
            "otx": "otx",
            "username_enum": "web_scrape",
            "email_accounts": "web_scrape",
            "pivot_breach": "web_scrape",
            "pivot_email_accounts": "web_scrape",
            "pivot_whois": "whois",
        }
        mapped = source_map.get(src_lower, src_lower)
        grade = _PLATFORM_GRADES.get(mapped, "F")
        idx = _grade_index(grade)
        if idx < best_idx:
            best_idx = idx

    best_grade = _index_to_grade(best_idx)
    return {
        "grade": best_grade,
        "label": GRADE_LABELS[best_grade],
        "credibility": _default_credibility(best_grade),
        "rationale": f"Based on enrichment sources: {', '.join(enrichment_sources)}",
    }


def format_reliability_tag(reliability: dict[str, str]) -> str:
    """Format a reliability dict as a compact inline tag.

    Example: ``[B - Usually reliable]``
    """
    grade = reliability.get("grade", "F")
    label = reliability.get("label", GRADE_LABELS.get(grade, "?"))
    return f"[{grade} - {label}]"


# ---------------------------------------------------------------------------
# Per-entity confidence scoring (A3)
# ---------------------------------------------------------------------------

_GRADE_WEIGHT = {"A": 1.0, "B": 0.85, "C": 0.65, "D": 0.45, "E": 0.25, "F": 0.1}

_SOURCE_MAP = {
    "whois": "whois",
    "dns": "dns",
    "dnsdumpster": "dns",
    "reverse_dns": "dns",
    "reverse_ip": "dns",
    "ip_geolocation": "shodan",
    "ip_intel": "shodan",
    "domain_intel": "whois",
    "social_search": "twitter",
    "news": "news",
    "nlp": "web_scrape",
    "username_enum": "web_scrape",
    "email_accounts": "web_scrape",
    "pivot_breach": "web_scrape",
    "pivot_email_accounts": "web_scrape",
    "pivot_whois": "whois",
    "crt.sh": "crt.sh",
    "abuseipdb": "abuseipdb",
    "otx": "otx",
}


def compute_entity_confidence(
    enrichment_sources: list[str],
    has_geo: bool = False,
    profile_count: int = 0,
    mention_count: int = 0,
) -> dict[str, Any]:
    """Compute a weighted confidence score for an enriched entity.

    Considers source reliability grades rather than raw source count.
    Returns the score plus a breakdown of contributing factors.
    """
    if not enrichment_sources:
        return {"score": 0.1, "breakdown": {"reason": "no enrichment sources"}}

    unique_platforms = set()
    total_weight = 0.0
    breakdown = {}

    for src in enrichment_sources:
        mapped = _SOURCE_MAP.get(src.lower(), src.lower())
        grade = _PLATFORM_GRADES.get(mapped, "F")
        weight = _GRADE_WEIGHT.get(grade, 0.1)
        unique_platforms.add(mapped)
        total_weight += weight
        breakdown[src] = {"grade": grade, "weight": weight}

    base = min(total_weight / max(len(enrichment_sources), 1), 1.0)

    corroboration_bonus = min(len(unique_platforms) * 0.08, 0.24)
    geo_bonus = 0.05 if has_geo else 0.0
    profile_bonus = min(profile_count * 0.03, 0.12)
    mention_bonus = min(mention_count * 0.02, 0.08)

    score = min(base + corroboration_bonus + geo_bonus + profile_bonus + mention_bonus, 0.99)
    score = round(max(score, 0.05), 3)

    return {
        "score": score,
        "unique_platforms": len(unique_platforms),
        "corroboration_bonus": round(corroboration_bonus, 3),
        "breakdown": breakdown,
    }


# ---------------------------------------------------------------------------
# Cross-source contradiction detection (A4)
# ---------------------------------------------------------------------------

def detect_contradictions(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Detect contradictions among entities from different sources.

    Groups entities by value and checks for conflicting information:
    - Same entity value with different types
    - Geo points with large spatial disagreement
    - Conflicting raw data (e.g. whois registrant vs social profile name)
    """
    contradictions = []

    value_groups: dict[str, list[dict]] = {}
    for ent in entities:
        val = str(ent.get("entity_value", "")).strip().lower()
        if val:
            value_groups.setdefault(val, []).append(ent)

    for val, group in value_groups.items():
        if len(group) < 2:
            continue

        types = set(e.get("entity_type", "unknown") for e in group)
        if len(types) > 1:
            contradictions.append({
                "type": "type_conflict",
                "entity_value": val,
                "conflicting_types": sorted(types),
                "severity": "medium",
                "detail": f"Entity '{val}' appears as {', '.join(sorted(types))} across sources",
            })

    geo_entities = [e for e in entities if e.get("geo_points")]
    if len(geo_entities) >= 2:
        from math import radians, cos, sin, asin, sqrt

        def _haversine(lat1, lon1, lat2, lon2):
            lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
            return 2 * 6371 * asin(sqrt(a))

        all_geo = []
        for ent in geo_entities:
            for gp in ent.get("geo_points", []):
                lat, lon = gp.get("lat"), gp.get("lon")
                if lat is not None and lon is not None:
                    all_geo.append({
                        "lat": lat, "lon": lon,
                        "source": gp.get("source", "unknown"),
                        "entity": ent.get("entity_value", ""),
                    })

        for i in range(len(all_geo)):
            for j in range(i + 1, len(all_geo)):
                dist = _haversine(
                    all_geo[i]["lat"], all_geo[i]["lon"],
                    all_geo[j]["lat"], all_geo[j]["lon"],
                )
                if dist > 500:
                    contradictions.append({
                        "type": "geo_disagreement",
                        "entities": [all_geo[i]["entity"], all_geo[j]["entity"]],
                        "distance_km": round(dist, 1),
                        "sources": [all_geo[i]["source"], all_geo[j]["source"]],
                        "severity": "high" if dist > 2000 else "medium",
                        "detail": (
                            f"Geo sources disagree by {dist:.0f}km: "
                            f"{all_geo[i]['source']} vs {all_geo[j]['source']}"
                        ),
                    })

    return contradictions
