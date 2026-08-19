"""Bias Audit module for Fortis Intelligence Hub.

Analyses investigation reports and their underlying OSINT data for common
cognitive biases that degrade intelligence analysis accuracy.  All checks
are deterministic (no LLM calls) so results are reproducible.

Detected biases:
    - Source concentration  — over-reliance on a single platform
    - Confirmation pattern  — zero contradicting/alternative findings
    - Temporal skew         — evidence clustered in a narrow time window
    - Coverage gaps         — platforms queried but returned nothing
    - Single-source claims  — key assertions backed by only one source

Exports:
    run_bias_audit  -- main entry point
"""

import logging
import re
from collections import Counter
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)

# ── Thresholds ────────────────────────────────────────────────────────
SOURCE_CONCENTRATION_THRESHOLD = 0.60  # flag if one platform > 60%
TEMPORAL_WINDOW_HOURS = 48  # flag if all evidence within this window
MIN_PLATFORMS_FOR_COVERAGE_CHECK = 3


def run_bias_audit(
    report_text: str,
    findings_dict: dict[str, Any],
    platforms_queried: list[str] | None = None,
) -> dict[str, Any]:
    """Run a comprehensive bias audit on an investigation and its data.

    Parameters
    ----------
    report_text:
        The LLM-generated investigation report.
    findings_dict:
        Serialised ``OSINTFindings`` dict with profiles, posts,
        web_mentions, entities, etc.
    platforms_queried:
        List of platforms that were queried (to detect coverage gaps).

    Returns
    -------
    dict with keys:
        - ``overall_risk``: HEALTHY | ELEVATED | HIGH
        - ``score``: 0.0-1.0 composite bias risk
        - ``checks``: list of individual check results
        - ``warnings``: list of human-readable warning strings
        - ``recommendations``: list of actionable suggestions
    """
    checks: list[dict[str, Any]] = []
    warnings: list[str] = []
    recommendations: list[str] = []

    try:
        checks.append(_check_source_concentration(findings_dict))
        checks.append(_check_confirmation_pattern(report_text))
        checks.append(_check_temporal_skew(findings_dict))
        checks.append(_check_coverage_gaps(findings_dict, platforms_queried))
        checks.append(_check_single_source_claims(report_text, findings_dict))
    except Exception as exc:
        log.error("Bias audit encountered an error: %s", exc)

    for check in checks:
        if check.get("flagged"):
            warnings.append(check["warning"])
            if check.get("recommendation"):
                recommendations.append(check["recommendation"])

    flagged_count = sum(1 for c in checks if c.get("flagged"))
    total_checks = len(checks) or 1
    score = round(flagged_count / total_checks, 2)

    if score >= 0.6:
        overall_risk = "HIGH"
    elif score >= 0.3:
        overall_risk = "ELEVATED"
    else:
        overall_risk = "HEALTHY"

    log.info(
        "Bias audit complete: %s (%.0f%% checks flagged, %d warnings)",
        overall_risk, score * 100, len(warnings),
    )

    return {
        "overall_risk": overall_risk,
        "score": score,
        "checks": checks,
        "warnings": warnings,
        "recommendations": recommendations,
    }


# ── Individual checks ─────────────────────────────────────────────────

def _check_source_concentration(
    findings_dict: dict[str, Any],
) -> dict[str, Any]:
    """Flag when one platform provides >60% of all evidence."""
    platform_counts: Counter[str] = Counter()

    for profile in findings_dict.get("profiles", []):
        platform_counts[profile.get("platform", "unknown")] += 1
    for post in findings_dict.get("posts", []):
        platform_counts[post.get("platform", "unknown")] += 1
    for wm in findings_dict.get("web_mentions", []):
        platform_counts[wm.get("domain", "web")] += 1

    total = sum(platform_counts.values())
    if total == 0:
        return {
            "name": "source_concentration",
            "flagged": False,
            "detail": "No source data to assess.",
        }

    top_platform, top_count = platform_counts.most_common(1)[0]
    concentration = top_count / total

    flagged = concentration > SOURCE_CONCENTRATION_THRESHOLD
    return {
        "name": "source_concentration",
        "flagged": flagged,
        "concentration": round(concentration, 2),
        "top_platform": top_platform,
        "platform_distribution": dict(platform_counts),
        "total_items": total,
        "warning": (
            f"Source concentration bias: {top_platform} accounts for "
            f"{concentration:.0%} of all evidence ({top_count}/{total} items). "
            f"Findings may reflect this platform's user base rather than ground truth."
        ) if flagged else "",
        "recommendation": (
            f"Seek corroborating evidence from platforms other than {top_platform}. "
            f"Cross-reference key claims with independent sources."
        ) if flagged else "",
    }


def _check_confirmation_pattern(report_text: str) -> dict[str, Any]:
    """Flag when the report contains zero contradiction/uncertainty language."""
    contradiction_signals = [
        r"\bcontradicted?\b",
        r"\binconsisten(?:t|cy)\b",
        r"\bconflicting\b",
        r"\bhowever\b",
        r"\bon the other hand\b",
        r"\balternative(?:ly)?\b",
        r"\bdisputed?\b",
        r"\bunverified\b",
        r"\bunconfirmed\b",
        r"\bunclear\b",
        r"\buncertain(?:ty)?\b",
        r"\bcould also\b",
        r"\bmay not\b",
        r"\bcannot confirm\b",
        r"\binsufficient\b",
        r"\blimited evidence\b",
    ]

    lower_text = report_text.lower()
    found_signals: list[str] = []
    for pattern in contradiction_signals:
        if re.search(pattern, lower_text):
            found_signals.append(pattern.replace(r"\b", "").replace("\\b", ""))

    flagged = len(found_signals) == 0
    return {
        "name": "confirmation_pattern",
        "flagged": flagged,
        "contradiction_signals_found": len(found_signals),
        "signals": found_signals[:5],
        "warning": (
            "Confirmation bias risk: the report contains no contradiction, "
            "uncertainty, or alternative-hypothesis language. All findings "
            "appear to confirm a single narrative without nuance."
        ) if flagged else "",
        "recommendation": (
            "Consider what evidence would disprove the main conclusions. "
            "Add a 'Competing Hypotheses' or 'Limitations' section."
        ) if flagged else "",
    }


def _check_temporal_skew(findings_dict: dict[str, Any]) -> dict[str, Any]:
    """Flag when all evidence comes from a narrow time window."""
    timestamps: list[datetime] = []

    for post in findings_dict.get("posts", []):
        ts_str = post.get("timestamp", "")
        if ts_str:
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                timestamps.append(dt)
            except (ValueError, TypeError):
                continue

    if len(timestamps) < 3:
        return {
            "name": "temporal_skew",
            "flagged": False,
            "detail": f"Only {len(timestamps)} timestamped items — insufficient for temporal analysis.",
        }

    timestamps.sort()
    span_hours = (timestamps[-1] - timestamps[0]).total_seconds() / 3600

    flagged = span_hours <= TEMPORAL_WINDOW_HOURS
    return {
        "name": "temporal_skew",
        "flagged": flagged,
        "span_hours": round(span_hours, 1),
        "earliest": timestamps[0].isoformat(),
        "latest": timestamps[-1].isoformat(),
        "sample_count": len(timestamps),
        "warning": (
            f"Temporal skew: all {len(timestamps)} timestamped items fall within "
            f"a {span_hours:.0f}-hour window ({timestamps[0].date()} to "
            f"{timestamps[-1].date()}). The analysis may not reflect the "
            f"subject's full history."
        ) if flagged else "",
        "recommendation": (
            "Broaden the collection time window. Historical data may "
            "reveal patterns not visible in the current snapshot."
        ) if flagged else "",
    }


def _check_coverage_gaps(
    findings_dict: dict[str, Any],
    platforms_queried: list[str] | None,
) -> dict[str, Any]:
    """Flag platforms that were queried but returned no data."""
    if not platforms_queried or len(platforms_queried) < MIN_PLATFORMS_FOR_COVERAGE_CHECK:
        return {
            "name": "coverage_gaps",
            "flagged": False,
            "detail": "Fewer than 3 platforms queried — skipping coverage gap check.",
        }

    platforms_with_data: set[str] = set()
    for profile in findings_dict.get("profiles", []):
        platforms_with_data.add(profile.get("platform", ""))
    for post in findings_dict.get("posts", []):
        platforms_with_data.add(post.get("platform", ""))

    queried_set = set(p.lower() for p in platforms_queried)
    data_set = set(p.lower() for p in platforms_with_data if p)
    gaps = queried_set - data_set

    gap_ratio = len(gaps) / len(queried_set) if queried_set else 0
    flagged = gap_ratio > 0.5

    return {
        "name": "coverage_gaps",
        "flagged": flagged,
        "platforms_queried": sorted(queried_set),
        "platforms_with_data": sorted(data_set),
        "gaps": sorted(gaps),
        "gap_ratio": round(gap_ratio, 2),
        "warning": (
            f"Coverage gaps: {len(gaps)}/{len(queried_set)} queried platforms "
            f"returned no data ({', '.join(sorted(gaps))}). Conclusions are "
            f"based on a narrow slice of available sources."
        ) if flagged else "",
        "recommendation": (
            f"Investigate why {', '.join(sorted(gaps))} returned no results. "
            f"The subject may be active under different identifiers on those platforms."
        ) if flagged else "",
    }


def _check_single_source_claims(
    report_text: str,
    findings_dict: dict[str, Any],
) -> dict[str, Any]:
    """Flag when key entities appear in only one source."""
    entity_sources: dict[str, set[str]] = {}

    for profile in findings_dict.get("profiles", []):
        platform = profile.get("platform", "unknown")
        for field in ("username", "display_name", "bio"):
            val = str(profile.get(field, ""))
            for word in val.split():
                clean = word.strip("@.,;:!?()[]").lower()
                if len(clean) > 2:
                    entity_sources.setdefault(clean, set()).add(platform)

    for post in findings_dict.get("posts", []):
        platform = post.get("platform", "unknown")
        content = str(post.get("content", ""))
        for word in content.split():
            clean = word.strip("@.,;:!?()[]").lower()
            if len(clean) > 2:
                entity_sources.setdefault(clean, set()).add(platform)

    entities = findings_dict.get("entities", [])
    single_source_entities = []
    for ent in entities:
        value = ent.get("entity_value", "").lower()
        sources = entity_sources.get(value, set())
        if len(sources) <= 1 and ent.get("entity_type") in (
            "PERSON", "ORG", "GPE", "LOC",
        ):
            single_source_entities.append({
                "entity": ent.get("entity_value", ""),
                "type": ent.get("entity_type", ""),
                "source_count": len(sources),
                "sources": sorted(sources),
            })

    flagged = len(single_source_entities) > len(entities) * 0.5 if entities else False

    return {
        "name": "single_source_claims",
        "flagged": flagged,
        "single_source_entities": single_source_entities[:10],
        "total_entities": len(entities),
        "single_source_count": len(single_source_entities),
        "warning": (
            f"Single-source risk: {len(single_source_entities)}/{len(entities)} "
            f"key entities appear in only one source. These claims lack "
            f"independent corroboration."
        ) if flagged else "",
        "recommendation": (
            "Cross-reference single-source entities against independent "
            "databases, news archives, or additional OSINT platforms."
        ) if flagged else "",
    }
