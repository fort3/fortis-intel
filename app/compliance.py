"""Data protection compliance helpers for Fortis Intelligence Hub.

Implements GDPR and NIST CSF 2.0 controls:
- Data classification enforcement
- Retention policy with configurable TTL
- Right to erasure (GDPR Art. 17)
- Processing record generation (GDPR Art. 30)
- Lawful basis documentation via investigation purpose
"""

import os
import logging
from datetime import datetime, timezone, timedelta

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATA_RETENTION_DAYS = int(os.environ.get("DATA_RETENTION_DAYS", "90"))
CACHE_TTL_HOURS = int(os.environ.get("CACHE_TTL_HOURS", "24"))

CLASSIFICATION_LEVELS = {
    "PUBLIC": {
        "label": "PUBLIC",
        "description": "No PII, general trends only",
        "retention_days": DATA_RETENTION_DAYS,
        "requires_auth": False,
    },
    "INTERNAL": {
        "label": "INTERNAL",
        "description": "Contains identifying details, organisational use",
        "retention_days": DATA_RETENTION_DAYS,
        "requires_auth": True,
    },
    "RESTRICTED": {
        "label": "RESTRICTED",
        "description": "Sensitive location or behavioural patterns",
        "retention_days": max(DATA_RETENTION_DAYS // 2, 30),
        "requires_auth": True,
    },
    "CONFIDENTIAL": {
        "label": "CONFIDENTIAL",
        "description": "Could endanger if disclosed",
        "retention_days": max(DATA_RETENTION_DAYS // 3, 14),
        "requires_auth": True,
    },
}

# GDPR lawful bases applicable to OSINT
LAWFUL_BASES = {
    "legitimate_interest": "Processing necessary for legitimate interests (Art. 6(1)(f))",
    "public_task": "Processing necessary for a task in the public interest (Art. 6(1)(e))",
    "legal_obligation": "Processing necessary for compliance with a legal obligation (Art. 6(1)(c))",
}

# NIST CSF 2.0 function mapping for ForgeChain
NIST_CSF_MAPPING = {
    "GV.PO": "ForgeChain governance policy — 3-verifier consensus gate on all LLM invocations",
    "GV.RM": "Risk management via sensitivity classification (PUBLIC/INTERNAL/RESTRICTED/CONFIDENTIAL)",
    "PR.AA": "Authentication via Google OAuth + session management; rate limiting per endpoint",
    "PR.DS": "Data security — input/output sanitisation, injection scanning, trusted/untrusted key separation",
    "PR.PS": "Platform security — dependency pinning, security headers (CSP, HSTS, X-Frame-Options)",
    "DE.CM": "Continuous monitoring — prompt injection detection, harassment/stalking detection, minor protection",
    "DE.AE": "Adverse event analysis — ForgeChain audit trail (ForgeBlocks), verifier vote logging",
    "RS.AN": "Response analysis — policy veto blocks with reason codes, fail-open with low confidence logging",
    "RS.MI": "Mitigation — rate limiting, query sanitisation, confidence-gated deep scraping",
    "RC.CO": "Recovery communications — graceful degradation when APIs unavailable",
}


# ---------------------------------------------------------------------------
# Retention enforcement
# ---------------------------------------------------------------------------

def get_retention_days(sensitivity_level: str) -> int:
    level = CLASSIFICATION_LEVELS.get(sensitivity_level, CLASSIFICATION_LEVELS["INTERNAL"])
    return level["retention_days"]


def evict_expired_cache(stored_reports: dict, ttl_hours: int | None = None) -> int:
    """Remove in-memory cached reports older than TTL. Returns count evicted."""
    ttl = ttl_hours or CACHE_TTL_HOURS
    cutoff = datetime.now(tz=timezone.utc) - timedelta(hours=ttl)
    expired = [
        sid for sid, report in stored_reports.items()
        if report.get("created_at") and report["created_at"] < cutoff
    ]
    for sid in expired:
        del stored_reports[sid]
    if expired:
        log.info("Cache eviction: removed %d expired reports (TTL=%dh)", len(expired), ttl)
    return len(expired)


def enforce_retention(report_store, sensitivity_level: str | None = None) -> int:
    """Hard-delete reports past their retention period from SQLite. Returns count deleted."""
    from datetime import datetime, timezone, timedelta

    deleted = 0
    for level_name, level_config in CLASSIFICATION_LEVELS.items():
        if sensitivity_level and level_name != sensitivity_level:
            continue
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=level_config["retention_days"])
        cutoff_iso = cutoff.isoformat()

        conn = report_store._connect()
        try:
            cursor = conn.execute(
                "DELETE FROM analysis_reports WHERE sensitivity_level = ? AND created_at < ?",
                (level_name, cutoff_iso),
            )
            conn.commit()
            count = cursor.rowcount
            if count > 0:
                log.info("Retention: deleted %d %s reports older than %d days",
                         count, level_name, level_config["retention_days"])
            deleted += count
        finally:
            conn.close()

    return deleted


# ---------------------------------------------------------------------------
# Right to erasure (GDPR Art. 17)
# ---------------------------------------------------------------------------

def erase_subject_data(report_store, subject_identifier: str,
                       stored_reports: dict | None = None) -> dict:
    """Delete ALL data associated with a subject identifier.

    Covers: analysis_reports, investigation_subjects, geo_data_points,
    entity_relationships, and in-memory cache.
    Returns a summary of what was deleted.
    """
    summary = {
        "subject": subject_identifier,
        "reports_deleted": 0,
        "subjects_deleted": 0,
        "geo_points_deleted": 0,
        "relationships_deleted": 0,
        "cache_entries_removed": 0,
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
    }

    conn = report_store._connect()
    try:
        # Delete analysis reports
        report_rows = conn.execute(
            "SELECT report_id FROM analysis_reports WHERE subject_identifier = ?",
            (subject_identifier,),
        ).fetchall()
        report_ids = [r["report_id"] for r in report_rows]

        if report_ids:
            placeholders = ",".join("?" * len(report_ids))
            # Delete geo points linked to these reports
            cursor = conn.execute(
                f"DELETE FROM geo_data_points WHERE investigation_id IN ({placeholders})",
                report_ids,
            )
            summary["geo_points_deleted"] += cursor.rowcount

            # Delete the reports themselves
            cursor = conn.execute(
                f"DELETE FROM analysis_reports WHERE report_id IN ({placeholders})",
                report_ids,
            )
            summary["reports_deleted"] = cursor.rowcount

        # Delete geo points by subject identifier directly
        cursor = conn.execute(
            "DELETE FROM geo_data_points WHERE subject_identifier = ?",
            (subject_identifier,),
        )
        summary["geo_points_deleted"] += cursor.rowcount

        # Delete entity relationships mentioning this subject
        cursor = conn.execute(
            "DELETE FROM entity_relationships WHERE source_entity = ? OR target_entity = ?",
            (subject_identifier, subject_identifier),
        )
        summary["relationships_deleted"] = cursor.rowcount

        # Delete investigation subject record
        cursor = conn.execute(
            "DELETE FROM investigation_subjects WHERE identifier = ?",
            (subject_identifier,),
        )
        summary["subjects_deleted"] = cursor.rowcount

        conn.commit()
    finally:
        conn.close()

    # Purge from in-memory cache
    if stored_reports is not None:
        to_remove = [
            sid for sid, report in stored_reports.items()
            if report.get("identifier") == subject_identifier
        ]
        for sid in to_remove:
            del stored_reports[sid]
        summary["cache_entries_removed"] = len(to_remove)

    log.info("Right to erasure: subject=%s, deleted=%s", subject_identifier, summary)
    return summary


# ---------------------------------------------------------------------------
# Processing record (GDPR Art. 30)
# ---------------------------------------------------------------------------

def generate_processing_record(report_store) -> dict:
    """Generate a GDPR Article 30 processing record from current data state."""
    stats = report_store.get_stats()

    return {
        "controller": "Fortis Intelligence Hub",
        "purpose": "Open-source intelligence (OSINT) collection, analysis, and reporting",
        "lawful_bases": LAWFUL_BASES,
        "categories_of_data_subjects": [
            "Investigation subjects (individuals, organisations, infrastructure)",
        ],
        "categories_of_personal_data": [
            "Usernames and online identifiers",
            "Email addresses",
            "Phone numbers",
            "IP addresses and domain names",
            "Geolocation data",
            "Social media profile data and public posts",
            "Public records and web mentions",
            "Entity relationships and network connections",
        ],
        "recipients": [
            "Authenticated platform users (investigators/analysts)",
        ],
        "retention_policy": {
            "policy": "Tiered by classification level",
            "levels": {
                level: f"{config['retention_days']} days"
                for level, config in CLASSIFICATION_LEVELS.items()
            },
            "in_memory_cache_ttl": f"{CACHE_TTL_HOURS} hours",
        },
        "security_measures": [
            "ForgeChain 3-verifier governance gate on all LLM invocations",
            "Input/output sanitisation with injection pattern scanning",
            "Google OAuth authentication with session management",
            "Rate limiting per endpoint",
            "Security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)",
            "User identity hashing (SHA-256) for audit trail",
            "Trusted/untrusted key separation for web-sourced content",
            "System credential leak detection (platform secrets only)",
        ],
        "nist_csf_mapping": NIST_CSF_MAPPING,
        "data_statistics": stats,
        "record_generated_at": datetime.now(tz=timezone.utc).isoformat(),
    }
