"""Breach and credential exposure lookup for Fortis Intelligence Hub.

Queries HaveIBeenPwned (v3) and optionally LeakCheck to find breach
exposures, paste mentions, and credential leaks for email addresses.

This is the single highest-value pivot in threat actor deanonymization:
a leaked password shared across a school email and a personal Gmail
can crack an entire attribution chain open.

Env vars:
    HIBP_API_KEY        — HaveIBeenPwned API key (paid, ~$3.50/mo)
    LEAKCHECK_API_KEY   — LeakCheck API key (optional, paid)
    BREACH_ENABLED      — Master toggle (default: true)
"""

import logging
import os
import time
from typing import Any

import requests

log = logging.getLogger(__name__)

BREACH_ENABLED = os.getenv("BREACH_ENABLED", "true").lower() in ("1", "true", "yes")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")
LEAKCHECK_API_KEY = os.getenv("LEAKCHECK_API_KEY", "")

_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_LEAKCHECK_BASE = "https://leakcheck.io/api/v2"
_USER_AGENT = "Fortis-Intelligence-Hub"
_HIBP_RATE_DELAY = 1.6  # HIBP requires >= 1.5s between requests

_last_hibp_call = 0.0


def _hibp_rate_wait():
    """Enforce HIBP rate limit."""
    global _last_hibp_call
    elapsed = time.time() - _last_hibp_call
    if elapsed < _HIBP_RATE_DELAY:
        time.sleep(_HIBP_RATE_DELAY - elapsed)
    _last_hibp_call = time.time()


def check_breaches(email: str) -> dict[str, Any]:
    """Check an email against breach databases.

    Returns a dict with breaches, pastes, and optional leak details.
    """
    if not BREACH_ENABLED:
        return {"enabled": False, "reason": "BREACH_ENABLED is false"}

    result: dict[str, Any] = {
        "enabled": True,
        "email": email,
        "breaches": [],
        "pastes": [],
        "leakcheck": [],
        "total_breaches": 0,
        "total_pastes": 0,
        "data_classes_exposed": [],
        "earliest_breach": None,
        "latest_breach": None,
    }

    if HIBP_API_KEY:
        result["breaches"] = _hibp_breached_account(email)
        result["pastes"] = _hibp_paste_account(email)
    else:
        result["breaches"] = _hibp_breaches_free(email)
        result["hibp_note"] = "Using free API — set HIBP_API_KEY for full breach details and paste search"

    if LEAKCHECK_API_KEY:
        result["leakcheck"] = _leakcheck_query(email)

    breaches = result["breaches"]
    result["total_breaches"] = len(breaches)
    result["total_pastes"] = len(result["pastes"])

    all_data_classes = set()
    dates = []
    for b in breaches:
        for dc in b.get("data_classes", []):
            all_data_classes.add(dc)
        bd = b.get("breach_date")
        if bd:
            dates.append(bd)

    result["data_classes_exposed"] = sorted(all_data_classes)
    if dates:
        result["earliest_breach"] = min(dates)
        result["latest_breach"] = max(dates)

    has_passwords = "Passwords" in all_data_classes
    has_emails = "Email addresses" in all_data_classes
    result["password_exposed"] = has_passwords
    result["credential_reuse_risk"] = has_passwords and has_emails

    return result


def _hibp_breached_account(email: str) -> list[dict[str, Any]]:
    """Query HIBP v3 breachedaccount endpoint (requires API key)."""
    _hibp_rate_wait()
    try:
        resp = requests.get(
            f"{_HIBP_BASE}/breachedaccount/{requests.utils.quote(email)}",
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "user-agent": _USER_AGENT,
            },
            params={"truncateResponse": "false"},
            timeout=15,
        )
        if resp.status_code == 200:
            raw = resp.json()
            return [_normalize_breach(b) for b in raw]
        if resp.status_code == 404:
            return []
        log.warning("HIBP breachedaccount returned %d: %s", resp.status_code, resp.text[:200])
        return []
    except Exception as exc:
        log.warning("HIBP breachedaccount failed: %s", exc)
        return []


def _hibp_paste_account(email: str) -> list[dict[str, Any]]:
    """Query HIBP v3 pasteaccount endpoint (requires API key)."""
    _hibp_rate_wait()
    try:
        resp = requests.get(
            f"{_HIBP_BASE}/pasteaccount/{requests.utils.quote(email)}",
            headers={
                "hibp-api-key": HIBP_API_KEY,
                "user-agent": _USER_AGENT,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            raw = resp.json()
            return [_normalize_paste(p) for p in raw]
        if resp.status_code == 404:
            return []
        log.warning("HIBP pasteaccount returned %d", resp.status_code)
        return []
    except Exception as exc:
        log.warning("HIBP pasteaccount failed: %s", exc)
        return []


def _hibp_breaches_free(email: str) -> list[dict[str, Any]]:
    """Fallback: query HIBP breach names without API key (truncated)."""
    _hibp_rate_wait()
    try:
        resp = requests.get(
            f"{_HIBP_BASE}/breachedaccount/{requests.utils.quote(email)}",
            headers={"user-agent": _USER_AGENT},
            params={"truncateResponse": "true"},
            timeout=15,
        )
        if resp.status_code == 200:
            return [{"name": b.get("Name", "unknown"), "source": "hibp_free"} for b in resp.json()]
        if resp.status_code in (401, 404):
            return []
        return []
    except Exception:
        return []


def _leakcheck_query(email: str) -> list[dict[str, Any]]:
    """Query LeakCheck API for credential exposures."""
    try:
        resp = requests.get(
            f"{_LEAKCHECK_BASE}/query/{requests.utils.quote(email)}",
            headers={"X-API-Key": LEAKCHECK_API_KEY},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success") and data.get("result"):
                return [
                    {
                        "source": entry.get("source", {}).get("name", "unknown"),
                        "breach_date": entry.get("source", {}).get("date"),
                        "fields": entry.get("fields", []),
                        "has_password": "password" in entry.get("fields", []),
                    }
                    for entry in data["result"]
                ]
        return []
    except Exception as exc:
        log.warning("LeakCheck query failed: %s", exc)
        return []


def _normalize_breach(b: dict) -> dict[str, Any]:
    """Normalize an HIBP breach object."""
    return {
        "name": b.get("Name", ""),
        "title": b.get("Title", ""),
        "domain": b.get("Domain", ""),
        "breach_date": b.get("BreachDate", ""),
        "added_date": b.get("AddedDate", ""),
        "pwn_count": b.get("PwnCount", 0),
        "data_classes": b.get("DataClasses", []),
        "is_verified": b.get("IsVerified", False),
        "is_sensitive": b.get("IsSensitive", False),
        "is_fabricated": b.get("IsFabricated", False),
        "description": b.get("Description", ""),
        "source": "hibp",
    }


def _normalize_paste(p: dict) -> dict[str, Any]:
    """Normalize an HIBP paste object."""
    return {
        "source": p.get("Source", ""),
        "paste_id": p.get("Id", ""),
        "title": p.get("Title", ""),
        "date": p.get("Date", ""),
        "email_count": p.get("EmailCount", 0),
    }


def breach_summary_text(result: dict[str, Any]) -> str:
    """Produce a compact text summary for LLM context."""
    if not result.get("enabled"):
        return ""

    lines = []
    breaches = result.get("breaches", [])
    pastes = result.get("pastes", [])
    leaks = result.get("leakcheck", [])

    if not breaches and not pastes and not leaks:
        lines.append(f"BREACH CHECK ({result['email']}): No known breaches or credential exposures found.")
        return "\n".join(lines)

    lines.append(f"BREACH CHECK ({result['email']}):")
    if breaches:
        lines.append(f"  Found in {len(breaches)} breach(es):")
        for b in breaches[:10]:
            data = ", ".join(b.get("data_classes", [])[:5]) if b.get("data_classes") else "unknown"
            lines.append(f"    - {b.get('name', '?')} ({b.get('breach_date', '?')}): {data}")

    if result.get("password_exposed"):
        lines.append("  !! PASSWORD EXPOSED in at least one breach — credential reuse risk")
    if result.get("credential_reuse_risk"):
        lines.append("  !! HIGH RISK: Email + password both leaked — pivot on password reuse")

    if pastes:
        lines.append(f"  Found in {len(pastes)} paste(s):")
        for p in pastes[:5]:
            lines.append(f"    - {p.get('source', '?')}/{p.get('paste_id', '?')} ({p.get('date', '?')})")

    if leaks:
        pw_leaks = [lk for lk in leaks if lk.get("has_password")]
        if pw_leaks:
            lines.append(f"  LeakCheck: {len(pw_leaks)} source(s) with password exposure:")
            for lk in pw_leaks[:5]:
                lines.append(f"    - {lk.get('source', '?')} ({lk.get('breach_date', '?')})")

    data_classes = result.get("data_classes_exposed", [])
    if data_classes:
        lines.append(f"  Data types exposed: {', '.join(data_classes[:15])}")

    return "\n".join(lines)
