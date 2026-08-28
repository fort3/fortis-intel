"""Email-to-accounts resolution for Fortis Intelligence Hub.

Discovers which online services an email address is registered on by
probing password-reset, signup, and login endpoints. Equivalent to
Holehe/PredictaGraph-style service detection.

This fills a critical gap in the deanonymization chain: given an email
like surfinup8@gmail.com, we can discover linked TikTok, LinkedIn,
Adobe, Spotify accounts — each of which may reveal real names, avatars,
or other pivotable identifiers.

Uses Holehe library when available, falls back to a built-in probe set.

Env vars:
    EMAIL_ACCOUNTS_ENABLED  — Master toggle (default: true)
    EMAIL_ACCOUNTS_TIMEOUT  — Per-request timeout in seconds (default: 10)
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

log = logging.getLogger(__name__)

EMAIL_ACCOUNTS_ENABLED = os.getenv("EMAIL_ACCOUNTS_ENABLED", "true").lower() in ("1", "true", "yes")
_TIMEOUT = int(os.getenv("EMAIL_ACCOUNTS_TIMEOUT", "10"))
_WORKERS = 10

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "application/json, text/html",
    "Accept-Language": "en-US,en;q=0.9",
}

_HOLEHE_AVAILABLE = False
try:
    import holehe
    _HOLEHE_AVAILABLE = True
except ImportError:
    pass


def check_email_accounts(email: str) -> dict[str, Any]:
    """Discover services an email is registered on.

    Returns a dict with found services, their categories, and metadata.
    """
    if not EMAIL_ACCOUNTS_ENABLED:
        return {"enabled": False, "reason": "EMAIL_ACCOUNTS_ENABLED is false"}

    if not email or "@" not in email:
        return {"enabled": True, "email": email, "services": [], "total_found": 0}

    if _HOLEHE_AVAILABLE:
        return _check_via_holehe(email)

    return _check_builtin(email)


def _check_via_holehe(email: str) -> dict[str, Any]:
    """Use Holehe library for comprehensive service detection."""
    import asyncio

    try:
        from holehe.core import import_submodules, get_functions

        loop = asyncio.new_event_loop()

        async def _run():
            modules = import_submodules("holehe.modules")
            websites = get_functions(modules)
            client_session = requests.Session()
            out = []
            for website in websites:
                try:
                    result = await website(email)
                    if result and result.get("exists"):
                        out.append({
                            "service": result.get("name", "unknown"),
                            "exists": True,
                            "category": _categorize_service(result.get("name", "")),
                            "method": "holehe",
                        })
                except Exception:
                    pass
            return out

        services = loop.run_until_complete(_run())
        loop.close()

        return {
            "enabled": True,
            "email": email,
            "services": services,
            "total_found": len(services),
            "method": "holehe",
        }
    except Exception as exc:
        log.warning("Holehe check failed, falling back to builtin: %s", exc)
        return _check_builtin(email)


# Built-in service probes when Holehe isn't installed
_BUILTIN_PROBES: list[dict[str, Any]] = [
    {
        "name": "Twitter/X",
        "url": "https://api.twitter.com/i/users/email_available.json",
        "method": "GET",
        "params_key": "email",
        "exists_when": "taken",
        "check_field": "taken",
        "category": "social",
    },
    {
        "name": "GitHub",
        "url": "https://github.com/signup_check/email",
        "method": "POST",
        "json_body": True,
        "body_key": "value",
        "exists_when": "unavailable",
        "check_text": "unavailable",
        "category": "developer",
    },
    {
        "name": "Spotify",
        "url": "https://spclient.wg.spotify.com/signup/public/v1/account",
        "method": "GET",
        "params_key": "validate",
        "params_extra": {"key": "email"},
        "exists_when": "status_20",
        "check_field": "status",
        "check_value": 20,
        "category": "media",
    },
    {
        "name": "Pinterest",
        "url": "https://www.pinterest.com/resource/EmailExistsResource/get/",
        "method": "GET",
        "params_key": "source_url",
        "params_template": '/login/?email={}',
        "exists_when": "json_exists",
        "category": "social",
    },
    {
        "name": "Imgur",
        "url": "https://imgur.com/signin/ajax_email_check",
        "method": "POST",
        "form_key": "email",
        "exists_when": "json_status",
        "check_field": "data",
        "check_subfield": "available",
        "invert": True,
        "category": "media",
    },
    {
        "name": "WordPress",
        "url": "https://public-api.wordpress.com/rest/v1.1/users/suggest",
        "method": "GET",
        "params_key": "email",
        "exists_when": "status_200",
        "category": "blogging",
    },
    {
        "name": "Gravatar",
        "url": "https://en.gravatar.com/{}.json",
        "method": "hash_email",
        "exists_when": "status_200",
        "category": "identity",
    },
    {
        "name": "Discord",
        "url": "https://discord.com/api/v9/unique-username/username-suggestions-unauthed",
        "method": "POST",
        "json_body": True,
        "body_key": "email",
        "exists_when": "status_200",
        "category": "social",
    },
    {
        "name": "Adobe",
        "url": "https://auth.services.adobe.com/signin/v2/users/accounts",
        "method": "POST",
        "json_body": True,
        "body_key": "username",
        "exists_when": "json_has_accounts",
        "check_field": "accounts",
        "category": "creative",
    },
]


def _check_builtin(email: str) -> dict[str, Any]:
    """Built-in probe set for common services."""
    services: list[dict[str, Any]] = []

    def _probe_service(probe: dict) -> dict[str, Any] | None:
        try:
            if probe["method"] == "hash_email":
                import hashlib
                email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
                url = probe["url"].format(email_hash)
                resp = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)
                if resp.status_code == 200:
                    return {"service": probe["name"], "exists": True, "category": probe["category"], "method": "builtin"}
                return None

            if probe["method"] == "GET":
                params = {}
                if probe.get("params_key"):
                    if probe.get("params_template"):
                        params[probe["params_key"]] = probe["params_template"].format(email)
                    else:
                        params[probe["params_key"]] = email
                if probe.get("params_extra"):
                    params.update(probe["params_extra"])
                resp = requests.get(probe["url"], params=params, headers=_HEADERS, timeout=_TIMEOUT)

            elif probe["method"] == "POST":
                if probe.get("json_body"):
                    resp = requests.post(
                        probe["url"],
                        json={probe.get("body_key", "email"): email},
                        headers={**_HEADERS, "Content-Type": "application/json"},
                        timeout=_TIMEOUT,
                    )
                elif probe.get("form_key"):
                    resp = requests.post(
                        probe["url"],
                        data={probe["form_key"]: email},
                        headers=_HEADERS,
                        timeout=_TIMEOUT,
                    )
                else:
                    return None
            else:
                return None

            exists = _check_existence(resp, probe)
            if exists:
                return {"service": probe["name"], "exists": True, "category": probe["category"], "method": "builtin"}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        futures = {pool.submit(_probe_service, p): p for p in _BUILTIN_PROBES}
        for future in as_completed(futures):
            result = future.result()
            if result:
                services.append(result)

    return {
        "enabled": True,
        "email": email,
        "services": services,
        "total_found": len(services),
        "method": "builtin",
        "note": "Install holehe for broader coverage (pip install holehe)" if not _HOLEHE_AVAILABLE else None,
    }


def _check_existence(resp: requests.Response, probe: dict) -> bool:
    """Evaluate response to determine if account exists."""
    check = probe.get("exists_when", "")

    if check == "status_200":
        return resp.status_code == 200
    if check == "status_20":
        try:
            return resp.json().get(probe.get("check_field")) == probe.get("check_value")
        except Exception:
            return False
    if check == "taken":
        try:
            return resp.json().get(probe.get("check_field")) is True
        except Exception:
            return False
    if check == "unavailable":
        return probe.get("check_text", "") in resp.text.lower()
    if check == "json_exists":
        try:
            return resp.status_code == 200
        except Exception:
            return False
    if check == "json_status":
        try:
            data = resp.json()
            val = data.get(probe.get("check_field", ""), {})
            if probe.get("check_subfield"):
                val = val.get(probe["check_subfield"])
            if probe.get("invert"):
                return val is False
            return val is True
        except Exception:
            return False
    if check == "json_has_accounts":
        try:
            data = resp.json()
            accounts = data.get(probe.get("check_field", "accounts"), [])
            return len(accounts) > 0
        except Exception:
            return False
    return False


def _categorize_service(name: str) -> str:
    """Assign a category to a service name."""
    name_lower = name.lower()
    social = {"twitter", "facebook", "instagram", "tiktok", "snapchat", "pinterest", "vk", "ok.ru", "discord", "threads", "mastodon"}
    developer = {"github", "gitlab", "bitbucket", "npm", "pypi", "docker", "hugging", "stackoverflow", "kaggle"}
    media = {"spotify", "soundcloud", "youtube", "twitch", "vimeo", "imgur", "flickr", "dailymotion"}
    gaming = {"steam", "xbox", "playstation", "roblox", "chess.com", "lichess"}
    commerce = {"ebay", "etsy", "amazon", "paypal", "stripe"}

    for cat, keywords in [("social", social), ("developer", developer), ("media", media), ("gaming", gaming), ("commerce", commerce)]:
        if any(k in name_lower for k in keywords):
            return cat
    return "other"


def accounts_summary_text(result: dict[str, Any]) -> str:
    """Produce a compact text summary for LLM context."""
    if not result.get("enabled"):
        return ""

    services = result.get("services", [])
    email = result.get("email", "?")

    if not services:
        return f"EMAIL ACCOUNT CHECK ({email}): No registered services detected."

    lines = [f"EMAIL ACCOUNT CHECK ({email}): Registered on {len(services)} service(s):"]
    by_cat: dict[str, list] = {}
    for s in services:
        by_cat.setdefault(s.get("category", "other"), []).append(s)

    for cat in sorted(by_cat.keys()):
        names = ", ".join(s["service"] for s in by_cat[cat])
        lines.append(f"  [{cat}] {names}")

    lines.append("  → Check each service for: display name, avatar, bio, linked accounts, public activity")
    return "\n".join(lines)
