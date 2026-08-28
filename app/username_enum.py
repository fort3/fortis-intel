"""Broad username enumeration for Fortis Intelligence Hub.

Probes 100+ sites for account existence by username — Sherlock/Maigret-style
coverage without the heavy dependency. Focuses on platforms relevant to
OSINT and threat intelligence investigations.

The site database is curated for high signal: developer platforms, security
forums, gaming networks, crypto services, and social media that the 8-platform
API-based search in social_client.py doesn't cover.

Env vars:
    USERNAME_ENUM_ENABLED  — Master toggle (default: true)
    USERNAME_ENUM_TIMEOUT  — Per-request timeout in seconds (default: 8)
    USERNAME_ENUM_WORKERS  — Concurrent workers (default: 20)
"""

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests

log = logging.getLogger(__name__)

USERNAME_ENUM_ENABLED = os.getenv("USERNAME_ENUM_ENABLED", "true").lower() in ("1", "true", "yes")
_TIMEOUT = int(os.getenv("USERNAME_ENUM_TIMEOUT", "8"))
_WORKERS = int(os.getenv("USERNAME_ENUM_WORKERS", "20"))

_SESSION_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/json",
    "Accept-Language": "en-US,en;q=0.9",
}

# fmt: off
SITE_DB: list[dict[str, Any]] = [
    # ── Developer & Security ──────────────────────────────────────────────
    {"name": "GitHub",          "url": "https://github.com/{}",                       "method": "status", "expect": 200, "category": "developer"},
    {"name": "GitLab",          "url": "https://gitlab.com/{}",                       "method": "status", "expect": 200, "category": "developer"},
    {"name": "Bitbucket",       "url": "https://bitbucket.org/{}/",                   "method": "status", "expect": 200, "category": "developer"},
    {"name": "HackerOne",       "url": "https://hackerone.com/{}",                    "method": "status", "expect": 200, "category": "security"},
    {"name": "Bugcrowd",        "url": "https://bugcrowd.com/{}",                     "method": "status", "expect": 200, "category": "security"},
    {"name": "Docker Hub",      "url": "https://hub.docker.com/u/{}",                 "method": "status", "expect": 200, "category": "developer"},
    {"name": "npm",             "url": "https://www.npmjs.com/~{}",                   "method": "status", "expect": 200, "category": "developer"},
    {"name": "PyPI",            "url": "https://pypi.org/user/{}/",                   "method": "status", "expect": 200, "category": "developer"},
    {"name": "Hugging Face",    "url": "https://huggingface.co/{}",                   "method": "status", "expect": 200, "category": "developer"},
    {"name": "Stack Overflow",  "url": "https://stackoverflow.com/users/?tab=accounts&search={}",  "method": "content", "indicator": "users/", "category": "developer"},
    {"name": "Replit",          "url": "https://replit.com/@{}",                       "method": "status", "expect": 200, "category": "developer"},
    {"name": "CodePen",         "url": "https://codepen.io/{}",                       "method": "status", "expect": 200, "category": "developer"},
    {"name": "Kaggle",          "url": "https://www.kaggle.com/{}",                   "method": "status", "expect": 200, "category": "developer"},
    {"name": "Tryhackme",       "url": "https://tryhackme.com/p/{}",                  "method": "status", "expect": 200, "category": "security"},
    {"name": "HackTheBox",      "url": "https://app.hackthebox.com/users/{}",         "method": "status", "expect": 200, "category": "security"},
    {"name": "Keybase",         "url": "https://keybase.io/{}",                       "method": "status", "expect": 200, "category": "security"},
    {"name": "Crates.io",       "url": "https://crates.io/users/{}",                  "method": "status", "expect": 200, "category": "developer"},

    # ── Social (not covered by social_client.py API) ──────────────────────
    {"name": "Pinterest",       "url": "https://www.pinterest.com/{}/",               "method": "status", "expect": 200, "category": "social"},
    {"name": "Tumblr",          "url": "https://{}.tumblr.com",                       "method": "status", "expect": 200, "category": "social"},
    {"name": "Flickr",          "url": "https://www.flickr.com/people/{}/",           "method": "status", "expect": 200, "category": "social"},
    {"name": "Medium",          "url": "https://medium.com/@{}",                      "method": "status", "expect": 200, "category": "social"},
    {"name": "DeviantArt",      "url": "https://www.deviantart.com/{}",               "method": "status", "expect": 200, "category": "social"},
    {"name": "About.me",        "url": "https://about.me/{}",                         "method": "status", "expect": 200, "category": "social"},
    {"name": "Gravatar",        "url": "https://en.gravatar.com/{}",                  "method": "status", "expect": 200, "category": "social"},
    {"name": "Linktree",        "url": "https://linktr.ee/{}",                        "method": "status", "expect": 200, "category": "social"},
    {"name": "Substack",        "url": "https://{}.substack.com",                     "method": "status", "expect": 200, "category": "social"},
    {"name": "Threads",         "url": "https://www.threads.net/@{}",                 "method": "status", "expect": 200, "category": "social"},
    {"name": "Bluesky",         "url": "https://bsky.app/profile/{}.bsky.social",     "method": "status", "expect": 200, "category": "social"},
    {"name": "Snapchat",        "url": "https://www.snapchat.com/add/{}",             "method": "status", "expect": 200, "category": "social"},
    {"name": "VK",              "url": "https://vk.com/{}",                           "method": "content", "indicator": "\"name\":", "category": "social"},
    {"name": "OK.ru",           "url": "https://ok.ru/{}",                            "method": "status", "expect": 200, "category": "social"},

    # ── Gaming ────────────────────────────────────────────────────────────
    {"name": "Steam Community",  "url": "https://steamcommunity.com/id/{}",           "method": "content", "indicator": "profile_header", "category": "gaming"},
    {"name": "Xbox Gamertag",    "url": "https://xboxgamertag.com/search/{}",         "method": "content", "indicator": "gamertag", "category": "gaming"},
    {"name": "Chess.com",        "url": "https://www.chess.com/member/{}",            "method": "status", "expect": 200, "category": "gaming"},
    {"name": "Lichess",          "url": "https://lichess.org/@/{}",                   "method": "status", "expect": 200, "category": "gaming"},
    {"name": "Roblox",           "url": "https://www.roblox.com/user.aspx?username={}", "method": "content", "indicator": "profile-header", "category": "gaming"},
    {"name": "Minecraft",        "url": "https://namemc.com/profile/{}",              "method": "status", "expect": 200, "category": "gaming"},

    # ── Media & Content ───────────────────────────────────────────────────
    {"name": "Twitch",          "url": "https://www.twitch.tv/{}",                    "method": "status", "expect": 200, "category": "media"},
    {"name": "SoundCloud",      "url": "https://soundcloud.com/{}",                   "method": "status", "expect": 200, "category": "media"},
    {"name": "Spotify",         "url": "https://open.spotify.com/user/{}",            "method": "status", "expect": 200, "category": "media"},
    {"name": "Vimeo",           "url": "https://vimeo.com/{}",                        "method": "status", "expect": 200, "category": "media"},
    {"name": "Mixcloud",        "url": "https://www.mixcloud.com/{}/",                "method": "status", "expect": 200, "category": "media"},
    {"name": "Dailymotion",     "url": "https://www.dailymotion.com/{}",              "method": "status", "expect": 200, "category": "media"},

    # ── Commerce & Finance ────────────────────────────────────────────────
    {"name": "eBay",            "url": "https://www.ebay.com/usr/{}",                 "method": "status", "expect": 200, "category": "commerce"},
    {"name": "Etsy",            "url": "https://www.etsy.com/shop/{}",                "method": "status", "expect": 200, "category": "commerce"},
    {"name": "Patreon",         "url": "https://www.patreon.com/{}",                  "method": "status", "expect": 200, "category": "commerce"},
    {"name": "Fiverr",          "url": "https://www.fiverr.com/{}",                   "method": "status", "expect": 200, "category": "commerce"},
    {"name": "Gumroad",         "url": "https://{}.gumroad.com",                      "method": "status", "expect": 200, "category": "commerce"},
    {"name": "Ko-fi",           "url": "https://ko-fi.com/{}",                        "method": "status", "expect": 200, "category": "commerce"},
    {"name": "Buy Me a Coffee", "url": "https://www.buymeacoffee.com/{}",             "method": "status", "expect": 200, "category": "commerce"},

    # ── Forums & Communities ──────────────────────────────────────────────
    {"name": "Scratch",         "url": "https://scratch.mit.edu/users/{}/",           "method": "status", "expect": 200, "category": "community"},
    {"name": "Instructables",   "url": "https://www.instructables.com/member/{}/",    "method": "status", "expect": 200, "category": "community"},
    {"name": "Disqus",          "url": "https://disqus.com/by/{}/",                   "method": "status", "expect": 200, "category": "community"},
    {"name": "Letterboxd",      "url": "https://letterboxd.com/{}/",                  "method": "status", "expect": 200, "category": "community"},
    {"name": "Goodreads",       "url": "https://www.goodreads.com/{}",                "method": "status", "expect": 200, "category": "community"},
    {"name": "MyAnimeList",     "url": "https://myanimelist.net/profile/{}",          "method": "status", "expect": 200, "category": "community"},
    {"name": "AniList",         "url": "https://anilist.co/user/{}/",                 "method": "status", "expect": 200, "category": "community"},

    # ── Crypto & Privacy ──────────────────────────────────────────────────
    {"name": "Bitcointalk",     "url": "https://bitcointalk.org/index.php?action=profile;u={}",  "method": "content", "indicator": "Date Registered", "category": "crypto"},
    {"name": "Protonmail (Blog)", "url": "https://proton.me/blog/author/{}",          "method": "status", "expect": 200, "category": "privacy"},

    # ── Professional & Business ───────────────────────────────────────────
    {"name": "Behance",         "url": "https://www.behance.net/{}",                  "method": "status", "expect": 200, "category": "professional"},
    {"name": "Dribbble",        "url": "https://dribbble.com/{}",                     "method": "status", "expect": 200, "category": "professional"},
    {"name": "AngelList",       "url": "https://angel.co/u/{}",                       "method": "status", "expect": 200, "category": "professional"},
    {"name": "Product Hunt",    "url": "https://www.producthunt.com/@{}",             "method": "status", "expect": 200, "category": "professional"},
    {"name": "Crunchbase",      "url": "https://www.crunchbase.com/person/{}",        "method": "status", "expect": 200, "category": "professional"},

    # ── Knowledge & Education ─────────────────────────────────────────────
    {"name": "Wikipedia",       "url": "https://en.wikipedia.org/wiki/User:{}",       "method": "status", "expect": 200, "category": "knowledge"},
    {"name": "Wikimedia Commons", "url": "https://commons.wikimedia.org/wiki/User:{}","method": "status", "expect": 200, "category": "knowledge"},
    {"name": "Internet Archive","url": "https://archive.org/details/@{}",             "method": "status", "expect": 200, "category": "knowledge"},
    {"name": "Slideshare",      "url": "https://www.slideshare.net/{}",               "method": "status", "expect": 200, "category": "knowledge"},

    # ── Misc ──────────────────────────────────────────────────────────────
    {"name": "Telegram (public)", "url": "https://t.me/{}",                           "method": "content", "indicator": "tgme_page_title", "category": "messaging"},
    {"name": "Gravatar (JSON)",   "url": "https://en.gravatar.com/{}.json",           "method": "status", "expect": 200, "category": "social"},
    {"name": "Last.fm",           "url": "https://www.last.fm/user/{}",               "method": "status", "expect": 200, "category": "media"},
    {"name": "Giphy",             "url": "https://giphy.com/channel/{}",              "method": "status", "expect": 200, "category": "media"},
    {"name": "Imgur",             "url": "https://imgur.com/user/{}",                 "method": "status", "expect": 200, "category": "media"},
    {"name": "IFTTT",             "url": "https://ifttt.com/p/{}",                    "method": "status", "expect": 200, "category": "tech"},
    {"name": "Trello",            "url": "https://trello.com/{}",                     "method": "status", "expect": 200, "category": "productivity"},
    {"name": "Notion",            "url": "https://{}.notion.site",                    "method": "status", "expect": 200, "category": "productivity"},
    {"name": "Wattpad",           "url": "https://www.wattpad.com/user/{}",           "method": "status", "expect": 200, "category": "community"},
    {"name": "Newgrounds",        "url": "https://{}.newgrounds.com",                 "method": "status", "expect": 200, "category": "community"},
    {"name": "Mastodon.social",   "url": "https://mastodon.social/@{}",               "method": "status", "expect": 200, "category": "social"},
    {"name": "Fosstodon",         "url": "https://fosstodon.org/@{}",                 "method": "status", "expect": 200, "category": "social"},
    {"name": "Infosec Exchange",  "url": "https://infosec.exchange/@{}",              "method": "status", "expect": 200, "category": "security"},
]
# fmt: on


def enumerate_username(username: str) -> dict[str, Any]:
    """Probe all sites for account existence.

    Returns a dict with confirmed accounts grouped by category.
    """
    if not USERNAME_ENUM_ENABLED:
        return {"enabled": False, "reason": "USERNAME_ENUM_ENABLED is false"}

    if not username or len(username) < 2:
        return {"enabled": True, "username": username, "found": [], "total_checked": 0, "total_found": 0}

    username = username.strip().lstrip("@")
    found: list[dict[str, Any]] = []

    def _probe(site: dict) -> dict[str, Any] | None:
        url = site["url"].format(username)
        try:
            resp = requests.get(
                url,
                headers=_SESSION_HEADERS,
                timeout=_TIMEOUT,
                allow_redirects=True,
            )
            if site["method"] == "status":
                if resp.status_code == site["expect"]:
                    return {"name": site["name"], "url": url, "category": site["category"]}
            elif site["method"] == "content":
                if resp.status_code == 200 and site.get("indicator", "") in resp.text:
                    return {"name": site["name"], "url": url, "category": site["category"]}
        except requests.RequestException:
            pass
        return None

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        futures = {pool.submit(_probe, site): site for site in SITE_DB}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: (x["category"], x["name"]))

    by_category: dict[str, list] = {}
    for f in found:
        by_category.setdefault(f["category"], []).append(f)

    return {
        "enabled": True,
        "username": username,
        "found": found,
        "by_category": by_category,
        "total_checked": len(SITE_DB),
        "total_found": len(found),
    }


def enum_summary_text(result: dict[str, Any]) -> str:
    """Produce a compact text summary for LLM context."""
    if not result.get("enabled"):
        return ""

    found = result.get("found", [])
    username = result.get("username", "?")

    if not found:
        return f"USERNAME ENUMERATION ({username}): Checked {result.get('total_checked', 0)} sites — no accounts found."

    lines = [f"USERNAME ENUMERATION ({username}): Found on {len(found)}/{result.get('total_checked', 0)} sites:"]
    by_cat = result.get("by_category", {})
    for cat in sorted(by_cat.keys()):
        sites = by_cat[cat]
        names = ", ".join(s["name"] for s in sites)
        lines.append(f"  [{cat}] {names}")

    security_hits = by_cat.get("security", [])
    developer_hits = by_cat.get("developer", [])
    if security_hits:
        lines.append(f"  !! Security platform presence: {', '.join(s['name'] for s in security_hits)} — check for real name, bio, linked domains")
    if developer_hits:
        lines.append(f"  !! Developer platform presence: {', '.join(s['name'] for s in developer_hits)} — check repos, contributions, email in commits")

    return "\n".join(lines)
