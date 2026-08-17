"""Multi-platform social media client for Fortis Intelligence Hub.

Real API integrations for Twitter/X, Reddit, Instagram, YouTube,
Mastodon, Facebook, TikTok, and Telegram.  Every platform call is
wrapped in try/except so the client degrades gracefully when
credentials are missing or a library is not installed.
"""

import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Any

import requests

from app.constants import SOCIAL_PLATFORMS
from app.http_client import create_session

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Optional library availability flags
# ---------------------------------------------------------------------------

HAS_TWEEPY = False
try:
    import tweepy  # noqa: F401
    HAS_TWEEPY = True
except ImportError:
    pass

HAS_PRAW = False
try:
    import praw  # noqa: F401
    HAS_PRAW = True
except ImportError:
    pass

HAS_TELETHON = False
try:
    from telethon import TelegramClient as _TC
    from telethon import functions as _tl_functions  # noqa: F401
    from telethon.tl.types import (
        User as _TLUser,
        Channel as _TLChannel,
        Chat as _TLChat,
    )
    HAS_TELETHON = True
except ImportError:
    _TC = None  # type: ignore[assignment,misc]
    _TLUser = None  # type: ignore[assignment,misc]
    _TLChannel = None  # type: ignore[assignment,misc]
    _TLChat = None  # type: ignore[assignment,misc]

HAS_INSTALOADER = False
try:
    import instaloader  # noqa: F401
    HAS_INSTALOADER = True
except ImportError:
    pass

HAS_YOUTUBE = False
try:
    from googleapiclient.discovery import build as _yt_build  # noqa: F401
    HAS_YOUTUBE = True
except ImportError:
    pass

HAS_MASTODON = False
try:
    # Mastodon uses plain requests; flag is gated on env vars instead.
    _mastodon_url = os.getenv("MASTODON_INSTANCE_URL")
    _mastodon_tok = os.getenv("MASTODON_ACCESS_TOKEN")
    if _mastodon_url and _mastodon_tok:
        HAS_MASTODON = True
except Exception:
    pass

HAS_FACEBOOK = bool(os.getenv("FACEBOOK_ACCESS_TOKEN"))

HAS_TIKTOK = bool(os.getenv("TIKTOK_API_KEY"))

HAS_PYKTOK = False
try:
    import pyktok as pyk  # noqa: F401
    HAS_PYKTOK = True
except ImportError:
    pass

HAS_MASTO_LIB = False
try:
    from masto import Masto as _MastoClient  # noqa: F401
    HAS_MASTO_LIB = True
except ImportError:
    _MastoClient = None  # type: ignore[assignment,misc]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_HASHTAG_RE = re.compile(r"#(\w+)")
_MENTION_RE = re.compile(r"@(\w+)")


def _iso(dt: datetime | str | None) -> str | None:
    """Normalise a datetime or string to ISO-8601 or return None."""
    if dt is None:
        return None
    if isinstance(dt, datetime):
        return dt.isoformat()
    return str(dt)


def _extract_tags(text: str | None) -> tuple[list[str], list[str]]:
    """Return (hashtags, mentions) extracted from *text*."""
    if not text:
        return [], []
    return _HASHTAG_RE.findall(text), _MENTION_RE.findall(text)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class SocialClient:
    """Unified interface for querying multiple social media platforms.

    Phase 1: dispatches to real platform APIs when credentials and
    libraries are available; falls back to a logged warning otherwise.
    """

    LIBRARY_FLAGS: dict[str, bool] = {
        "twitter": True,
        "reddit": True,
        "telegram": HAS_TELETHON,
        "instagram": HAS_INSTALOADER,
        "youtube": HAS_YOUTUBE,
        "mastodon": HAS_MASTODON or HAS_MASTO_LIB,
        "facebook": True,
        "tiktok": True,
    }

    _INSTA_MIN_DELAY = 3.0
    _INSTA_POST_DELAY = 1.8
    _INSTA_POST_CAP = 12

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def __init__(self) -> None:
        log.info("SocialClient initialising (Phase 1)")
        self._http = create_session(timeout=15.0)

        self._insta_last_req: float = 0.0

        self._twitter_client: Any | None = None
        self._reddit_client: Any | None = None
        self._instaloader: Any | None = None
        self._youtube_client: Any | None = None
        self._mastodon_base_url: str | None = None
        self._mastodon_token: str | None = None
        self._facebook_token: str | None = None
        self._tiktok_api_key: str | None = None
        self._tiktok_pyktok: bool = False
        self._telegram_api_id: int | None = None
        self._telegram_api_hash: str | None = None
        self._telegram_session_path: str | None = None

        self._init_twitter()
        self._init_reddit()
        self._init_instagram()
        self._init_youtube()
        self._init_mastodon()
        self._init_facebook()
        self._init_tiktok()
        self._init_telegram()

        available = [k for k, v in self.LIBRARY_FLAGS.items() if v]
        ready = [k for k in available if self._platform_ready(k)]
        if ready:
            log.info("Social platforms ready: %s", ", ".join(ready))
        else:
            log.info("No social platform clients could be initialised")

    # -- lazy client builders ------------------------------------------

    def _init_twitter(self) -> None:
        if not HAS_TWEEPY:
            return
        bearer = os.getenv("TWITTER_BEARER_TOKEN")
        if not bearer:
            log.debug("TWITTER_BEARER_TOKEN not set; Twitter disabled")
            return
        try:
            self._twitter_client = tweepy.Client(
                bearer_token=bearer,
                wait_on_rate_limit=True,
            )
            log.info("Twitter/X client initialised")
        except Exception as exc:
            log.warning("Failed to initialise Twitter client: %s", exc)

    def _init_reddit(self) -> None:
        if not HAS_PRAW:
            return
        client_id = os.getenv("REDDIT_CLIENT_ID")
        client_secret = os.getenv("REDDIT_CLIENT_SECRET")
        user_agent = os.getenv("REDDIT_USER_AGENT", "FortisIntelHub/1.0")
        if not (client_id and client_secret):
            log.debug("REDDIT_CLIENT_ID / REDDIT_CLIENT_SECRET not set; Reddit disabled")
            return
        try:
            self._reddit_client = praw.Reddit(
                client_id=client_id,
                client_secret=client_secret,
                user_agent=user_agent,
            )
            log.info("Reddit client initialised")
        except Exception as exc:
            log.warning("Failed to initialise Reddit client: %s", exc)

    def _init_instagram(self) -> None:
        if not HAS_INSTALOADER:
            return
        try:
            self._instaloader = instaloader.Instaloader(
                download_pictures=False,
                download_videos=False,
                download_video_thumbnails=False,
                download_geotags=True,
                download_comments=False,
                save_metadata=False,
                compress_json=False,
                request_timeout=15,
                max_connection_attempts=2,
            )
            log.info("Instaloader initialised (public-profile mode)")
        except Exception as exc:
            log.warning("Failed to initialise Instaloader: %s", exc)

    def _init_youtube(self) -> None:
        if not HAS_YOUTUBE:
            return
        api_key = os.getenv("YOUTUBE_API_KEY")
        if not api_key:
            log.debug("YOUTUBE_API_KEY not set; YouTube disabled")
            return
        try:
            from googleapiclient.discovery import build
            self._youtube_client = build("youtube", "v3", developerKey=api_key)
            log.info("YouTube Data API client initialised")
        except Exception as exc:
            log.warning("Failed to initialise YouTube client: %s", exc)

    def _init_mastodon(self) -> None:
        base_url = os.getenv("MASTODON_INSTANCE_URL", "").rstrip("/")
        token = os.getenv("MASTODON_ACCESS_TOKEN")
        if base_url and token:
            self._mastodon_base_url = base_url
            self._mastodon_token = token
            extra = " + Masto cross-instance search" if HAS_MASTO_LIB else ""
            log.info("Mastodon client initialised (instance=%s, token=%s…%s)", base_url, token[:8] if token else "?", extra)
        elif HAS_MASTO_LIB:
            log.info("Mastodon will use cross-instance search only (no MASTODON_ACCESS_TOKEN — limited to username lookup)")
        else:
            log.debug("MASTODON_INSTANCE_URL / MASTODON_ACCESS_TOKEN not set and masto not installed; Mastodon disabled")

    def _init_facebook(self) -> None:
        token = os.getenv("FACEBOOK_ACCESS_TOKEN")
        if not token:
            log.debug("FACEBOOK_ACCESS_TOKEN not set; Facebook disabled")
            return
        self._facebook_token = token
        log.info("Facebook Graph API client initialised")

    def _init_tiktok(self) -> None:
        api_key = os.getenv("TIKTOK_API_KEY")
        if api_key:
            self._tiktok_api_key = api_key
            log.info("TikTok Research API client initialised")
            return
        if HAS_PYKTOK:
            self._tiktok_pyktok = True
            try:
                pyk.specify_browser("chrome")
            except Exception:
                pass
            log.info("TikTok will use Pyktok scraper (no API key — slower, content search only)")
            return
        log.debug("TIKTOK_API_KEY not set and pyktok not installed; TikTok disabled")

    def _init_telegram(self) -> None:
        if not HAS_TELETHON:
            return
        api_id_str = os.getenv("TELEGRAM_API_ID", "")
        api_hash = os.getenv("TELEGRAM_API_HASH", "")
        if not (api_id_str and api_hash):
            log.debug("TELEGRAM_API_ID / TELEGRAM_API_HASH not set; Telegram disabled")
            return
        try:
            self._telegram_api_id = int(api_id_str)
        except ValueError:
            log.warning("TELEGRAM_API_ID must be an integer; Telegram disabled")
            return
        self._telegram_api_hash = api_hash
        session_path = os.getenv("TELEGRAM_SESSION_PATH", "data/telegram_session")
        self._telegram_session_path = session_path
        session_file = session_path + ".session"
        if not os.path.isfile(session_file):
            log.warning(
                "Telegram session file not found at %s — run "
                "'python -m app.telegram_auth' to authenticate first",
                session_file,
            )
            self._telegram_api_id = None
            return
        log.info("Telegram client initialised (session: %s)", session_path)

    def _platform_ready(self, platform: str) -> bool:
        """Return True if the platform's API client was successfully built."""
        return {
            "twitter": True,
            "reddit": True,
            "instagram": self._instaloader is not None,
            "youtube": self._youtube_client is not None,
            "mastodon": self._mastodon_base_url is not None or HAS_MASTO_LIB,
            "facebook": True,
            "tiktok": True,
            "telegram": self._telegram_api_id is not None,
        }.get(platform, False)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_platforms(platforms: list[str] | None) -> list[str]:
        """Return the list of platforms to query, defaulting to all known."""
        if platforms:
            return [p for p in platforms if p in SOCIAL_PLATFORMS]
        return list(SOCIAL_PLATFORMS.keys())

    def _stub_warn(self, method: str, platform: str) -> None:
        log.warning(
            "SocialClient.%s() -- platform %r is not yet implemented or not configured",
            method,
            platform,
        )

    # ------------------------------------------------------------------
    # Profile normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_profile(
        *,
        platform: str,
        user_id: str,
        username: str,
        display_name: str = "",
        bio: str = "",
        url: str = "",
        followers: int = 0,
        following: int = 0,
        post_count: int = 0,
        created_at: str | None = None,
        verified: bool = False,
        profile_image_url: str = "",
    ) -> dict[str, Any]:
        return {
            "platform": platform,
            "user_id": str(user_id),
            "username": username,
            "display_name": display_name,
            "bio": bio,
            "url": url,
            "followers": followers,
            "following": following,
            "post_count": post_count,
            "created_at": created_at,
            "verified": verified,
            "profile_image_url": profile_image_url,
        }

    @staticmethod
    def _normalise_post(
        *,
        platform: str,
        post_id: str,
        author_username: str = "",
        content: str = "",
        url: str = "",
        timestamp: str | None = None,
        likes: int = 0,
        shares: int = 0,
        replies: int = 0,
        hashtags: list[str] | None = None,
        mentions: list[str] | None = None,
        media_urls: list[str] | None = None,
        geo: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "platform": platform,
            "post_id": str(post_id),
            "author_username": author_username,
            "content": content,
            "url": url,
            "timestamp": timestamp,
            "likes": likes,
            "shares": shares,
            "replies": replies,
            "hashtags": hashtags or [],
            "mentions": mentions or [],
            "media_urls": media_urls or [],
            "geo": geo,
        }

    # ==================================================================
    # TWITTER / X  (tweepy API v2, with syndication scrape fallback)
    # ==================================================================

    def _twitter_search_username(self, username: str) -> list[dict[str, Any]]:
        if not self._twitter_client:
            return self._twitter_search_username_scrape(username)
        try:
            user_fields = [
                "id", "name", "username", "description", "public_metrics",
                "created_at", "profile_image_url", "verified",
            ]
            resp = self._twitter_client.get_user(
                username=username,
                user_fields=user_fields,
            )
            if resp.data is None:
                return []
            u = resp.data
            pm = u.public_metrics or {}
            return [self._normalise_profile(
                platform="twitter",
                user_id=str(u.id),
                username=u.username,
                display_name=u.name or "",
                bio=getattr(u, "description", "") or "",
                url=f"https://x.com/{u.username}",
                followers=pm.get("followers_count", 0),
                following=pm.get("following_count", 0),
                post_count=pm.get("tweet_count", 0),
                created_at=_iso(getattr(u, "created_at", None)),
                verified=getattr(u, "verified", False) or False,
                profile_image_url=getattr(u, "profile_image_url", "") or "",
            )]
        except Exception as exc:
            log.warning("Twitter API search_username(%r) failed, trying scrape: %s", username, exc)
            return self._twitter_search_username_scrape(username)

    def _twitter_get_user_posts(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        if not self._twitter_client:
            return self._twitter_get_user_posts_scrape(user_id, limit, since)
        try:
            tweet_fields = [
                "id", "text", "author_id", "created_at", "public_metrics",
                "entities", "geo",
            ]
            kwargs: dict[str, Any] = {
                "id": user_id,
                "max_results": min(limit, 100),
                "tweet_fields": tweet_fields,
            }
            if since:
                kwargs["start_time"] = since
            resp = self._twitter_client.get_users_tweets(**kwargs)
            if resp.data is None:
                return []
            posts: list[dict[str, Any]] = []
            for tw in resp.data:
                pm = tw.public_metrics or {}
                hashtags, mentions = _extract_tags(tw.text)
                geo = None
                if tw.geo:
                    geo = {"raw": tw.geo}
                posts.append(self._normalise_post(
                    platform="twitter",
                    post_id=str(tw.id),
                    author_username="",  # not in tweet payload without expansion
                    content=tw.text or "",
                    url=f"https://x.com/i/status/{tw.id}",
                    timestamp=_iso(getattr(tw, "created_at", None)),
                    likes=pm.get("like_count", 0),
                    shares=pm.get("retweet_count", 0),
                    replies=pm.get("reply_count", 0),
                    hashtags=hashtags,
                    mentions=mentions,
                    geo=geo,
                ))
            return posts
        except Exception as exc:
            log.warning("Twitter API get_user_posts(%r) failed, trying scrape: %s", user_id, exc)
            return self._twitter_get_user_posts_scrape(user_id, limit, since)

    def _twitter_search_content(
        self, query: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        if not self._twitter_client:
            return self._twitter_search_content_scrape(query, limit)
        try:
            tweet_fields = [
                "id", "text", "author_id", "created_at", "public_metrics",
                "entities", "geo",
            ]
            resp = self._twitter_client.search_recent_tweets(
                query=query,
                max_results=min(limit, 100),
                tweet_fields=tweet_fields,
            )
            if resp.data is None:
                return []
            posts: list[dict[str, Any]] = []
            for tw in resp.data:
                pm = tw.public_metrics or {}
                hashtags, mentions = _extract_tags(tw.text)
                geo = None
                if tw.geo:
                    geo = {"raw": tw.geo}
                posts.append(self._normalise_post(
                    platform="twitter",
                    post_id=str(tw.id),
                    author_username="",
                    content=tw.text or "",
                    url=f"https://x.com/i/status/{tw.id}",
                    timestamp=_iso(getattr(tw, "created_at", None)),
                    likes=pm.get("like_count", 0),
                    shares=pm.get("retweet_count", 0),
                    replies=pm.get("reply_count", 0),
                    hashtags=hashtags,
                    mentions=mentions,
                    geo=geo,
                ))
            return posts
        except Exception as exc:
            log.warning("Twitter API search_content(%r) failed, trying scrape: %s", query, exc)
            return self._twitter_search_content_scrape(query, limit)

    # --- Twitter/X syndication scrape fallbacks ---

    _TWITTER_SYNDICATION = "https://syndication.twitter.com/srv/timeline-profile/screen-name"

    def _twitter_scrape_timeline(self, username: str) -> str | None:
        url = f"{self._TWITTER_SYNDICATION}/{username}"
        try:
            resp = self._http.get(url, params={"dnt": "true", "embedId": "twitter-widget-0"}, timeout=15)
            if resp.status_code == 200:
                return resp.text
            log.debug("Twitter syndication %s returned %d", username, resp.status_code)
        except Exception as exc:
            log.debug("Twitter syndication scrape failed: %s", exc)
        return None

    def _twitter_parse_syndication_tweets(self, html: str, limit: int) -> list[dict[str, Any]]:
        posts: list[dict[str, Any]] = []
        tweet_re = re.compile(
            r'data-tweet-id="(\d+)".*?'
            r'class="[^"]*timeline-Tweet-text[^"]*"[^>]*>(.*?)</(?:p|div)>',
            re.DOTALL,
        )
        author_re = re.compile(r'data-screen-name="([^"]+)"')
        time_re = re.compile(r'<time[^>]*datetime="([^"]+)"')
        for m in tweet_re.finditer(html):
            if len(posts) >= limit:
                break
            tweet_id = m.group(1)
            raw_text = re.sub(r"<[^>]+>", "", m.group(2)).strip()
            block = html[max(0, m.start() - 500):m.end() + 200]
            author_m = author_re.search(block)
            author = author_m.group(1) if author_m else ""
            time_m = time_re.search(block)
            ts = time_m.group(1) if time_m else None
            hashtags, mentions = _extract_tags(raw_text)
            posts.append(self._normalise_post(
                platform="twitter",
                post_id=tweet_id,
                author_username=author,
                content=raw_text,
                url=f"https://x.com/{author}/status/{tweet_id}" if author else f"https://x.com/i/status/{tweet_id}",
                timestamp=ts,
                likes=0,
                shares=0,
                replies=0,
                hashtags=hashtags,
                mentions=mentions,
            ))
        return posts

    def _twitter_search_username_scrape(self, username: str) -> list[dict[str, Any]]:
        html = self._twitter_scrape_timeline(username)
        if not html:
            log.error("Twitter scrape search_username(%r) failed — syndication unavailable", username)
            return []
        display_re = re.compile(r'class="[^"]*TweetAuthor-name[^"]*"[^>]*>([^<]+)<')
        bio_re = re.compile(r'class="[^"]*timeline-Header-description[^"]*"[^>]*>(.*?)</(?:p|div)>', re.DOTALL)
        avatar_re = re.compile(r'class="[^"]*TweetAuthor-avatar[^"]*"[^>]*src="([^"]+)"')
        display = display_re.search(html)
        bio = bio_re.search(html)
        avatar = avatar_re.search(html)
        return [self._normalise_profile(
            platform="twitter",
            user_id="",
            username=username,
            display_name=display.group(1).strip() if display else "",
            bio=re.sub(r"<[^>]+>", "", bio.group(1)).strip() if bio else "",
            url=f"https://x.com/{username}",
            followers=0,
            following=0,
            post_count=0,
            created_at=None,
            verified=False,
            profile_image_url=avatar.group(1) if avatar else "",
        )]

    def _twitter_get_user_posts_scrape(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        html = self._twitter_scrape_timeline(user_id)
        if not html:
            return []
        posts = self._twitter_parse_syndication_tweets(html, min(limit, 20))
        if since:
            posts = [p for p in posts if not p.get("timestamp") or p["timestamp"] >= since]
        return posts

    def _twitter_search_content_scrape(
        self, query: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        log.info("Twitter content search requires API access — scrape fallback not available for keyword search")
        return []

    # ==================================================================
    # REDDIT  (praw, with curl_cffi scrape fallback)
    # ==================================================================

    _REDDIT_JSON_HEADERS = {
        "Accept": "application/json",
    }

    def _reddit_search_username(self, username: str) -> list[dict[str, Any]]:
        if not self._reddit_client:
            return self._reddit_search_username_scrape(username)
        try:
            redditor = self._reddit_client.redditor(username)
            # Force fetch to verify user exists
            _ = redditor.id
            return [self._normalise_profile(
                platform="reddit",
                user_id=str(redditor.id),
                username=redditor.name,
                display_name=getattr(redditor, "subreddit", {}).get("title", "") if isinstance(getattr(redditor, "subreddit", None), dict) else "",
                bio=getattr(redditor, "subreddit", {}).get("public_description", "") if isinstance(getattr(redditor, "subreddit", None), dict) else "",
                url=f"https://www.reddit.com/user/{redditor.name}",
                followers=0,  # not reliably exposed
                following=0,
                post_count=getattr(redditor, "link_karma", 0) + getattr(redditor, "comment_karma", 0),
                created_at=_iso(datetime.fromtimestamp(redditor.created_utc, tz=timezone.utc)),
                verified=getattr(redditor, "has_verified_email", False) or False,
                profile_image_url=getattr(redditor, "icon_img", "") or "",
            )]
        except Exception as exc:
            log.warning("Reddit PRAW search_username(%r) failed, trying scrape: %s", username, exc)
            return self._reddit_search_username_scrape(username)

    def _reddit_get_user_posts(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        """Fetch submissions and comments.  *user_id* is treated as username."""
        if not self._reddit_client:
            return self._reddit_get_user_posts_scrape(user_id, limit, since)
        try:
            redditor = self._reddit_client.redditor(user_id)
            posts: list[dict[str, Any]] = []
            half = max(limit // 2, 1)

            # Submissions
            for sub in redditor.submissions.new(limit=half):
                ts = _iso(datetime.fromtimestamp(sub.created_utc, tz=timezone.utc))
                if since and ts and ts < since:
                    continue
                hashtags, mentions = _extract_tags(sub.selftext or sub.title)
                posts.append(self._normalise_post(
                    platform="reddit",
                    post_id=str(sub.id),
                    author_username=str(sub.author) if sub.author else "[deleted]",
                    content=sub.selftext or sub.title or "",
                    url=f"https://www.reddit.com{sub.permalink}",
                    timestamp=ts,
                    likes=sub.score,
                    shares=0,
                    replies=sub.num_comments,
                    hashtags=hashtags,
                    mentions=mentions,
                    media_urls=[sub.url] if sub.url and sub.url != sub.permalink else [],
                ))

            # Comments
            for comment in redditor.comments.new(limit=half):
                ts = _iso(datetime.fromtimestamp(comment.created_utc, tz=timezone.utc))
                if since and ts and ts < since:
                    continue
                hashtags, mentions = _extract_tags(comment.body)
                posts.append(self._normalise_post(
                    platform="reddit",
                    post_id=str(comment.id),
                    author_username=str(comment.author) if comment.author else "[deleted]",
                    content=comment.body or "",
                    url=f"https://www.reddit.com{comment.permalink}",
                    timestamp=ts,
                    likes=comment.score,
                    shares=0,
                    replies=0,
                    hashtags=hashtags,
                    mentions=mentions,
                ))

            return posts
        except Exception as exc:
            log.warning("Reddit PRAW get_user_posts(%r) failed, trying scrape: %s", user_id, exc)
            return self._reddit_get_user_posts_scrape(user_id, limit, since)

    def _reddit_search_content(
        self, query: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        if not self._reddit_client:
            return self._reddit_search_content_scrape(query, limit)
        try:
            posts: list[dict[str, Any]] = []
            for sub in self._reddit_client.subreddit("all").search(query, limit=limit):
                hashtags, mentions = _extract_tags(sub.selftext or sub.title)
                posts.append(self._normalise_post(
                    platform="reddit",
                    post_id=str(sub.id),
                    author_username=str(sub.author) if sub.author else "[deleted]",
                    content=sub.selftext or sub.title or "",
                    url=f"https://www.reddit.com{sub.permalink}",
                    timestamp=_iso(datetime.fromtimestamp(sub.created_utc, tz=timezone.utc)),
                    likes=sub.score,
                    shares=0,
                    replies=sub.num_comments,
                    hashtags=hashtags,
                    mentions=mentions,
                    media_urls=[sub.url] if sub.url and sub.url != sub.permalink else [],
                ))
            return posts
        except Exception as exc:
            log.warning("Reddit PRAW search_content(%r) failed, trying scrape: %s", query, exc)
            return self._reddit_search_content_scrape(query, limit)

    # --- Reddit curl_cffi scrape fallbacks ---

    def _reddit_scrape_get(self, path: str) -> dict | None:
        url = f"https://www.reddit.com{path}"
        try:
            resp = self._http.get(url, headers=self._REDDIT_JSON_HEADERS, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            log.debug("Reddit scrape %s returned %d", path, resp.status_code)
        except Exception as exc:
            log.debug("Reddit scrape %s failed: %s", path, exc)
        return None

    def _reddit_search_username_scrape(self, username: str) -> list[dict[str, Any]]:
        data = self._reddit_scrape_get(f"/user/{username}/about.json")
        if not data or "data" not in data:
            log.error("Reddit scrape search_username(%r) failed", username)
            return []
        try:
            u = data["data"]
            return [self._normalise_profile(
                platform="reddit",
                user_id=u.get("id", ""),
                username=u.get("name", username),
                display_name=u.get("subreddit", {}).get("title", ""),
                bio=u.get("subreddit", {}).get("public_description", ""),
                url=f"https://www.reddit.com/user/{u.get('name', username)}",
                followers=0,
                following=0,
                post_count=u.get("link_karma", 0) + u.get("comment_karma", 0),
                created_at=_iso(datetime.fromtimestamp(u["created_utc"], tz=timezone.utc)) if u.get("created_utc") else None,
                verified=u.get("has_verified_email", False),
                profile_image_url=u.get("icon_img", ""),
            )]
        except Exception as exc:
            log.error("Reddit scrape parse user %r failed: %s", username, exc)
            return []

    def _reddit_get_user_posts_scrape(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        posts: list[dict[str, Any]] = []
        half = max(limit // 2, 1)
        for endpoint, is_comment in [("/submitted.json", False), ("/comments.json", True)]:
            data = self._reddit_scrape_get(f"/user/{user_id}{endpoint}?limit={half}&raw_json=1")
            if not data or "data" not in data:
                continue
            for child in data["data"].get("children", []):
                item = child.get("data", {})
                ts = _iso(datetime.fromtimestamp(item["created_utc"], tz=timezone.utc)) if item.get("created_utc") else None
                if since and ts and ts < since:
                    continue
                content = item.get("body", "") if is_comment else (item.get("selftext", "") or item.get("title", ""))
                hashtags, mentions = _extract_tags(content)
                permalink = item.get("permalink", "")
                media_urls: list[str] = []
                if not is_comment:
                    item_url = item.get("url", "")
                    if item_url and item_url != permalink:
                        media_urls.append(item_url)
                posts.append(self._normalise_post(
                    platform="reddit",
                    post_id=item.get("id", ""),
                    author_username=item.get("author", "[deleted]"),
                    content=content,
                    url=f"https://www.reddit.com{permalink}" if permalink else "",
                    timestamp=ts,
                    likes=item.get("score", 0),
                    shares=0,
                    replies=item.get("num_comments", 0) if not is_comment else 0,
                    hashtags=hashtags,
                    mentions=mentions,
                    media_urls=media_urls,
                ))
        return posts

    def _reddit_search_content_scrape(
        self, query: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        from urllib.parse import quote_plus
        data = self._reddit_scrape_get(f"/search.json?q={quote_plus(query)}&limit={min(limit, 100)}&raw_json=1")
        if not data or "data" not in data:
            log.error("Reddit scrape search_content(%r) failed", query)
            return []
        posts: list[dict[str, Any]] = []
        for child in data["data"].get("children", []):
            item = child.get("data", {})
            content = item.get("selftext", "") or item.get("title", "")
            hashtags, mentions = _extract_tags(content)
            permalink = item.get("permalink", "")
            item_url = item.get("url", "")
            posts.append(self._normalise_post(
                platform="reddit",
                post_id=item.get("id", ""),
                author_username=item.get("author", "[deleted]"),
                content=content,
                url=f"https://www.reddit.com{permalink}" if permalink else "",
                timestamp=_iso(datetime.fromtimestamp(item["created_utc"], tz=timezone.utc)) if item.get("created_utc") else None,
                likes=item.get("score", 0),
                shares=0,
                replies=item.get("num_comments", 0),
                hashtags=hashtags,
                mentions=mentions,
                media_urls=[item_url] if item_url and item_url != permalink else [],
            ))
        return posts

    # ==================================================================
    # INSTAGRAM  (instaloader, public profiles only)
    # ==================================================================

    def _instagram_throttle(self) -> None:
        elapsed = time.monotonic() - self._insta_last_req
        if elapsed < self._INSTA_MIN_DELAY:
            wait = self._INSTA_MIN_DELAY - elapsed
            log.debug("Instagram throttle: sleeping %.1fs", wait)
            time.sleep(wait)
        self._insta_last_req = time.monotonic()

    def _instagram_search_username(self, username: str) -> list[dict[str, Any]]:
        if not self._instaloader:
            return []
        try:
            self._instagram_throttle()
            profile = instaloader.Profile.from_username(
                self._instaloader.context, username,
            )
            return [self._normalise_profile(
                platform="instagram",
                user_id=str(profile.userid),
                username=profile.username,
                display_name=profile.full_name or "",
                bio=profile.biography or "",
                url=f"https://www.instagram.com/{profile.username}/",
                followers=profile.followers,
                following=profile.followees,
                post_count=profile.mediacount,
                created_at=None,  # not exposed publicly
                verified=profile.is_verified,
                profile_image_url=profile.profile_pic_url or "",
            )]
        except Exception as exc:
            log.error("Instagram search_username(%r) failed: %s", username, exc)
            return []

    def _instagram_get_user_posts(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        """Fetch recent posts.  *user_id* is treated as username for public lookup."""
        if not self._instaloader:
            return []
        try:
            self._instagram_throttle()
            profile = instaloader.Profile.from_username(
                self._instaloader.context, user_id,
            )
            posts: list[dict[str, Any]] = []
            cap = min(limit, self._INSTA_POST_CAP)
            for i, post in enumerate(profile.get_posts()):
                if i >= cap:
                    break
                if i > 0:
                    time.sleep(self._INSTA_POST_DELAY)
                ts = _iso(post.date_utc.replace(tzinfo=timezone.utc) if post.date_utc else None)
                if since and ts and ts < since:
                    continue
                caption = post.caption or ""
                hashtags_list = list(post.caption_hashtags) if post.caption_hashtags else []
                mentions_list = list(post.caption_mentions) if post.caption_mentions else []
                geo = None
                if post.location:
                    loc = post.location
                    geo = {
                        "name": getattr(loc, "name", None),
                        "lat": getattr(loc, "lat", None),
                        "lng": getattr(loc, "lng", None),
                    }
                media: list[str] = []
                if post.url:
                    media.append(post.url)
                posts.append(self._normalise_post(
                    platform="instagram",
                    post_id=str(post.shortcode),
                    author_username=profile.username,
                    content=caption,
                    url=f"https://www.instagram.com/p/{post.shortcode}/",
                    timestamp=ts,
                    likes=post.likes,
                    shares=0,
                    replies=post.comments,
                    hashtags=hashtags_list,
                    mentions=mentions_list,
                    media_urls=media,
                    geo=geo,
                ))
            return posts
        except Exception as exc:
            log.error("Instagram get_user_posts(%r) failed: %s", user_id, exc)
            return []

    # ==================================================================
    # YOUTUBE  (google-api-python-client)
    # ==================================================================

    def _youtube_search_content(
        self, query: str, limit: int = 25,
    ) -> list[dict[str, Any]]:
        if not self._youtube_client:
            return []
        try:
            req = self._youtube_client.search().list(
                q=query,
                type="video",
                part="snippet",
                maxResults=min(limit, 50),
            )
            resp = req.execute()
            posts: list[dict[str, Any]] = []
            for item in resp.get("items", []):
                snippet = item.get("snippet", {})
                video_id = item.get("id", {}).get("videoId", "")
                title = snippet.get("title", "")
                desc = snippet.get("description", "")
                hashtags, mentions = _extract_tags(f"{title} {desc}")
                posts.append(self._normalise_post(
                    platform="youtube",
                    post_id=video_id,
                    author_username=snippet.get("channelTitle", ""),
                    content=title,
                    url=f"https://www.youtube.com/watch?v={video_id}",
                    timestamp=snippet.get("publishedAt"),
                    likes=0,  # requires separate videos().list call
                    shares=0,
                    replies=0,
                    hashtags=hashtags,
                    mentions=mentions,
                    media_urls=[snippet["thumbnails"]["high"]["url"]]
                    if "thumbnails" in snippet and "high" in snippet["thumbnails"]
                    else [],
                ))
            return posts
        except Exception as exc:
            log.error("YouTube search_content(%r) failed: %s", query, exc)
            return []

    def _youtube_get_user_posts(
        self, channel_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        """List recent videos for a channel.  *channel_id* should be a YouTube channel ID."""
        if not self._youtube_client:
            return []
        try:
            kwargs: dict[str, Any] = {
                "channelId": channel_id,
                "type": "video",
                "part": "snippet",
                "order": "date",
                "maxResults": min(limit, 50),
            }
            if since:
                kwargs["publishedAfter"] = since
            req = self._youtube_client.search().list(**kwargs)
            resp = req.execute()
            posts: list[dict[str, Any]] = []
            for item in resp.get("items", []):
                snippet = item.get("snippet", {})
                video_id = item.get("id", {}).get("videoId", "")
                title = snippet.get("title", "")
                desc = snippet.get("description", "")
                hashtags, mentions = _extract_tags(f"{title} {desc}")
                posts.append(self._normalise_post(
                    platform="youtube",
                    post_id=video_id,
                    author_username=snippet.get("channelTitle", ""),
                    content=title,
                    url=f"https://www.youtube.com/watch?v={video_id}",
                    timestamp=snippet.get("publishedAt"),
                    likes=0,
                    shares=0,
                    replies=0,
                    hashtags=hashtags,
                    mentions=mentions,
                    media_urls=[snippet["thumbnails"]["high"]["url"]]
                    if "thumbnails" in snippet and "high" in snippet["thumbnails"]
                    else [],
                ))
            return posts
        except Exception as exc:
            log.error("YouTube get_user_posts(%r) failed: %s", channel_id, exc)
            return []

    # ==================================================================
    # MASTODON  (requests-based, no special library)
    # ==================================================================

    def _mastodon_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._mastodon_token}"}

    def _mastodon_json(self, resp: requests.Response) -> Any:
        """Parse a Mastodon API response, returning None if the body is not JSON."""
        ct = resp.headers.get("Content-Type", "")
        if "application/json" not in ct:
            log.warning(
                "Mastodon returned non-JSON response (Content-Type: %s, status: %s, body: %.200s)",
                ct, resp.status_code, resp.text[:200],
            )
            return None
        body = resp.text.strip()
        if not body:
            return None
        return resp.json()

    def _mastodon_search_username(self, username: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        # Layer 1: token-based instance API (single instance)
        if self._mastodon_base_url:
            try:
                url = f"{self._mastodon_base_url}/api/v2/search"
                resp = self._http.get(
                    url,
                    params={"q": username, "type": "accounts", "limit": 5},
                    headers=self._mastodon_headers(),
                    timeout=15,
                )
                resp.raise_for_status()
                data = self._mastodon_json(resp)
                if data is not None:
                    for acct in data.get("accounts", []):
                        uid = str(acct.get("id", ""))
                        if uid in seen_ids:
                            continue
                        seen_ids.add(uid)
                        results.append(self._normalise_profile(
                            platform="mastodon",
                            user_id=uid,
                            username=acct.get("acct", ""),
                            display_name=acct.get("display_name", ""),
                            bio=acct.get("note", ""),
                            url=acct.get("url", ""),
                            followers=acct.get("followers_count", 0),
                            following=acct.get("following_count", 0),
                            post_count=acct.get("statuses_count", 0),
                            created_at=acct.get("created_at"),
                            verified=bool(acct.get("locked", False)),
                            profile_image_url=acct.get("avatar", ""),
                        ))
            except Exception as exc:
                log.warning("Mastodon API search_username(%r) failed: %s", username, exc)

        # Layer 2: Masto library — cross-instance search (no token needed)
        if HAS_MASTO_LIB:
            try:
                masto_results = self._masto_lib_search_username(username)
                for profile in masto_results:
                    uid = profile.get("user_id", "")
                    acct = profile.get("username", "")
                    dedup_key = f"{acct}@{uid}"
                    if dedup_key not in seen_ids:
                        seen_ids.add(dedup_key)
                        results.append(profile)
            except Exception as exc:
                log.warning("Masto lib search_username(%r) failed: %s", username, exc)

        if not results:
            log.info("Mastodon search_username(%r): no results from API or Masto lib", username)
        return results

    def _masto_lib_search_username(self, username: str) -> list[dict[str, Any]]:
        """Search for a Mastodon user across multiple instances using the Masto library."""
        try:
            import subprocess
            import json as _json
            result = subprocess.run(
                ["python", "-m", "masto", "-user", username, "--json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode != 0:
                # Masto CLI may not support --json; fall back to API-based cross-instance scan
                return self._masto_cross_instance_search(username)
            data = _json.loads(result.stdout)
            profiles: list[dict[str, Any]] = []
            for acct in data if isinstance(data, list) else [data]:
                profiles.append(self._normalise_profile(
                    platform="mastodon",
                    user_id=str(acct.get("id", "")),
                    username=acct.get("username", username),
                    display_name=acct.get("display_name", ""),
                    bio=acct.get("note", acct.get("bio", "")),
                    url=acct.get("url", ""),
                    followers=acct.get("followers_count", 0),
                    following=acct.get("following_count", 0),
                    post_count=acct.get("statuses_count", 0),
                    created_at=acct.get("created_at"),
                    verified=bool(acct.get("locked", False)),
                    profile_image_url=acct.get("avatar", ""),
                ))
            return profiles
        except Exception as exc:
            log.debug("Masto CLI search failed, trying cross-instance: %s", exc)
            return self._masto_cross_instance_search(username)

    def _masto_cross_instance_search(self, username: str) -> list[dict[str, Any]]:
        """Search for a user across popular Mastodon instances (no token needed)."""
        instances = [
            "https://mastodon.social",
            "https://mastodon.online",
            "https://mstdn.social",
            "https://infosec.exchange",
            "https://hachyderm.io",
            "https://fosstodon.org",
        ]
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for base in instances:
            if self._mastodon_base_url and base.rstrip("/") == self._mastodon_base_url.rstrip("/"):
                continue
            try:
                resp = self._http.get(
                    f"{base}/api/v2/search",
                    params={"q": username, "type": "accounts", "limit": 3, "resolve": "true"},
                    timeout=8,
                )
                if resp.status_code != 200:
                    continue
                data = resp.json()
                if not isinstance(data, dict):
                    continue
                for acct in data.get("accounts", []):
                    acct_name = acct.get("acct", "")
                    if acct_name in seen:
                        continue
                    seen.add(acct_name)
                    results.append(self._normalise_profile(
                        platform="mastodon",
                        user_id=str(acct.get("id", "")),
                        username=acct_name,
                        display_name=acct.get("display_name", ""),
                        bio=acct.get("note", ""),
                        url=acct.get("url", ""),
                        followers=acct.get("followers_count", 0),
                        following=acct.get("following_count", 0),
                        post_count=acct.get("statuses_count", 0),
                        created_at=acct.get("created_at"),
                        verified=bool(acct.get("locked", False)),
                        profile_image_url=acct.get("avatar", ""),
                    ))
            except Exception:
                continue
        return results

    def _mastodon_get_user_posts(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        if not self._mastodon_base_url:
            return []
        try:
            url = f"{self._mastodon_base_url}/api/v1/accounts/{user_id}/statuses"
            params: dict[str, Any] = {"limit": min(limit, 40)}
            if since:
                params["since_id"] = since  # Mastodon uses snowflake-like IDs, caller may pass id
            resp = self._http.get(
                url,
                params=params,
                headers=self._mastodon_headers(),
                timeout=15,
            )
            resp.raise_for_status()
            statuses = self._mastodon_json(resp)
            if not statuses:
                return []
            return self._mastodon_parse_statuses(statuses)
        except Exception as exc:
            log.error("Mastodon get_user_posts(%r) failed: %s", user_id, exc)
            return []

    def _mastodon_parse_statuses(self, statuses: list[dict]) -> list[dict[str, Any]]:
        posts: list[dict[str, Any]] = []
        for st in statuses:
            content = st.get("content", "")
            hashtags_raw = [t.get("name", "") for t in st.get("tags", [])]
            mentions_raw = [m.get("acct", "") for m in st.get("mentions", [])]
            media_urls = [m.get("url", "") for m in st.get("media_attachments", []) if m.get("url")]
            posts.append(self._normalise_post(
                platform="mastodon",
                post_id=str(st.get("id", "")),
                author_username=st.get("account", {}).get("acct", ""),
                content=content,
                url=st.get("url", ""),
                timestamp=st.get("created_at"),
                likes=st.get("favourites_count", 0),
                shares=st.get("reblogs_count", 0),
                replies=st.get("replies_count", 0),
                hashtags=hashtags_raw,
                mentions=mentions_raw,
                media_urls=media_urls,
            ))
        return posts

    def _mastodon_search_content(
        self, query: str, limit: int = 40,
    ) -> list[dict[str, Any]]:
        if not self._mastodon_base_url:
            return []

        seen_ids: set[str] = set()
        posts: list[dict[str, Any]] = []
        cap = min(limit, 40)

        # Layer 1: hashtag timeline — public posts across the fediverse
        tags = [w.lstrip("#") for w in query.split() if len(w.lstrip("#")) >= 2]
        for tag in tags[:3]:
            try:
                resp = self._http.get(
                    f"{self._mastodon_base_url}/api/v1/timelines/tag/{tag}",
                    params={"limit": cap},
                    headers=self._mastodon_headers(),
                    timeout=15,
                )
                resp.raise_for_status()
                data = self._mastodon_json(resp)
                if isinstance(data, list):
                    for p in self._mastodon_parse_statuses(data):
                        pid = p.get("post_id", "")
                        if pid and pid not in seen_ids:
                            seen_ids.add(pid)
                            posts.append(p)
            except Exception as exc:
                log.warning("Mastodon hashtag timeline(%r) failed: %s", tag, exc)

        # Layer 2: interaction-based search (returns posts you interacted with)
        try:
            resp = self._http.get(
                f"{self._mastodon_base_url}/api/v2/search",
                params={"q": query, "type": "statuses", "limit": cap},
                headers=self._mastodon_headers(),
                timeout=15,
            )
            resp.raise_for_status()
            data = self._mastodon_json(resp)
            if isinstance(data, dict):
                for p in self._mastodon_parse_statuses(data.get("statuses", [])):
                    pid = p.get("post_id", "")
                    if pid and pid not in seen_ids:
                        seen_ids.add(pid)
                        posts.append(p)
        except Exception as exc:
            log.warning("Mastodon search API(%r) failed: %s", query, exc)

        if not posts:
            log.info("Mastodon search_content(%r): no results from hashtag timeline or search API", query)
        else:
            log.info("Mastodon search_content(%r): %d results", query, len(posts))
        return posts

    def _mastodon_public_timeline(
        self, limit: int = 40, since_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch the federated public timeline. Used by the feed monitor."""
        if not self._mastodon_base_url:
            return []
        try:
            params: dict[str, Any] = {"limit": min(limit, 40)}
            if since_id:
                params["since_id"] = since_id
            resp = self._http.get(
                f"{self._mastodon_base_url}/api/v1/timelines/public",
                params=params,
                headers=self._mastodon_headers(),
                timeout=15,
            )
            resp.raise_for_status()
            data = self._mastodon_json(resp)
            if not isinstance(data, list):
                return []
            return self._mastodon_parse_statuses(data)
        except Exception as exc:
            log.error("Mastodon public_timeline failed: %s", exc)
            return []

    # ==================================================================
    # FACEBOOK  (Graph API, with mbasic scrape fallback)
    # ==================================================================

    def _facebook_search_username(self, username: str) -> list[dict[str, Any]]:
        if not self._facebook_token:
            return self._facebook_search_username_scrape(username)
        try:
            url = f"https://graph.facebook.com/v19.0/{username}"
            resp = self._http.get(
                url,
                params={
                    "fields": "id,name,about,link,followers_count,fan_count,category",
                    "access_token": self._facebook_token,
                },
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            return [self._normalise_profile(
                platform="facebook",
                user_id=str(data.get("id", "")),
                username=username,
                display_name=data.get("name", ""),
                bio=data.get("about", ""),
                url=data.get("link", f"https://www.facebook.com/{username}"),
                followers=data.get("followers_count", 0) or data.get("fan_count", 0),
                following=0,
                post_count=0,
                created_at=None,
                verified=False,
                profile_image_url="",
            )]
        except Exception as exc:
            log.warning("Facebook API search_username(%r) failed, trying scrape: %s", username, exc)
            return self._facebook_search_username_scrape(username)

    def _facebook_search_content(
        self, query: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        if not self._facebook_token:
            log.info("Facebook content search requires Graph API access — scrape fallback not available")
            return []
        try:
            url = "https://graph.facebook.com/v19.0/search"
            resp = self._http.get(
                url,
                params={
                    "q": query,
                    "type": "post",
                    "access_token": self._facebook_token,
                    "limit": min(limit, 100),
                },
                timeout=15,
            )
            resp.raise_for_status()
            items = resp.json().get("data", [])
            posts: list[dict[str, Any]] = []
            for item in items:
                message = item.get("message", "")
                hashtags, mentions = _extract_tags(message)
                posts.append(self._normalise_post(
                    platform="facebook",
                    post_id=str(item.get("id", "")),
                    author_username=item.get("from", {}).get("name", ""),
                    content=message,
                    url=item.get("permalink_url", ""),
                    timestamp=item.get("created_time"),
                    likes=item.get("likes", {}).get("summary", {}).get("total_count", 0) if isinstance(item.get("likes"), dict) else 0,
                    shares=item.get("shares", {}).get("count", 0) if isinstance(item.get("shares"), dict) else 0,
                    replies=item.get("comments", {}).get("summary", {}).get("total_count", 0) if isinstance(item.get("comments"), dict) else 0,
                    hashtags=hashtags,
                    mentions=mentions,
                ))
            return posts
        except Exception as exc:
            log.error("Facebook search_content(%r) failed: %s", query, exc)
            return []

    def _facebook_get_user_posts(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        if not self._facebook_token:
            return self._facebook_get_user_posts_scrape(user_id, limit, since)
        try:
            url = f"https://graph.facebook.com/v19.0/{user_id}/posts"
            params: dict[str, Any] = {
                "fields": "id,message,created_time,permalink_url,shares,likes.summary(true),comments.summary(true)",
                "access_token": self._facebook_token,
                "limit": min(limit, 100),
            }
            if since:
                params["since"] = since
            resp = self._http.get(url, params=params, timeout=15)
            resp.raise_for_status()
            items = resp.json().get("data", [])
            posts: list[dict[str, Any]] = []
            for item in items:
                message = item.get("message", "")
                hashtags, mentions = _extract_tags(message)
                posts.append(self._normalise_post(
                    platform="facebook",
                    post_id=str(item.get("id", "")),
                    author_username=user_id,
                    content=message,
                    url=item.get("permalink_url", ""),
                    timestamp=item.get("created_time"),
                    likes=item.get("likes", {}).get("summary", {}).get("total_count", 0) if isinstance(item.get("likes"), dict) else 0,
                    shares=item.get("shares", {}).get("count", 0) if isinstance(item.get("shares"), dict) else 0,
                    replies=item.get("comments", {}).get("summary", {}).get("total_count", 0) if isinstance(item.get("comments"), dict) else 0,
                    hashtags=hashtags,
                    mentions=mentions,
                ))
            return posts
        except Exception as exc:
            log.warning("Facebook API get_user_posts(%r) failed, trying scrape: %s", user_id, exc)
            return self._facebook_get_user_posts_scrape(user_id, limit, since)

    # --- Facebook mbasic scrape fallbacks ---

    def _facebook_scrape_page(self, page_name: str) -> str | None:
        url = f"https://mbasic.facebook.com/{page_name}"
        try:
            resp = self._http.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.text
            log.debug("Facebook mbasic %s returned %d", page_name, resp.status_code)
        except Exception as exc:
            log.debug("Facebook mbasic scrape failed: %s", exc)
        return None

    def _facebook_search_username_scrape(self, username: str) -> list[dict[str, Any]]:
        html = self._facebook_scrape_page(username)
        if not html:
            log.error("Facebook scrape search_username(%r) failed", username)
            return []
        try:
            title_re = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE)
            title_m = title_re.search(html)
            display_name = title_m.group(1).strip() if title_m else username
            bio_re = re.compile(r'id="bio"[^>]*>(.*?)</div>', re.DOTALL | re.IGNORECASE)
            bio_m = bio_re.search(html)
            bio = re.sub(r"<[^>]+>", "", bio_m.group(1)).strip() if bio_m else ""
            avatar_re = re.compile(r'<img[^>]*class="[^"]*profpic[^"]*"[^>]*src="([^"]+)"', re.IGNORECASE)
            avatar_m = avatar_re.search(html)
            avatar = avatar_m.group(1) if avatar_m else ""
            return [self._normalise_profile(
                platform="facebook",
                user_id="",
                username=username,
                display_name=display_name,
                bio=bio,
                url=f"https://www.facebook.com/{username}",
                followers=0,
                following=0,
                post_count=0,
                created_at=None,
                verified=False,
                profile_image_url=avatar,
            )]
        except Exception as exc:
            log.error("Facebook scrape parse %r failed: %s", username, exc)
            return []

    def _facebook_get_user_posts_scrape(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        html = self._facebook_scrape_page(user_id)
        if not html:
            return []
        try:
            post_re = re.compile(
                r'<div[^>]*class="[^"]*(?:story_body_container|_55wo)[^"]*"[^>]*>(.*?)</div>\s*</div>',
                re.DOTALL,
            )
            posts: list[dict[str, Any]] = []
            for m in post_re.finditer(html):
                if len(posts) >= min(limit, 10):
                    break
                raw = m.group(1)
                text = re.sub(r"<[^>]+>", " ", raw).strip()
                text = re.sub(r"\s+", " ", text)
                if len(text) < 10:
                    continue
                hashtags, mentions = _extract_tags(text)
                posts.append(self._normalise_post(
                    platform="facebook",
                    post_id="",
                    author_username=user_id,
                    content=text[:1000],
                    url=f"https://www.facebook.com/{user_id}",
                    timestamp=None,
                    likes=0,
                    shares=0,
                    replies=0,
                    hashtags=hashtags,
                    mentions=mentions,
                ))
            return posts
        except Exception as exc:
            log.error("Facebook scrape posts %r failed: %s", user_id, exc)
            return []

    # ==================================================================
    # TIKTOK  (Research API + Pyktok fallback)
    # ==================================================================

    def _tiktok_search_username(self, username: str) -> list[dict[str, Any]]:
        if self._tiktok_api_key:
            result = self._tiktok_search_username_api(username)
            if result:
                return result
        if self._tiktok_pyktok:
            result = self._tiktok_search_username_pyktok(username)
            if result:
                return result
        return self._tiktok_search_username_scrape(username)

    def _tiktok_search_username_api(self, username: str) -> list[dict[str, Any]]:
        try:
            url = "https://open.tiktokapis.com/v2/research/user/info/"
            headers = {
                "Authorization": f"Bearer {self._tiktok_api_key}",
                "Content-Type": "application/json",
            }
            payload = {"username": username}
            resp = self._http.post(url, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return [self._normalise_profile(
                platform="tiktok",
                user_id=str(data.get("user_id", "")),
                username=data.get("username", username),
                display_name=data.get("display_name", ""),
                bio=data.get("bio_description", ""),
                url=f"https://www.tiktok.com/@{data.get('username', username)}",
                followers=data.get("follower_count", 0),
                following=data.get("following_count", 0),
                post_count=data.get("video_count", 0),
                created_at=None,
                verified=data.get("is_verified", False),
                profile_image_url=data.get("avatar_url", ""),
            )]
        except Exception as exc:
            log.error("TikTok API search_username(%r) failed: %s", username, exc)
            return []

    def _tiktok_search_username_pyktok(self, username: str) -> list[dict[str, Any]]:
        """Scrape a TikTok user profile page via Pyktok."""
        try:
            data = pyk.alt_get_tiktok_json(
                f"https://www.tiktok.com/@{username}", browser_name="chrome",
            )
            if not data:
                return []
            user_info = data.get("UserModule", {}).get("users", {}).get(username, {})
            stats = data.get("UserModule", {}).get("stats", {}).get(username, {})
            if not user_info:
                return []
            return [self._normalise_profile(
                platform="tiktok",
                user_id=str(user_info.get("id", "")),
                username=user_info.get("uniqueId", username),
                display_name=user_info.get("nickname", ""),
                bio=user_info.get("signature", ""),
                url=f"https://www.tiktok.com/@{user_info.get('uniqueId', username)}",
                followers=stats.get("followerCount", 0),
                following=stats.get("followingCount", 0),
                post_count=stats.get("videoCount", 0),
                created_at=None,
                verified=user_info.get("verified", False),
                profile_image_url=user_info.get("avatarLarger", ""),
            )]
        except Exception as exc:
            log.error("TikTok Pyktok search_username(%r) failed: %s", username, exc)
            return []

    def _tiktok_search_content(
        self, query: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        if self._tiktok_api_key:
            result = self._tiktok_search_content_api(query, limit)
            if result:
                return result
        if self._tiktok_pyktok:
            result = self._tiktok_search_content_pyktok(query, limit)
            if result:
                return result
        return self._tiktok_search_content_scrape(query, limit)

    def _tiktok_search_content_api(
        self, query: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        try:
            url = "https://open.tiktokapis.com/v2/research/video/query/"
            headers = {
                "Authorization": f"Bearer {self._tiktok_api_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "query": {"and": [{"operation": "IN", "field_name": "keyword", "field_values": [query]}]},
                "max_count": min(limit, 50),
            }
            resp = self._http.post(url, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            videos = resp.json().get("data", {}).get("videos", [])
            posts: list[dict[str, Any]] = []
            for video in videos:
                desc = video.get("video_description", "")
                hashtags, mentions = _extract_tags(desc)
                video_id = str(video.get("id", ""))
                posts.append(self._normalise_post(
                    platform="tiktok",
                    post_id=video_id,
                    author_username=video.get("username", ""),
                    content=desc,
                    url=f"https://www.tiktok.com/@{video.get('username', '')}/video/{video_id}",
                    timestamp=_iso(datetime.fromtimestamp(video["create_time"], tz=timezone.utc))
                    if video.get("create_time") else None,
                    likes=video.get("like_count", 0),
                    shares=video.get("share_count", 0),
                    replies=video.get("comment_count", 0),
                    hashtags=hashtags or video.get("hashtag_names", []),
                    mentions=mentions,
                ))
            return posts
        except Exception as exc:
            log.error("TikTok API search_content(%r) failed: %s", query, exc)
            return []

    def _tiktok_search_content_pyktok(
        self, query: str, limit: int = 30,
    ) -> list[dict[str, Any]]:
        """Scrape TikTok search results via Pyktok (no API key needed)."""
        try:
            import tempfile
            import json as _json
            cap = min(limit, 30)
            with tempfile.TemporaryDirectory() as tmpdir:
                csv_path = os.path.join(tmpdir, "tiktok_data.csv")
                pyk.save_tiktok_multi_page(
                    query, ent_type="search", save_video=False,
                    browser_name="chrome",
                )
                json_path = os.path.join(tmpdir, "tiktok_data.json")
                data = pyk.alt_get_tiktok_json(
                    f"https://www.tiktok.com/search?q={query}",
                    browser_name="chrome",
                )
                if not data:
                    log.info("Pyktok search_content(%r): no data returned", query)
                    return []

                items = []
                item_list = data.get("ItemModule", {})
                if isinstance(item_list, dict):
                    items = list(item_list.values())[:cap]

                posts: list[dict[str, Any]] = []
                for item in items:
                    desc = item.get("desc", "")
                    hashtags, mentions = _extract_tags(desc)
                    video_id = str(item.get("id", ""))
                    author = item.get("author", "")
                    stats = item.get("stats", {})
                    posts.append(self._normalise_post(
                        platform="tiktok",
                        post_id=video_id,
                        author_username=author,
                        content=desc,
                        url=f"https://www.tiktok.com/@{author}/video/{video_id}",
                        timestamp=_iso(datetime.fromtimestamp(
                            int(item["createTime"]), tz=timezone.utc,
                        )) if item.get("createTime") else None,
                        likes=stats.get("diggCount", 0),
                        shares=stats.get("shareCount", 0),
                        replies=stats.get("commentCount", 0),
                        hashtags=hashtags or [
                            c.get("hashtagName", "") for c in item.get("challenges", [])
                        ],
                        mentions=mentions,
                    ))
                return posts
        except Exception as exc:
            log.error("TikTok Pyktok search_content(%r) failed: %s", query, exc)
            return []

    def _tiktok_get_user_posts(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        if self._tiktok_api_key:
            result = self._tiktok_get_user_posts_api(user_id, limit, since)
            if result:
                return result
        if self._tiktok_pyktok:
            result = self._tiktok_get_user_posts_pyktok(user_id, limit, since)
            if result:
                return result
        return self._tiktok_get_user_posts_scrape(user_id, limit, since)

    def _tiktok_get_user_posts_api(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        """Fetch recent videos by a TikTok user via the Research API."""
        try:
            url = "https://open.tiktokapis.com/v2/research/video/query/"
            headers = {
                "Authorization": f"Bearer {self._tiktok_api_key}",
                "Content-Type": "application/json",
            }
            payload: dict[str, Any] = {
                "query": {"and": [{"operation": "EQ", "field_name": "username", "field_values": [user_id]}]},
                "max_count": min(limit, 50),
            }
            if since:
                payload["start_date"] = since[:10]  # YYYY-MM-DD
            resp = self._http.post(url, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            videos = resp.json().get("data", {}).get("videos", [])
            posts: list[dict[str, Any]] = []
            for video in videos:
                desc = video.get("video_description", "")
                hashtags, mentions = _extract_tags(desc)
                video_id = str(video.get("id", ""))
                posts.append(self._normalise_post(
                    platform="tiktok",
                    post_id=video_id,
                    author_username=video.get("username", user_id),
                    content=desc,
                    url=f"https://www.tiktok.com/@{video.get('username', user_id)}/video/{video_id}",
                    timestamp=_iso(datetime.fromtimestamp(video["create_time"], tz=timezone.utc))
                    if video.get("create_time") else None,
                    likes=video.get("like_count", 0),
                    shares=video.get("share_count", 0),
                    replies=video.get("comment_count", 0),
                    hashtags=hashtags or video.get("hashtag_names", []),
                    mentions=mentions,
                ))
            return posts
        except Exception as exc:
            log.error("TikTok API get_user_posts(%r) failed: %s", user_id, exc)
            return []

    def _tiktok_get_user_posts_pyktok(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        """Scrape a TikTok user's recent videos via Pyktok."""
        try:
            data = pyk.alt_get_tiktok_json(
                f"https://www.tiktok.com/@{user_id}", browser_name="chrome",
            )
            if not data:
                return []
            item_list = data.get("ItemModule", {})
            if isinstance(item_list, dict):
                items = list(item_list.values())[:min(limit, 30)]
            else:
                return []

            posts: list[dict[str, Any]] = []
            for item in items:
                desc = item.get("desc", "")
                hashtags, mentions = _extract_tags(desc)
                video_id = str(item.get("id", ""))
                author = item.get("author", user_id)
                stats = item.get("stats", {})
                ts = None
                if item.get("createTime"):
                    ts = _iso(datetime.fromtimestamp(
                        int(item["createTime"]), tz=timezone.utc,
                    ))
                if since and ts and ts < since:
                    continue
                posts.append(self._normalise_post(
                    platform="tiktok",
                    post_id=video_id,
                    author_username=author,
                    content=desc,
                    url=f"https://www.tiktok.com/@{author}/video/{video_id}",
                    timestamp=ts,
                    likes=stats.get("diggCount", 0),
                    shares=stats.get("shareCount", 0),
                    replies=stats.get("commentCount", 0),
                    hashtags=hashtags or [
                        c.get("hashtagName", "") for c in item.get("challenges", [])
                    ],
                    mentions=mentions,
                ))
            return posts
        except Exception as exc:
            log.error("TikTok Pyktok get_user_posts(%r) failed: %s", user_id, exc)
            return []

    # --- TikTok curl_cffi scrape fallbacks ---

    _TIKTOK_REHYDRATION_RE = re.compile(
        r'<script\s+id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>',
        re.DOTALL,
    )
    _TIKTOK_SIGI_RE = re.compile(
        r'<script\s+id="SIGI_STATE"[^>]*>(.*?)</script>',
        re.DOTALL,
    )

    def _tiktok_scrape_page(self, url: str) -> dict | None:
        try:
            resp = self._http.get(url, timeout=15)
            if resp.status_code != 200:
                log.debug("TikTok scrape %s returned %d", url, resp.status_code)
                return None
            html = resp.text
            import json as _json
            for pattern in (self._TIKTOK_REHYDRATION_RE, self._TIKTOK_SIGI_RE):
                m = pattern.search(html)
                if m:
                    return _json.loads(m.group(1))
        except Exception as exc:
            log.debug("TikTok scrape %s failed: %s", url, exc)
        return None

    def _tiktok_extract_user(self, data: dict, username: str) -> dict | None:
        scope = data.get("__DEFAULT_SCOPE__", {})
        detail = scope.get("webapp.user-detail", {})
        user_info = detail.get("userInfo", {})
        if user_info:
            return user_info
        users = data.get("UserModule", {}).get("users", {})
        if username in users:
            stats = data.get("UserModule", {}).get("stats", {}).get(username, {})
            return {"user": users[username], "stats": stats}
        return None

    def _tiktok_search_username_scrape(self, username: str) -> list[dict[str, Any]]:
        data = self._tiktok_scrape_page(f"https://www.tiktok.com/@{username}")
        if not data:
            log.error("TikTok scrape search_username(%r) failed", username)
            return []
        try:
            info = self._tiktok_extract_user(data, username)
            if not info:
                return []
            user = info.get("user", info)
            stats = info.get("stats", {})
            return [self._normalise_profile(
                platform="tiktok",
                user_id=str(user.get("id", user.get("uid", ""))),
                username=user.get("uniqueId", user.get("unique_id", username)),
                display_name=user.get("nickname", ""),
                bio=user.get("signature", ""),
                url=f"https://www.tiktok.com/@{user.get('uniqueId', username)}",
                followers=stats.get("followerCount", stats.get("follower_count", 0)),
                following=stats.get("followingCount", stats.get("following_count", 0)),
                post_count=stats.get("videoCount", stats.get("video_count", 0)),
                created_at=None,
                verified=user.get("verified", False),
                profile_image_url=user.get("avatarLarger", user.get("avatar_larger", "")),
            )]
        except Exception as exc:
            log.error("TikTok scrape parse user %r failed: %s", username, exc)
            return []

    def _tiktok_extract_items(self, data: dict) -> list[dict]:
        scope = data.get("__DEFAULT_SCOPE__", {})
        detail = scope.get("webapp.user-detail", {})
        item_list = detail.get("itemList", [])
        if item_list:
            return item_list
        items = data.get("ItemModule", {})
        if isinstance(items, dict):
            return list(items.values())
        return []

    def _tiktok_parse_video_items(
        self, items: list[dict], limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        posts: list[dict[str, Any]] = []
        for item in items[:limit]:
            desc = item.get("desc", item.get("video_description", ""))
            hashtags, mentions = _extract_tags(desc)
            video_id = str(item.get("id", ""))
            author = item.get("author", "")
            if isinstance(author, dict):
                author = author.get("uniqueId", "")
            stats = item.get("stats", {})
            ts = None
            create_time = item.get("createTime", item.get("create_time"))
            if create_time:
                ts = _iso(datetime.fromtimestamp(int(create_time), tz=timezone.utc))
            if since and ts and ts < since:
                continue
            likes = stats.get("diggCount", stats.get("like_count", item.get("like_count", 0)))
            shares = stats.get("shareCount", stats.get("share_count", item.get("share_count", 0)))
            replies = stats.get("commentCount", stats.get("comment_count", item.get("comment_count", 0)))
            challenges = item.get("challenges", [])
            if not hashtags and challenges:
                hashtags = [c.get("hashtagName", c.get("title", "")) for c in challenges]
            posts.append(self._normalise_post(
                platform="tiktok",
                post_id=video_id,
                author_username=author,
                content=desc,
                url=f"https://www.tiktok.com/@{author}/video/{video_id}" if author else "",
                timestamp=ts,
                likes=likes,
                shares=shares,
                replies=replies,
                hashtags=hashtags,
                mentions=mentions,
            ))
        return posts

    def _tiktok_get_user_posts_scrape(
        self, user_id: str, limit: int, since: str | None,
    ) -> list[dict[str, Any]]:
        data = self._tiktok_scrape_page(f"https://www.tiktok.com/@{user_id}")
        if not data:
            log.error("TikTok scrape get_user_posts(%r) failed", user_id)
            return []
        items = self._tiktok_extract_items(data)
        return self._tiktok_parse_video_items(items, min(limit, 30), since)

    def _tiktok_search_content_scrape(
        self, query: str, limit: int = 30,
    ) -> list[dict[str, Any]]:
        from urllib.parse import quote_plus
        data = self._tiktok_scrape_page(f"https://www.tiktok.com/search?q={quote_plus(query)}")
        if not data:
            log.error("TikTok scrape search_content(%r) failed", query)
            return []
        items = self._tiktok_extract_items(data)
        return self._tiktok_parse_video_items(items, min(limit, 30), None)

    # ==================================================================
    # TELEGRAM  (Telethon — async bridge)
    # ==================================================================

    def _telegram_run(self, coro_fn):
        """Run an async Telethon coroutine synchronously.

        Creates a fresh TelegramClient using the persisted session file,
        connects, runs the coroutine, then disconnects.
        """
        import asyncio

        async def _wrapper():
            client = _TC(
                self._telegram_session_path,
                self._telegram_api_id,
                self._telegram_api_hash,
            )
            await client.connect()
            if not await client.is_user_authorized():
                log.error("Telegram session is not authorized — re-run 'python -m app.telegram_auth'")
                await client.disconnect()
                return None
            try:
                return await coro_fn(client)
            finally:
                await client.disconnect()

        try:
            import sys
            if sys.platform == "win32":
                loop = asyncio.SelectorEventLoop()
            else:
                loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(_wrapper())
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                except Exception:
                    pass
                loop.close()
                asyncio.set_event_loop(None)
            return result
        except Exception as exc:
            log.error("Telegram async bridge failed: %s", exc)
            return None

    def _telegram_search_username(self, username: str) -> list[dict[str, Any]]:
        if not self._telegram_api_id:
            return []

        async def _search(client):
            try:
                entity = await client.get_entity(username)
            except Exception:
                return []

            results = []
            if isinstance(entity, _TLChannel):
                results.append(self._normalise_profile(
                    platform="telegram",
                    user_id=str(entity.id),
                    username=entity.username or "",
                    display_name=entity.title or "",
                    bio=getattr(entity, "about", "") or "",
                    url=f"https://t.me/{entity.username}" if entity.username else "",
                    followers=getattr(entity, "participants_count", 0) or 0,
                    following=0,
                    post_count=0,
                    verified=getattr(entity, "verified", False),
                ))
            elif isinstance(entity, _TLUser):
                name_parts = [entity.first_name or "", entity.last_name or ""]
                display = " ".join(p for p in name_parts if p)
                results.append(self._normalise_profile(
                    platform="telegram",
                    user_id=str(entity.id),
                    username=entity.username or "",
                    display_name=display,
                    bio="",
                    url=f"https://t.me/{entity.username}" if entity.username else "",
                    followers=0,
                    following=0,
                    post_count=0,
                    verified=getattr(entity, "verified", False),
                    profile_image_url="",
                ))
            elif isinstance(entity, _TLChat):
                results.append(self._normalise_profile(
                    platform="telegram",
                    user_id=str(entity.id),
                    username="",
                    display_name=entity.title or "",
                    bio="",
                    url="",
                    followers=getattr(entity, "participants_count", 0) or 0,
                    following=0,
                    post_count=0,
                ))
            return results

        result = self._telegram_run(_search)
        return result if result is not None else []

    def _telegram_search_content(
        self, query: str, limit: int = 50,
    ) -> list[dict[str, Any]]:
        if not self._telegram_api_id:
            return []

        async def _search(client):
            from telethon.tl.functions.messages import SearchGlobalRequest
            from telethon.tl.types import InputMessagesFilterEmpty

            try:
                result = await client(SearchGlobalRequest(
                    q=query,
                    filter=InputMessagesFilterEmpty(),
                    min_date=None,
                    max_date=None,
                    offset_rate=0,
                    offset_peer=await client.get_input_entity("me"),
                    offset_id=0,
                    limit=min(limit, 50),
                ))
            except Exception as exc:
                log.warning("Telegram global search failed: %s", exc)
                return []

            posts = []
            for msg in result.messages:
                if not msg.message:
                    continue
                chat_title = ""
                for chat in result.chats:
                    if chat.id == getattr(msg.peer_id, "channel_id", None) or \
                       chat.id == getattr(msg.peer_id, "chat_id", None):
                        chat_title = getattr(chat, "title", "") or ""
                        break
                ts = msg.date.isoformat() if msg.date else ""
                posts.append(self._normalise_post(
                    platform="telegram",
                    post_id=str(msg.id),
                    author_username=chat_title,
                    content=msg.message,
                    url="",
                    timestamp=ts,
                    likes=0,
                    shares=getattr(msg, "forwards", 0) or 0,
                    replies=0,
                    media_urls=[],
                ))
            return posts

        result = self._telegram_run(_search)
        return result if result is not None else []

    def _telegram_get_user_posts(
        self, user_id: str, limit: int = 100, since: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self._telegram_api_id:
            return []

        async def _get_posts(client):
            from datetime import datetime, timezone as tz
            try:
                entity = await client.get_entity(user_id)
            except Exception as exc:
                log.warning("Telegram get_entity(%r) failed: %s", user_id, exc)
                return []

            offset_date = None
            if since:
                try:
                    offset_date = datetime.fromisoformat(since).replace(tzinfo=tz.utc)
                except (ValueError, TypeError):
                    pass

            posts = []
            async for msg in client.iter_messages(
                entity, limit=min(limit, 200), offset_date=offset_date,
            ):
                if not msg.message:
                    continue
                ts = msg.date.isoformat() if msg.date else ""
                chat_title = getattr(entity, "title", "") or getattr(entity, "username", "") or ""
                media_urls = []
                if msg.photo:
                    media_urls.append("telegram://photo")
                if msg.document:
                    media_urls.append("telegram://document")
                posts.append(self._normalise_post(
                    platform="telegram",
                    post_id=str(msg.id),
                    author_username=chat_title,
                    content=msg.message,
                    url=f"https://t.me/{getattr(entity, 'username', '')}/{msg.id}" if getattr(entity, "username", "") else "",
                    timestamp=ts,
                    likes=0,
                    shares=getattr(msg, "forwards", 0) or 0,
                    replies=getattr(msg, "replies", None) and getattr(msg.replies, "replies", 0) or 0,
                    media_urls=media_urls,
                ))
            return posts

        result = self._telegram_run(_get_posts)
        return result if result is not None else []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def search_username(
        self,
        username: str,
        platforms: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Search for a username across social platforms.

        Args:
            username: The username to search for.
            platforms: Optional subset of platform keys to query.

        Returns:
            List of normalised profile dicts.
        """
        results: list[dict[str, Any]] = []
        for platform in self._resolve_platforms(platforms):
            if platform == "twitter":
                results.extend(self._twitter_search_username(username))
            elif platform == "reddit":
                results.extend(self._reddit_search_username(username))
            elif platform == "instagram":
                results.extend(self._instagram_search_username(username))
            elif platform == "mastodon":
                results.extend(self._mastodon_search_username(username))
            elif platform == "facebook":
                results.extend(self._facebook_search_username(username))
            elif platform == "tiktok":
                results.extend(self._tiktok_search_username(username))
            elif platform == "telegram":
                results.extend(self._telegram_search_username(username))
            elif platform == "youtube":
                # YouTube search is content-centric; username lookup not supported
                log.debug("YouTube does not support username search; skipping")
            else:
                self._stub_warn("search_username", platform)
        return results

    def search_content(
        self,
        query: str,
        platforms: list[str] | None = None,
        date_from: str | None = None,
        date_to: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search for content/posts matching *query* across platforms.

        Args:
            query: Free-text search query.
            platforms: Optional subset of platform keys.
            date_from: ISO-8601 start date (used where the API supports it).
            date_to: ISO-8601 end date.

        Returns:
            List of normalised post dicts.
        """
        results: list[dict[str, Any]] = []
        for platform in self._resolve_platforms(platforms):
            if platform == "twitter":
                results.extend(self._twitter_search_content(query))
            elif platform == "reddit":
                results.extend(self._reddit_search_content(query))
            elif platform == "youtube":
                results.extend(self._youtube_search_content(query))
            elif platform == "mastodon":
                results.extend(self._mastodon_search_content(query))
            elif platform == "facebook":
                results.extend(self._facebook_search_content(query))
            elif platform == "tiktok":
                results.extend(self._tiktok_search_content(query))
            elif platform == "telegram":
                results.extend(self._telegram_search_content(query))
            elif platform == "instagram":
                # Instagram public scraping doesn't support content search
                log.debug("Instagram content search not available via public API; skipping")
            else:
                self._stub_warn("search_content", platform)
        return results

    def get_user_profile(
        self,
        platform: str,
        user_id: str,
    ) -> dict[str, Any]:
        """Fetch a single user profile from *platform*.

        Args:
            platform: Platform key (e.g. ``twitter``).
            user_id: Platform-specific user identifier.

        Returns:
            Profile dict, or empty dict if unavailable.
        """
        profiles = self.search_username(user_id, platforms=[platform])
        return profiles[0] if profiles else {}

    def get_user_posts(
        self,
        platform: str,
        user_id: str,
        limit: int = 100,
        since: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch recent posts by a user on *platform*.

        Args:
            platform: Platform key.
            user_id: Platform-specific user identifier.
            limit: Maximum number of posts to return.
            since: ISO-8601 timestamp -- only return posts after this date.

        Returns:
            List of normalised post dicts.
        """
        if platform == "twitter":
            return self._twitter_get_user_posts(user_id, limit, since)
        if platform == "reddit":
            return self._reddit_get_user_posts(user_id, limit, since)
        if platform == "instagram":
            return self._instagram_get_user_posts(user_id, limit, since)
        if platform == "youtube":
            return self._youtube_get_user_posts(user_id, limit, since)
        if platform == "mastodon":
            return self._mastodon_get_user_posts(user_id, limit, since)
        if platform == "facebook":
            return self._facebook_get_user_posts(user_id, limit, since)
        if platform == "tiktok":
            return self._tiktok_get_user_posts(user_id, limit, since)
        if platform == "telegram":
            return self._telegram_get_user_posts(user_id, limit, since)
        self._stub_warn("get_user_posts", platform)
        return []

    def extract_geotags(
        self,
        posts: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Extract geolocation tags from a batch of posts.

        Args:
            posts: List of post dicts (as returned by other methods).

        Returns:
            List of geo-point dicts with keys: lat, lng, source, platform,
            post_id, name, confidence.
        """
        geo_points: list[dict[str, Any]] = []
        for post in posts:
            geo = post.get("geo")
            if not geo:
                continue
            lat = geo.get("lat")
            lon = geo.get("lon") or geo.get("lng")
            if lat is not None and lon is not None:
                geo_points.append({
                    "lat": float(lat),
                    "lon": float(lon),
                    "source": "geotag",
                    "platform": post.get("platform", "unknown"),
                    "post_id": post.get("post_id", ""),
                    "name": geo.get("name", ""),
                    "confidence": 0.85,
                })
            elif "raw" in geo:
                # Twitter geo object -- may contain place info
                raw = geo["raw"]
                if isinstance(raw, dict):
                    coords = raw.get("coordinates")
                    if coords and isinstance(coords, dict):
                        coord_list = coords.get("coordinates", [])
                        if len(coord_list) == 2:
                            geo_points.append({
                                "lat": float(coord_list[1]),
                                "lon": float(coord_list[0]),
                                "source": "geotag",
                                "platform": post.get("platform", "unknown"),
                                "post_id": post.get("post_id", ""),
                                "name": raw.get("place_id", ""),
                                "confidence": 0.80,
                            })
        return geo_points

    def poll(
        self,
        monitor_config: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Execute a single poll cycle for a feed monitor.

        Args:
            monitor_config: Dict describing what to monitor.  Must contain
                at least ``query`` and ``platforms``.  Optionally includes
                ``date_from``, ``date_to``, and ``monitor_type``.

        Returns:
            List of new finding dicts.
        """
        query = monitor_config.get("query")
        if not query:
            log.warning("poll() called without a query in monitor_config")
            return []

        platforms = monitor_config.get("platforms")
        date_from = monitor_config.get("date_from")
        date_to = monitor_config.get("date_to")
        monitor_type = monitor_config.get("monitor_type", "keyword")

        if monitor_type == "username":
            return self.search_username(query, platforms=platforms)

        results = self.search_content(
            query,
            platforms=platforms,
            date_from=date_from,
            date_to=date_to,
        )

        # For keyword monitors, also pull the Mastodon public timeline and
        # filter client-side — the search API only covers your own interactions.
        resolved = self._resolve_platforms(platforms)
        if "mastodon" in resolved and self._mastodon_base_url:
            try:
                timeline = self._mastodon_public_timeline(limit=40)
                seen_ids = {r.get("post_id") for r in results}
                q_lower = query.lower()
                for post in timeline:
                    pid = post.get("post_id", "")
                    if pid in seen_ids:
                        continue
                    content = (post.get("content") or "").lower()
                    tags = " ".join(post.get("hashtags") or []).lower()
                    if q_lower in content or q_lower in tags:
                        results.append(post)
                        seen_ids.add(pid)
            except Exception as exc:
                log.warning("Mastodon public timeline poll failed: %s", exc)

        return results
