"""Reverse image search module for Fortis Intelligence Hub.

Provides perceptual-hash based duplicate detection, optional TinEye API
lookups, and informational search URLs for Google Lens, Yandex Images,
and Bing Visual Search.  No LLM calls are made; all processing is local
image hashing or external image-search APIs.

Exports:
    reverse_image_search  -- main entry point
    compute_image_hashes  -- standalone hash computation
    IMAGE_SEARCH_ENABLED  -- feature toggle (env var)
"""

import base64
import hashlib
import io
import logging
import os
import threading
from collections import OrderedDict
from typing import Any

import imagehash
from PIL import Image

try:
    from pytineye import TinEyeAPIRequest

    HAS_TINEYE = True
except ImportError:
    HAS_TINEYE = False

log = logging.getLogger(__name__)

IMAGE_SEARCH_ENABLED: bool = os.environ.get("IMAGE_SEARCH_ENABLED", "true").lower() in (
    "true",
    "1",
    "yes",
)

_TINEYE_API_KEY: str | None = os.environ.get("TINEYE_API_KEY")

# ---------------------------------------------------------------------------
# Bounded LRU hash cache
# ---------------------------------------------------------------------------
_HASH_CACHE_MAX = 5000
_hash_cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
_cache_lock = threading.Lock()


def _cache_put(key: str, entry: dict[str, Any]) -> None:
    """Insert *entry* under *key*, evicting the oldest if at capacity."""
    with _cache_lock:
        if key in _hash_cache:
            _hash_cache.move_to_end(key)
            _hash_cache[key] = entry
        else:
            _hash_cache[key] = entry
            if len(_hash_cache) > _HASH_CACHE_MAX:
                _hash_cache.popitem(last=False)


def _cache_find_similar(
    phash: imagehash.ImageHash,
    dhash: imagehash.ImageHash,
    ahash: imagehash.ImageHash,
    threshold: int = 10,
    exclude_key: str | None = None,
) -> list[dict[str, Any]]:
    """Return cached entries whose perceptual hashes are within *threshold*."""
    similar: list[dict[str, Any]] = []
    with _cache_lock:
        for key, entry in _hash_cache.items():
            if key == exclude_key:
                continue
            try:
                p_dist = phash - imagehash.hex_to_hash(entry["phash"])
                d_dist = dhash - imagehash.hex_to_hash(entry["dhash"])
                a_dist = ahash - imagehash.hex_to_hash(entry["ahash"])
            except Exception:
                continue
            avg_dist = (p_dist + d_dist + a_dist) / 3
            if avg_dist <= threshold:
                similar.append(
                    {
                        "filename": entry.get("filename"),
                        "md5": key,
                        "distance": round(avg_dist, 2),
                        "phash": entry["phash"],
                    }
                )
    return similar


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------

def compute_image_hashes(image_bytes: bytes) -> dict[str, str]:
    """Compute perceptual hashes (pHash, dHash, aHash) for raw image bytes.

    Returns a dict with keys ``phash``, ``dhash``, ``ahash`` — each value is
    the hex string representation of the hash.
    """
    img = Image.open(io.BytesIO(image_bytes))
    return {
        "phash": str(imagehash.phash(img)),
        "dhash": str(imagehash.dhash(img)),
        "ahash": str(imagehash.average_hash(img)),
    }


# ---------------------------------------------------------------------------
# TinEye lookup
# ---------------------------------------------------------------------------

def _tineye_search(image_bytes: bytes, filename: str | None = None) -> list[dict[str, Any]] | None:
    """Query TinEye API.  Returns *None* when unavailable."""
    if not HAS_TINEYE or not _TINEYE_API_KEY:
        return None
    try:
        api = TinEyeAPIRequest(api_url="https://api.tineye.com/rest/", api_key=_TINEYE_API_KEY)
        response = api.search_data(image_bytes, filename or "upload.jpg")
        results: list[dict[str, Any]] = []
        for match in response.matches:
            results.append(
                {
                    "url": getattr(match, "image_url", None),
                    "domain": getattr(match, "domain", None),
                    "crawl_date": str(getattr(match, "crawl_date", "")),
                    "backlink": getattr(match, "backlink", None),
                }
            )
        log.info("TinEye returned %d match(es)", len(results))
        return results
    except Exception as exc:
        log.warning("TinEye search failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Search URL construction
# ---------------------------------------------------------------------------

def _build_search_urls(image_bytes: bytes) -> dict[str, str]:
    """Build informational reverse-image search URLs.

    * **Google Lens** requires a publicly reachable URL, so we return the
      upload endpoint template — the caller must substitute a hosted link.
    * **Yandex** accepts a base64-encoded ``img_url`` parameter.
    * **Bing** works similarly to Google (public URL needed).

    These URLs are *informational* — the user can paste/open them manually.
    """
    b64 = base64.b64encode(image_bytes).decode("ascii")
    md5 = hashlib.md5(image_bytes).hexdigest()

    return {
        "google_lens": (
            "https://lens.google.com/uploadbyurl?url="
            "  [requires a publicly hosted image URL]"
        ),
        "yandex": (
            f"https://yandex.com/images/search?rpt=imageview&img_url=data:image/jpeg;base64,{b64[:64]}..."
            "  [truncated — open Yandex Images and upload the file directly for best results]"
        ),
        "bing": (
            "https://www.bing.com/images/search?view=detailv2&iss=sbi"
            "  [requires a publicly hosted image URL or manual upload via Bing Visual Search]"
        ),
        "image_md5": md5,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def reverse_image_search(
    image_bytes: bytes,
    filename: str | None = None,
) -> dict[str, Any]:
    """Run a reverse image search pipeline on raw image bytes.

    Parameters
    ----------
    image_bytes:
        Raw bytes of the image file (JPEG, PNG, etc.).
    filename:
        Optional original filename for logging and cache labelling.

    Returns
    -------
    dict with keys:
        - ``tineye_results``: list of match dicts, or *None* if no API key.
        - ``search_urls``: dict of ``{engine: url}`` for manual searches.
        - ``perceptual_hashes``: dict with ``phash``, ``dhash``, ``ahash``.
        - ``similar_cached``: list of previously seen similar images.
    """
    if not IMAGE_SEARCH_ENABLED:
        return {
            "tineye_results": None,
            "search_urls": {},
            "perceptual_hashes": {},
            "similar_cached": [],
            "disabled": True,
        }

    md5 = hashlib.md5(image_bytes).hexdigest()
    label = filename or md5[:12]
    log.info("Reverse image search started for %s (%d bytes)", label, len(image_bytes))

    # 1. Perceptual hashes
    hashes = compute_image_hashes(image_bytes)

    phash_obj = imagehash.hex_to_hash(hashes["phash"])
    dhash_obj = imagehash.hex_to_hash(hashes["dhash"])
    ahash_obj = imagehash.hex_to_hash(hashes["ahash"])

    # 2. Find similar images already in cache
    similar = _cache_find_similar(phash_obj, dhash_obj, ahash_obj, exclude_key=md5)

    # 3. Store this image in cache
    _cache_put(md5, {"filename": filename, **hashes})

    # 4. TinEye lookup (optional)
    tineye_results = _tineye_search(image_bytes, filename)

    # 5. Informational search URLs
    search_urls = _build_search_urls(image_bytes)

    log.info(
        "Reverse image search complete for %s — %d similar cached, TinEye: %s",
        label,
        len(similar),
        "available" if tineye_results is not None else "skipped",
    )

    return {
        "tineye_results": tineye_results,
        "search_urls": search_urls,
        "perceptual_hashes": hashes,
        "similar_cached": similar,
    }
