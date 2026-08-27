"""Reverse image search module for Fortis Intelligence Hub.

Uses PicImageSearch to query free reverse image search engines (Yandex,
Google Lens, Bing) without API keys.  Optional TinEye API support via
pytineye for users who have a paid key.

Perceptual-hash cache detects similar images across investigations within
the same server session.

Exports:
    reverse_image_search  -- main entry point
    compute_image_hashes  -- standalone hash computation
    IMAGE_SEARCH_ENABLED  -- feature toggle (env var)
"""

import hashlib
import io
import logging
import os
import tempfile
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from typing import Any

import imagehash
from PIL import Image

try:
    from pytineye import TinEyeAPIRequest
    HAS_TINEYE = True
except ImportError:
    HAS_TINEYE = False

try:
    from PicImageSearch.sync import Yandex as YandexSearch
    HAS_YANDEX = True
except ImportError:
    HAS_YANDEX = False

try:
    from PicImageSearch.sync import GoogleLens as GoogleLensSearch
    HAS_GOOGLE_LENS = True
except ImportError:
    try:
        from PicImageSearch.sync import Google as GoogleLensSearch
        HAS_GOOGLE_LENS = True
    except ImportError:
        HAS_GOOGLE_LENS = False

try:
    from PicImageSearch.sync import Bing as BingSearch
    HAS_BING = True
except ImportError:
    HAS_BING = False

log = logging.getLogger(__name__)

IMAGE_SEARCH_ENABLED: bool = os.environ.get(
    "IMAGE_SEARCH_ENABLED", "true"
).lower() in ("true", "1", "yes")

_TINEYE_API_KEY: str | None = os.environ.get("TINEYE_API_KEY")

_ENGINE_DELAY_SECONDS = 2.5
_ENGINE_TIMEOUT_SECONDS = int(os.environ.get("IMAGE_SEARCH_TIMEOUT", "30"))

# ---------------------------------------------------------------------------
# Bounded LRU hash cache
# ---------------------------------------------------------------------------
_HASH_CACHE_MAX = 5000
_hash_cache: OrderedDict[str, dict[str, Any]] = OrderedDict()
_cache_lock = threading.Lock()


def _cache_put(key: str, entry: dict[str, Any]) -> None:
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
                similar.append({
                    "filename": entry.get("filename"),
                    "md5": key,
                    "distance": round(avg_dist, 2),
                    "phash": entry["phash"],
                })
    return similar


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------

def compute_image_hashes(image_bytes: bytes) -> dict[str, str]:
    img = Image.open(io.BytesIO(image_bytes))
    return {
        "phash": str(imagehash.phash(img)),
        "dhash": str(imagehash.dhash(img)),
        "ahash": str(imagehash.average_hash(img)),
    }


# ---------------------------------------------------------------------------
# PicImageSearch engines (free, no API key)
# ---------------------------------------------------------------------------

def _write_temp_image(image_bytes: bytes, filename: str | None) -> str:
    suffix = ".jpg"
    if filename:
        low = filename.lower()
        if low.endswith(".png"):
            suffix = ".png"
        elif low.endswith((".tiff", ".tif")):
            suffix = ".tiff"
        elif low.endswith(".webp"):
            suffix = ".webp"
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, image_bytes)
    finally:
        os.close(fd)
    return path


def _yandex_search(tmp_path: str) -> dict[str, Any] | None:
    if not HAS_YANDEX:
        return None
    try:
        engine = YandexSearch()
        resp = engine.search(file=tmp_path)
        if resp is None:
            return None
        matches = []
        if hasattr(resp, "raw") and resp.raw:
            for item in resp.raw[:15]:
                title = getattr(item, "title", "") or ""
                url = getattr(item, "url", "") or ""
                thumbnail = getattr(item, "thumbnail", "") or ""
                if url:
                    matches.append({
                        "title": str(title)[:200],
                        "url": str(url),
                        "thumbnail": str(thumbnail)[:500],
                        "source": "yandex",
                    })
        search_url = getattr(resp, "url", "") or ""
        log.info("Yandex: %d match(es), search_url=%s", len(matches), bool(search_url))
        return {
            "search_url": str(search_url),
            "matches": matches[:10],
        }
    except Exception as exc:
        log.warning("Yandex reverse search failed: %s", exc)
        return None


def _google_lens_search(tmp_path: str) -> dict[str, Any] | None:
    if not HAS_GOOGLE_LENS:
        return None
    try:
        engine = GoogleLensSearch()
        resp = engine.search(file=tmp_path)
        if resp is None:
            return None
        matches = []
        if hasattr(resp, "raw") and resp.raw:
            for item in resp.raw[:15]:
                title = getattr(item, "title", "") or ""
                url = getattr(item, "url", "") or ""
                thumbnail = getattr(item, "thumbnail", "") or ""
                if url:
                    matches.append({
                        "title": str(title)[:200],
                        "url": str(url),
                        "thumbnail": str(thumbnail)[:500],
                        "source": "google_lens",
                    })
        search_url = getattr(resp, "url", "") or ""
        log.info("Google Lens: %d match(es)", len(matches))
        return {
            "search_url": str(search_url),
            "matches": matches[:10],
        }
    except Exception as exc:
        log.warning("Google Lens reverse search failed: %s", exc)
        return None


def _bing_search(tmp_path: str) -> dict[str, Any] | None:
    if not HAS_BING:
        return None
    try:
        engine = BingSearch()
        resp = engine.search(file=tmp_path)
        if resp is None:
            return None
        matches = []
        if hasattr(resp, "raw") and resp.raw:
            for item in resp.raw[:15]:
                title = getattr(item, "title", "") or ""
                url = getattr(item, "url", "") or ""
                thumbnail = getattr(item, "thumbnail", "") or ""
                if url:
                    matches.append({
                        "title": str(title)[:200],
                        "url": str(url),
                        "thumbnail": str(thumbnail)[:500],
                        "source": "bing",
                    })
        search_url = getattr(resp, "url", "") or ""
        log.info("Bing: %d match(es)", len(matches))
        return {
            "search_url": str(search_url),
            "matches": matches[:10],
        }
    except Exception as exc:
        log.warning("Bing reverse search failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# TinEye (optional, requires paid API key)
# ---------------------------------------------------------------------------

def _tineye_search(
    image_bytes: bytes, filename: str | None = None,
) -> list[dict[str, Any]] | None:
    if not HAS_TINEYE or not _TINEYE_API_KEY:
        return None
    try:
        api = TinEyeAPIRequest(
            api_url="https://api.tineye.com/rest/", api_key=_TINEYE_API_KEY,
        )
        response = api.search_data(image_bytes, filename or "upload.jpg")
        results: list[dict[str, Any]] = []
        for match in response.matches:
            results.append({
                "url": getattr(match, "image_url", None),
                "domain": getattr(match, "domain", None),
                "crawl_date": str(getattr(match, "crawl_date", "")),
                "backlink": getattr(match, "backlink", None),
            })
        log.info("TinEye returned %d match(es)", len(results))
        return results
    except Exception as exc:
        log.warning("TinEye search failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def reverse_image_search(
    image_bytes: bytes,
    filename: str | None = None,
) -> dict[str, Any]:
    """Run reverse image search across available engines.

    Returns dict with keys:
        - ``yandex_results``: dict with search_url + matches, or None
        - ``google_lens_results``: dict with search_url + matches, or None
        - ``bing_results``: dict with search_url + matches, or None
        - ``tineye_results``: list of match dicts, or None
        - ``search_urls``: dict of engine → working search URL
        - ``perceptual_hashes``: dict with phash, dhash, ahash
        - ``similar_cached``: list of perceptually similar cached images
        - ``engines_searched``: list of engine names that were queried
    """
    if not IMAGE_SEARCH_ENABLED:
        return {
            "yandex_results": None,
            "google_lens_results": None,
            "bing_results": None,
            "tineye_results": None,
            "search_urls": {},
            "perceptual_hashes": {},
            "similar_cached": [],
            "engines_searched": [],
            "disabled": True,
        }

    md5 = hashlib.md5(image_bytes).hexdigest()
    label = filename or md5[:12]
    log.info("Reverse image search started for %s (%d bytes)", label, len(image_bytes))

    hashes = compute_image_hashes(image_bytes)
    phash_obj = imagehash.hex_to_hash(hashes["phash"])
    dhash_obj = imagehash.hex_to_hash(hashes["dhash"])
    ahash_obj = imagehash.hex_to_hash(hashes["ahash"])

    similar = _cache_find_similar(phash_obj, dhash_obj, ahash_obj, exclude_key=md5)
    _cache_put(md5, {"filename": filename, **hashes})

    tmp_path = _write_temp_image(image_bytes, filename)
    engines_searched: list[str] = []
    yandex_results = None
    google_lens_results = None
    bing_results = None
    tineye_results = None

    def _run_engine(name, fn, *args):
        try:
            with ThreadPoolExecutor(max_workers=1) as ex:
                future = ex.submit(fn, *args)
                return future.result(timeout=_ENGINE_TIMEOUT_SECONDS)
        except FuturesTimeout:
            log.warning("%s reverse search timed out after %ds", name, _ENGINE_TIMEOUT_SECONDS)
            return None
        except Exception as exc:
            log.warning("%s reverse search executor failed: %s", name, exc)
            return None

    try:
        yandex_results = _run_engine("Yandex", _yandex_search, tmp_path)
        if yandex_results is not None:
            engines_searched.append("yandex")

        if engines_searched:
            time.sleep(_ENGINE_DELAY_SECONDS)

        google_lens_results = _run_engine("Google Lens", _google_lens_search, tmp_path)
        if google_lens_results is not None:
            engines_searched.append("google_lens")

        if len(engines_searched) >= 2:
            time.sleep(_ENGINE_DELAY_SECONDS)

        bing_results = _run_engine("Bing", _bing_search, tmp_path)
        if bing_results is not None:
            engines_searched.append("bing")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    tineye_results = _tineye_search(image_bytes, filename)
    if tineye_results is not None:
        engines_searched.append("tineye")

    search_urls: dict[str, str] = {}
    if yandex_results and yandex_results.get("search_url"):
        search_urls["yandex"] = yandex_results["search_url"]
    if google_lens_results and google_lens_results.get("search_url"):
        search_urls["google_lens"] = google_lens_results["search_url"]
    if bing_results and bing_results.get("search_url"):
        search_urls["bing"] = bing_results["search_url"]

    total_matches = sum(
        len(r.get("matches", [])) for r in
        [yandex_results, google_lens_results, bing_results]
        if r
    )
    log.info(
        "Reverse image search complete for %s — %d engine(s), %d total match(es), "
        "%d similar cached",
        label, len(engines_searched), total_matches, len(similar),
    )

    return {
        "yandex_results": yandex_results,
        "google_lens_results": google_lens_results,
        "bing_results": bing_results,
        "tineye_results": tineye_results,
        "search_urls": search_urls,
        "perceptual_hashes": hashes,
        "similar_cached": similar,
        "engines_searched": engines_searched,
    }
