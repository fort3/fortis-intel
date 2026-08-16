"""Video frame extraction and landmark geolocation for Fortis Intelligence Hub.

Phase 2: Extracts keyframes from video URLs/bytes using OpenCV,
runs perceptual deduplication, extracts EXIF from frames, and
performs OCR-based text detection for location clue extraction.
"""

import io
import logging
import re
import tempfile
from dataclasses import dataclass, field
from typing import Any

import requests as _requests
from requests.adapters import HTTPAdapter as _HTTPAdapter

log = logging.getLogger(__name__)

_video_http = _requests.Session()
_video_adapter = _HTTPAdapter(pool_connections=2, pool_maxsize=4, max_retries=1)
_video_http.mount("https://", _video_adapter)
_video_http.mount("http://", _video_adapter)

# ---------------------------------------------------------------------------
# Optional library availability
# ---------------------------------------------------------------------------

HAS_CV2 = False
try:
    import cv2
    HAS_CV2 = True
except ImportError:
    pass

HAS_PILLOW = False
try:
    from PIL import Image
    HAS_PILLOW = True
except ImportError:
    pass

HAS_IMAGEHASH = False
try:
    import imagehash
    HAS_IMAGEHASH = True
except ImportError:
    pass

HAS_PYTESSERACT = False
try:
    import pytesseract
    HAS_PYTESSERACT = True
except ImportError:
    pass


_VIDEO_EXT_RE = re.compile(
    r"\.(mp4|avi|mov|mkv|webm|flv|wmv|m4v|3gp)(\?.*)?$", re.I
)
_VIDEO_URL_HINTS = ("/video/", "/videos/", "video_url", ".mp4", ".webm")

LIBRARY_FLAGS = {
    "opencv": HAS_CV2,
    "imagehash": HAS_IMAGEHASH,
    "pytesseract": HAS_PYTESSERACT,
}


@dataclass
class VideoFrame:
    """A single extracted keyframe with metadata."""
    frame_index: int = 0
    timestamp_sec: float = 0.0
    image_bytes: bytes = b""
    phash: str = ""
    is_duplicate: bool = False


@dataclass
class VideoGeoResult:
    """Geolocation signal derived from video analysis."""
    lat: float = 0.0
    lon: float = 0.0
    source: str = "video_landmark"
    confidence: float = 0.0
    label: str = ""
    method: str = ""
    media_url: str = ""
    platform: str = ""
    frame_index: int = 0
    detected_text: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class VideoGeoExtractor:
    """Extracts geolocation signals from video content.

    Capabilities (progressive, based on available libraries):
    1. OpenCV keyframe extraction (requires opencv-python)
    2. Perceptual dedup via imagehash (requires imagehash)
    3. EXIF extraction from frames (uses MetadataExtractor)
    4. OCR text detection for location clues (requires pytesseract)
    5. Location resolution via GeoClient geocoding
    """

    _MAX_VIDEO_SIZE = 100 * 1024 * 1024  # 100 MB
    _DOWNLOAD_TIMEOUT = 30
    _KEYFRAME_INTERVAL = 2.0  # seconds between sampled frames
    _MAX_KEYFRAMES = 30
    _HASH_THRESHOLD = 8  # hamming distance for dedup

    def __init__(self):
        from app.metadata_extractor import MetadataExtractor
        self._extractor = MetadataExtractor()
        self._geo_client = None

    def _get_geo_client(self):
        if self._geo_client is None:
            from app.geo_client import GeoClient
            self._geo_client = GeoClient()
        return self._geo_client

    @staticmethod
    def is_video_url(url: str) -> bool:
        if not url or not url.startswith("http"):
            return False
        if _VIDEO_EXT_RE.search(url):
            return True
        return any(hint in url.lower() for hint in _VIDEO_URL_HINTS)

    def extract_from_urls(
        self,
        video_urls: list[tuple[str, str]],
    ) -> list[dict[str, Any]]:
        """Download videos and extract geo signals.

        Args:
            video_urls: List of (url, platform) tuples.

        Returns:
            List of geo-point dicts compatible with findings.geo_points.
        """
        if not HAS_CV2:
            log.info("OpenCV not installed — skipping video geo extraction")
            return []

        all_results: list[dict[str, Any]] = []
        for url, platform in video_urls[:10]:
            try:
                video_bytes = self._download_video(url)
                if not video_bytes:
                    continue
                results = self._process_video(video_bytes, url, platform)
                all_results.extend(results)
            except Exception as exc:
                log.debug("Video geo extraction failed for %s: %s", url[:80], exc)

        log.info(
            "Video geo extraction: %d signals from %d videos",
            len(all_results), len(video_urls[:10]),
        )
        return all_results

    def extract_from_bytes(
        self,
        video_data: bytes,
        source_url: str = "",
        platform: str = "",
    ) -> list[dict[str, Any]]:
        """Extract geo signals from raw video bytes."""
        if not HAS_CV2:
            return []
        return self._process_video(video_data, source_url, platform)

    def extract_keyframes(self, video_data: bytes) -> list[VideoFrame]:
        """Extract keyframes from video bytes using OpenCV."""
        if not HAS_CV2:
            return []

        frames: list[VideoFrame] = []
        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile(suffix=".mp4", delete=False)
            tmp.write(video_data)
            tmp.flush()
            tmp_path = tmp.name
            tmp.close()

            cap = cv2.VideoCapture(tmp_path)
            if not cap.isOpened():
                log.warning("OpenCV could not open video file")
                return []

            fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            frame_interval = max(1, int(fps * self._KEYFRAME_INTERVAL))

            frame_idx = 0
            extracted = 0
            while extracted < self._MAX_KEYFRAMES:
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
                ret, frame = cap.read()
                if not ret:
                    break

                timestamp_sec = frame_idx / fps
                img_bytes = self._frame_to_bytes(frame)
                phash = self._compute_phash(img_bytes)

                vf = VideoFrame(
                    frame_index=frame_idx,
                    timestamp_sec=round(timestamp_sec, 2),
                    image_bytes=img_bytes,
                    phash=phash,
                )
                frames.append(vf)
                extracted += 1
                frame_idx += frame_interval

                if frame_idx >= total_frames:
                    break

            cap.release()
        except Exception as exc:
            log.error("Keyframe extraction failed: %s", exc)
        finally:
            if tmp is not None:
                import os
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass

        self._deduplicate_frames(frames)
        unique = [f for f in frames if not f.is_duplicate]
        log.info(
            "Extracted %d keyframes (%d unique) from video",
            len(frames), len(unique),
        )
        return frames

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _download_video(self, url: str) -> bytes | None:
        try:
            resp = _video_http.get(
                url, timeout=self._DOWNLOAD_TIMEOUT, stream=True
            )
            if resp.status_code != 200:
                return None

            ct = resp.headers.get("Content-Type", "")
            if "text/html" in ct:
                return None

            chunks = []
            total = 0
            for chunk in resp.iter_content(chunk_size=1024 * 1024):
                chunks.append(chunk)
                total += len(chunk)
                if total > self._MAX_VIDEO_SIZE:
                    log.debug("Video too large (>%d MB), skipping", self._MAX_VIDEO_SIZE // (1024*1024))
                    return None
            return b"".join(chunks)
        except Exception as exc:
            log.debug("Video download failed for %s: %s", url[:80], exc)
            return None

    def _process_video(
        self,
        video_bytes: bytes,
        source_url: str,
        platform: str,
    ) -> list[dict[str, Any]]:
        """Full pipeline: keyframes → EXIF + OCR → geocode → geo points."""
        frames = self.extract_keyframes(video_bytes)
        unique_frames = [f for f in frames if not f.is_duplicate]

        if not unique_frames:
            return []

        geo_points: list[dict[str, Any]] = []

        # 1. EXIF extraction from frames (cameras sometimes embed GPS in video frames)
        frame_bytes = [f.image_bytes for f in unique_frames]
        exif_points = self._extractor.extract_geo_from_images(frame_bytes)
        for i, gp in enumerate(exif_points):
            gp["source"] = "video_exif"
            gp["confidence"] = 0.90
            gp["media_url"] = source_url
            gp["platform"] = platform
            gp["method"] = "video_frame_exif"
            if i < len(unique_frames):
                gp["frame_index"] = unique_frames[i].frame_index
                gp["frame_timestamp"] = unique_frames[i].timestamp_sec
        geo_points.extend(exif_points)

        # 2. OCR text detection → geocode location mentions
        if HAS_PYTESSERACT:
            ocr_points = self._ocr_geocode_frames(unique_frames, source_url, platform)
            geo_points.extend(ocr_points)

        # 3. Visual text detection via OpenCV (signs, banners) — no pytesseract needed
        opencv_text_points = self._detect_text_regions(unique_frames, source_url, platform)
        geo_points.extend(opencv_text_points)

        return geo_points

    @staticmethod
    def _frame_to_bytes(frame) -> bytes:
        """Convert an OpenCV frame (numpy array) to JPEG bytes."""
        success, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
        if success:
            return buffer.tobytes()
        return b""

    def _compute_phash(self, image_bytes: bytes) -> str:
        """Compute perceptual hash for deduplication."""
        if not HAS_IMAGEHASH or not HAS_PILLOW or not image_bytes:
            return ""
        try:
            img = Image.open(io.BytesIO(image_bytes))
            return str(imagehash.phash(img))
        except Exception:
            return ""

    def _deduplicate_frames(self, frames: list[VideoFrame]) -> None:
        """Mark near-duplicate frames based on perceptual hash distance."""
        if not HAS_IMAGEHASH:
            return

        seen_hashes: list[str] = []
        for frame in frames:
            if not frame.phash:
                continue
            try:
                current = imagehash.hex_to_hash(frame.phash)
                for seen_str in seen_hashes:
                    seen = imagehash.hex_to_hash(seen_str)
                    if (current - seen) < self._HASH_THRESHOLD:
                        frame.is_duplicate = True
                        break
                if not frame.is_duplicate:
                    seen_hashes.append(frame.phash)
            except Exception:
                pass

    def _ocr_geocode_frames(
        self,
        frames: list[VideoFrame],
        source_url: str,
        platform: str,
    ) -> list[dict[str, Any]]:
        """Run OCR on frames, extract location text, geocode matches."""
        if not HAS_PYTESSERACT or not HAS_PILLOW:
            return []

        geo_points: list[dict[str, Any]] = []
        seen_locations: set[str] = set()
        geo = self._get_geo_client()

        for frame in frames[:15]:
            if not frame.image_bytes:
                continue
            try:
                img = Image.open(io.BytesIO(frame.image_bytes))
                text = pytesseract.image_to_string(img, timeout=5)
                if not text or len(text.strip()) < 3:
                    continue

                locations = geo.resolve_locations([text])
                for loc_point in locations:
                    loc_key = f"{loc_point.lat:.4f},{loc_point.lon:.4f}"
                    if loc_key in seen_locations:
                        continue
                    seen_locations.add(loc_key)

                    geo_points.append({
                        "lat": loc_point.lat,
                        "lon": loc_point.lon,
                        "source": "video_landmark",
                        "confidence": min(0.55, loc_point.confidence),
                        "label": loc_point.label,
                        "method": "video_ocr_geocode",
                        "media_url": source_url,
                        "platform": platform,
                        "frame_index": frame.frame_index,
                        "frame_timestamp": frame.timestamp_sec,
                        "detected_text": text[:200],
                    })
            except Exception as exc:
                log.debug("OCR frame analysis failed: %s", exc)

        return geo_points

    def _detect_text_regions(
        self,
        frames: list[VideoFrame],
        source_url: str,
        platform: str,
    ) -> list[dict[str, Any]]:
        """Use OpenCV EAST or MSER to detect text regions in frames.

        This is a lightweight structural detection — it identifies frames
        that contain significant text (signs, banners, watermarks) which
        may contain location information. When pytesseract is available,
        detected regions are OCR'd for location names.
        """
        if not HAS_CV2:
            return []

        import numpy as np

        geo_points: list[dict[str, Any]] = []
        seen_locations: set[str] = set()

        mser = cv2.MSER_create()
        mser.setMinArea(100)
        mser.setMaxArea(10000)

        for frame in frames[:15]:
            if not frame.image_bytes:
                continue
            try:
                nparr = np.frombuffer(frame.image_bytes, np.uint8)
                img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
                if img is None:
                    continue

                gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                regions, _ = mser.detectRegions(gray)

                if len(regions) < 5:
                    continue

                if not HAS_PYTESSERACT or not HAS_PILLOW:
                    continue

                pil_img = Image.open(io.BytesIO(frame.image_bytes))
                text = pytesseract.image_to_string(pil_img, timeout=5)
                if not text or len(text.strip()) < 5:
                    continue

                geo = self._get_geo_client()
                locations = geo.resolve_locations([text])
                for loc_point in locations:
                    loc_key = f"{loc_point.lat:.4f},{loc_point.lon:.4f}"
                    if loc_key in seen_locations:
                        continue
                    seen_locations.add(loc_key)

                    geo_points.append({
                        "lat": loc_point.lat,
                        "lon": loc_point.lon,
                        "source": "video_landmark",
                        "confidence": min(0.50, loc_point.confidence),
                        "label": loc_point.label,
                        "method": "video_text_region_ocr",
                        "media_url": source_url,
                        "platform": platform,
                        "frame_index": frame.frame_index,
                        "frame_timestamp": frame.timestamp_sec,
                        "detected_text": text[:200],
                    })
            except Exception as exc:
                log.debug("Text region detection failed: %s", exc)

        return geo_points
