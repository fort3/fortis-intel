"""Metadata extraction utilities for Fortis Intelligence Hub.

Phase 1: All extraction methods are functional. ``extract_exif()`` uses
Pillow or exifread. NLP entity extraction requires spaCy with
``en_core_web_sm``. Language detection requires ``langdetect``.
"""

import io
import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Optional library availability
# ---------------------------------------------------------------------------

HAS_PILLOW = False
try:
    from PIL import Image
    from PIL.ExifTags import TAGS as PILLOW_TAGS, GPSTAGS as PILLOW_GPSTAGS
    HAS_PILLOW = True
except ImportError:
    pass

HAS_EXIFREAD = False
try:
    import exifread  # noqa: F401
    HAS_EXIFREAD = True
except ImportError:
    pass

HAS_LANGDETECT = False
try:
    from langdetect import detect as _langdetect_detect
    HAS_LANGDETECT = True
except ImportError:
    pass

HAS_SPACY = False
try:
    import spacy  # noqa: F401
    HAS_SPACY = True
except ImportError:
    pass


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class MetadataBundle:
    """Aggregated metadata extracted from one or more content items."""

    source_id: str = ""
    content_type: str = ""  # image, video, document, post, etc.
    exif: dict[str, Any] = field(default_factory=dict)
    geo: dict[str, Any] = field(default_factory=dict)  # lat, lon, altitude
    camera: dict[str, Any] = field(default_factory=dict)  # make, model, lens
    timestamps: dict[str, str] = field(default_factory=dict)  # original, modified, gps
    software: str = ""
    dimensions: dict[str, int] = field(default_factory=dict)  # width, height
    language: str = ""
    region: str = ""
    timezone: str = ""
    entities: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

class MetadataExtractor:
    """Extract and normalise metadata from images, text, and other content.

    Phase 1: All extraction methods are functional.
    """

    _nlp = None

    def __init__(self):
        log.info(
            "MetadataExtractor initialised (Phase 1) — "
            "Pillow=%s, exifread=%s, langdetect=%s, spacy=%s",
            HAS_PILLOW, HAS_EXIFREAD, HAS_LANGDETECT, HAS_SPACY,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_all(
        self,
        content_items: list[dict[str, Any]],
    ) -> list[MetadataBundle]:
        """Extract metadata from a batch of content items.

        Args:
            content_items: Dicts with ``type`` and ``data`` keys.

        Returns:
            List of :class:`MetadataBundle`.
        """
        results: list[MetadataBundle] = []
        for item in content_items:
            try:
                item_type = item.get("type", "unknown")
                data = item.get("data")
                bundle = MetadataBundle(
                    source_id=item.get("id", ""),
                    content_type=item_type,
                )

                if item_type == "image" and isinstance(data, bytes):
                    bundle = self.extract_exif(data)
                    bundle.source_id = item.get("id", "")

                elif item_type == "text" and isinstance(data, str):
                    entities = self.extract_entities_nlp(data)
                    bundle.entities = entities
                    lang_info = self.detect_language_region([data])
                    bundle.language = lang_info.get("language", "")
                    bundle.region = lang_info.get("region", "")

                results.append(bundle)
            except Exception as exc:
                log.error("extract_all failed for item %s: %s", item.get("id", "?"), exc)
                results.append(
                    MetadataBundle(
                        source_id=item.get("id", ""),
                        content_type=item.get("type", "unknown"),
                    )
                )
        return results

    def extract_exif(self, image_data: bytes) -> MetadataBundle:
        """Extract EXIF metadata from image bytes.

        This method is functional when Pillow or exifread is installed.

        Args:
            image_data: Raw image bytes (JPEG, TIFF, etc.).

        Returns:
            A :class:`MetadataBundle` populated with EXIF data.
        """
        bundle = MetadataBundle(content_type="image")

        if HAS_PILLOW:
            return self._extract_exif_pillow(image_data, bundle)
        if HAS_EXIFREAD:
            return self._extract_exif_exifread(image_data, bundle)

        log.warning(
            "MetadataExtractor.extract_exif() — neither Pillow nor exifread "
            "is installed; returning empty bundle"
        )
        return bundle

    def extract_geo_from_images(
        self,
        images: list[bytes],
    ) -> list[dict[str, Any]]:
        """Extract geolocation data from a batch of images.

        Args:
            images: List of raw image byte strings.

        Returns:
            List of geo-point dicts (empty if required library is missing).
        """
        geo_points: list[dict[str, Any]] = []
        for image_data in images:
            try:
                bundle = self.extract_exif(image_data)
                geo = bundle.geo
                if geo.get("lat") is not None and geo.get("lon") is not None:
                    point: dict[str, Any] = {
                        "lat": geo["lat"],
                        "lon": geo["lon"],
                        "source": "exif",
                        "gps_time": geo.get("gps_time", ""),
                        "gps_date": geo.get("gps_date", ""),
                    }
                    if "altitude" in geo:
                        point["altitude"] = geo["altitude"]
                    geo_points.append(point)
            except Exception as exc:
                log.error("extract_geo_from_images failed for an image: %s", exc)
        return geo_points

    def infer_timezone(
        self,
        posting_times: list[str],
    ) -> dict[str, Any]:
        """Infer a probable timezone from a set of posting timestamps.

        Args:
            posting_times: List of ISO-8601 timestamp strings.

        Returns:
            Dict with ``timezone``, ``confidence``, and ``method`` keys
            (empty if required library is missing).
        """
        if not posting_times:
            return {
                "timezone": "",
                "confidence": 0.0,
                "method": "posting_time_analysis",
                "peak_hour_utc": -1,
                "sample_size": 0,
            }

        utc_hours: list[int] = []
        for ts_str in posting_times:
            try:
                dt = datetime.fromisoformat(ts_str)
                if dt.tzinfo is not None:
                    dt = dt.astimezone(timezone.utc)
                utc_hours.append(dt.hour)
            except Exception:
                continue

        if not utc_hours:
            return {
                "timezone": "",
                "confidence": 0.0,
                "method": "posting_time_analysis",
                "peak_hour_utc": -1,
                "sample_size": 0,
            }

        hour_counts = Counter(utc_hours)
        peak_hour_utc = hour_counts.most_common(1)[0][0]

        mid_local = 15
        offset = (mid_local - peak_hour_utc) % 24
        if offset > 12:
            offset -= 24

        active_window_hours = set()
        for h in range(9, 22):
            active_window_hours.add((h - offset) % 24)

        hits = sum(1 for h in utc_hours if h in active_window_hours)
        confidence = round(hits / len(utc_hours), 2) if utc_hours else 0.0

        if offset >= 0:
            tz_str = f"UTC+{offset}"
        else:
            tz_str = f"UTC{offset}"

        return {
            "timezone": tz_str,
            "confidence": confidence,
            "method": "posting_time_analysis",
            "peak_hour_utc": peak_hour_utc,
            "sample_size": len(utc_hours),
        }

    def detect_language_region(
        self,
        texts: list[str],
    ) -> dict[str, Any]:
        """Detect primary language and probable geographic region from texts.

        Args:
            texts: List of text samples.

        Returns:
            Dict with ``language``, ``region``, ``confidence`` keys
            (empty if required library is missing).
        """
        if not HAS_LANGDETECT:
            log.warning("langdetect is not installed — returning empty dict")
            return {}

        if not texts:
            return {}

        lang_to_region = {
            "en": "United States/United Kingdom",
            "es": "Spain/Latin America",
            "fr": "France",
            "de": "Germany",
            "it": "Italy",
            "pt": "Portugal/Brazil",
            "ru": "Russia",
            "zh-cn": "China",
            "zh-tw": "Taiwan",
            "ja": "Japan",
            "ko": "South Korea",
            "ar": "Middle East/North Africa",
            "hi": "India",
            "tr": "Turkey",
            "nl": "Netherlands",
            "pl": "Poland",
            "sv": "Sweden",
            "da": "Denmark",
            "fi": "Finland",
            "no": "Norway",
            "uk": "Ukraine",
            "he": "Israel",
            "th": "Thailand",
            "vi": "Vietnam",
            "id": "Indonesia",
            "ms": "Malaysia",
            "tl": "Philippines",
            "fa": "Iran",
        }

        lang_names = {
            "en": "English", "es": "Spanish", "fr": "French",
            "de": "German", "it": "Italian", "pt": "Portuguese",
            "ru": "Russian", "zh-cn": "Chinese (Simplified)",
            "zh-tw": "Chinese (Traditional)", "ja": "Japanese",
            "ko": "Korean", "ar": "Arabic", "hi": "Hindi",
            "tr": "Turkish", "nl": "Dutch", "pl": "Polish",
            "sv": "Swedish", "da": "Danish", "fi": "Finnish",
            "no": "Norwegian", "uk": "Ukrainian", "he": "Hebrew",
            "th": "Thai", "vi": "Vietnamese", "id": "Indonesian",
            "ms": "Malay", "tl": "Filipino", "fa": "Persian",
        }

        all_detected: list[dict[str, Any]] = []
        detected_langs: list[str] = []

        for text in texts:
            try:
                lang = _langdetect_detect(text)
                detected_langs.append(lang)
                all_detected.append({"text_snippet": text[:80], "language": lang})
            except Exception as exc:
                log.debug("Language detection failed for a text: %s", exc)
                all_detected.append({"text_snippet": text[:80], "language": "unknown"})

        if not detected_langs:
            return {}

        lang_counter = Counter(detected_langs)
        primary_lang, primary_count = lang_counter.most_common(1)[0]
        confidence = round(primary_count / len(detected_langs), 2)

        return {
            "language": primary_lang,
            "language_name": lang_names.get(primary_lang, primary_lang),
            "region": lang_to_region.get(primary_lang, "Unknown"),
            "confidence": confidence,
            "all_detected": all_detected,
        }

    def extract_entities_nlp(
        self,
        text: str,
    ) -> list[dict[str, Any]]:
        """Extract named entities from text using NLP.

        Args:
            text: Input text.

        Returns:
            List of entity dicts with ``type``, ``value``, ``start``,
            ``end`` keys (empty if required library is missing).
        """
        if not HAS_SPACY:
            log.warning("spacy is not installed — returning empty list")
            return []

        if not text or not text.strip():
            return []

        try:
            if not hasattr(MetadataExtractor, "_nlp") or MetadataExtractor._nlp is None:
                MetadataExtractor._nlp = spacy.load("en_core_web_sm")

            doc = MetadataExtractor._nlp(text)
            entities: list[dict[str, Any]] = []
            for ent in doc.ents:
                entities.append({
                    "type": ent.label_,
                    "value": ent.text,
                    "start": ent.start_char,
                    "end": ent.end_char,
                })
            return entities
        except Exception as exc:
            log.error("spaCy NER extraction failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Internal: Pillow-based EXIF extraction
    # ------------------------------------------------------------------

    def _extract_exif_pillow(
        self, image_data: bytes, bundle: MetadataBundle
    ) -> MetadataBundle:
        """Extract EXIF using Pillow (PIL)."""
        try:
            img = Image.open(io.BytesIO(image_data))
            bundle.dimensions = {"width": img.width, "height": img.height}

            exif_raw = img._getexif()
            if not exif_raw:
                log.info("No EXIF data found in image")
                return bundle

            exif_decoded: dict[str, Any] = {}
            for tag_id, value in exif_raw.items():
                tag_name = PILLOW_TAGS.get(tag_id, str(tag_id))
                # Skip binary blobs
                if isinstance(value, bytes) and len(value) > 256:
                    continue
                exif_decoded[tag_name] = value

            bundle.exif = exif_decoded

            # Camera info
            bundle.camera = {
                "make": exif_decoded.get("Make", ""),
                "model": exif_decoded.get("Model", ""),
                "lens": exif_decoded.get("LensModel", ""),
            }
            bundle.software = str(exif_decoded.get("Software", ""))

            # Timestamps
            ts: dict[str, str] = {}
            if "DateTimeOriginal" in exif_decoded:
                ts["original"] = str(exif_decoded["DateTimeOriginal"])
            if "DateTime" in exif_decoded:
                ts["modified"] = str(exif_decoded["DateTime"])
            if "DateTimeDigitized" in exif_decoded:
                ts["digitized"] = str(exif_decoded["DateTimeDigitized"])
            bundle.timestamps = ts

            # GPS
            gps_info = exif_decoded.get("GPSInfo")
            if gps_info and isinstance(gps_info, dict):
                bundle.geo = self._parse_gps_pillow(gps_info)

        except Exception as exc:
            log.error("Pillow EXIF extraction failed: %s", exc)

        return bundle

    @staticmethod
    def _parse_gps_pillow(gps_info: dict) -> dict[str, Any]:
        """Parse Pillow GPSInfo dict into lat/lon floats."""
        geo: dict[str, Any] = {}
        try:
            # Decode GPS tag names
            decoded: dict[str, Any] = {}
            for key, val in gps_info.items():
                tag_name = PILLOW_GPSTAGS.get(key, str(key))
                decoded[tag_name] = val

            def _to_degrees(values) -> float:
                """Convert GPS coordinate tuple to decimal degrees."""
                d = float(values[0])
                m = float(values[1])
                s = float(values[2])
                return d + m / 60.0 + s / 3600.0

            if "GPSLatitude" in decoded and "GPSLatitudeRef" in decoded:
                lat = _to_degrees(decoded["GPSLatitude"])
                if decoded["GPSLatitudeRef"] == "S":
                    lat = -lat
                geo["lat"] = lat

            if "GPSLongitude" in decoded and "GPSLongitudeRef" in decoded:
                lon = _to_degrees(decoded["GPSLongitude"])
                if decoded["GPSLongitudeRef"] == "W":
                    lon = -lon
                geo["lon"] = lon

            if "GPSAltitude" in decoded:
                alt = float(decoded["GPSAltitude"])
                ref = decoded.get("GPSAltitudeRef", 0)
                if ref == 1:
                    alt = -alt
                geo["altitude"] = alt

            if "GPSTimeStamp" in decoded:
                ts = decoded["GPSTimeStamp"]
                geo["gps_time"] = f"{int(ts[0]):02d}:{int(ts[1]):02d}:{int(ts[2]):02d}"

            if "GPSDateStamp" in decoded:
                geo["gps_date"] = str(decoded["GPSDateStamp"])

        except Exception as exc:
            log.error("GPS parsing failed: %s", exc)

        return geo

    # ------------------------------------------------------------------
    # Internal: exifread-based EXIF extraction
    # ------------------------------------------------------------------

    def _extract_exif_exifread(
        self, image_data: bytes, bundle: MetadataBundle
    ) -> MetadataBundle:
        """Extract EXIF using the exifread library."""
        try:
            import exifread as _exifread

            tags = _exifread.process_file(io.BytesIO(image_data), details=False)
            if not tags:
                log.info("No EXIF data found in image (exifread)")
                return bundle

            exif_decoded: dict[str, str] = {
                k: str(v) for k, v in tags.items()
                if not k.startswith("Thumbnail")
            }
            bundle.exif = exif_decoded

            # Camera
            bundle.camera = {
                "make": exif_decoded.get("Image Make", ""),
                "model": exif_decoded.get("Image Model", ""),
                "lens": exif_decoded.get("EXIF LensModel", ""),
            }
            bundle.software = exif_decoded.get("Image Software", "")

            # Timestamps
            ts: dict[str, str] = {}
            if "EXIF DateTimeOriginal" in exif_decoded:
                ts["original"] = exif_decoded["EXIF DateTimeOriginal"]
            if "Image DateTime" in exif_decoded:
                ts["modified"] = exif_decoded["Image DateTime"]
            bundle.timestamps = ts

            # GPS
            lat_tag = tags.get("GPS GPSLatitude")
            lat_ref = tags.get("GPS GPSLatitudeRef")
            lon_tag = tags.get("GPS GPSLongitude")
            lon_ref = tags.get("GPS GPSLongitudeRef")

            if lat_tag and lat_ref and lon_tag and lon_ref:
                lat = self._exifread_to_degrees(lat_tag.values)
                if str(lat_ref) == "S":
                    lat = -lat
                lon = self._exifread_to_degrees(lon_tag.values)
                if str(lon_ref) == "W":
                    lon = -lon
                bundle.geo = {"lat": lat, "lon": lon}

        except Exception as exc:
            log.error("exifread EXIF extraction failed: %s", exc)

        return bundle

    @staticmethod
    def _exifread_to_degrees(values) -> float:
        """Convert exifread Ratio values to decimal degrees."""
        d = float(values[0].num) / float(values[0].den)
        m = float(values[1].num) / float(values[1].den)
        s = float(values[2].num) / float(values[2].den)
        return d + m / 60.0 + s / 3600.0
