"""Vision-based geolocation for Fortis Intelligence Hub.

Uses DeepSeek Vision to extract location clues from images and video
keyframes — architecture, signage, vegetation, terrain, road markings,
cultural markers — then geocodes them via GeoClient.

Works without EXIF data. Designed as a fallback/complement to EXIF and
OCR pipelines, producing geo_points with source="vision_geolocation".
"""

import json
import logging
import re
from typing import Any

log = logging.getLogger(__name__)

_GEO_PROMPT = """You are a geolocation analyst. Your task is to identify the geographic location shown in this image using ONLY visual clues.

Analyse every visible detail:
- **Signs & text**: Language, script, store names, street names, highway markers, license plates — transcribe exactly.
- **Architecture**: Building style, construction materials, roof shapes, window patterns, balcony styles, door types.
- **Road infrastructure**: Road markings (colour, style), traffic signs (shape, colour), traffic lights, road surface, lane markings, pedestrian crossings.
- **Vehicles**: Car makes/models common to specific regions, driving side (left/right), license plate format.
- **Vegetation**: Plant species, tree types, grass, crops, seasonal indicators.
- **Terrain & geography**: Flat/hilly/mountainous, coastal, desert, urban density, soil colour.
- **Utility infrastructure**: Power line style, pole types, street lighting, fire hydrants, post boxes.
- **Cultural markers**: Clothing, flags, commercial brands, chain stores, currency symbols, religious buildings.
- **Sky & weather**: Sun position, cloud patterns, light quality (tropical vs northern).

Respond in this EXACT JSON format (no markdown fences):
{
  "locations": [
    {
      "name": "specific place, city, or region name",
      "country": "country name or null",
      "region": "state/province/region or null",
      "confidence": 0.0 to 1.0,
      "reasoning": "brief explanation of which visual clues support this"
    }
  ],
  "coordinates_mentioned": [
    {"lat": 0.0, "lon": 0.0, "label": "description"}
  ],
  "driving_side": "left or right or unknown",
  "language_detected": "language(s) visible on signs/text or null",
  "climate_zone": "tropical/subtropical/temperate/arid/continental/polar or null",
  "urbanization": "urban/suburban/rural/wilderness",
  "key_clues": ["list of the most diagnostic visual clues found"]
}

If you cannot determine any location, return {"locations": [], "coordinates_mentioned": [], "key_clues": ["reason why location cannot be determined"]}.
Be specific — prefer "Osaka, Japan" over "East Asia". Include ALL candidate locations ranked by confidence."""


def extract_geo_clues(
    image_bytes: bytes,
    filename: str | None = None,
    context: str | None = None,
) -> dict[str, Any]:
    """Extract geolocation clues from an image using DeepSeek Vision.

    Returns a dict with ``clues`` (parsed JSON from the model),
    ``geo_points`` (geocoded locations ready for the map), and metadata.
    """
    from app.image_deepseek_vision import DEEPSEEK_VISION_ENABLED, _call_vision

    if not DEEPSEEK_VISION_ENABLED:
        return {"enabled": False, "clues": None, "geo_points": []}

    prompt = _GEO_PROMPT
    if context:
        prompt += f"\n\nAdditional context about this image: {context}"

    log.info(
        "Vision geolocation analysis%s",
        f" ({filename})" if filename else "",
    )

    raw = _call_vision(image_bytes, prompt, detail="high", max_tokens=1024)
    if not raw:
        return {"enabled": True, "clues": None, "geo_points": [], "error": "Vision API returned no response"}

    clues = _parse_clues(raw)
    geo_points = _geocode_clues(clues)

    return {
        "enabled": True,
        "clues": clues,
        "geo_points": geo_points,
        "raw_response": raw,
    }


def extract_geo_from_frames(
    frames: list[tuple[bytes, int, float]],
    source_url: str = "",
    platform: str = "",
) -> list[dict[str, Any]]:
    """Run vision geolocation on a list of video keyframes.

    Args:
        frames: List of (image_bytes, frame_index, timestamp_sec) tuples.
        source_url: Original video URL for provenance.
        platform: Source platform name.

    Returns:
        List of geo_point dicts.
    """
    from app.image_deepseek_vision import DEEPSEEK_VISION_ENABLED

    if not DEEPSEEK_VISION_ENABLED:
        return []

    all_points: list[dict[str, Any]] = []
    seen: set[str] = set()

    for img_bytes, frame_idx, timestamp in frames[:10]:
        if not img_bytes:
            continue
        try:
            result = extract_geo_clues(
                img_bytes,
                filename=f"frame_{frame_idx}.jpg",
                context=f"Video keyframe at {timestamp:.1f}s" + (f" from {platform}" if platform else ""),
            )
            for gp in result.get("geo_points", []):
                coord_key = f"{gp['lat']:.4f},{gp['lon']:.4f}"
                if coord_key in seen:
                    continue
                seen.add(coord_key)
                gp["media_url"] = source_url
                gp["platform"] = platform
                gp["frame_index"] = frame_idx
                gp["frame_timestamp"] = timestamp
                all_points.append(gp)
        except Exception as exc:
            log.debug("Vision geo failed for frame %d: %s", frame_idx, exc)

    log.info("Vision geolocation: %d points from %d frames", len(all_points), len(frames[:10]))
    return all_points


def _parse_clues(raw: str) -> dict[str, Any]:
    """Parse the structured JSON from the vision model response."""
    cleaned = raw.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{[\s\S]*\}", cleaned)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    log.warning("Could not parse vision geolocation JSON, extracting locations from text")
    return _extract_locations_from_text(raw)


def _extract_locations_from_text(text: str) -> dict[str, Any]:
    """Fallback: extract location names from free-text response."""
    locations = []

    country_pattern = re.compile(
        r'\b(?:located in|appears to be in|suggests?|likely|possibly|probably)\s+'
        r'(?:in\s+)?([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)',
        re.IGNORECASE,
    )
    for m in country_pattern.finditer(text):
        name = m.group(1).strip()
        if len(name) > 2 and name.lower() not in ("the", "this", "that", "these", "those"):
            locations.append({
                "name": name,
                "country": None,
                "region": None,
                "confidence": 0.3,
                "reasoning": "Extracted from unstructured text",
            })

    return {
        "locations": locations[:5],
        "coordinates_mentioned": [],
        "key_clues": ["Response was unstructured text — locations extracted via regex"],
    }


def _geocode_clues(clues: dict[str, Any]) -> list[dict[str, Any]]:
    """Geocode parsed location clues into geo_point dicts."""
    geo_points: list[dict[str, Any]] = []

    for coord in clues.get("coordinates_mentioned", []):
        lat = coord.get("lat")
        lon = coord.get("lon")
        if lat is not None and lon is not None:
            try:
                lat, lon = float(lat), float(lon)
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    geo_points.append({
                        "lat": lat,
                        "lon": lon,
                        "source": "vision_geolocation",
                        "confidence": 0.65,
                        "label": coord.get("label", "Vision coordinate"),
                        "method": "vision_coordinate_mention",
                    })
            except (ValueError, TypeError):
                pass

    locations = clues.get("locations", [])
    if not locations:
        return geo_points

    try:
        from app.geo_client import GeoClient
        geo = GeoClient()
    except Exception as exc:
        log.warning("GeoClient unavailable for vision geocoding: %s", exc)
        return geo_points

    seen: set[str] = set()
    for loc in locations:
        name = loc.get("name", "").strip()
        if not name:
            continue

        country = loc.get("country")
        region = loc.get("region")
        query_parts = [name]
        if region:
            query_parts.append(region)
        if country:
            query_parts.append(country)
        query = ", ".join(query_parts)

        if query.lower() in seen:
            continue
        seen.add(query.lower())

        try:
            result = geo.geocode(query)
            if result is None:
                continue

            model_conf = loc.get("confidence", 0.4)
            if not isinstance(model_conf, (int, float)):
                model_conf = 0.4
            final_conf = min(0.75, max(0.25, model_conf * 0.85))

            geo_points.append({
                "lat": result.lat,
                "lon": result.lon,
                "source": "vision_geolocation",
                "confidence": round(final_conf, 2),
                "label": result.label or query,
                "method": "vision_clue_geocode",
                "vision_reasoning": loc.get("reasoning", ""),
                "vision_confidence": model_conf,
            })
        except Exception as exc:
            log.debug("Geocoding failed for '%s': %s", query, exc)

    return geo_points
