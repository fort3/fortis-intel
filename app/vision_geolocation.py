"""Vision-based geolocation for Fortis Intelligence Hub.

Uses DeepSeek Vision to extract location clues from images and video
keyframes — architecture, signage, vegetation, terrain, road markings,
cultural markers — then geocodes them via GeoClient.

Two-pass analysis:
  Pass 1 (Observation): Exhaustive visual clue extraction with geolocation methodology
  Pass 2 (Synthesis): Location hypothesis generation from extracted clues

Works without EXIF data. Designed as a fallback/complement to EXIF and
OCR pipelines, producing geo_points with source="vision_geolocation".
"""

import json
import logging
import os
import re
from typing import Any

log = logging.getLogger(__name__)

VISION_GEO_TWO_PASS = os.getenv("VISION_GEO_TWO_PASS", "true").lower() in ("1", "true", "yes")
VISION_GEO_REFINE = os.getenv("VISION_GEO_REFINE", "true").lower() in ("1", "true", "yes")
VISION_GEO_REFINE_THRESHOLD = float(os.getenv("VISION_GEO_REFINE_THRESHOLD", "0.3"))

# ---------------------------------------------------------------------------
# Pass 1: Exhaustive observation — teach the model HOW to geolocate
# ---------------------------------------------------------------------------
_OBSERVE_PROMPT = """You are an expert geolocation analyst trained in GeoGuessr methodology, Bellingcat verification techniques, and OSINT tradecraft. Your task is to exhaustively catalogue every visual clue in this image that could help determine its geographic location.

Examine EVERY pixel. Report what you SEE, not what you guess. Use this systematic checklist:

**TEXT & SIGNAGE** (highest value — transcribe EXACTLY, note language/script):
- Street signs, road names, highway route numbers, distance markers
- Store names, brands, advertisements, billboards
- License plates (format, colour, characters visible)
- Government signs, regulatory notices, public information boards
- Graffiti, stickers, posters (language, content)
- Digital displays, timestamps, phone numbers (country code)

**ROAD INFRASTRUCTURE** (very diagnostic):
- Driving side (LEFT or RIGHT — check vehicle positions, road markings)
- Road surface (asphalt quality, concrete, dirt, cobblestone)
- Lane markings: white vs yellow centre lines, dashed vs solid, style
- Traffic signs: shape (octagon/triangle/diamond/rectangle), colours, pictograms
- Traffic lights: vertical vs horizontal, LED vs bulb, pole style
- Bollards: shape, colour, material (each country has distinctive bollards)
- Pedestrian crossings: zebra style, signals, button type
- Road barriers, guardrails: W-beam vs cable vs concrete, post colour

**ARCHITECTURE & BUILT ENVIRONMENT**:
- Building materials: brick colour, stone type, stucco, wood, concrete
- Roof style: flat, pitched, tile colour (red/grey/blue), thatch, corrugated
- Window style: size, shutters, double-glazing, air conditioning units
- Electrical: power line type (wood poles, concrete, steel lattice), wire count
- Utility poles: material, transformer style, insulators
- Street lights: style (cobra head, lantern, modern LED, sodium vapour)
- Postal infrastructure: mailbox style, colour
- Fire hydrants: colour, style (varies dramatically by country)

**VEHICLES & TRANSPORT**:
- Car makes/models (some brands dominate certain regions)
- Bus/tram types, livery, transit system branding
- Motorcycle/scooter prevalence, types
- Commercial vehicle types, delivery company logos

**NATURAL ENVIRONMENT**:
- Vegetation: tree species, palm types, conifer vs broadleaf, seasonal state
- Terrain: flat, rolling, mountainous, coastal, desert
- Soil colour: red laterite, black, grey, sandy
- Sky: sun angle (estimate latitude from shadow length), cloud patterns
- Season indicators: leaf state, snow, rain, flowering plants

**CULTURAL MARKERS**:
- Clothing styles, head coverings, uniforms
- Commercial chains (McDonald's menu style varies by country)
- Currency symbols on price tags
- Flags, national symbols
- Religious buildings: mosque, church, temple, synagogue (architectural style)
- Waste bins, benches, urban furniture style

**CAMERA & META CLUES**:
- Google Street View artifacts: car type, camera rig, blur patterns
- Dashboard camera angle
- Watermarks, photographer credits
- Image quality suggesting specific camera phone models

For EACH clue you find, rate its diagnostic value:
- DECISIVE: Uniquely identifies a specific location (readable address, recognisable landmark)
- STRONG: Narrows to a specific country or small region (distinctive sign system, language)
- MODERATE: Narrows to a continent or climate zone (vegetation, architecture style)
- WEAK: Provides context but is common across many regions

Respond in this JSON format (no markdown fences):
{
  "text_found": [
    {"text": "exact transcription", "type": "sign/license/store/etc", "language": "detected language", "diagnostic_value": "DECISIVE/STRONG/MODERATE/WEAK"}
  ],
  "infrastructure": {
    "driving_side": "left/right/unknown",
    "road_markings": "description",
    "sign_system": "description of traffic sign style",
    "bollard_style": "description or null",
    "power_lines": "description or null",
    "street_lights": "description or null"
  },
  "architecture": {
    "building_style": "description",
    "roof_type": "description",
    "materials": "description"
  },
  "environment": {
    "vegetation": "description",
    "terrain": "description",
    "climate_indicators": "description",
    "season": "estimated season or null"
  },
  "vehicles": "description of vehicles visible or null",
  "cultural_markers": "description or null",
  "camera_clues": "description or null",
  "all_clues_summary": ["list of ALL diagnostic clues found, ordered by diagnostic value"]
}"""

# ---------------------------------------------------------------------------
# Pass 2: Synthesise location hypotheses from observations
# ---------------------------------------------------------------------------
_SYNTHESIZE_PROMPT_TEMPLATE = """You are an expert geolocation analyst. Based on these visual observations from an image, determine the most likely geographic location(s).

OBSERVED CLUES:
{observations}

METHODOLOGY:
1. Start with the highest-diagnostic-value clues (text, signs, license plates)
2. Cross-reference infrastructure clues (driving side, sign system, road markings) to narrow the country
3. Use architectural and environmental clues to narrow the region
4. Estimate approximate coordinates if you can identify a specific area

For each candidate location, explain your reasoning chain — which specific clues support it and which clues could contradict it.

If you recognise a specific landmark, building, intersection, or place: name it precisely and estimate its coordinates.

If you can only narrow to a country or region: provide the most likely specific city or area within that region.

IMPORTANT: Do not guess randomly. Only propose locations supported by multiple corroborating clues. Rate your confidence honestly:
- 0.9+: Readable address, recognisable landmark, or multiple decisive clues
- 0.7-0.9: Strong clues (language + sign system + architecture all consistent)
- 0.5-0.7: Moderate clues (consistent pattern but could match multiple locations)
- 0.3-0.5: Weak inference (general region based on vegetation/climate only)
- <0.3: Very uncertain, limited clues

Respond in this JSON format (no markdown fences):
{{
  "locations": [
    {{
      "name": "specific place, city, or region",
      "country": "country name",
      "region": "state/province/region or null",
      "confidence": 0.0 to 1.0,
      "reasoning": "which clues support this and why",
      "contradicting_clues": "any clues that don't fit this hypothesis, or null"
    }}
  ],
  "coordinates_estimated": [
    {{"lat": 0.0, "lon": 0.0, "label": "what this point represents", "confidence": 0.0 to 1.0}}
  ],
  "country_narrowing": {{
    "most_likely": "country name",
    "alternatives": ["other possible countries"],
    "ruling_out": "countries/regions ruled out by the clues and why"
  }},
  "driving_side": "left or right or unknown",
  "language_detected": "language(s) visible or null",
  "climate_zone": "tropical/subtropical/temperate/arid/continental/polar or null",
  "urbanization": "urban/suburban/rural/wilderness",
  "key_clues": ["the most diagnostic clues that drove the location determination"]
}}"""

# ---------------------------------------------------------------------------
# Pass 3 (optional): Refinement — re-examine image to confirm/refute
# ---------------------------------------------------------------------------
_REFINEMENT_PROMPT_TEMPLATE = """You are an expert geolocation analyst performing a REFINEMENT pass. A previous analysis of this image produced the following location hypothesis:

TOP HYPOTHESIS: {top_location} (confidence: {top_confidence})
Reasoning: {top_reasoning}
Contradicting clues: {contradicting}

Other candidates considered: {alternatives}

Your task: Look at the image AGAIN with fresh eyes, specifically searching for evidence that CONFIRMS or REFUTES the top hypothesis. Focus on:

1. **Re-examine text**: Look harder at any text, signs, or license plates you may have missed. Can you read partial text more clearly now? Any small print, watermarks, or distant signs?
2. **Infrastructure details**: Look at bollard shapes, guardrail styles, traffic light orientation, road surface texture — these are highly country-specific. Do they match {top_country}?
3. **Regional specifics for {top_country}**: What features would you EXPECT to see in {top_location} that ARE or ARE NOT present?
4. **Alternative hypothesis check**: Could the clues better match any of these alternatives: {alternatives}? What specific evidence favors one over the other?
5. **Coordinate refinement**: If the location is correct, can you narrow it further? Specific neighborhood, intersection, or landmark?

IMPORTANT: Be a skeptical verifier. Don't just confirm — actively try to find evidence against the hypothesis. If you find contradicting evidence, adjust the location and confidence accordingly.

Respond in this JSON format (no markdown fences):
{{
  "confirmed": true or false,
  "refined_location": {{
    "name": "refined place name (more specific if possible)",
    "country": "country",
    "region": "state/province/region or null",
    "confidence": 0.0 to 1.0,
    "reasoning": "what evidence confirms or changes the location"
  }},
  "new_evidence": ["list of new clues found in this pass that were missed before"],
  "contradicting_evidence": ["evidence found against the original hypothesis, or empty list"],
  "coordinates_refined": [
    {{"lat": 0.0, "lon": 0.0, "label": "refined estimate", "confidence": 0.0 to 1.0}}
  ],
  "confidence_adjustment": "higher/lower/same — explain why",
  "key_clues": ["combined list of strongest clues from both passes"]
}}"""

# ---------------------------------------------------------------------------
# Single-pass prompt (fallback / fast mode)
# ---------------------------------------------------------------------------
_SINGLE_PASS_PROMPT = """You are an expert geolocation analyst trained in GeoGuessr methodology and Bellingcat OSINT verification. Identify the geographic location in this image using ONLY visual clues.

Use this systematic approach:
1. **Text first**: Read ALL visible text — signs, license plates, store names, ads. Transcribe exactly. Identify the language and script.
2. **Driving side**: Determine if vehicles drive on the left or right.
3. **Sign system**: Identify traffic sign shapes, colours, and style (these are country-specific).
4. **Infrastructure**: Road markings (white/yellow, dashed/solid), bollard style, power lines, street lights.
5. **Architecture**: Building materials, roof types, window styles.
6. **Vegetation & terrain**: Plant species, landscape, soil colour, climate indicators.
7. **Vehicles & culture**: Car brands, clothing, commercial chains, flags.

Cross-reference ALL clues to narrow the location. If you recognise a specific landmark or place, name it precisely and estimate coordinates.

Rate confidence honestly:
- 0.9+: Readable address or recognisable landmark
- 0.7-0.9: Multiple strong clues all pointing to same location
- 0.5-0.7: Consistent pattern but could match multiple locations
- <0.5: Uncertain, limited clues

Respond in this JSON format (no markdown fences):
{
  "locations": [
    {
      "name": "specific place, city, or region name",
      "country": "country name or null",
      "region": "state/province/region or null",
      "confidence": 0.0 to 1.0,
      "reasoning": "which visual clues support this location"
    }
  ],
  "coordinates_estimated": [
    {"lat": 0.0, "lon": 0.0, "label": "description", "confidence": 0.0 to 1.0}
  ],
  "driving_side": "left or right or unknown",
  "language_detected": "language(s) visible on signs/text or null",
  "climate_zone": "tropical/subtropical/temperate/arid/continental/polar or null",
  "urbanization": "urban/suburban/rural/wilderness",
  "key_clues": ["the most diagnostic visual clues found"]
}

If you cannot determine any location, return {"locations": [], "coordinates_estimated": [], "key_clues": ["reason why"]}.
Be specific — prefer "Osaka, Japan" over "East Asia". Include ALL candidate locations ranked by confidence."""


def extract_geo_clues(
    image_bytes: bytes,
    filename: str | None = None,
    context: str | None = None,
    reverse_search_context: str | None = None,
) -> dict[str, Any]:
    """Extract geolocation clues from an image using DeepSeek Vision.

    Args:
        image_bytes: Raw image bytes.
        filename: Optional filename for logging.
        context: Additional context about the image source.
        reverse_search_context: Results from reverse image search
            that can help narrow the location.

    Returns a dict with ``clues`` (parsed JSON from the model),
    ``geo_points`` (geocoded locations ready for the map), and metadata.
    """
    from app.image_deepseek_vision import DEEPSEEK_VISION_ENABLED, _call_vision

    if not DEEPSEEK_VISION_ENABLED:
        return {"enabled": False, "clues": None, "geo_points": []}

    log.info(
        "Vision geolocation analysis%s",
        f" ({filename})" if filename else "",
    )

    if VISION_GEO_TWO_PASS:
        return _two_pass_analysis(image_bytes, filename, context, reverse_search_context)

    return _single_pass_analysis(image_bytes, filename, context, reverse_search_context)


def _single_pass_analysis(
    image_bytes: bytes,
    filename: str | None,
    context: str | None,
    reverse_search_context: str | None,
) -> dict[str, Any]:
    """Single-pass geolocation analysis."""
    from app.image_deepseek_vision import _call_vision

    prompt = _SINGLE_PASS_PROMPT
    if context:
        prompt += f"\n\nImage context: {context}"
    if reverse_search_context:
        prompt += f"\n\nReverse image search found these related results (use to help narrow location): {reverse_search_context}"

    raw = _call_vision(image_bytes, prompt, detail="high", max_tokens=1200)
    if not raw:
        return {"enabled": True, "clues": None, "geo_points": [], "error": "Vision API returned no response"}

    clues = _parse_clues(raw)
    geo_points = _geocode_clues(clues)

    return {
        "enabled": True,
        "clues": clues,
        "geo_points": geo_points,
        "raw_response": raw,
        "method": "single_pass",
    }


def _two_pass_analysis(
    image_bytes: bytes,
    filename: str | None,
    context: str | None,
    reverse_search_context: str | None,
) -> dict[str, Any]:
    """Two-pass analysis: observe then synthesize."""
    from app.image_deepseek_vision import _call_vision

    # Pass 1: Exhaustive observation
    observe_prompt = _OBSERVE_PROMPT
    if context:
        observe_prompt += f"\n\nImage context: {context}"

    log.info("Vision geo pass 1: observation")
    obs_raw = _call_vision(image_bytes, observe_prompt, detail="high", max_tokens=1200)
    if not obs_raw:
        return {"enabled": True, "clues": None, "geo_points": [], "error": "Vision API observation pass failed"}

    observations = _parse_observations(obs_raw)

    # Build observation summary for pass 2
    obs_summary = _summarize_observations(observations, obs_raw)
    if reverse_search_context:
        obs_summary += f"\n\nReverse image search context: {reverse_search_context}"

    # Pass 2: Synthesize location hypotheses (text-only, no image needed)
    synth_prompt = _SYNTHESIZE_PROMPT_TEMPLATE.format(observations=obs_summary)

    log.info("Vision geo pass 2: synthesis")
    synth_raw = _call_vision(image_bytes, synth_prompt, detail="low", max_tokens=1024)
    if not synth_raw:
        # Fall back to single-pass result from observations
        clues = _observations_to_clues(observations)
        geo_points = _geocode_clues(clues)
        return {
            "enabled": True,
            "clues": clues,
            "geo_points": geo_points,
            "observations": observations,
            "raw_response": obs_raw,
            "method": "two_pass_partial",
        }

    clues = _parse_clues(synth_raw)

    # Pass 3 (optional): Refinement — re-examine image to confirm/refute
    if VISION_GEO_REFINE:
        locations = clues.get("locations", [])
        top = locations[0] if locations else None
        if top and isinstance(top.get("confidence"), (int, float)):
            top_conf = float(top["confidence"])
            if VISION_GEO_REFINE_THRESHOLD <= top_conf < 0.90:
                refined = _refinement_pass(image_bytes, clues)
                if refined:
                    clues = _merge_refinement(clues, refined)

    geo_points = _geocode_clues(clues)

    return {
        "enabled": True,
        "clues": clues,
        "geo_points": geo_points,
        "observations": observations,
        "raw_observation": obs_raw,
        "raw_synthesis": synth_raw,
        "method": "two_pass_refined" if clues.get("_refined") else "two_pass",
    }


def _refinement_pass(
    image_bytes: bytes,
    clues: dict[str, Any],
) -> dict[str, Any] | None:
    """Pass 3: Re-examine the image to confirm or refute the top hypothesis."""
    from app.image_deepseek_vision import _call_vision

    locations = clues.get("locations", [])
    if not locations:
        return None

    top = locations[0]
    top_name = top.get("name", "unknown")
    top_country = top.get("country", "unknown")
    top_conf = top.get("confidence", 0.5)
    top_reasoning = top.get("reasoning", "")
    contradicting = top.get("contradicting_clues") or "none noted"

    alternatives = "; ".join(
        f"{loc.get('name', '?')}, {loc.get('country', '?')} (conf={loc.get('confidence', '?')})"
        for loc in locations[1:4]
    ) or "none"

    prompt = _REFINEMENT_PROMPT_TEMPLATE.format(
        top_location=top_name,
        top_confidence=top_conf,
        top_reasoning=top_reasoning,
        contradicting=contradicting,
        top_country=top_country,
        alternatives=alternatives,
    )

    log.info("Vision geo pass 3: refinement for '%s, %s'", top_name, top_country)
    raw = _call_vision(image_bytes, prompt, detail="high", max_tokens=1024)
    if not raw:
        log.debug("Refinement pass returned no response")
        return None

    parsed = _parse_clues(raw)
    if not parsed or parsed.get("locations"):
        return parsed

    return parsed


def _merge_refinement(
    clues: dict[str, Any],
    refined: dict[str, Any],
) -> dict[str, Any]:
    """Merge refinement pass results into the existing clues."""
    clues["_refined"] = True
    clues["refinement"] = refined

    ref_loc = refined.get("refined_location")
    if ref_loc and ref_loc.get("name"):
        ref_conf = ref_loc.get("confidence")
        if isinstance(ref_conf, (int, float)):
            existing_locations = clues.get("locations", [])

            if refined.get("confirmed", True):
                if existing_locations:
                    existing_locations[0]["name"] = ref_loc["name"]
                    existing_locations[0]["confidence"] = max(
                        existing_locations[0].get("confidence", 0),
                        float(ref_conf),
                    )
                    if ref_loc.get("region"):
                        existing_locations[0]["region"] = ref_loc["region"]
                    existing_locations[0]["reasoning"] = (
                        existing_locations[0].get("reasoning", "")
                        + " | Refined: " + ref_loc.get("reasoning", "")
                    )
            else:
                new_loc = {
                    "name": ref_loc["name"],
                    "country": ref_loc.get("country"),
                    "region": ref_loc.get("region"),
                    "confidence": float(ref_conf),
                    "reasoning": ref_loc.get("reasoning", "Refinement pass correction"),
                }
                existing_locations.insert(0, new_loc)
                if len(existing_locations) > 1:
                    existing_locations[1]["confidence"] = min(
                        existing_locations[1].get("confidence", 0.5),
                        float(ref_conf) * 0.7,
                    )
            clues["locations"] = existing_locations

    ref_coords = refined.get("coordinates_refined", [])
    if ref_coords:
        existing_coords = clues.get("coordinates_estimated", [])
        for rc in ref_coords:
            if rc.get("lat") is not None and rc.get("lon") is not None:
                existing_coords.insert(0, rc)
        clues["coordinates_estimated"] = existing_coords

    new_evidence = refined.get("new_evidence", [])
    if new_evidence:
        existing_clues = clues.get("key_clues", [])
        existing_clues.extend(new_evidence)
        clues["key_clues"] = existing_clues

    ref_key_clues = refined.get("key_clues", [])
    if ref_key_clues and not new_evidence:
        existing_clues = clues.get("key_clues", [])
        for kc in ref_key_clues:
            if kc not in existing_clues:
                existing_clues.append(kc)
        clues["key_clues"] = existing_clues

    return clues


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


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

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


def _parse_observations(raw: str) -> dict[str, Any]:
    """Parse the observation pass JSON."""
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

    return {"all_clues_summary": [raw[:500]], "parse_failed": True}


def _summarize_observations(observations: dict[str, Any], raw: str) -> str:
    """Build a text summary of observations for the synthesis pass."""
    if observations.get("parse_failed"):
        return raw[:1500]

    parts = []

    text_found = observations.get("text_found", [])
    if text_found:
        parts.append("VISIBLE TEXT:")
        for t in text_found:
            parts.append(f'  - "{t.get("text", "")}" ({t.get("type", "")}, '
                         f'language: {t.get("language", "?")}, '
                         f'value: {t.get("diagnostic_value", "?")})')

    infra = observations.get("infrastructure", {})
    if infra:
        parts.append(f"\nINFRASTRUCTURE:")
        parts.append(f"  Driving side: {infra.get('driving_side', '?')}")
        if infra.get("road_markings"):
            parts.append(f"  Road markings: {infra['road_markings']}")
        if infra.get("sign_system"):
            parts.append(f"  Sign system: {infra['sign_system']}")
        if infra.get("bollard_style"):
            parts.append(f"  Bollards: {infra['bollard_style']}")
        if infra.get("power_lines"):
            parts.append(f"  Power lines: {infra['power_lines']}")
        if infra.get("street_lights"):
            parts.append(f"  Street lights: {infra['street_lights']}")

    arch = observations.get("architecture", {})
    if arch:
        parts.append(f"\nARCHITECTURE:")
        if arch.get("building_style"):
            parts.append(f"  Style: {arch['building_style']}")
        if arch.get("roof_type"):
            parts.append(f"  Roofs: {arch['roof_type']}")
        if arch.get("materials"):
            parts.append(f"  Materials: {arch['materials']}")

    env = observations.get("environment", {})
    if env:
        parts.append(f"\nENVIRONMENT:")
        if env.get("vegetation"):
            parts.append(f"  Vegetation: {env['vegetation']}")
        if env.get("terrain"):
            parts.append(f"  Terrain: {env['terrain']}")
        if env.get("climate_indicators"):
            parts.append(f"  Climate: {env['climate_indicators']}")

    if observations.get("vehicles"):
        parts.append(f"\nVEHICLES: {observations['vehicles']}")
    if observations.get("cultural_markers"):
        parts.append(f"\nCULTURAL: {observations['cultural_markers']}")
    if observations.get("camera_clues"):
        parts.append(f"\nCAMERA: {observations['camera_clues']}")

    summary = observations.get("all_clues_summary", [])
    if summary:
        parts.append(f"\nALL CLUES (by diagnostic value): {', '.join(str(c) for c in summary)}")

    return "\n".join(parts) if parts else raw[:1500]


def _observations_to_clues(observations: dict[str, Any]) -> dict[str, Any]:
    """Convert observation-format data to clues-format for geocoding fallback."""
    locations = []

    text_found = observations.get("text_found", [])
    for t in text_found:
        if t.get("diagnostic_value") in ("DECISIVE", "STRONG") and t.get("text"):
            locations.append({
                "name": t["text"],
                "country": None,
                "region": None,
                "confidence": 0.5 if t["diagnostic_value"] == "STRONG" else 0.7,
                "reasoning": f"{t.get('type', 'text')} clue: {t['text']}",
            })

    return {
        "locations": locations[:5],
        "coordinates_estimated": [],
        "driving_side": observations.get("infrastructure", {}).get("driving_side", "unknown"),
        "key_clues": observations.get("all_clues_summary", [])[:10],
    }


def _extract_locations_from_text(text: str) -> dict[str, Any]:
    """Fallback: extract location names from free-text response."""
    locations = []

    patterns = [
        re.compile(r'\b(?:located in|appears to be in|likely|possibly|probably)\s+'
                   r'(?:in\s+)?([A-Z][a-z]+(?:[\s-][A-Z][a-z]+)*)', re.IGNORECASE),
        re.compile(r'\b(?:this is|looks like|resembles)\s+'
                   r'([A-Z][a-z]+(?:[\s-][A-Z][a-z]+)*)', re.IGNORECASE),
        re.compile(r'\b([A-Z][a-z]+(?:[\s-][A-Z][a-z]+)*),\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b'),
    ]

    seen = set()
    for pattern in patterns:
        for m in pattern.finditer(text):
            name = m.group(1).strip()
            country = m.group(2).strip() if m.lastindex and m.lastindex >= 2 else None
            if len(name) < 3 or name.lower() in ("the", "this", "that", "these", "those", "image", "photo"):
                continue
            if name.lower() in seen:
                continue
            seen.add(name.lower())
            locations.append({
                "name": name,
                "country": country,
                "region": None,
                "confidence": 0.3,
                "reasoning": "Extracted from unstructured text",
            })

    return {
        "locations": locations[:5],
        "coordinates_estimated": [],
        "key_clues": ["Response was unstructured text — locations extracted via regex"],
    }


# ---------------------------------------------------------------------------
# Geocoding
# ---------------------------------------------------------------------------

def _geocode_clues(clues: dict[str, Any]) -> list[dict[str, Any]]:
    """Geocode parsed location clues into geo_point dicts."""
    geo_points: list[dict[str, Any]] = []

    # Handle both "coordinates_mentioned" and "coordinates_estimated" keys
    coords = clues.get("coordinates_estimated", clues.get("coordinates_mentioned", []))
    for coord in coords:
        lat = coord.get("lat")
        lon = coord.get("lon")
        if lat is not None and lon is not None:
            try:
                lat, lon = float(lat), float(lon)
                if -90 <= lat <= 90 and -180 <= lon <= 180:
                    coord_conf = coord.get("confidence", 0.6)
                    if not isinstance(coord_conf, (int, float)):
                        coord_conf = 0.6
                    geo_points.append({
                        "lat": lat,
                        "lon": lon,
                        "source": "vision_geolocation",
                        "confidence": round(min(0.85, max(0.3, float(coord_conf))), 2),
                        "label": coord.get("label", "Vision coordinate estimate"),
                        "method": "vision_coordinate_estimate",
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

        # Build geocoding query — most specific to least specific
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
            if result is None and len(query_parts) > 1:
                # Try without region (name + country)
                fallback_query = f"{name}, {country}" if country else name
                result = geo.geocode(fallback_query)
            if result is None:
                continue

            model_conf = loc.get("confidence", 0.4)
            if not isinstance(model_conf, (int, float)):
                model_conf = 0.4
            # Scale confidence: trust the model more for high-confidence calls
            final_conf = min(0.90, max(0.20, float(model_conf) * 0.90))

            geo_points.append({
                "lat": result.lat,
                "lon": result.lon,
                "source": "vision_geolocation",
                "confidence": round(final_conf, 2),
                "label": result.label or query,
                "method": "vision_clue_geocode",
                "vision_reasoning": loc.get("reasoning", ""),
                "vision_confidence": model_conf,
                "contradicting_clues": loc.get("contradicting_clues"),
            })
        except Exception as exc:
            log.debug("Geocoding failed for '%s': %s", query, exc)

    return geo_points
