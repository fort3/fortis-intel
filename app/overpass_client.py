"""Overpass API client for spatial context in vision geolocation.

Queries OpenStreetMap via the Overpass API to retrieve nearby features
(streets, POIs, landmarks, administrative boundaries) around a coordinate
estimate. Returns structured spatial context that can be fed back to the
vision model to refine its geolocation hypothesis.

Free, no API key needed. Uses public Overpass endpoints with polite
rate limiting.
"""

import logging
import os
import time
from typing import Any

log = logging.getLogger(__name__)

OVERPASS_ENABLED = os.getenv("OVERPASS_ENABLED", "true").lower() in ("1", "true", "yes")
OVERPASS_URL = os.getenv(
    "OVERPASS_URL",
    "https://overpass-api.de/api/interpreter",
)
OVERPASS_TIMEOUT = int(os.getenv("OVERPASS_TIMEOUT", "10"))
OVERPASS_RADIUS_M = int(os.getenv("OVERPASS_RADIUS_M", "500"))

_last_request_time = 0.0
_MIN_INTERVAL = 1.5


def _rate_limit():
    """Enforce minimum interval between Overpass requests."""
    global _last_request_time
    now = time.time()
    elapsed = now - _last_request_time
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_request_time = time.time()


def query_nearby_features(
    lat: float,
    lon: float,
    radius_m: int | None = None,
) -> dict[str, Any]:
    """Query OSM for features near a coordinate.

    Returns a structured dict with streets, POIs, admin boundaries,
    and other features found within the radius.
    """
    if not OVERPASS_ENABLED:
        return {"enabled": False}

    radius = radius_m or OVERPASS_RADIUS_M

    query = f"""
[out:json][timeout:{OVERPASS_TIMEOUT}];
(
  // Streets and roads within radius
  way["highway"](around:{radius},{lat},{lon});
  // Named places/buildings
  node["name"](around:{radius},{lat},{lon});
  way["name"]["building"](around:{radius},{lat},{lon});
  // Amenities
  node["amenity"](around:{radius},{lat},{lon});
  // Shops
  node["shop"](around:{radius},{lat},{lon});
  // Tourism
  node["tourism"](around:{radius},{lat},{lon});
  // Religious buildings
  node["amenity"="place_of_worship"](around:{radius},{lat},{lon});
  way["amenity"="place_of_worship"](around:{radius},{lat},{lon});
);
out tags center 50;
"""

    try:
        import requests
        _rate_limit()
        resp = requests.post(
            OVERPASS_URL,
            data={"data": query},
            timeout=OVERPASS_TIMEOUT + 5,
            headers={"User-Agent": "Fortis-Intelligence-Hub/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
    except ImportError:
        log.warning("requests not installed — Overpass API disabled")
        return {"enabled": True, "available": False, "error": "requests not installed"}
    except Exception as exc:
        log.warning("Overpass API query failed: %s", exc)
        return {"enabled": True, "available": True, "error": str(exc)}

    elements = data.get("elements", [])
    if not elements:
        return {
            "enabled": True,
            "available": True,
            "features_found": 0,
            "context": f"No OSM features found within {radius}m of ({lat:.4f}, {lon:.4f})",
        }

    return _parse_overpass_results(elements, lat, lon, radius)


def query_admin_area(lat: float, lon: float) -> dict[str, Any]:
    """Query OSM for the administrative area containing a coordinate.

    Returns country, state/province, city, and neighborhood.
    """
    if not OVERPASS_ENABLED:
        return {"enabled": False}

    query = f"""
[out:json][timeout:{OVERPASS_TIMEOUT}];
is_in({lat},{lon})->.a;
area.a["admin_level"];
out tags;
"""

    try:
        import requests
        _rate_limit()
        resp = requests.post(
            OVERPASS_URL,
            data={"data": query},
            timeout=OVERPASS_TIMEOUT + 5,
            headers={"User-Agent": "Fortis-Intelligence-Hub/1.0"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        log.warning("Overpass admin area query failed: %s", exc)
        return {"enabled": True, "error": str(exc)}

    elements = data.get("elements", [])
    if not elements:
        return {
            "enabled": True,
            "admin_areas": [],
            "context": f"No admin areas found for ({lat:.4f}, {lon:.4f})",
        }

    areas = []
    for el in elements:
        tags = el.get("tags", {})
        name = tags.get("name", tags.get("name:en", ""))
        admin_level = tags.get("admin_level", "")
        area_type = _admin_level_label(admin_level)
        if name:
            areas.append({
                "name": name,
                "admin_level": admin_level,
                "type": area_type,
                "name_en": tags.get("name:en", name),
            })

    areas.sort(key=lambda a: int(a["admin_level"]) if a["admin_level"].isdigit() else 99)

    context_parts = []
    for a in areas:
        context_parts.append(f"{a['type']}: {a['name_en']}")

    return {
        "enabled": True,
        "admin_areas": areas,
        "context": ", ".join(context_parts) if context_parts else "No admin data",
    }


def build_spatial_context(
    lat: float,
    lon: float,
    radius_m: int | None = None,
) -> str:
    """Build a text summary of spatial context for the vision model.

    Combines nearby features and admin area data into a structured
    string the model can use to verify/refine its location estimate.
    """
    if not OVERPASS_ENABLED:
        return ""

    parts = [f"SPATIAL CONTEXT from OpenStreetMap near ({lat:.4f}, {lon:.4f}):"]

    admin = query_admin_area(lat, lon)
    if admin.get("admin_areas"):
        parts.append(f"\nAdministrative area: {admin['context']}")

    features = query_nearby_features(lat, lon, radius_m)
    if features.get("streets"):
        street_names = [s["name"] for s in features["streets"][:8]]
        parts.append(f"\nNearby streets: {', '.join(street_names)}")

    if features.get("landmarks"):
        for lm in features["landmarks"][:5]:
            parts.append(f"  Landmark: {lm['name']} ({lm.get('type', 'unknown')})")

    if features.get("amenities"):
        amenity_list = [f"{a['name']} ({a.get('type', '')})" for a in features["amenities"][:8]]
        parts.append(f"\nNearby amenities: {', '.join(amenity_list)}")

    if features.get("shops"):
        shop_list = [f"{s['name']} ({s.get('type', '')})" for s in features["shops"][:5]]
        parts.append(f"Shops: {', '.join(shop_list)}")

    if features.get("religious"):
        for r in features["religious"][:3]:
            parts.append(f"  Religious: {r['name']} ({r.get('religion', 'unknown')})")

    parts.append(f"\nTotal features found: {features.get('features_found', 0)} within {radius_m or OVERPASS_RADIUS_M}m")

    if len(parts) <= 2:
        return ""

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _parse_overpass_results(
    elements: list[dict],
    lat: float,
    lon: float,
    radius: int,
) -> dict[str, Any]:
    """Parse Overpass API elements into categorised features."""
    streets = []
    landmarks = []
    amenities = []
    shops = []
    religious = []
    other_named = []

    seen_names: set[str] = set()

    for el in elements:
        tags = el.get("tags", {})
        name = tags.get("name", tags.get("name:en", ""))

        if tags.get("highway") and not name:
            continue

        if name and name.lower() in seen_names:
            continue
        if name:
            seen_names.add(name.lower())

        if tags.get("highway"):
            hw_type = tags["highway"]
            if hw_type in ("residential", "tertiary", "secondary", "primary",
                           "trunk", "motorway", "unclassified", "living_street",
                           "pedestrian", "service"):
                streets.append({
                    "name": name or f"unnamed {hw_type}",
                    "type": hw_type,
                    "ref": tags.get("ref", ""),
                })

        elif tags.get("tourism"):
            landmarks.append({
                "name": name,
                "type": tags["tourism"],
                "description": tags.get("description", ""),
            })

        elif tags.get("amenity") == "place_of_worship":
            religious.append({
                "name": name,
                "religion": tags.get("religion", ""),
                "denomination": tags.get("denomination", ""),
            })

        elif tags.get("amenity"):
            amenities.append({
                "name": name,
                "type": tags["amenity"],
                "cuisine": tags.get("cuisine", ""),
                "brand": tags.get("brand", ""),
            })

        elif tags.get("shop"):
            shops.append({
                "name": name,
                "type": tags["shop"],
                "brand": tags.get("brand", ""),
            })

        elif tags.get("building") and name:
            landmarks.append({
                "name": name,
                "type": f"building ({tags.get('building', 'yes')})",
            })

        elif name:
            other_named.append({
                "name": name,
                "tags": {k: v for k, v in list(tags.items())[:5]},
            })

    total = len(streets) + len(landmarks) + len(amenities) + len(shops) + len(religious)

    context_parts = []
    if streets:
        context_parts.append(f"Streets: {', '.join(s['name'] for s in streets[:5])}")
    if landmarks:
        context_parts.append(f"Landmarks: {', '.join(l['name'] for l in landmarks[:3])}")
    if amenities:
        context_parts.append(f"Amenities: {', '.join(a['name'] for a in amenities[:5])}")
    if religious:
        context_parts.append(f"Religious: {', '.join(r['name'] + ' (' + r.get('religion', '') + ')' for r in religious[:3])}")

    return {
        "enabled": True,
        "available": True,
        "features_found": total,
        "streets": streets[:10],
        "landmarks": landmarks[:5],
        "amenities": amenities[:10],
        "shops": shops[:5],
        "religious": religious[:5],
        "other": other_named[:5],
        "context": "; ".join(context_parts) if context_parts else f"Limited features near ({lat:.4f}, {lon:.4f})",
    }


def _admin_level_label(level: str) -> str:
    """Map OSM admin_level to human-readable type."""
    mapping = {
        "2": "Country",
        "3": "Region/Territory",
        "4": "State/Province",
        "5": "District",
        "6": "County",
        "7": "Municipality",
        "8": "City/Town",
        "9": "Borough/Ward",
        "10": "Neighborhood",
        "11": "Sub-neighborhood",
    }
    return mapping.get(str(level), f"Admin level {level}")
