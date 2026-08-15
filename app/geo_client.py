"""Geolocation client for Fortis Intelligence Hub.

Phase 1: Geocoding, reverse geocoding, IP geolocation, triangulation,
and NLP-based location resolution are now functional.
``build_map_data()`` remains fully functional and produces
Leaflet.js-compatible JSON from provided geo points.
"""

from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import requests

try:
    from geopy.geocoders import Nominatim, GoogleV3
    HAS_GEOPY = True
except ImportError:  # pragma: no cover
    HAS_GEOPY = False

try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:  # pragma: no cover
    HAS_GEOIP2 = False

try:
    from sklearn.cluster import DBSCAN
    HAS_SKLEARN = True
except ImportError:  # pragma: no cover
    HAS_SKLEARN = False

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class GeoDataPoint:
    """A single geolocation data point with provenance metadata."""

    lat: float = 0.0
    lon: float = 0.0
    label: str = ""
    source: str = ""  # exif, geotag, ip, checkin, mention, timezone
    confidence: float = 0.0
    timestamp: str = ""
    radius_m: float | None = None  # Uncertainty radius in metres
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class TriangulationResult:
    """Result of triangulating multiple geo data points."""

    center_lat: float = 0.0
    center_lon: float = 0.0
    radius_m: float = 0.0
    confidence: float = 0.0
    point_count: int = 0
    method: str = ""  # weighted_centroid, dbscan, convex_hull
    cluster_points: list[GeoDataPoint] = field(default_factory=list)
    outliers: list[GeoDataPoint] = field(default_factory=list)
    bounding_box: dict[str, float] = field(default_factory=dict)


@dataclass
class MapData:
    """Leaflet.js-compatible map payload."""

    markers: list[dict[str, Any]] = field(default_factory=list)
    center: list[float] = field(default_factory=lambda: [0.0, 0.0])
    zoom: int = 2
    bounds: list[list[float]] = field(default_factory=list)
    circles: list[dict[str, Any]] = field(default_factory=list)
    polylines: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Source confidence and colour mapping
# ---------------------------------------------------------------------------

_SOURCE_COLORS: dict[str, str] = {
    "exif": "#22c55e",
    "geotag": "#3b82f6",
    "ip": "#f59e0b",
    "checkin": "#8b5cf6",
    "mention": "#ef4444",
    "timezone": "#6b7280",
}

_SOURCE_ICONS: dict[str, str] = {
    "exif": "camera",
    "geotag": "map-pin",
    "ip": "globe",
    "checkin": "map-marker-alt",
    "mention": "comment-dots",
    "timezone": "clock",
}


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class GeoClient:
    """Geolocation utilities: geocoding, triangulation, and map rendering.

    Phase 1: All methods are functional.  Geocoding uses Nominatim
    (with optional Google fallback), IP geolocation uses MaxMind
    GeoLite2 (with ip-api.com fallback), triangulation supports
    weighted-centroid and DBSCAN clustering, and location resolution
    extracts GPE/LOC entities via spaCy NLP before geocoding.
    ``build_map_data`` produces Leaflet.js-compatible JSON.
    """

    def __init__(self):
        self._user_agent = os.getenv("NOMINATIM_USER_AGENT", "Fortis/1.0")
        self._nominatim = None
        self._google_geocoder = None
        self._geoip_reader = None

        if HAS_GEOPY:
            try:
                self._nominatim = Nominatim(user_agent=self._user_agent)
            except Exception as exc:
                log.error("Failed to initialise Nominatim geocoder: %s", exc)

            google_key = os.getenv("GOOGLE_GEOCODING_API_KEY")
            if google_key:
                try:
                    self._google_geocoder = GoogleV3(api_key=google_key)
                except Exception as exc:
                    log.error("Failed to initialise Google geocoder: %s", exc)
        else:
            log.warning("geopy is not installed — geocoding will be unavailable")

        if HAS_GEOIP2:
            db_path = os.getenv("MAXMIND_DB_PATH", "data/GeoLite2-City.mmdb")
            if Path(db_path).is_file():
                try:
                    self._geoip_reader = geoip2.database.Reader(db_path)
                except Exception as exc:
                    log.error("Failed to open MaxMind DB at %s: %s", db_path, exc)
            else:
                log.info("MaxMind DB not found at %s — will use ip-api fallback", db_path)

        log.info("GeoClient initialised (Phase 1)")

    # ------------------------------------------------------------------
    # Geocoding & geolocation
    # ------------------------------------------------------------------

    def geocode(self, location_text: str) -> GeoDataPoint | None:
        """Convert a free-text location to coordinates.

        Uses Nominatim as the primary geocoder. Falls back to Google
        Geocoding API if ``GOOGLE_GEOCODING_API_KEY`` is configured and
        Nominatim fails.

        Args:
            location_text: Human-readable location string.

        Returns:
            A :class:`GeoDataPoint` or ``None`` on failure.
        """
        if not location_text or not location_text.strip():
            return None

        # --- Try Nominatim first ---
        if self._nominatim is not None:
            try:
                location = self._nominatim.geocode(location_text, timeout=10)
                if location is not None:
                    return GeoDataPoint(
                        lat=location.latitude,
                        lon=location.longitude,
                        label=location_text,
                        source="geocoding",
                        confidence=0.8,
                        raw=location.raw if hasattr(location, "raw") else {},
                    )
            except Exception as exc:
                log.warning("Nominatim geocode failed for %r: %s", location_text, exc)

        # --- Fallback to Google ---
        if self._google_geocoder is not None:
            try:
                location = self._google_geocoder.geocode(location_text, timeout=10)
                if location is not None:
                    return GeoDataPoint(
                        lat=location.latitude,
                        lon=location.longitude,
                        label=location_text,
                        source="geocoding",
                        confidence=0.9,
                        raw=location.raw if hasattr(location, "raw") else {},
                    )
            except Exception as exc:
                log.warning("Google geocode failed for %r: %s", location_text, exc)

        log.info("Could not geocode %r with any available provider", location_text)
        return None

    def reverse_geocode(self, lat: float, lon: float) -> dict[str, Any]:
        """Convert coordinates to a human-readable address.

        Uses Nominatim reverse geocoding.

        Args:
            lat: Latitude.
            lon: Longitude.

        Returns:
            Dict with ``address``, ``city``, ``country``, and ``raw`` keys.
            Returns an empty dict on failure.
        """
        if self._nominatim is None:
            log.warning("Nominatim geocoder is not available for reverse geocoding")
            return {}

        try:
            location = self._nominatim.reverse(
                (lat, lon), exactly_one=True, timeout=10, language="en",
            )
            if location is None:
                log.info("Reverse geocode returned no result for (%s, %s)", lat, lon)
                return {}

            raw = location.raw if hasattr(location, "raw") else {}
            address_parts = raw.get("address", {})

            city = (
                address_parts.get("city")
                or address_parts.get("town")
                or address_parts.get("village")
                or address_parts.get("municipality")
                or ""
            )
            country = address_parts.get("country", "")

            return {
                "address": location.address or "",
                "city": city,
                "country": country,
                "raw": raw,
            }
        except Exception as exc:
            log.error("Reverse geocode failed for (%s, %s): %s", lat, lon, exc)
            return {}

    def ip_geolocate(self, ip_address: str) -> GeoDataPoint | None:
        """Geolocate an IP address.

        Uses MaxMind GeoLite2 database if available, otherwise falls back
        to the free ip-api.com JSON endpoint.

        Args:
            ip_address: IPv4 or IPv6 address.

        Returns:
            A :class:`GeoDataPoint` or ``None`` on failure.
        """
        if not ip_address or not ip_address.strip():
            return None

        # --- Try MaxMind GeoIP2 database ---
        if self._geoip_reader is not None:
            try:
                response = self._geoip_reader.city(ip_address)
                lat = response.location.latitude
                lon = response.location.longitude
                if lat is not None and lon is not None:
                    city_name = (
                        response.city.name or ""
                    ) if response.city else ""
                    country_name = (
                        response.country.name or ""
                    ) if response.country else ""
                    label = ", ".join(filter(None, [city_name, country_name])) or ip_address
                    accuracy = response.location.accuracy_radius
                    return GeoDataPoint(
                        lat=lat,
                        lon=lon,
                        label=label,
                        source="ip_geolocation",
                        confidence=0.6,
                        radius_m=float(accuracy * 1000) if accuracy else None,
                        raw={
                            "ip": ip_address,
                            "provider": "maxmind",
                            "city": city_name,
                            "country": country_name,
                            "accuracy_radius_km": accuracy,
                        },
                    )
            except Exception as exc:
                log.warning("MaxMind lookup failed for %r: %s", ip_address, exc)

        # --- Fallback to ip-api.com ---
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=10,
                params={"fields": "status,message,lat,lon,city,country,regionName,isp,query"},
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") == "success":
                lat = data.get("lat", 0.0)
                lon = data.get("lon", 0.0)
                city = data.get("city", "")
                country = data.get("country", "")
                label = ", ".join(filter(None, [city, country])) or ip_address
                return GeoDataPoint(
                    lat=float(lat),
                    lon=float(lon),
                    label=label,
                    source="ip_geolocation",
                    confidence=0.5,
                    raw={
                        "ip": ip_address,
                        "provider": "ip-api",
                        **data,
                    },
                )
            else:
                log.warning(
                    "ip-api.com returned failure for %r: %s",
                    ip_address, data.get("message", "unknown"),
                )
        except Exception as exc:
            log.error("ip-api.com request failed for %r: %s", ip_address, exc)

        return None

    def triangulate(
        self,
        data_points: list[GeoDataPoint],
    ) -> TriangulationResult:
        """Triangulate a probable location from multiple data points.

        Computes a weighted centroid (weighted by confidence). If more than
        five points are provided and scikit-learn is available, DBSCAN
        clustering is applied to identify spatial clusters and outliers.

        Args:
            data_points: Geo data points with varying confidence levels.

        Returns:
            A :class:`TriangulationResult` with centroid, radius, and
            optional cluster information.
        """
        if not data_points:
            return TriangulationResult()

        try:
            # --- Weighted centroid ---
            weights = np.array(
                [max(p.confidence, 0.01) for p in data_points], dtype=float,
            )
            lats = np.array([p.lat for p in data_points], dtype=float)
            lons = np.array([p.lon for p in data_points], dtype=float)

            total_weight = weights.sum()
            center_lat = float(np.dot(weights, lats) / total_weight)
            center_lon = float(np.dot(weights, lons) / total_weight)

            # --- Confidence radius (max distance from centroid to any point) ---
            max_dist_km = 0.0
            for pt in data_points:
                d = self._haversine_km(center_lat, center_lon, pt.lat, pt.lon)
                if d > max_dist_km:
                    max_dist_km = d

            radius_m = max_dist_km * 1000.0
            avg_confidence = float(weights.mean())

            method = "weighted_centroid"
            cluster_points: list[GeoDataPoint] = list(data_points)
            outliers: list[GeoDataPoint] = []

            # --- DBSCAN clustering for >5 points ---
            if len(data_points) > 5 and HAS_SKLEARN:
                try:
                    coords = np.column_stack([lats, lons])
                    # eps=0.01 roughly corresponds to ~1 km at mid-latitudes
                    db = DBSCAN(eps=0.01, min_samples=2, metric="euclidean")
                    labels = db.fit_predict(coords)

                    method = "dbscan"
                    cluster_points = []
                    outliers = []

                    for pt, label in zip(data_points, labels):
                        if label == -1:
                            outliers.append(pt)
                        else:
                            cluster_points.append(pt)

                    # Recompute centroid from largest cluster
                    unique_labels = set(labels) - {-1}
                    if unique_labels:
                        # Find the largest cluster
                        best_label = max(
                            unique_labels,
                            key=lambda lb: int(np.sum(labels == lb)),
                        )
                        mask = labels == best_label
                        cluster_weights = weights[mask]
                        cluster_lats = lats[mask]
                        cluster_lons = lons[mask]
                        cw_total = cluster_weights.sum()
                        center_lat = float(np.dot(cluster_weights, cluster_lats) / cw_total)
                        center_lon = float(np.dot(cluster_weights, cluster_lons) / cw_total)

                        # Recompute radius from cluster points
                        max_dist_km = 0.0
                        for i in range(len(cluster_lats)):
                            d = self._haversine_km(
                                center_lat, center_lon,
                                float(cluster_lats[i]), float(cluster_lons[i]),
                            )
                            if d > max_dist_km:
                                max_dist_km = d
                        radius_m = max_dist_km * 1000.0
                        avg_confidence = float(cluster_weights.mean())

                except Exception as exc:
                    log.warning("DBSCAN clustering failed, using weighted centroid: %s", exc)

            # --- Bounding box ---
            bounding_box = {
                "south": float(lats.min()),
                "north": float(lats.max()),
                "west": float(lons.min()),
                "east": float(lons.max()),
            }

            return TriangulationResult(
                center_lat=center_lat,
                center_lon=center_lon,
                radius_m=radius_m,
                confidence=avg_confidence,
                point_count=len(data_points),
                method=method,
                cluster_points=cluster_points,
                outliers=outliers,
                bounding_box=bounding_box,
            )

        except Exception as exc:
            log.error("Triangulation failed for %d points: %s", len(data_points), exc)
            return TriangulationResult(point_count=len(data_points))

    def resolve_locations(
        self,
        location_mentions: list[str],
    ) -> list[GeoDataPoint]:
        """Batch-resolve free-text location mentions to coordinates.

        Uses :class:`~app.metadata_extractor.MetadataExtractor` NLP to
        extract GPE and LOC entities from each text, deduplicates them,
        and geocodes each unique location string.

        Args:
            location_mentions: List of text strings that may contain
                location references.

        Returns:
            List of :class:`GeoDataPoint` for every successfully geocoded
            location. Returns an empty list on failure.
        """
        if not location_mentions:
            return []

        # --- Extract location entities via NLP ---
        unique_locations: set[str] = set()
        try:
            from app.metadata_extractor import MetadataExtractor
            extractor = MetadataExtractor()

            for text in location_mentions:
                if not text or not text.strip():
                    continue
                try:
                    entities = extractor.extract_entities_nlp(text)
                    for ent in entities:
                        ent_type = ent.get("type", "")
                        ent_value = ent.get("value", "").strip()
                        if ent_type in ("GPE", "LOC") and ent_value:
                            unique_locations.add(ent_value)
                except Exception as exc:
                    log.warning("NLP entity extraction failed for text: %s", exc)
        except ImportError:
            log.warning(
                "MetadataExtractor not available — treating each input "
                "string as a literal location name"
            )
            for text in location_mentions:
                if text and text.strip():
                    unique_locations.add(text.strip())

        if not unique_locations:
            log.info("No location entities found in %d text(s)", len(location_mentions))
            return []

        # --- Geocode each unique location ---
        results: list[GeoDataPoint] = []
        for loc_name in sorted(unique_locations):
            try:
                point = self.geocode(loc_name)
                if point is not None:
                    results.append(point)
            except Exception as exc:
                log.warning("Failed to geocode resolved location %r: %s", loc_name, exc)

        log.info(
            "Resolved %d locations from %d text(s) (%d unique entities)",
            len(results), len(location_mentions), len(unique_locations),
        )
        return results

    # ------------------------------------------------------------------
    # Functional: map data builder
    # ------------------------------------------------------------------

    def build_map_data(
        self,
        geo_points: list[GeoDataPoint],
        triangulation: TriangulationResult | None = None,
    ) -> MapData:
        """Build Leaflet.js-compatible JSON from geo data.

        This method is fully functional in Phase 0.

        Args:
            geo_points: The data points to place on the map.
            triangulation: Optional triangulation result to render as a
                circle overlay.

        Returns:
            A :class:`MapData` instance ready for serialisation to JSON.
        """
        if not geo_points and not triangulation:
            return MapData()

        markers: list[dict[str, Any]] = []
        circles: list[dict[str, Any]] = []
        polylines: list[dict[str, Any]] = []

        lats: list[float] = []
        lons: list[float] = []

        # --- Markers from geo_points ---
        for idx, pt in enumerate(geo_points):
            color = _SOURCE_COLORS.get(pt.source, "#6b7280")
            icon = _SOURCE_ICONS.get(pt.source, "map-marker-alt")

            marker: dict[str, Any] = {
                "id": f"pt-{idx}",
                "position": [pt.lat, pt.lon],
                "popup": (
                    f"<b>{pt.label or 'Point ' + str(idx)}</b><br>"
                    f"Source: {pt.source}<br>"
                    f"Confidence: {pt.confidence:.0%}<br>"
                    f"{pt.timestamp or ''}"
                ),
                "tooltip": pt.label or f"Point {idx}",
                "icon": {
                    "type": "font-awesome",
                    "name": icon,
                    "color": color,
                },
            }
            markers.append(marker)
            lats.append(pt.lat)
            lons.append(pt.lon)

            # If the point has an uncertainty radius, draw a circle
            if pt.radius_m and pt.radius_m > 0:
                circles.append({
                    "center": [pt.lat, pt.lon],
                    "radius": pt.radius_m,
                    "color": color,
                    "fillColor": color,
                    "fillOpacity": 0.12,
                    "weight": 1,
                })

        # --- Triangulation circle overlay ---
        if triangulation and triangulation.center_lat and triangulation.center_lon:
            tri_color = "#ef4444"
            circles.append({
                "center": [triangulation.center_lat, triangulation.center_lon],
                "radius": triangulation.radius_m or 500,
                "color": tri_color,
                "fillColor": tri_color,
                "fillOpacity": 0.08,
                "weight": 2,
                "dashArray": "5 5",
                "popup": (
                    f"<b>Triangulated Location</b><br>"
                    f"Confidence: {triangulation.confidence:.0%}<br>"
                    f"Method: {triangulation.method}<br>"
                    f"Points: {triangulation.point_count}"
                ),
            })
            # Also add a marker at the triangulation centre
            markers.append({
                "id": "triangulation-center",
                "position": [triangulation.center_lat, triangulation.center_lon],
                "popup": (
                    f"<b>Estimated Location</b><br>"
                    f"Method: {triangulation.method}<br>"
                    f"Confidence: {triangulation.confidence:.0%}"
                ),
                "tooltip": "Estimated Location",
                "icon": {
                    "type": "font-awesome",
                    "name": "crosshairs",
                    "color": tri_color,
                },
            })
            lats.append(triangulation.center_lat)
            lons.append(triangulation.center_lon)

        # --- Connect points chronologically via polyline ---
        sorted_points = sorted(
            [p for p in geo_points if p.timestamp],
            key=lambda p: p.timestamp,
        )
        if len(sorted_points) >= 2:
            polylines.append({
                "positions": [[p.lat, p.lon] for p in sorted_points],
                "color": "#6366f1",
                "weight": 2,
                "opacity": 0.6,
                "dashArray": "4 6",
            })

        # --- Compute centre & bounds ---
        if lats and lons:
            center = [sum(lats) / len(lats), sum(lons) / len(lons)]
            sw = [min(lats), min(lons)]
            ne = [max(lats), max(lons)]
            bounds = [sw, ne]
            zoom = self._auto_zoom(sw, ne)
        else:
            center = [0.0, 0.0]
            bounds = []
            zoom = 2

        return MapData(
            markers=markers,
            center=center,
            zoom=zoom,
            bounds=bounds,
            circles=circles,
            polylines=polylines,
            metadata={
                "point_count": len(geo_points),
                "has_triangulation": triangulation is not None,
                "sources": list({p.source for p in geo_points}),
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _auto_zoom(sw: list[float], ne: list[float]) -> int:
        """Estimate a reasonable Leaflet zoom level from bounding box."""
        lat_span = abs(ne[0] - sw[0])
        lon_span = abs(ne[1] - sw[1])
        span = max(lat_span, lon_span, 0.001)

        if span < 0.005:
            return 16
        if span < 0.05:
            return 14
        if span < 0.5:
            return 11
        if span < 5:
            return 8
        if span < 50:
            return 5
        return 3

    @staticmethod
    def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Compute the great-circle distance between two points in km."""
        R = 6371.0  # Earth radius in kilometres
        d_lat = math.radians(lat2 - lat1)
        d_lon = math.radians(lon2 - lon1)
        a = (
            math.sin(d_lat / 2) ** 2
            + math.cos(math.radians(lat1))
            * math.cos(math.radians(lat2))
            * math.sin(d_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c
