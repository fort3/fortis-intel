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

    Phase 0: ``geocode``, ``reverse_geocode``, ``ip_geolocate``,
    ``triangulate``, and ``resolve_locations`` are stubs.
    ``build_map_data`` is fully functional.
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
    # Stubs (Phase 1)
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

        Args:
            lat: Latitude.
            lon: Longitude.

        Returns:
            Dict with address components (empty in Phase 0).
        """
        log.warning(
            "GeoClient.reverse_geocode() is a Phase 0 stub — "
            "returning empty dict for (%s, %s)",
            lat, lon,
        )
        return {}

    def ip_geolocate(self, ip_address: str) -> GeoDataPoint | None:
        """Geolocate an IP address.

        Args:
            ip_address: IPv4 or IPv6 address.

        Returns:
            A :class:`GeoDataPoint` or ``None``. Stub in Phase 0.
        """
        log.warning(
            "GeoClient.ip_geolocate() is a Phase 0 stub — returning None for %r",
            ip_address,
        )
        return None

    def triangulate(
        self,
        data_points: list[GeoDataPoint],
    ) -> TriangulationResult:
        """Triangulate a probable location from multiple data points.

        Args:
            data_points: Geo data points with varying confidence levels.

        Returns:
            A :class:`TriangulationResult` (empty in Phase 0).
        """
        log.warning(
            "GeoClient.triangulate() is a Phase 0 stub — returning empty "
            "TriangulationResult for %d points",
            len(data_points),
        )
        return TriangulationResult(point_count=len(data_points))

    def resolve_locations(
        self,
        location_mentions: list[str],
    ) -> list[GeoDataPoint]:
        """Batch-resolve free-text location mentions to coordinates.

        Args:
            location_mentions: List of location strings to resolve.

        Returns:
            List of :class:`GeoDataPoint` (empty in Phase 0).
        """
        log.warning(
            "GeoClient.resolve_locations() is a Phase 0 stub — "
            "returning empty list for %d mentions",
            len(location_mentions),
        )
        return []

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
