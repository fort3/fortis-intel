# Fortis Intelligence Hub — Map & Geospatial Feature Design

## Overview

The map feature is a first-class component of Fortis, not an add-on. Every
investigation that produces geolocation data renders an interactive map in
the results panel. The map supports triangulation visualization, heatmaps,
temporal playback, and PNG snapshot export.

---

## Technology Stack

| Component           | Library / Service              | Purpose                           |
|---------------------|--------------------------------|-----------------------------------|
| Map rendering       | Leaflet.js 1.9+               | Interactive map in browser        |
| Tile provider       | CartoDB Dark Matter            | Dark-themed map tiles             |
| Fallback tiles      | Stadia Alidade Smooth Dark     | Backup tile provider              |
| Heatmap layer       | Leaflet.heat                   | Density visualization             |
| Marker clustering   | Leaflet.markercluster          | Cluster dense marker groups       |
| Geocoding           | Nominatim (OpenStreetMap)      | Text → coordinates                |
| Reverse geocoding   | Nominatim                      | Coordinates → address             |
| IP geolocation      | MaxMind GeoLite2 (local DB)    | IP → coordinates (offline)        |
| IP geolocation (fb) | ipapi.co                       | IP → coordinates (API fallback)   |
| Map snapshot        | leaflet-image or html2canvas   | Export map as PNG                  |
| Timeline slider     | Leaflet.TimeDimension          | Temporal data playback            |

---

## Map Tile Configuration

### Primary: CartoDB Dark Matter

```
https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png
```

- Dark background matches Fortis theme
- Free for most usage tiers
- Good global coverage

### Satellite Toggle

```
https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}
```

- Toggle between dark street map and satellite imagery
- Useful for confirming location context (buildings, terrain)

---

## Map Marker Design

### Custom SVG Markers (Theme-consistent)

```svg
<!-- Primary location marker (pulsing) -->
<svg width="24" height="24" viewBox="0 0 24 24">
  <circle cx="12" cy="12" r="8" fill="#9b59b6" opacity="0.3">
    <animate attributeName="r" values="8;12;8" dur="2s" repeatCount="indefinite"/>
  </circle>
  <circle cx="12" cy="12" r="5" fill="#9b59b6" stroke="#d946ef" stroke-width="2"/>
</svg>

<!-- Data point marker (static) -->
<svg width="16" height="16" viewBox="0 0 16 16">
  <circle cx="8" cy="8" r="6" fill="#bb6bd9" stroke="#2a2a3d" stroke-width="1.5"/>
</svg>

<!-- Inferred location marker (dashed border) -->
<svg width="16" height="16" viewBox="0 0 16 16">
  <circle cx="8" cy="8" r="6" fill="none" stroke="#9b59b6" stroke-width="1.5" 
          stroke-dasharray="3,2"/>
  <circle cx="8" cy="8" r="3" fill="#9b59b640"/>
</svg>
```

### Marker Types by Source

| Source        | Shape     | Color     | Style                    |
|---------------|-----------|-----------|--------------------------|
| EXIF GPS      | Circle    | `#22c55e` | Solid (high confidence)  |
| Social geotag | Circle    | `#9b59b6` | Solid                    |
| IP geolocation| Diamond   | `#f59e0b` | Solid (lower confidence) |
| Check-in      | Circle    | `#8b5cf6` | Solid                    |
| Text mention  | Triangle  | `#bb6bd9` | Dashed (inferred)        |
| Timezone inf. | Square    | `#6b3fa0` | Dashed (inferred)        |
| Triangulated  | Star/Pulse| `#d946ef` | Pulsing animation        |

---

## Triangulation Visualization

When `geo_client.triangulate()` produces results, the map renders:

### 1. Source Points

All contributing data points as markers (colored by source type).

### 2. Connection Lines

Dashed purple lines from each source point to the triangulated center:

```javascript
L.polyline([sourcePoint, triangulatedCenter], {
    color: '#d946ef',
    weight: 1.5,
    dashArray: '6, 4',
    opacity: 0.6
});
```

### 3. Confidence Radius

Circle around the triangulated point showing the confidence radius:

```javascript
L.circle(triangulatedCenter, {
    radius: radiusMeters,
    color: '#9b59b6',
    fillColor: '#9b59b6',
    fillOpacity: 0.1,
    weight: 2,
    dashArray: '8, 6'
});
```

### 4. Confidence Label

Popup on the triangulated point showing:
- Assessed address/location name
- Confidence score (HIGH/MODERATE/LOW/SPECULATIVE)
- Radius in km
- Number of contributing data points
- Timestamp of most recent data point

---

## Heatmap Layer

For investigations with many location data points (batch or monitoring):

```javascript
L.heatLayer(points, {
    radius: 25,
    blur: 15,
    maxZoom: 12,
    gradient: {
        0.0: '#1a1a28',     // transparent dark
        0.3: '#2d1f4e',     // subtle purple
        0.5: '#6b3fa0',     // medium purple
        0.7: '#9b59b6',     // bright purple
        0.9: '#d946ef',     // neon purple
        1.0: '#f0abfc'      // hot pink-purple
    }
});
```

---

## Timeline Playback

For data with timestamps, a slider appears below the map:

```
┌─────────────────────────────────────────────────┐
│                    MAP                          │
├─────────────────────────────────────────────────┤
│ ◄ ▶ ║─────●──────────────────────────────║  ►► │
│  Jan 15    Feb 02                    Aug 12     │
│  2026       2026                      2026     │
└─────────────────────────────────────────────────┘
```

- Scrubbing the slider shows/hides markers by timestamp
- Play button animates through time
- Speed control: 1x, 2x, 5x, 10x
- Shows which markers are "active" at the current time position

---

## Map Controls

### Layer Control (top-right)

```
☑ Data Points
☑ Triangulation
☑ Confidence Radius
☑ Connections
☐ Heatmap
☐ Satellite
```

### Action Buttons (top-left, below zoom)

```
[⛶] Fullscreen toggle
[📷] Export map as PNG
[⊙] Center on triangulated location
[↺] Reset view to fit all markers
```

---

## Map Data API Format

The backend returns map data as a structured JSON object:

```json
{
  "map_data": {
    "center": [38.8977, -77.0365],
    "zoom": 12,
    "bounds": [[38.85, -77.10], [38.95, -76.97]],
    
    "markers": [
      {
        "id": "geo_001",
        "lat": 38.8977,
        "lon": -77.0365,
        "source": "social_geotag",
        "source_detail": "Twitter",
        "confidence": 0.85,
        "point_type": "exact",
        "timestamp": "2026-08-10T14:32:00Z",
        "label": "@username tweet geotag",
        "popup_html": "<b>Twitter Geotag</b><br>Conf: 85%<br>Aug 10, 2026"
      }
    ],
    
    "triangulation": {
      "center": [38.9002, -77.0350],
      "radius_km": 2.3,
      "confidence": 0.72,
      "confidence_label": "MODERATE",
      "address": "Washington, DC, USA",
      "source_count": 5,
      "connections": [
        {"from": [38.8977, -77.0365], "to": [38.9002, -77.0350]},
        {"from": [38.9050, -77.0290], "to": [38.9002, -77.0350]}
      ]
    },
    
    "heatmap_points": [
      [38.8977, -77.0365, 0.85],
      [38.9050, -77.0290, 0.6]
    ],
    
    "timeline": {
      "enabled": true,
      "start": "2026-01-15T00:00:00Z",
      "end": "2026-08-12T23:59:59Z",
      "points": [
        {"lat": 38.8977, "lon": -77.0365, "time": "2026-08-10T14:32:00Z"}
      ]
    }
  }
}
```

---

## Server-Side Map for PDF Export

PDF export cannot embed interactive maps. Instead:

1. The frontend captures the current map view as a PNG via `leaflet-image` or
   `html2canvas`
2. The PNG is sent to the backend as base64
3. `export.py` embeds the map snapshot in the PDF alongside charts

Alternatively, server-side static map generation via `staticmap` Python library:

```python
from staticmap import StaticMap, CircleMarker, Line

def generate_map_image(geo_points, triangulation, width=800, height=500):
    m = StaticMap(width, height, url_template='https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}.png')
    
    for point in geo_points:
        color = '#9b59b6'  # theme purple
        m.add_marker(CircleMarker((point.lon, point.lat), color, 8))
    
    if triangulation:
        m.add_marker(CircleMarker(
            (triangulation.lon, triangulation.lat), '#d946ef', 12
        ))
    
    image = m.render()
    return image  # PIL Image, can be saved as PNG
```

---

## Geocoding Strategy

### Priority Order

1. **Nominatim (OpenStreetMap)** — Free, no API key required
   - Rate limit: 1 request/second
   - Good global coverage
   - Self-hostable for higher throughput

2. **Google Geocoding API** — Fallback for ambiguous locations
   - Higher accuracy for informal place names
   - Requires API key and billing
   - Used only when Nominatim returns no/low-confidence results

### Caching

- All geocoding results cached in Redis (`fortis:cache:geocode:<hash>`, 24h TTL)
- Cache key: SHA-256 of normalized query string
- Prevents redundant API calls for repeated location references

### Ambiguity Resolution

For ambiguous locations (e.g., "Springfield"):
1. Return all candidates with confidence scores
2. If subject has known locations, prefer nearby candidates
3. If context provides country/state, filter accordingly
4. Present ambiguous results to the analyst with "Did you mean?" in the UI
