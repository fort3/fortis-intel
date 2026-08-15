# Fortis Intelligence Hub — Routes & API Design

## Overview

Flask routes follow the TIPS Hub pattern: `create_app()` factory with all routes
defined inside. Single-mode operation (no CTI/Red Team toggle) simplifies the
routing layer.

---

## Route Table

### Core Analysis Routes

| Route                    | Method | Purpose                                  | Auth     |
|--------------------------|--------|------------------------------------------|----------|
| `/`                      | GET    | Serve main SPA (`index.html`)            | Required |
| `/upload`                | POST   | PDF/MD ingestion → vectorstore           | Required |
| `/ask`                   | POST   | RAG Q&A against uploaded document        | Required |
| `/investigate`           | POST   | Full OSINT investigation on a subject    | Required |
| `/triangulate`           | POST   | Geolocation triangulation                | Required |
| `/batch-investigate`     | POST   | Multi-entity batch investigation         | Required |
| `/enrich`                | POST   | OSINT enrichment of uploaded document    | Required |
| `/scenario`              | POST   | Intelligence scenario generation         | Required |

### Feed Monitor Routes

| Route                    | Method | Purpose                                  | Auth     |
|--------------------------|--------|------------------------------------------|----------|
| `/monitor/create`        | POST   | Create a new feed monitor                | Required |
| `/monitor/<id>/pause`    | POST   | Pause an active monitor                  | Required |
| `/monitor/<id>/resume`   | POST   | Resume a paused monitor                  | Required |
| `/monitor/<id>/delete`   | DELETE | Delete a monitor                         | Required |
| `/monitor/list`          | GET    | List all monitors (active + paused)      | Required |
| `/monitor/watch`         | GET    | List pending findings for review         | Required |
| `/monitor/<id>/approve`  | POST   | Approve a finding → save to KB           | Required |
| `/monitor/<id>/dismiss`  | POST   | Dismiss a finding (reason required)      | Required |

### Export Routes

| Route                    | Method | Purpose                                  | Auth     |
|--------------------------|--------|------------------------------------------|----------|
| `/export/pdf`            | POST   | Generate PDF report                      | Required |
| `/export/markdown`       | POST   | Generate Markdown report                 | Required |
| `/export/stix`           | POST   | STIX 2.1 entity export                   | Required |
| `/export/csv`            | POST   | CSV entity export                        | Required |
| `/export/json`           | POST   | JSON entity/finding export               | Required |
| `/export/drive/<format>` | POST   | Upload export to Google Drive            | Required |
| `/export/map-snapshot`   | POST   | Save map PNG (from frontend capture)     | Required |

### Knowledge Base Routes

| Route                    | Method | Purpose                                  | Auth     |
|--------------------------|--------|------------------------------------------|----------|
| `/kb/reports`            | GET    | List KB reports (paginated)              | Required |
| `/kb/reports/<id>`       | GET    | Get specific report                      | Required |
| `/kb/reports/<id>`       | DELETE | Delete specific report                   | Required |
| `/kb/reports/<id>/toggle`| POST   | Toggle report in/out of KB               | Required |
| `/kb/stats`              | GET    | KB statistics                            | Required |
| `/kb/rebuild`            | POST   | Force KB rebuild from ReportStore        | Required |

### ForgeChain Routes

| Route                        | Method | Purpose                              | Auth     |
|------------------------------|--------|--------------------------------------|----------|
| `/forge/session/<id>/replay` | GET    | Forensic session replay              | Required |
| `/forge/session/<id>/verify` | GET    | Chain integrity verification         | Required |
| `/forge/health`              | GET    | ForgeChain health statistics         | Required |

### Auth Routes

| Route                    | Method | Purpose                                  | Auth     |
|--------------------------|--------|------------------------------------------|----------|
| `/oauth/login`           | GET    | Initiate Google OAuth flow               | None     |
| `/oauth/callback`        | GET    | OAuth callback handler                   | None     |
| `/logout`                | POST   | Session teardown                         | Required |
| `/me`                    | GET    | Current user info                        | Required |

### Utility Routes

| Route                    | Method | Purpose                                  | Auth     |
|--------------------------|--------|------------------------------------------|----------|
| `/gdrive-status`         | GET    | Google Drive configuration check         | Required |
| `/osint-status`          | GET    | OSINT source availability check          | Required |

---

## Request/Response Formats

### POST `/investigate`

**Request:**
```json
{
  "identifier": "@username_or_email_or_domain",
  "identifier_type": "username",
  "platforms": ["twitter", "reddit", "instagram"],
  "depth": "standard",
  "focus_areas": ["geolocation", "connections"],
  "investigation_purpose": "Background check for vendor due diligence"
}
```

**Response:**
```json
{
  "success": true,
  "analysis": "## Executive Summary\n...",
  "sensitivity_level": "INTERNAL",
  "map_data": { ... },
  "entity_graph": { ... },
  "charts": {
    "platform_distribution": "data:image/png;base64,...",
    "activity_timeline": "data:image/png;base64,..."
  },
  "osint_summary": {
    "platforms_queried": ["twitter", "reddit", "instagram"],
    "profiles_found": 2,
    "posts_analyzed": 47,
    "geo_points": 5,
    "entity_count": 12
  },
  "report_id": "abc123def456",
  "forge_block_id": "blk_789"
}
```

### POST `/triangulate`

**Request:**
```json
{
  "data_points": [
    {
      "type": "image",
      "data": "base64_encoded_image_data",
      "filename": "photo.jpg"
    },
    {
      "type": "social_post",
      "platform": "twitter",
      "url": "https://twitter.com/user/status/123",
      "content": "Great view from the café!",
      "geotag": {"lat": 48.8566, "lon": 2.3522}
    },
    {
      "type": "ip_address",
      "value": "203.0.113.42"
    },
    {
      "type": "manual_location",
      "address": "Eiffel Tower, Paris",
      "coordinates": {"lat": 48.8584, "lon": 2.2945}
    }
  ],
  "subject_context": "Subject is believed to be traveling in Europe",
  "investigation_purpose": "Location verification for asset tracking"
}
```

**Response:**
```json
{
  "success": true,
  "analysis": "## Location Assessment\n...",
  "triangulation": {
    "primary_location": {
      "lat": 48.8570,
      "lon": 2.3200,
      "address": "Paris, France",
      "confidence": 0.82,
      "confidence_label": "HIGH",
      "radius_km": 1.8
    },
    "alternate_locations": [],
    "data_point_count": 4,
    "cluster_count": 1
  },
  "map_data": { ... },
  "report_id": "geo123abc",
  "forge_block_id": "blk_456"
}
```

### POST `/batch-investigate`

**Request:**
```json
{
  "identifiers": ["@user1", "@user2", "user3@email.com", "example.com"],
  "identifier_type": "auto",
  "platforms": ["twitter", "reddit"],
  "investigation_purpose": "Network mapping for competitor analysis"
}
```

Or file upload (CSV/XLSX) via multipart form data.

**Response:**
```json
{
  "success": true,
  "synthesis": "## Batch Investigation Summary\n...",
  "per_entity_results": [
    {
      "identifier": "@user1",
      "status": "completed",
      "summary": "...",
      "geo_data": { ... },
      "entity_count": 8
    }
  ],
  "aggregate_map_data": { ... },
  "entity_graph": { ... },
  "charts": { ... },
  "report_id": "batch789",
  "sensitivity_level": "RESTRICTED"
}
```

### POST `/enrich`

**Request:**
```json
{
  "session_id": "abc123_uploaded_report",
  "enrich_types": ["entities", "geolocation", "social"],
  "platforms": ["twitter", "reddit"],
  "investigation_purpose": "Enriching field report with digital corroboration"
}
```

**Response:**
```json
{
  "success": true,
  "enrichment_analysis": "## Enrichment Summary\n...",
  "entities_found": 15,
  "entities_enriched": 9,
  "map_data": { ... },
  "entity_graph": { ... },
  "report_id": "enr456",
  "sensitivity_level": "INTERNAL"
}
```

### POST `/monitor/create`

**Request:**
```json
{
  "monitor_type": "keyword",
  "query": "subject name OR @handle",
  "platforms": ["twitter", "reddit", "telegram"],
  "interval_minutes": 15,
  "alert_threshold": "high_confidence"
}
```

**Response:**
```json
{
  "success": true,
  "monitor_id": "mon_abc123",
  "status": "active",
  "next_poll": "2026-08-15T10:15:00Z"
}
```

---

## Rate Limiting

| Route Group                  | Limit           | Window   |
|------------------------------|-----------------|----------|
| `/investigate`               | 20/hour         | Per user |
| `/triangulate`               | 30/hour         | Per user |
| `/batch-investigate`         | 5/hour          | Per user |
| `/enrich`                    | 15/hour         | Per user |
| `/ask`                       | 60/hour         | Per user |
| `/scenario`                  | 20/hour         | Per user |
| `/monitor/create`            | 10/hour         | Per user |
| `/monitor/watch`             | 120/hour        | Per user |
| `/export/*`                  | 30/hour         | Per user |
| `/kb/*`                      | 60/hour         | Per user |
| `/forge/*`                   | 30/hour         | Per user |

---

## Security Middleware

Carried over from TIPS Hub:

- **CORS** via flask-cors (configurable origins)
- **Rate limiting** via flask-limiter (Redis or in-memory backend)
- **CSP headers**: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://*.basemaps.cartocdn.com https://*.tile.openstreetmap.org; connect-src 'self'`
- **HSTS**: `max-age=31536000; includeSubDomains`
- **X-Content-Type-Options**: `nosniff`
- **X-Frame-Options**: `DENY`
- **Session cookie**: `HttpOnly`, `Secure`, `SameSite=Lax`

### OSINT-Specific Security

- **SSRF protection**: Whitelist for allowed external API domains
- **Image upload validation**: Magic byte verification, size limits (20MB per image)
- **Identifier sanitization**: Strip/normalize identifiers before API queries
- **No raw API keys in responses**: API credentials never appear in frontend responses
