# Fortis Intelligence Hub — Database & Storage Schema

## Overview

Fortis uses the same storage architecture as TIPS Hub: SQLite for structured data,
FAISS for vector similarity search, and Redis for ephemeral task/monitor state.
The schema is adapted for OSINT entities, geospatial data, and investigation records.

---

## SQLite: Report Store (`data/report_store.db`)

### Table: `analysis_reports`

Mirrors TIPS Hub's report store with OSINT-specific fields.

```sql
CREATE TABLE analysis_reports (
    report_id           TEXT PRIMARY KEY,
    source_route        TEXT NOT NULL,       -- /investigate, /triangulate, /batch, /ask, /enrich
    report_type         TEXT NOT NULL,       -- investigation, enrichment, triangulation, batch, rag, monitor
    subject_identifier  TEXT,                -- primary subject (username, email, domain, etc.)
    identifier_type     TEXT,                -- username, email, phone, domain, name, keyword
    analysis_text       TEXT NOT NULL,
    sensitivity_level   TEXT DEFAULT 'INTERNAL',  -- PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL
    platforms_queried   TEXT,                -- JSON array of platforms used
    geo_data            TEXT,                -- JSON: primary location, confidence, radius
    entity_count        INTEGER DEFAULT 0,
    source_count        INTEGER DEFAULT 0,  -- number of OSINT sources that contributed
    created_at          TEXT NOT NULL,
    created_by          TEXT,                -- hashed user email
    in_knowledge_base   INTEGER DEFAULT 0,
    kb_chunk_count      INTEGER DEFAULT 0,
    monitor_record_id   TEXT,               -- FK to monitor record if auto-generated
    tags                TEXT                 -- JSON array of analyst-assigned tags
);

CREATE INDEX idx_reports_created_at ON analysis_reports(created_at DESC);
CREATE INDEX idx_reports_type ON analysis_reports(report_type);
CREATE INDEX idx_reports_in_kb ON analysis_reports(in_knowledge_base);
CREATE INDEX idx_reports_subject ON analysis_reports(subject_identifier);
CREATE INDEX idx_reports_sensitivity ON analysis_reports(sensitivity_level);
```

### Table: `investigation_subjects`

Track subjects across investigations for cross-referencing.

```sql
CREATE TABLE investigation_subjects (
    subject_id          TEXT PRIMARY KEY,
    identifier          TEXT NOT NULL,
    identifier_type     TEXT NOT NULL,
    first_seen          TEXT NOT NULL,
    last_investigated   TEXT NOT NULL,
    investigation_count INTEGER DEFAULT 1,
    known_aliases       TEXT,               -- JSON array
    known_platforms     TEXT,               -- JSON array
    last_known_location TEXT,               -- JSON: {lat, lon, address, confidence, as_of}
    notes               TEXT,
    created_by          TEXT
);

CREATE INDEX idx_subjects_identifier ON investigation_subjects(identifier);
CREATE INDEX idx_subjects_type ON investigation_subjects(identifier_type);
```

### Table: `geo_data_points`

Persistent geolocation data points for historical analysis.

```sql
CREATE TABLE geo_data_points (
    point_id            TEXT PRIMARY KEY,
    investigation_id    TEXT NOT NULL,       -- FK to analysis_reports.report_id
    subject_identifier  TEXT,
    latitude            REAL NOT NULL,
    longitude           REAL NOT NULL,
    source              TEXT NOT NULL,       -- exif, geotag, ip, checkin, mention, timezone
    source_detail       TEXT,               -- platform name or file name
    confidence          REAL NOT NULL,       -- 0.0 - 1.0
    point_type          TEXT NOT NULL,       -- exact, approximate, inferred
    timestamp           TEXT,               -- when the data point was generated (not collected)
    collected_at        TEXT NOT NULL,       -- when we collected it
    raw_metadata        TEXT                -- JSON: source-specific metadata
);

CREATE INDEX idx_geo_investigation ON geo_data_points(investigation_id);
CREATE INDEX idx_geo_subject ON geo_data_points(subject_identifier);
CREATE INDEX idx_geo_coords ON geo_data_points(latitude, longitude);
CREATE INDEX idx_geo_timestamp ON geo_data_points(timestamp);
```

### Table: `entity_relationships`

Cross-investigation entity relationships for the knowledge graph.

```sql
CREATE TABLE entity_relationships (
    relationship_id     TEXT PRIMARY KEY,
    source_entity       TEXT NOT NULL,       -- identifier or subject_id
    source_type         TEXT NOT NULL,       -- person, organization, location, account, domain
    target_entity       TEXT NOT NULL,
    target_type         TEXT NOT NULL,
    relationship_type   TEXT NOT NULL,       -- associated_with, located_at, posted_from, 
                                            -- linked_to, mentioned_by, alias_of, member_of
    confidence          REAL DEFAULT 0.5,
    evidence_source     TEXT,               -- investigation_id or "manual"
    first_observed      TEXT NOT NULL,
    last_observed       TEXT NOT NULL,
    observation_count   INTEGER DEFAULT 1
);

CREATE INDEX idx_rel_source ON entity_relationships(source_entity);
CREATE INDEX idx_rel_target ON entity_relationships(target_entity);
CREATE INDEX idx_rel_type ON entity_relationships(relationship_type);
```

---

## SQLite: ForgeChain Store (`data/forge_chain.db`)

Carried over unchanged from TIPS Hub.

```sql
CREATE TABLE forge_sessions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT UNIQUE NOT NULL,
    session_key_encrypted TEXT NOT NULL,     -- Fernet-encrypted session key
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE forge_blocks (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT NOT NULL,
    block_json          TEXT NOT NULL,       -- Full ForgeBlock serialized
    gate_outcome        TEXT NOT NULL,       -- executed, refused, blocked
    endpoint            TEXT,
    timestamp           TEXT NOT NULL
);

CREATE INDEX idx_blocks_session ON forge_blocks(session_id);
CREATE INDEX idx_blocks_outcome ON forge_blocks(gate_outcome);
CREATE INDEX idx_blocks_timestamp ON forge_blocks(timestamp);
```

---

## FAISS Vectorstore (`vectorstores/`)

Same architecture as TIPS Hub.

```
vectorstores/
├── _knowledge_base/           # Persistent global KB
│   ├── index.faiss            # FAISS index file
│   ├── index.pkl              # Document metadata
│   └── .hmac                  # HMAC-SHA256 integrity hash
│
├── <session_id>/              # Per-upload session vectorstore
│   ├── index.faiss
│   ├── index.pkl
│   └── .hmac
```

**Configuration:**
- Embeddings: `BAAI/bge-base-en-v1.5` (768 dims, MTEB retrieval ~53, instruction-aware prefixes)
- Chunk size: 1000 characters
- Chunk overlap: 150 characters
- Similarity search k: 5 (per-session), 3 (KB context)
- HMAC key: `VECTORSTORE_HMAC_KEY` or `SESSION_SECRET_KEY`

---

## Redis (Optional — Feed Monitor State)

```
fortis:monitor:<monitor_id>         # JSON: MonitorConfig
fortis:monitor:active               # Set of active monitor IDs
fortis:finding:<finding_id>         # JSON: MonitorFinding (7-day TTL)
fortis:finding:pending              # Set of pending finding IDs
fortis:rate_limit:<platform>        # Rate limit counters per platform
fortis:cache:geocode:<hash>         # Geocoding cache (24-hour TTL)
fortis:cache:profile:<platform>:<id> # Profile cache (1-hour TTL)
```

### MonitorConfig

```python
@dataclass
class MonitorConfig:
    monitor_id: str
    monitor_type: str         # keyword, username, hashtag, location_radius
    query: str                # the search term or username
    platforms: list[str]      # which platforms to poll
    interval_minutes: int     # polling interval (default 15)
    created_at: str
    created_by: str
    last_poll: str | None
    status: str               # active, paused, expired
    alert_threshold: str      # all, high_confidence, geo_match
```

### MonitorFinding

```python
@dataclass
class MonitorFinding:
    finding_id: str
    monitor_id: str
    content_type: str         # post, image, article, profile_change
    platform: str
    content_summary: str
    geo_data: dict | None     # extracted location if any
    metadata: dict            # platform-specific metadata
    analysis_text: str        # LLM-generated analysis
    status: str               # pending_review, approved, dismissed
    created_at: str
    reviewed_at: str | None
    reviewed_by: str | None
    dismiss_reason: str | None
```

---

## Environment Variables

```bash
# === Core ===
FLASK_SECRET_KEY=           # Flask session secret
SESSION_SECRET_KEY=         # ForgeChain encryption + HMAC key
AUTH_ENABLED=true           # Enable/disable Google OAuth

# === LLM — DeepSeek (single provider) ===
DEEPSEEK_API_KEY=           # DeepSeek platform API key
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1      # default
DEEPSEEK_ANALYSIS_MODEL=deepseek-v4-flash   # analysis chains
DEEPSEEK_FORGE_MODEL=deepseek-v4-pro        # ForgeChain verifiers

# === Social Media APIs ===
TWITTER_BEARER_TOKEN=       # X/Twitter API v2
REDDIT_CLIENT_ID=           # Reddit API
REDDIT_CLIENT_SECRET=
REDDIT_USER_AGENT=Fortis/1.0
TELEGRAM_API_ID=            # Telegram API
TELEGRAM_API_HASH=
INSTAGRAM_ACCESS_TOKEN=     # Instagram Graph API
YOUTUBE_API_KEY=            # YouTube Data API v3
MASTODON_INSTANCE_URL=      # e.g., https://mastodon.social
MASTODON_ACCESS_TOKEN=

# === Geolocation ===
MAXMIND_LICENSE_KEY=        # MaxMind GeoLite2 DB updates
GOOGLE_GEOCODING_API_KEY=   # Optional: Google Geocoding fallback
NOMINATIM_USER_AGENT=Fortis/1.0

# === Optional Integrations ===
SHODAN_API_KEY=             # Shodan IP intelligence
VIRUSTOTAL_API_KEY=         # VirusTotal reputation
NEWSAPI_KEY=                # NewsAPI.org

# === Google OAuth ===
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
OAUTH_REDIRECT_URI=

# === Google Drive Export ===
GDRIVE_SERVICE_ACCOUNT_KEY= # Path to service account JSON
GDRIVE_FOLDER_ID=

# === Notifications ===
SLACK_WEBHOOK_URL=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
NOTIFICATION_EMAIL=

# === Redis (optional) ===
REDIS_URL=redis://localhost:6379/0

# === ForgeChain ===
FORGE_ENABLED=true
FORGE_CONSENSUS_THRESHOLD=0.67
FORGE_HEALING_ENABLED=true
FORGE_MAX_PROMPT_LENGTH=50000
FORGE_SAFETY_VETO_THRESHOLD=0.95
FORGE_LLM_VERIFIER_TIMEOUT=15
FORGE_DB_PATH=data/forge_chain.db

# === Knowledge Base ===
KB_RETENTION_DAYS=90
VECTORSTORE_HMAC_KEY=

# === Feed Monitor ===
MONITOR_DEFAULT_INTERVAL=15  # minutes
MONITOR_MAX_ACTIVE=20        # max concurrent monitors
```

---

## Data Retention Policy

| Data Type               | Default Retention  | Storage        | Configurable         |
|-------------------------|--------------------|----------------|----------------------|
| Analysis reports        | 90 days in KB      | SQLite         | KB_RETENTION_DAYS    |
| Raw OSINT data          | 7 days             | Redis          | TTL on Redis keys    |
| Geo data points         | Indefinite         | SQLite         | Manual cleanup       |
| Entity relationships    | Indefinite         | SQLite         | Manual cleanup       |
| Session vectorstores    | Session lifetime   | FAISS (disk)   | Cleared on new upload|
| Knowledge Base          | 90 days            | FAISS (disk)   | KB_RETENTION_DAYS    |
| ForgeChain blocks       | Indefinite         | SQLite         | Audit requirement    |
| Monitor findings        | 7 days             | Redis          | TTL on Redis keys    |
| Geocoding cache         | 24 hours           | Redis          | TTL                  |
| Profile cache           | 1 hour             | Redis          | TTL                  |
| Audit logs              | Indefinite         | File (JSON)    | Log rotation         |
