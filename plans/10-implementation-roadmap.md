# Fortis Intelligence Hub — Implementation Roadmap

## Phase 0: Scaffold (Foundation)

**Goal:** Bootable app with TIPS Hub skeleton adapted for Fortis.

### Tasks

- [ ] Initialize git repo at `C:\Users\fokon\Documents\Fortis-Intelligence-Hub`
- [ ] Create directory structure (app/, templates/, static/, data/, etc.)
- [ ] Copy and adapt from TIPS Hub:
  - [ ] `run.py`, `run_windows.py`
  - [ ] `app/__init__.py`
  - [ ] `app/web.py` — strip all RF/MISP/Jira routes, keep skeleton with `/`, `/upload`, `/ask`, `/export/*`, `/kb/*`, `/forge/*`, auth routes
  - [ ] `app/llm.py` — reduce to 2 instances (analyst + batch), remove Red Team LLMs
  - [ ] `app/rag_store.py` — copy and upgrade embedding model: replace `sentence-transformers/all-MiniLM-L6-v2` (384 dims, MTEB retrieval ~41) with `BAAI/bge-base-en-v1.5` (768 dims, MTEB retrieval ~53) in `get_embedder()`. +29% retrieval quality improves `_get_kb_context()` and `similarity_search()` across all routes. Instruction-aware prefixes improve query-vs-document matching. Model size ~440 MB (negligible for server). No migration needed since Fortis starts with fresh FAISS indices.
  - [ ] `app/report_store.py` — adapt schema (new fields: sensitivity_level, platforms_queried, geo_data, tags)
  - [ ] `app/export.py` — adapt theme colors (purple accent), remove TLP for sensitivity levels
  - [ ] `app/export_ioc.py` — adapt for OSINT entities instead of CVE IOCs
  - [ ] `app/intel_graph.py` — adapt node/edge types for OSINT entities
  - [ ] `app/charts.py` — new chart types (platform distribution, timeline, geo)
  - [ ] `app/forge/` — copy entire directory, update verifiers.py rule set
  - [ ] `app/auth/` — copy, simplify (remove Jira role resolution, keep OAuth)
  - [ ] `app/utils/` — copy pdf_reader.py and uploads.py
  - [ ] `app/celery_app.py` — adapt queue name
  - [ ] `app/notifications.py` — copy unchanged
  - [ ] `app/constants.py` — replace product constants with OSINT platform configs
- [ ] Create `.env.example` with all Fortis env vars
- [ ] Create `requirements.txt`
- [ ] Create `templates/index.html` — black/purple punk theme skeleton
- [ ] Create `static/css/styles.css` — full punk theme
- [ ] Create `static/js/app.js` — basic SPA logic (auth, upload, Q&A, export)
- [ ] Verify: app boots, login works, PDF upload + Q&A works, export works

**Deliverable:** Running app with auth, document ingestion, RAG Q&A, KB, ForgeChain, and export. No OSINT features yet.

---

## Phase 1: OSINT Core

**Goal:** Social media and web intelligence gathering.

### Tasks

- [ ] Implement `app/social_client.py`
  - [ ] Twitter/X integration (tweepy + X API v2)
  - [ ] Reddit integration (PRAW)
  - [ ] Telegram integration (Telethon)
  - [ ] Instagram integration (instaloader for public data)
  - [ ] YouTube integration (Data API v3)
  - [ ] Mastodon integration (API client)
  - [ ] Graceful degradation per platform (HAS_* flags)
- [ ] Implement `app/osint_client.py`
  - [ ] `investigate()` — orchestrate social_client across platforms
  - [ ] `enrich_entities()` — entity-based OSINT lookup
  - [ ] `search()` — general OSINT search
  - [ ] `is_configured()` — source availability check
- [ ] Implement `app/web_scraper.py`
  - [ ] RSS feed parsing (feedparser)
  - [ ] News article fetching (NewsAPI)
  - [ ] WHOIS lookup (python-whois)
  - [ ] DNS record lookup (dnspython)
  - [ ] robots.txt compliance
- [ ] Implement `app/metadata_extractor.py`
  - [ ] EXIF extraction (Pillow + exifread)
  - [ ] NER extraction (spaCy en_core_web_sm)
  - [ ] Language detection (langdetect)
  - [ ] Timezone inference from posting patterns
- [ ] Create LLM chains in `app/chains.py`
  - [ ] Investigation chain
  - [ ] Enrichment chain
  - [ ] Batch item chain
  - [ ] Batch synthesis chain
- [ ] Add routes to `app/web.py`
  - [ ] `POST /investigate`
  - [ ] `POST /enrich`
  - [ ] `POST /batch-investigate`
  - [ ] `GET /osint-status`
- [ ] Update frontend
  - [ ] Investigation tool card + form
  - [ ] Batch investigation tool card + form
  - [ ] Enrichment button on document upload
  - [ ] OSINT status indicator in top bar
  - [ ] Results rendering for investigation reports
- [ ] Update ForgeChain rule verifier with OSINT policies
- [ ] Tests: social_client, osint_client, metadata_extractor, investigation chain

**Deliverable:** Working investigation flow — enter a username, get OSINT report with entity graph.

---

## Phase 2: Geolocation & Mapping

**Goal:** Location triangulation and interactive map.

### Tasks

- [ ] Implement `app/geo_client.py`
  - [ ] Nominatim geocoding + reverse geocoding
  - [ ] Google Geocoding API fallback
  - [ ] MaxMind GeoLite2 IP geolocation
  - [ ] ipapi.co fallback
  - [ ] DBSCAN triangulation algorithm
  - [ ] `build_map_data()` for Leaflet.js
  - [ ] Geocoding cache (Redis or in-memory)
- [ ] Create `static/js/map.js`
  - [ ] Leaflet.js initialization with CartoDB Dark Matter tiles
  - [ ] Custom purple SVG markers by source type
  - [ ] Triangulation overlay (radius, connections, pulsing center)
  - [ ] Heatmap layer (Leaflet.heat)
  - [ ] Marker clustering (Leaflet.markercluster)
  - [ ] Timeline slider (Leaflet.TimeDimension)
  - [ ] Layer toggle control
  - [ ] Fullscreen toggle
  - [ ] Map PNG snapshot export
  - [ ] Marker click popups
- [ ] Create geolocation LLM chain in `app/chains.py`
- [ ] Add routes to `app/web.py`
  - [ ] `POST /triangulate`
  - [ ] `POST /export/map-snapshot`
- [ ] Update frontend
  - [ ] Geolocation tool card + form (image upload, social posts, IPs, manual)
  - [ ] Map component in results panel
  - [ ] Map integration in investigation results
  - [ ] Map integration in batch results
- [ ] Update `app/export.py` for map snapshot in PDF
- [ ] Server-side static map generation (`staticmap`) for PDF export
- [ ] Tests: geo_client triangulation, geocoding, map data generation

**Deliverable:** Enter data points → see triangulated location on dark-themed map → export PDF with map snapshot.

---

## Phase 3: Feed Monitoring

**Goal:** Automated OSINT monitoring with analyst review.

### Tasks

- [ ] Implement `app/feed_monitor.py`
  - [ ] Celery periodic task for polling
  - [ ] Monitor lifecycle (create, pause, resume, delete)
  - [ ] New content detection (since last poll)
  - [ ] Auto-enrichment of new findings
  - [ ] Integration with ForgeChain for analysis
- [ ] Implement `app/redis_store.py` (adapted from TIPS Hub)
  - [ ] MonitorConfig CRUD
  - [ ] MonitorFinding CRUD with pending/approved/dismissed states
  - [ ] In-memory fallback when Redis unavailable
- [ ] Create monitor alert LLM chain in `app/chains.py`
- [ ] Add routes to `app/web.py`
  - [ ] All `/monitor/*` routes
- [ ] Update frontend
  - [ ] Feed Monitor tool card + form
  - [ ] Active monitors list with status indicators
  - [ ] Watch panel (slide-in from right)
  - [ ] Finding cards with approve/dismiss buttons
  - [ ] Auto-refresh for watch panel
- [ ] Update notifications for monitor findings
- [ ] Tests: feed_monitor, monitor_store, alert chain

**Deliverable:** Configure a keyword/username monitor → get alerts in Watch panel → approve/dismiss findings.

---

## Phase 4: Entity Graph & Scenarios

**Goal:** Cross-investigation entity graph and scenario generation.

### Tasks

- [ ] Enhance `app/intel_graph.py` for OSINT entities
  - [ ] Node types: person, organization, location, account, domain, event, media
  - [ ] Edge types: associated_with, located_at, posted_from, linked_to, alias_of, member_of, mentioned_by
  - [ ] Cross-investigation relationship persistence (entity_relationships table)
  - [ ] Graph queries: shared_connections, location_clusters, activity_overlap
  - [ ] graph_context() for LLM consumption
- [ ] Create scenario LLM chain in `app/chains.py`
  - [ ] Pattern of life
  - [ ] Network mapping
  - [ ] Location prediction
  - [ ] Influence analysis
- [ ] Add scenario route to `app/web.py`
- [ ] Update frontend
  - [ ] Enhanced Cytoscape.js graph (purple-themed node colors)
  - [ ] Graph query panel (click node → drill down)
  - [ ] Scenario tool card + form
  - [ ] Scenario type selector
- [ ] Add entity_relationships and investigation_subjects tables to SQLite
- [ ] Tests: graph construction, graph queries, scenario chain

**Deliverable:** Entity graph showing connections across investigations + scenario generation from OSINT patterns.

---

## Phase 5: Polish & Deploy

**Goal:** Production-ready with deployment artifacts.

### Tasks

- [ ] UI polish
  - [ ] Responsive layout (tablet, mobile)
  - [ ] Loading animations (purple scanline)
  - [ ] Error states and empty states
  - [ ] Keyboard accessibility
  - [ ] Welcome/landing page
- [ ] Security hardening
  - [ ] Full CSP policy with map tile domains
  - [ ] Input sanitization audit
  - [ ] Rate limit tuning
  - [ ] ForgeChain rule verifier review
- [ ] Performance
  - [ ] Geocoding cache optimization
  - [ ] Profile cache for repeated lookups
  - [ ] Lazy loading for map tiles
  - [ ] Pagination for large batch results
- [ ] Deployment
  - [ ] Dockerfile
  - [ ] docker-compose.yml (app + redis)
  - [ ] OpenShift Kustomize overlays (mirror TIPS Hub deploy structure)
  - [ ] Health check endpoint
  - [ ] Startup verification script
- [ ] Documentation
  - [ ] CLAUDE.md for the project
  - [ ] .env.example with comments
  - [ ] API documentation (if needed)
- [ ] Tests
  - [ ] Integration tests for full pipelines
  - [ ] Security tests (carried from TIPS Hub test_security_fixes.py pattern)
  - [ ] ForgeChain governance tests

**Deliverable:** Production-ready containerized app with deployment manifests.

---

## Estimated Effort

| Phase   | Description          | Estimated Effort | Cumulative |
|---------|----------------------|------------------|------------|
| Phase 0 | Scaffold             | 2-3 days         | 2-3 days   |
| Phase 1 | OSINT Core           | 4-5 days         | 6-8 days   |
| Phase 2 | Geolocation & Map    | 3-4 days         | 9-12 days  |
| Phase 3 | Feed Monitoring      | 2-3 days         | 11-15 days |
| Phase 4 | Entity Graph         | 2-3 days         | 13-18 days |
| Phase 5 | Polish & Deploy      | 2-3 days         | 15-21 days |

---

## Risk Considerations

1. **Social media API access** — Platform APIs have varying access tiers and costs.
   Twitter/X Academic Research API is the most capable but requires application.
   Instagram official API is limited; instaloader covers public data.

2. **Rate limiting across platforms** — Concurrent investigation across 6+ platforms
   needs careful rate management. The OSINT client should implement platform-specific
   rate limiters with request queuing.

3. **Legal/ethical compliance** — OSINT collection must stay within legal bounds.
   The ForgeChain rule verifier's OSINT policies (minor protection, harassment
   detection, purpose documentation) are critical guardrails.

4. **Data volume** — Social media queries can return large volumes. Implement
   result limits per platform (e.g., max 200 posts per query) and progressive
   loading in the UI.

5. **Map tile costs** — CartoDB Dark Matter is free for moderate usage. If traffic
   grows, consider self-hosted tiles or a paid Mapbox plan.

6. **EXIF stripping** — Many platforms strip EXIF from uploaded images. The EXIF
   extraction feature is most valuable for images obtained outside social platforms
   (direct shares, email attachments, forum posts).

