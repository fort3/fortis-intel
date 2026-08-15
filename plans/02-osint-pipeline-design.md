# Fortis Intelligence Hub — OSINT Pipeline Design

## Overview

The OSINT pipeline replaces TIPS Hub's Recorded Future API integration with a
multi-source open-source intelligence gathering system. The pipeline collects,
correlates, and enriches data from social media, public web sources, and metadata
analysis, with location triangulation as its signature capability.

---

## Intelligence Sources

### Tier 1 — Social Media APIs (Primary)

| Platform   | API / Method                    | Data Extracted                              |
|------------|---------------------------------|---------------------------------------------|
| X/Twitter  | X API v2 (Academic/Pro)         | Tweets, user profiles, geotags, media URLs  |
| Reddit     | Reddit API (PRAW)               | Posts, comments, user history, subreddits    |
| Telegram   | Telethon / Bot API              | Channel posts, forwarded messages, media     |
| Instagram  | Instagram Graph API             | Posts, stories, location tags, EXIF metadata |
| Facebook   | CrowdTangle or Graph API        | Public posts, pages, groups, check-ins       |
| YouTube    | YouTube Data API v3             | Video metadata, descriptions, comments       |
| TikTok     | TikTok Research API             | Video metadata, user profiles, hashtags      |
| Mastodon   | Mastodon API                    | Toots, user profiles, instance federation    |

### Tier 2 — Web Intelligence

| Source           | Method                          | Data Extracted                              |
|------------------|---------------------------------|---------------------------------------------|
| News outlets     | RSS feeds + NewsAPI             | Articles, headlines, publication dates       |
| Public records   | Web scraping (BeautifulSoup)    | Court records, property, business filings   |
| Forums           | Web scraping + API where avail  | Posts, threads, user profiles               |
| Paste sites      | Pastebin API / scraping         | Pastes mentioning subjects of interest      |
| WHOIS            | python-whois                    | Domain registration, registrant info        |
| DNS              | dnspython                       | DNS records, subdomains, history            |
| Shodan           | Shodan API                      | IP intelligence, device fingerprints        |
| VirusTotal       | VT API (optional)               | URL/domain reputation (if needed)           |

### Tier 3 — Metadata & Geospatial

| Source           | Method                          | Data Extracted                              |
|------------------|---------------------------------|---------------------------------------------|
| Image EXIF       | Pillow / exifread               | GPS coords, camera model, timestamp         |
| Reverse image    | Google Vision API or TinEye API | Image origin, similar images, context       |
| IP Geolocation   | ipapi.co / MaxMind GeoLite2     | IP → city/country/ASN mapping               |
| Timezone analysis| NLP + metadata                  | Posting patterns → probable timezone        |
| Language analysis| langdetect + NLP                | Language → region inference                 |
| Social graph     | Network analysis                | Connection patterns → location clusters     |

---

## Pipeline Architecture

### Pipeline 1: Subject Investigation (Manual)

```
Analyst enters subject identifier (username, name, email, phone, domain)
  → /investigate endpoint
  → osint_client.investigate(identifier, platforms=[...])
    → parallel social API queries per platform
    → metadata_extractor.extract_all(results)
    → geo_client.triangulate(metadata_points)
  → build_entity_graph(findings)
  → gated_invoke(chain=investigation_chain, input={osint_data, geo_data, graph_context})
  → sensitivity_classification (analyst-assigned)
  → _save_to_kb()
  → generate_investigation_charts()
  → Return: analysis, map_data, entity_graph, charts
```

### Pipeline 2: Document Ingestion + OSINT Enrichment

```
Analyst uploads PDF/MD report
  → validate_upload_file()
  → extract_pdf_text() or read markdown
  → build_vectorstore(text, session_id)
  → entity_extractor.extract(text)
    → Names, locations, dates, organizations, identifiers
  → osint_client.enrich_entities(entities)
    → Per entity: social search, web search, metadata lookup
    → geo_client.resolve_locations(location_mentions)
  → gated_invoke(chain=enrichment_chain, input={document, entities, osint_data, geo_data})
  → _save_to_kb()
  → Return: enriched_analysis, map_data, entity_graph
```

### Pipeline 3: Social Media Monitor (Automated via Celery)

```
Analyst configures watch on keyword/username/hashtag
  → monitor saved to Redis (watch_monitors set)
  → Celery periodic task (configurable interval, default 15 min)
    → social_client.poll(monitor_config)
    → filter new content since last poll
    → metadata_extractor.extract_all(new_content)
    → geo_client.triangulate(metadata_points)
    → gated_invoke(chain=monitor_alert_chain)
    → save MonitorRecord to Redis (status=pending_review)
    → notify_new_finding() [Slack + email]
  → Analyst reviews in Watch panel
    → Approve: save to KB + export
    → Dismiss: reason required, archived
```

### Pipeline 4: Geolocation Triangulation

```
Analyst provides data points (images, social posts, IP addresses)
  → /triangulate endpoint
  → metadata_extractor.extract_geo_from_images(images)
    → EXIF GPS extraction
    → Reverse image search for location context
  → social_client.extract_geotags(posts)
    → Platform geotags, check-in data
    → Mentioned location names → geocode
  → geo_client.analyze_posting_patterns(posts)
    → Timezone inference from posting times
    → Language-region correlation
  → geo_client.triangulate(all_data_points)
    → Weighted centroid calculation
    → Confidence radius estimation
    → Cluster analysis for multiple locations
  → gated_invoke(chain=geolocation_chain)
  → Return: primary_location, alternate_locations, confidence, map_data, timeline
```

### Pipeline 5: Batch Entity Processing

```
Analyst provides list of identifiers (CSV/XLSX or pasted list)
  → /batch-investigate endpoint
  → parse identifiers (usernames, emails, domains, phones)
  → ThreadPoolExecutor(max_workers=8)
    → Per entity: osint_client.investigate(identifier)
    → metadata_extractor.extract_all(results)
    → geo_client.resolve_locations(metadata)
  → aggregate_findings(all_results)
  → build_entity_graph(all_findings)  [cross-entity relationships]
  → gated_invoke(chain=batch_synthesis_chain)
  → _save_to_kb()
  → generate_batch_charts()
  → Return: synthesis, per_entity_results, aggregate_map, entity_graph, charts
```

### Pipeline 6: RAG Q&A (Same as TIPS Hub)

```
Analyst asks question about uploaded document
  → /ask endpoint
  → load_vectorstore(session_id)
  → similarity_search(question, k=5)
  → _get_kb_context(question)  [global KB enrichment]
  → gated_invoke(chain=rag_chain, input={question, context, kb_context})
  → Return: answer
```

---

## OSINT Client Design (`osint_client.py`)

The `OSINTClient` class is the primary aggregator, orchestrating calls to
platform-specific sub-clients and the metadata extractor.

```python
class OSINTClient:
    """Aggregated OSINT intelligence client.
    
    Coordinates social_client, web_scraper, metadata_extractor, and geo_client
    to produce unified findings from multiple OSINT sources.
    """
    
    def investigate(self, identifier, platforms=None, depth="standard"):
        """Full-spectrum investigation on a subject identifier.
        
        Args:
            identifier: Username, email, phone, domain, or real name
            platforms: List of platforms to query (None = all configured)
            depth: "quick" (API only), "standard" (API + web), "deep" (all sources)
        
        Returns:
            OSINTFindings with profiles, posts, metadata, geo_points, timeline
        """
    
    def enrich_entities(self, entities):
        """Enrich extracted entities with OSINT data.
        
        Args:
            entities: List of EntityMention (name, type, source_context)
        
        Returns:
            List of EnrichedEntity with OSINT matches and confidence scores
        """
    
    def search(self, query, sources=None, date_from=None, date_to=None):
        """General OSINT search across configured sources."""
    
    def is_configured(self):
        """Check which OSINT sources have valid API credentials."""
```

---

## Social Media Client Design (`social_client.py`)

```python
class SocialClient:
    """Multi-platform social media API client."""
    
    def search_username(self, username, platforms=None):
        """Search for a username across platforms."""
    
    def search_content(self, query, platforms=None, date_from=None, date_to=None):
        """Search for content matching a query."""
    
    def get_user_profile(self, platform, user_id):
        """Fetch full user profile from a specific platform."""
    
    def get_user_posts(self, platform, user_id, limit=100, since=None):
        """Fetch recent posts/content from a user."""
    
    def extract_geotags(self, posts):
        """Extract geolocation data from social media posts."""
    
    def poll(self, monitor_config):
        """Poll for new content matching monitor criteria."""
    
    # Platform-specific private methods
    def _query_twitter(self, query, params): ...
    def _query_reddit(self, query, params): ...
    def _query_telegram(self, query, params): ...
    def _query_instagram(self, query, params): ...
    def _query_mastodon(self, query, params): ...
```

---

## Metadata Extractor Design (`metadata_extractor.py`)

```python
class MetadataExtractor:
    """Extract and analyze metadata from various content types."""
    
    def extract_all(self, content_items):
        """Extract all available metadata from a list of content items.
        
        Returns:
            MetadataBundle with geo_points, timestamps, device_info, 
            language_data, network_data
        """
    
    def extract_exif(self, image_data):
        """Extract EXIF data from image bytes.
        
        Returns GPS coords, camera model, datetime, software, etc.
        """
    
    def extract_geo_from_images(self, images):
        """Batch EXIF GPS extraction from multiple images."""
    
    def infer_timezone(self, posting_times):
        """Analyze posting time distribution to infer timezone.
        
        Uses gap analysis (sleeping hours) and peak activity patterns.
        Returns ranked timezone candidates with confidence.
        """
    
    def detect_language_region(self, texts):
        """Detect language and infer regional dialect/variant.
        
        Returns language code, regional variant, confidence.
        """
    
    def extract_entities_nlp(self, text):
        """NER extraction: names, locations, organizations, dates, identifiers."""
```

---

## Geolocation Client Design (`geo_client.py`)

```python
class GeoClient:
    """Geolocation services: geocoding, reverse geocoding, triangulation."""
    
    def geocode(self, location_text):
        """Convert location text to coordinates.
        
        Uses Nominatim (OpenStreetMap) with fallback to Google Geocoding API.
        """
    
    def reverse_geocode(self, lat, lon):
        """Convert coordinates to address/place name."""
    
    def ip_geolocate(self, ip_address):
        """Geolocate an IP address using MaxMind GeoLite2 or ipapi.co."""
    
    def triangulate(self, data_points):
        """Triangulate probable location from multiple data points.
        
        Args:
            data_points: List of GeoDataPoint (lat, lon, source, confidence,
                         timestamp, point_type)
        
        Algorithm:
            1. Cluster data points using DBSCAN (eps=0.05 degrees, min_samples=2)
            2. For each cluster: compute weighted centroid (weighted by confidence)
            3. Compute confidence radius (95th percentile distance from centroid)
            4. Rank clusters by total weight and recency
            5. Return primary location + alternates with confidence scores
        
        Returns:
            TriangulationResult with primary_location, alternate_locations,
            confidence_score, radius_km, data_point_count, cluster_map
        """
    
    def resolve_locations(self, location_mentions):
        """Batch geocode location mentions from text.
        
        Handles ambiguity (e.g., "Springfield" → ranked candidates).
        """
    
    def build_map_data(self, geo_points, triangulation=None):
        """Build Leaflet.js-compatible map data structure.
        
        Returns:
            MapData with markers, heatmap_points, polylines, 
            triangulation_overlay, bounds
        """
```

---

## Data Models

### OSINTFindings

```python
@dataclass
class OSINTFindings:
    subject_id: str
    identifier: str
    identifier_type: str  # username, email, phone, domain, name
    profiles: list[SocialProfile]
    posts: list[SocialPost]
    web_mentions: list[WebMention]
    metadata: MetadataBundle
    geo_points: list[GeoDataPoint]
    triangulation: TriangulationResult | None
    entity_graph: dict  # Cytoscape-compatible JSON
    timeline: list[TimelineEvent]
    source_count: int
    collection_timestamp: str
```

### GeoDataPoint

```python
@dataclass
class GeoDataPoint:
    latitude: float
    longitude: float
    source: str           # "exif", "geotag", "ip", "checkin", "mention", "timezone"
    source_detail: str    # Platform or file name
    confidence: float     # 0.0 - 1.0
    timestamp: str | None
    point_type: str       # "exact", "approximate", "inferred"
    raw_data: dict        # Source-specific metadata
```

### TriangulationResult

```python
@dataclass
class TriangulationResult:
    primary_location: dict    # {lat, lon, address, confidence, radius_km}
    alternate_locations: list  # Ranked alternatives
    data_point_count: int
    cluster_count: int
    confidence_score: float   # Overall triangulation confidence (0-1)
    methodology_notes: str    # How the triangulation was computed
    timeline: list            # Location over time if temporal data available
```

---

## Rate Limiting & Ethics

### API Rate Limits

| Platform   | Rate Limit                | Strategy                              |
|------------|---------------------------|---------------------------------------|
| X/Twitter  | 300 req/15min (v2 Basic)  | Token bucket, exponential backoff     |
| Reddit     | 60 req/min                | Request queue with delay              |
| Telegram   | Varies                    | Respectful polling intervals          |
| Instagram  | 200 req/hour              | Batch requests, cache responses       |
| Nominatim  | 1 req/sec                 | Request queue with 1.1s delay         |
| ipapi.co   | 1000 req/day (free)       | Cache results, batch where possible   |

### Ethical Guardrails

1. **Public data only** — Never attempt to access private profiles or protected content
2. **No impersonation** — API calls use authenticated application credentials, never
   impersonate users
3. **Respectful scraping** — Honor robots.txt, rate limits, and ToS
4. **Data minimization** — Collect only what's needed for the investigation scope
5. **Audit trail** — Every OSINT query is logged via ForgeChain with analyst attribution
6. **Retention policy** — Configurable data retention; default 90 days for KB,
   7 days for raw collection data
7. **ForgeChain governance** — All LLM analysis passes through the consensus gate;
   the rule verifier includes OSINT-specific policy checks (e.g., no queries on
   minors without elevated authorization)
