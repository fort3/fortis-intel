# Fortis Intelligence Hub

An OSINT-driven intelligence and analysis platform for open-source intelligence gathering, geospatial triangulation, and analyst-grade report generation.

![alt text](fortis-1.png)

## Key Features

- **Multi-Platform OSINT** -- Investigate usernames, emails, domains, and IPs across Twitter/X, Reddit, YouTube, Instagram, Mastodon, Facebook, TikTok, and Telegram
- **Geospatial Triangulation** -- Triangulate locations from EXIF data, social geotags, IP addresses, check-ins, and text mentions with interactive Leaflet.js maps
- **AI-Powered Analysis** -- DeepSeek LLM generates investigation reports, pattern-of-life analyses, network mapping, and influence assessments
- **RAG Knowledge Base** -- Upload PDF and Markdown reports, index them with FAISS vectorstore, and ask natural-language questions
- **Analytical Scenarios** -- Generate pattern-of-life, network mapping, location prediction, and influence analysis from collected OSINT data
- **Feed Monitoring** -- Set up keyword, username, and hashtag monitors with Celery background tasks and automatic enrichment
- **ForgeChain Governance** -- Every LLM request passes through a 3-verifier consensus gate (rule, safety, consistency) before execution
- **Elevated Authorization** -- Investigation endpoints support elevated authorization for privileged analysts handling sensitive cases
- **Entity Relationship Graphs** -- Cytoscape.js-powered interactive graphs with click-to-drill-down entity detail popups
- **Multi-Format Export** -- PDF, Markdown, STIX 2.1, CSV, JSON, and Google Drive export with map snapshots
- **Docker Ready** -- Dockerfile and docker-compose.yml for containerized deployment with Redis, Celery worker, and Celery beat

---

## Tech Stack

### Backend

| Component | Technology |
|-----------|-----------|
| Web Framework | Flask 3.x with Jinja2 SPA |
| LLM | DeepSeek v4-flash (analysis) + v4-pro (governance) via `langchain-openai` |
| Vectorstore | FAISS with `BAAI/bge-base-en-v1.5` embeddings |
| Database | SQLite (reports, ForgeChain audit trail) |
| Task Queue | Celery + Redis (feed monitoring, background enrichment) |
| NLP | spaCy (NER), langdetect (language detection) |
| Geolocation | geopy, MaxMind GeoLite2, DBSCAN clustering |
| PDF Processing | PyMuPDF, pypdf (3-tier extraction pipeline) |

### Frontend

| Component | Technology |
|-----------|-----------|
| UI | Vanilla JS single-page application |
| Maps | Leaflet.js with CartoDB Voyager tiles |
| Graphs | Cytoscape.js entity relationship visualization |
| Charts | Chart.js + Matplotlib (server-side) |
| Theme | Black and purple cyberpunk aesthetic |

### Security

| Component | Technology |
|-----------|-----------|
| AI Governance | ForgeChain -- 3 verifiers, 2/3 consensus gate |
| Authentication | Google OAuth 2.0 |
| Encryption | Fernet (ForgeChain token minting) |
| Rate Limiting | Flask-Limiter |

---

## Prerequisites

- **Python 3.11+**
- **Git**
- **Redis** (optional -- required only for feed monitoring with Celery)

---

## Local Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/Fortis-Intelligence-Hub.git
cd Fortis-Intelligence-Hub
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it:

```bash
# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Download the spaCy NLP Model

```bash
python -m spacy download en_core_web_sm
```

### 5. Configure Environment Variables

```bash
cp .env.example .env
```

Open `.env` and configure at minimum:

```
FLASK_SECRET_KEY=<random-string>
SESSION_SECRET_KEY=<random-string>
DEEPSEEK_API_KEY=<your-deepseek-key>
```

Generate secure keys with: `python -c "import secrets; print(secrets.token_hex(32))"`

See the [OSINT API Configuration Guide](#osint-api-configuration-guide) below for all available API keys.

### 6. Run the Application

```bash
# Option A: Flask development server
python run.py

# Option B: Waitress (Windows production server)
python run_windows.py
```

The app will be available at `http://localhost:5000`.

### 7. Run with Feed Monitoring (Optional)

Feed monitoring requires Redis and Celery. Open three terminals:

```bash
# Terminal 1: Start Redis
redis-server

# Terminal 2: Start Celery worker
celery -A app.celery_app worker --loglevel=info --pool=solo

# Terminal 3: Start the app
python run.py
```

---

## OSINT API Configuration Guide

The platform supports graceful degradation -- it runs with zero API keys configured (except DeepSeek for LLM analysis). Each unconfigured platform simply shows as disabled in the UI. Configure only the sources you need.

### DeepSeek (REQUIRED)

The LLM that powers all analysis, enrichment, and governance chains.

| Env Variable | Description |
|---|---|
| `DEEPSEEK_API_KEY` | Your DeepSeek API key |
| `DEEPSEEK_BASE_URL` | API endpoint (default: `https://api.deepseek.com/v1`) |
| `DEEPSEEK_ANALYSIS_MODEL` | Model for analysis chains (default: `deepseek-v4-flash`) |
| `DEEPSEEK_FORGE_MODEL` | Model for ForgeChain governance (default: `deepseek-v4-pro`) |

**How to get the key:**

1. Register at [platform.deepseek.com](https://platform.deepseek.com)
2. New accounts receive 5 million free tokens valid for 30 days
3. Navigate to **API Keys** in the dashboard
4. Click **Create new API key** and copy it immediately
5. To continue beyond the free tier, add balance to your account

**Free tier:** 5M tokens for 30 days. After that, pay-as-you-go at approximately $0.14/$0.28 per million input/output tokens (v4-flash). Estimated monthly cost at moderate usage: $2--5.

**Alternative:** Both DeepSeek models are also available on Ollama Cloud. Set `DEEPSEEK_BASE_URL` to `https://ollama.com/v1` and use your Ollama API key -- no other changes needed.

---

### Twitter / X

| Env Variable | Description |
|---|---|
| `TWITTER_BEARER_TOKEN` | Bearer token for X API v2 |

**How to get the key:**

1. Go to [developer.x.com](https://developer.x.com) and sign in with your X account
2. Apply for a developer account (free tier available)
3. Create a **Project**, then create an **App** within the project
4. Navigate to **Keys and Tokens** for your app
5. Generate a **Bearer Token** and copy it

**Free tier:** The free tier allows 1,500 tweets read per month. The Basic tier ($100/month) allows 10,000 tweets read per month. Rate limit: 300 requests per 15 minutes.

---

### Reddit

| Env Variable | Description |
|---|---|
| `REDDIT_CLIENT_ID` | OAuth2 client ID |
| `REDDIT_CLIENT_SECRET` | OAuth2 client secret |
| `REDDIT_USER_AGENT` | User agent string (default: `Fortis/1.0`) |

**How to get the keys:**

1. Log in to Reddit and go to [reddit.com/prefs/apps](https://www.reddit.com/prefs/apps)
2. Scroll to the bottom and click **create another app...**
3. Select **script** as the app type
4. Fill in a name and set the redirect URI to `http://localhost:5000`
5. Click **create app**
6. The **client ID** is the string under the app name (below "personal use script")
7. The **client secret** is labeled on the page

**Free tier:** 60 requests per minute. No monthly cap for script-type apps.

---

### YouTube

| Env Variable | Description |
|---|---|
| `YOUTUBE_API_KEY` | Google API key with YouTube Data API v3 enabled |

**How to get the key:**

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select an existing one)
3. Navigate to **APIs & Services > Library**
4. Search for **YouTube Data API v3** and click **Enable**
5. Go to **APIs & Services > Credentials**
6. Click **Create Credentials > API Key**
7. Copy the generated API key
8. (Recommended) Click **Restrict Key** and limit it to YouTube Data API v3

**Free tier:** 10,000 units per day. A search request costs 100 units, so approximately 100 searches per day.

---

### Instagram

| Env Variable | Description |
|---|---|
| `INSTAGRAM_ACCESS_TOKEN` | Optional -- Instagram Graph API token |

Instagram integration uses [instaloader](https://instaloader.github.io/) for scraping public profiles and posts. No API key is required for basic public data access.

If you want to use the official Instagram Graph API for higher rate limits:

1. Create a [Facebook Developer](https://developers.facebook.com/) account
2. Create an app and add the **Instagram Graph API** product
3. Generate a long-lived access token via the Graph API Explorer

**Free tier:** Instaloader works without any key for public data. Rate limit: 200 requests per hour (self-throttled).

---

### Mastodon

| Env Variable | Description |
|---|---|
| `MASTODON_INSTANCE_URL` | Your Mastodon instance URL (e.g., `https://mastodon.social`) |
| `MASTODON_ACCESS_TOKEN` | Application access token |

**How to get the key:**

1. Log in to your Mastodon instance
2. Go to **Preferences > Development > New Application**
3. Set an application name (e.g., `Fortis`)
4. Select scopes: `read:search` and `read:statuses` (or simply `read` for all read access)
5. Click **Submit**
6. Copy the **Access Token** from the application page

**Free tier:** 300 requests per 5 minutes. No monthly cap.

---

### Facebook

| Env Variable | Description |
|---|---|
| `FACEBOOK_ACCESS_TOKEN` | Graph API access token |

**How to get the key:**

1. Create a [Facebook Developer](https://developers.facebook.com/) account
2. Create a new app (select **Business** type)
3. Go to **Graph API Explorer** in the developer tools
4. Generate an access token with the permissions you need
5. For long-lived tokens, exchange the short-lived token via the token exchange endpoint

**Free tier:** 200 requests per hour. Access to public pages and posts. User data requires additional review and permissions.

---

### TikTok

| Env Variable | Description |
|---|---|
| `TIKTOK_API_KEY` | TikTok Research API key |

**How to get the key:**

1. Go to [developers.tiktok.com](https://developers.tiktok.com/)
2. Create a developer account
3. Apply for the **TikTok Research API** (requires application with research purpose justification)
4. Once approved, generate an API key from the developer portal

**Free tier:** Research API access requires approval and is limited to academic and nonprofit researchers. Rate limit: 100 requests per minute.

---

### Telegram

| Env Variable | Description |
|---|---|
| `TELEGRAM_API_ID` | Telegram application API ID |
| `TELEGRAM_API_HASH` | Telegram application API hash |
| `TELEGRAM_SESSION_PATH` | Path to the session file (default: `data/telegram_session`) |

**How to get the keys:**

1. Log in to [my.telegram.org](https://my.telegram.org)
2. Click **API development tools**
3. Fill in the application form
4. Note the **api_id** and **api_hash**

**One-time session setup:**

Telegram uses Telethon, which requires a one-time interactive phone authentication to create a reusable session file. Run the built-in setup script:

```bash
python -m app.telegram_auth
```

The script will:

1. Prompt for your phone number (with country code, e.g. `+1234567890`)
2. Send a verification code via Telegram
3. Prompt for the code (and 2FA password if enabled)
4. Save the session to `data/telegram_session.session`

After this one-time setup, the session file persists on disk and the app reuses it automatically -- no further phone input is needed. If you move the app to a different machine, copy the `.session` file along with it.

**Free tier:** 30 requests per minute. Access to public channels and groups.

---

### NewsAPI

| Env Variable | Description |
|---|---|
| `NEWSAPI_KEY` | NewsAPI.org API key |

**How to get the key:**

1. Register at [newsapi.org](https://newsapi.org/register)
2. Your API key is shown on the dashboard immediately after registration

**Free tier:** 100 requests per day, articles up to 1 month old, for development use only. Paid plans start at $449/month for production use.

---

### Shodan

| Env Variable | Description |
|---|---|
| `SHODAN_API_KEY` | Shodan API key |

**How to get the key:**

1. Register at [shodan.io](https://account.shodan.io/register)
2. Your API key is shown on your [account page](https://account.shodan.io/)

**Free tier:** Limited to 100 results per search query and 1 scan credit per month. The Membership plan ($49 one-time) unlocks higher limits.

---

### VirusTotal

| Env Variable | Description |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |

**How to get the key:**

1. Register at [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Go to your profile and find the **API Key** section

**Free tier:** 4 lookups per minute, 500 lookups per day, 15,500 lookups per month.

---

### Google OAuth (Authentication)

| Env Variable | Description |
|---|---|
| `GOOGLE_CLIENT_ID` | OAuth 2.0 client ID |
| `GOOGLE_CLIENT_SECRET` | OAuth 2.0 client secret |
| `OAUTH_REDIRECT_URI` | Redirect URI (default: `http://localhost:5000/oauth/callback`) |

**How to set up:**

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to **APIs & Services > Credentials**
3. Click **Create Credentials > OAuth 2.0 Client ID**
4. Select **Web application** as the application type
5. Add `http://localhost:5000/oauth/callback` to **Authorized redirect URIs**
6. Copy the **Client ID** and **Client Secret**

To disable authentication entirely during development, set `AUTH_ENABLED=false` in `.env`.

---

### MaxMind GeoIP

| Env Variable | Description |
|---|---|
| `MAXMIND_LICENSE_KEY` | MaxMind license key for downloading the database |

**How to set up:**

1. Register for a free account at [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
2. Go to **Account > Manage License Keys > Generate New License Key**
3. Download the **GeoLite2-City.mmdb** database from [the download page](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
4. Place the file at `data/GeoLite2-City.mmdb`

**Free tier:** GeoLite2 is free with registration. Updated every 2 weeks. Falls back to ipapi.co free tier if no database is present.

---

### Google Geocoding (Optional)

| Env Variable | Description |
|---|---|
| `GOOGLE_GEOCODING_API_KEY` | Google Geocoding API key |

This is optional. The platform uses Nominatim (OpenStreetMap) as the default geocoder, which requires no API key. Google Geocoding serves as a higher-accuracy fallback.

**How to get the key:**

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Enable the **Geocoding API**
3. Create an API key under **Credentials**

**Free tier:** $200/month free credit ($0.005 per request = 40,000 free requests/month).

---

### Google Drive Export (Optional)

| Env Variable | Description |
|---|---|
| `GDRIVE_SERVICE_ACCOUNT_KEY` | Path to Google service account JSON key file |
| `GDRIVE_FOLDER_ID` | Target Drive folder ID for exported reports |

**How to set up:**

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Enable the **Google Drive API**
3. Create a **Service Account** under **IAM & Admin > Service Accounts**
4. Generate a JSON key for the service account and save it locally
5. Share the target Drive folder with the service account email
6. Set `GDRIVE_SERVICE_ACCOUNT_KEY` to the path of the JSON key file

---

### Notifications (Optional)

| Env Variable | Description |
|---|---|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook URL for feed monitor alerts |
| `SMTP_HOST` | SMTP server hostname (e.g., `smtp.gmail.com`) |
| `SMTP_PORT` | SMTP server port (default: `587`) |
| `SMTP_USER` | SMTP username / email address |
| `SMTP_PASSWORD` | SMTP password or app-specific password |
| `NOTIFICATION_EMAIL` | Recipient email for feed monitor alerts |

Configure either Slack, email, or both. Feed monitor findings will be sent as alerts when new content is detected.

---

### Feed Monitor & Knowledge Base Settings

| Env Variable | Description | Default |
|---|---|---|
| `MONITOR_DEFAULT_INTERVAL` | Default polling interval in minutes | `15` |
| `MONITOR_MAX_ACTIVE` | Maximum concurrent active monitors | `20` |
| `KB_RETENTION_DAYS` | Days before reports are auto-archived | `90` |
| `VECTORSTORE_HMAC_KEY` | HMAC key for vectorstore integrity checks | (auto-generated) |

---

## Docker Setup

A `Dockerfile` and `docker-compose.yml` are included for containerized deployment.

### Quick Start with Docker Compose

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your API keys

# Build and start all services (app + Redis + Celery worker + Celery beat)
docker-compose up --build
```

This starts four containers:
- **app** -- The Flask application on port 5000
- **redis** -- Redis 7 for Celery broker and feed monitor state
- **celery-worker** -- Background task worker for feed monitoring
- **celery-beat** -- Periodic task scheduler

### Standalone Docker

```bash
docker build -t fortis-intelligence-hub .
docker run -p 5000:5000 --env-file .env fortis-intelligence-hub
```

Note: Running without Redis disables feed monitoring. Core features (upload, investigation, Q&A, export) work without Redis.

---

## Usage Guide

### Report Ingestion

Upload PDF or Markdown files for AI-powered analysis. The platform extracts text using a 3-tier pipeline (PyMuPDF, pypdf fallback, OCR fallback), indexes it into the FAISS vectorstore, and makes it available for Q&A and cross-referencing.

### Investigation

Enter a username, email address, domain, IP address, or keyword. Select the investigation depth:

- **Quick** -- API lookups only (fast social media queries)
- **Standard** -- API + web scraping (social media plus WHOIS, DNS, news)
- **Deep** -- All sources including metadata analysis and entity extraction

Results include a structured report, entity graph, and links to source data.

### Geolocation

Triangulate locations from multiple data points:

- Upload images for EXIF GPS extraction
- Enter IP addresses for geolocation
- Paste social media posts with geotags or location mentions
- Enter coordinates manually

The interactive map (CartoDB Voyager tiles) shows markers with confidence radii, DBSCAN cluster analysis, and a triangulated probable location.

### Q&A

Ask natural-language questions about uploaded reports. The RAG pipeline retrieves relevant chunks from the FAISS vectorstore and generates answers with source citations.

### Feed Monitor

Set up automated monitors for keywords, usernames, or hashtags across configured platforms. Celery beat polls at configurable intervals (5, 15, 30, 60, or 240 minutes). New findings appear in the Watch panel for analyst review (approve or dismiss).

### Scenarios

Generate analytical scenarios from collected OSINT data:

- **Pattern of Life** -- Daily and weekly behavioral patterns from posting data
- **Network Mapping** -- Social graph and connection analysis
- **Location Prediction** -- Probable future locations based on historical patterns
- **Influence Analysis** -- Reach, engagement patterns, and influence networks

### Knowledge Base

Manage and search across all indexed reports. Archive old reports based on retention policy. Search uses semantic similarity via the FAISS vectorstore.

### Export

Export reports in multiple formats:

- **PDF** -- Dark cyberpunk-themed report matching the app's visual design:
  - **Title page** with Fortis branding, report metadata, and sensitivity classification badge
  - **Geographic overview** with embedded map snapshot (auto-captured from Leaflet) and geospatial data table listing all geo signals with source type, coordinates, and confidence
  - **Entity relationship graph** rendered server-side (networkx + matplotlib) with color-coded nodes and labeled edges
  - **Visual analytics** charts in 2-column grid (platform distribution, activity timeline, entity types, confidence breakdown, location frequency)
  - **Analysis content** with dark background, purple accent headings, and proper light-on-dark text contrast
  - Sensitivity banner and branded footer on every page
  - Triangulation summary (center, method, radius, confidence) when available
- **Markdown** -- Portable text format with metadata table
- **STIX 2.1** -- Structured threat intelligence standard for entity sharing
- **CSV** -- Tabular entity and finding data
- **JSON** -- Full structured data
- **Google Drive** -- Direct export to a configured Drive folder (all formats)

---

## Architecture Notes

### ForgeChain Governance Gate

Every LLM invocation passes through ForgeChain, a 3-verifier consensus gate:

1. **Rule Verifier** -- Checks inputs against OSINT-specific policies (prompt injection detection, minor protection, harassment detection, purpose documentation, identifier validation, sensitive data scanning)
2. **Safety Verifier** (LLM-based) -- DeepSeek v4-pro evaluates the request for safety concerns, social engineering, and ethical compliance
3. **Consistency Verifier** (LLM-based) -- DeepSeek v4-pro checks that the request is consistent with the stated intent

A 2-of-3 consensus is required to pass. Failed requests are either healed (automatically corrected) or rejected with an explanation. Investigation endpoints support `elevated_authorization` for privileged analysts handling sensitive cases (e.g., minor-adjacent investigations). All decisions are logged in the ForgeChain audit trail.

### Celery Beat Schedule

Feed monitors use Celery periodic tasks with configurable intervals. The beat scheduler dispatches poll tasks to the worker queue (`fortis_monitor`). Each poll checks for new content since the last run, applies auto-enrichment, and stores findings for analyst review.

### FAISS Vectorstore

Documents are embedded using `BAAI/bge-base-en-v1.5` (768 dimensions) and stored in a FAISS index. The RAG pipeline uses similarity search to retrieve relevant chunks for Q&A, enrichment context, and cross-investigation analysis.

### Graceful Degradation

The platform is designed to run with minimal configuration. Core features that work without any OSINT API keys:

- PDF/Markdown upload and RAG Q&A
- Manual EXIF extraction from uploaded images
- Manual coordinate entry for triangulation
- Knowledge Base management
- All export formats
- ForgeChain governance

### API-Free Fallbacks

Several platforms can operate without official API keys using optional scraper libraries:

| Platform | API Path | No-API Fallback | Install |
|---|---|---|---|
| TikTok | `TIKTOK_API_KEY` (Research API) | **Pyktok** -- Playwright-based scraping of public search/profile pages | `pip install pyktok && playwright install chromium` |
| Mastodon | `MASTODON_ACCESS_TOKEN` | **Cross-instance search** -- Queries 6 major instances directly (mastodon.social, mastodon.online, mstdn.social, infosec.exchange, hachyderm.io, fosstodon.org) | Built-in (no extra deps) |
| Mastodon | `MASTODON_ACCESS_TOKEN` | **Masto library** -- Cross-instance user OSINT (optional) | `pip install masto` |
| Instagram | (none needed) | **Instaloader** -- Scrapes public profiles and posts | Included in requirements.txt |

When an API key is configured, it is always preferred (faster, richer data). Fallbacks activate automatically when keys are absent.

### News Enrichment (RSS)

Investigation enrichment automatically queries curated RSS feeds from major news sources alongside NewsAPI:

- **BBC News** and **BBC World**
- **CNN Top Stories** and **CNN World**
- **Reuters**
- **AP News**
- **Al Jazeera**

When `NEWSAPI_KEY` is configured, both NewsAPI results and RSS results are merged and deduplicated. When it is not configured, RSS feeds provide free news enrichment with no API key required.

### Mastodon Content Search

Mastodon content search uses a multi-layer approach because the `/api/v2/search` endpoint only returns posts the authenticated user has interacted with:

1. **Hashtag timeline** (`/api/v1/timelines/tag/:tag`) -- Public posts across the fediverse matching query terms
2. **Search API** (`/api/v2/search?type=statuses`) -- Posts from the user's own interactions
3. **Public timeline** (feed monitor only) -- Federated timeline filtered by keyword for background monitoring

Results are deduplicated across all layers.

### Image EXIF Triangulation

The geolocation card supports direct image uploads for GPS triangulation. Upload JPEG/TIFF images with embedded EXIF geolocation data, and the platform will:

1. Extract GPS coordinates from each image's EXIF metadata
2. Plot all extracted locations on the interactive map
3. Run DBSCAN clustering and triangulation to identify probable areas of interest
4. Generate an AI analysis of the geographic pattern

---

## Roadmap: Media Geolocation Enrichment

The following capabilities are planned for future development:

### Automatic Media Geo-Extraction

Every OSINT enrichment captures `media_urls` from social media posts. The pipeline automatically:

1. **Downloads media from enrichment results** -- Fetches images referenced in `media_urls` from each platform's normalised post data (up to 50 images per investigation)
2. **Runs EXIF extraction on all collected media** -- Feeds downloaded images through `MetadataExtractor.extract_geo_from_images()` to extract GPS coordinates (confidence: 0.95)
3. **Injects extracted coordinates into the geospatial pipeline** -- EXIF-derived locations join geotags, IP geolocation, text-mentioned places for triangulation and mapping

### Video Frame Geolocation

Estimates location from video content using OpenCV keyframe analysis (`app/video_geo.py`):

1. **Frame extraction** -- Extracts keyframes at 2-second intervals from video URLs (up to 30 frames per video, 10 videos per investigation)
2. **Perceptual deduplication** -- Uses imagehash (pHash) to skip near-duplicate frames (hamming distance < 8)
3. **EXIF from video frames** -- Extracts GPS metadata embedded in video frame headers (source: `video_exif`, confidence: 0.90)
4. **OCR + geocoding** -- When pytesseract is installed, detects text in frames (signs, banners, watermarks) and geocodes location mentions via spaCy NER + Nominatim (source: `video_landmark`, confidence: 0.50-0.55)
5. **Text region detection** -- OpenCV MSER detects text-heavy regions in frames for targeted OCR analysis

**Optional dependencies**: `opencv-python>=4.9.0`, `imagehash>=4.3.0`, `pytesseract` (for OCR). The system degrades gracefully — without OpenCV, video analysis is skipped entirely.

### Unified Geo Signal Aggregation

All geolocation signals from an investigation are aggregated onto a single map with automatic triangulation:

| Signal Source | Method | Confidence | Source Type |
|---|---|---|---|
| Image EXIF GPS | `MetadataExtractor.extract_geo_from_images()` | 0.95 | `exif` |
| Video frame EXIF | `VideoGeoExtractor` keyframe analysis | 0.90 | `video_exif` |
| Video OCR landmarks | Frame OCR + NER geocoding | 0.50-0.55 | `video_landmark` |
| Social geotags | Platform check-ins and place objects | 0.85 | `geotag` |
| NLP location mentions | spaCy GPE/LOC entities + Nominatim geocoding | 0.55 | `nlp_mention` |
| IP geolocation | GeoIP2 / MaxMind | varies | `ip` |

Each signal carries confidence scores and source attribution. When 2+ geo points exist, automatic weighted-centroid triangulation (with DBSCAN clustering for 5+ points) computes a confidence radius and center point. The map legend dynamically shows only the source types present in each investigation.

The investigation pipeline (`OSINTClient.investigate()`) runs geo extraction in this order:
1. `_extract_geo()` -- Social geotags from post metadata
2. `_extract_media_geo()` -- EXIF GPS from downloaded images
3. `_extract_video_geo()` -- Video keyframe analysis (requires OpenCV)
4. `_geocode_entity_locations()` -- NLP-extracted place names geocoded to coordinates

---

## Project Structure

```
Fortis-Intelligence-Hub/
|-- run.py                       # Flask dev server entry point
|-- run_windows.py               # Waitress production server (Windows)
|-- requirements.txt             # Python dependencies
|-- Dockerfile                   # Container build
|-- docker-compose.yml           # Multi-container orchestration
|-- .env.example                 # Environment variable template
|
|-- app/
|   |-- __init__.py
|   |-- web.py                   # Flask app factory + all routes
|   |-- chains.py                # LLM prompt templates
|   |-- llm.py                   # DeepSeek LLM factory
|   |-- osint_client.py          # OSINT aggregator (unified geo pipeline)
|   |-- video_geo.py             # Video keyframe extraction + landmark geolocation
|   |-- social_client.py         # Social media API integrations (+ Pyktok/Masto fallbacks)
|   |-- telegram_auth.py         # One-time Telegram session setup (python -m app.telegram_auth)
|   |-- geo_client.py            # Geolocation + triangulation
|   |-- metadata_extractor.py    # EXIF, NER, language detection
|   |-- web_scraper.py           # News, WHOIS, DNS, RSS
|   |-- export.py                # PDF/Markdown export
|   |-- export_ioc.py            # STIX, CSV, JSON export
|   |-- rag_store.py             # FAISS vectorstore
|   |-- report_store.py          # SQLite report persistence
|   |-- intel_graph.py           # Entity relationship graph
|   |-- charts.py                # Server-side chart generation
|   |-- feed_monitor.py          # Feed monitor management
|   |-- tasks.py                 # Celery background tasks (poll, enrich)
|   |-- celery_app.py            # Celery configuration + beat schedule
|   |-- redis_store.py           # Monitor state store
|   |-- gdrive_client.py         # Google Drive export client
|   |-- constants.py             # Platform configs, endpoints
|   |-- notifications.py         # Slack/email alerts
|   |
|   |-- forge/                   # ForgeChain governance
|   |   |-- gate.py              # Consensus gate
|   |   |-- verifiers.py         # Rule, safety, consistency
|   |   |-- gated_invoke.py      # Governed LLM invocation
|   |   |-- executor.py          # Action execution
|   |   |-- healer.py            # Failed output healing
|   |   +-- ...
|   |
|   |-- auth/                    # Google OAuth + sessions
|   +-- utils/                   # PDF reader, uploads, sanitizer
|
|-- templates/
|   |-- index.html               # Main SPA
|   +-- welcome.html             # Landing page
|
|-- static/
|   |-- css/styles.css           # Black + purple cyberpunk theme
|   +-- js/
|       +-- app.js               # Application logic (SPA + Leaflet maps)
|
|-- data/                        # SQLite databases, GeoIP database
|-- vectorstores/                # FAISS indices
|-- logs/                        # Application logs
+-- plans/                       # Architecture and design docs
```

---

## License

This project is proprietary. All rights reserved.
