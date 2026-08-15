# Fortis Intelligence Hub — Dependencies & Setup

## Python Dependencies

### Core Web Stack (from TIPS Hub)

```
flask>=3.0.0
flask-cors>=4.0.0
flask-limiter>=3.5.0
flask-wtf>=1.2.0
gunicorn>=21.2.0
waitress>=2.1.0
```

### LLM / AI Stack (DeepSeek — single provider)

```
langchain>=1.3.9
langchain-core>=1.4.9
langchain-openai>=0.3.0          # OpenAI-compatible client (DeepSeek)
langchain-community>=0.3.0
langchain-text-splitters>=0.3.0
langchain-huggingface>=0.1.0
openai>=1.50.0                   # Underlying OpenAI SDK (DeepSeek is compatible)
sentence-transformers>=3.0.0
faiss-cpu>=1.8.0
```

**Removed from TIPS Hub stack:**
- `langchain-google-vertexai` — no longer using Claude on Vertex AI
- `anthropic[vertex]` — no Anthropic SDK needed
- `google-cloud-aiplatform` — no GCP AI Platform dependency

### OSINT & Social Media (NEW)

```
# Social media APIs
tweepy>=4.14.0               # Twitter/X API v2 client
praw>=7.7.0                  # Reddit API wrapper
telethon>=1.36.0             # Telegram client
instaloader>=4.11            # Instagram scraping (public data)
google-api-python-client>=2.100.0  # YouTube Data API

# Web scraping & parsing
beautifulsoup4>=4.12.0       # HTML parsing
requests>=2.32.5             # HTTP client
feedparser>=6.0.0            # RSS/Atom feed parsing
python-whois>=0.9.0          # WHOIS lookups
dnspython>=2.6.0             # DNS queries

# News & search
newsapi-python>=0.2.7        # NewsAPI.org client
```

### Geolocation & Mapping (NEW)

```
geopy>=2.4.0                 # Geocoding (Nominatim, Google, etc.)
geoip2>=4.8.0                # MaxMind GeoLite2 IP geolocation
folium>=0.16.0               # Server-side map generation (optional)
staticmap>=0.5.7             # Static map image generation for PDF
scikit-learn>=1.4.0          # DBSCAN clustering for triangulation
shapely>=2.0.0               # Geometric operations
```

### Metadata & NLP (NEW)

```
Pillow>=12.3.0               # Image processing + EXIF reading
exifread>=3.0.0              # Detailed EXIF extraction
langdetect>=1.0.9            # Language detection
spacy>=3.7.0                 # NER (entity extraction)
# Download model: python -m spacy download en_core_web_sm
```

### Data Processing (from TIPS Hub)

```
PyMuPDF>=1.24.0              # PDF text extraction + generation
pypdf>=6.14.2                # Fallback PDF extraction
markdown>=3.6                # Markdown → HTML
matplotlib>=3.8.0            # Server-side charts
networkx>=3.2                # Entity relationship graph
openpyxl>=3.1.0              # Excel parsing (batch upload)
```

### Security / Crypto (from TIPS Hub)

```
cryptography>=41.0.0         # Fernet encryption (ForgeChain)
google-auth>=2.48.1          # Google OAuth
google-auth-oauthlib>=1.2.0  # OAuth flow
```

### Task Queue (from TIPS Hub)

```
redis>=5.0.0                 # Monitor state + Celery broker
celery>=5.3.0                # Background task queue
```

### Optional Integrations

```
shodan>=1.30.0               # Shodan IP intelligence (optional)
# easyocr>=1.7.0             # OCR for scanned PDFs (optional, heavy)
```

### Testing

```
pytest>=8.0.0
pytest-cov>=5.0.0
```

---

## Total Dependency Delta from TIPS Hub

### Removed (TIPS Hub only)
- `pymisp` — No MISP integration
- `langchain-google-vertexai`, `anthropic[vertex]`, `google-cloud-aiplatform` —
  No Claude / Vertex AI dependency
- No Jira-specific libraries (auth/jira_client handles this in TIPS Hub)

### Added (Fortis only)
- `langchain-openai`, `openai` — OpenAI-compatible client for DeepSeek
- `tweepy`, `praw`, `telethon`, `instaloader` — Social media APIs
- `feedparser` — RSS/Atom feeds
- `python-whois`, `dnspython` — Domain intelligence
- `newsapi-python` — News API
- `geopy`, `geoip2`, `staticmap`, `shapely` — Geolocation stack
- `scikit-learn` — DBSCAN clustering
- `exifread` — EXIF metadata
- `langdetect`, `spacy` — NLP/NER
- `folium` — Map generation (optional)

### Shared (both)
- Flask stack, LangChain core, FAISS, matplotlib, networkx, cryptography,
  Redis, Celery, PyMuPDF, Pillow, requests, openpyxl, google-auth

---

## LLM Stack Setup — DeepSeek (Single Provider)

Fortis uses DeepSeek as its single LLM provider, accessed via OpenAI-compatible
API through `ChatOpenAI` from `langchain-openai`. One account, one API key.

### Provider Overview

| Role | Model | Cost (per MTok) |
|------|-------|-----------------|
| Analysis chains | deepseek-v4-flash | $0.14 in / $0.28 out |
| Batch items | deepseek-v4-flash | $0.14 in / $0.28 out |
| ForgeChain safety | deepseek-v4-pro | $0.435 in / $0.87 out |
| ForgeChain consistency | deepseek-v4-pro | $0.435 in / $0.87 out |

**Estimated monthly cost at moderate usage:** ~$2-5

### 1. Get API Key

1. Register at https://platform.deepseek.com (no credit card required)
2. Receive 5M free tokens valid for 30 days
3. Navigate to API Keys in the dashboard
4. Create a new API key and copy it immediately

### 2. Configure Environment

```bash
# .env file
DEEPSEEK_API_KEY=your_deepseek_api_key_here
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
DEEPSEEK_ANALYSIS_MODEL=deepseek-v4-flash
DEEPSEEK_FORGE_MODEL=deepseek-v4-pro
```

### 3. LLM Factory Implementation (`app/llm.py`)

```python
import os
from langchain_openai import ChatOpenAI

_analyst_llm = None
_batch_llm = None
_forge_safety_llm = None
_forge_consistency_llm = None

_BASE_URL = "https://api.deepseek.com/v1"


def get_analyst_llm():
    """DeepSeek v4-flash for all analysis chains (investigation, enrichment, geo, scenario)."""
    global _analyst_llm
    if _analyst_llm is None:
        _analyst_llm = ChatOpenAI(
            model=os.getenv("DEEPSEEK_ANALYSIS_MODEL", "deepseek-v4-flash"),
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url=os.getenv("DEEPSEEK_BASE_URL", _BASE_URL),
            temperature=0.2,
            max_tokens=8192,
        )
    return _analyst_llm


def get_batch_llm():
    """DeepSeek v4-flash at lower temperature for per-entity batch items."""
    global _batch_llm
    if _batch_llm is None:
        _batch_llm = ChatOpenAI(
            model=os.getenv("DEEPSEEK_ANALYSIS_MODEL", "deepseek-v4-flash"),
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url=os.getenv("DEEPSEEK_BASE_URL", _BASE_URL),
            temperature=0.1,
            max_tokens=2048,
        )
    return _batch_llm


def get_forge_safety_llm():
    """DeepSeek v4-pro for ForgeChain safety verification."""
    global _forge_safety_llm
    if _forge_safety_llm is None:
        _forge_safety_llm = ChatOpenAI(
            model=os.getenv("DEEPSEEK_FORGE_MODEL", "deepseek-v4-pro"),
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url=os.getenv("DEEPSEEK_BASE_URL", _BASE_URL),
            temperature=0.2,
            max_tokens=2048,
        )
    return _forge_safety_llm


def get_forge_consistency_llm():
    """DeepSeek v4-pro for ForgeChain consistency verification."""
    global _forge_consistency_llm
    if _forge_consistency_llm is None:
        _forge_consistency_llm = ChatOpenAI(
            model=os.getenv("DEEPSEEK_FORGE_MODEL", "deepseek-v4-pro"),
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url=os.getenv("DEEPSEEK_BASE_URL", _BASE_URL),
            temperature=0.1,
            max_tokens=2048,
        )
    return _forge_consistency_llm
```

### 4. Key Differences from TIPS Hub `llm.py`

| Aspect | TIPS Hub | Fortis |
|--------|----------|--------|
| Integration class | `ChatAnthropicVertex` | `ChatOpenAI` |
| Auth | GCP service account + Vertex AI | Simple API key (env var) |
| GCP dependency | Required (project, region) | None |
| Provider count | 1 (Anthropic via Vertex) | 1 (DeepSeek) |
| SDK packages | `anthropic[vertex]`, `google-cloud-aiplatform`, `langchain-google-vertexai` | `openai`, `langchain-openai` |

### 5. Notes

- **DeepSeek off-peak discount**: 50% off during off-peak hours (check schedule).
- **Context window**: Both v4-flash and v4-pro support 1M tokens — 5x larger than
  Claude's 200K. This benefits batch synthesis and large document enrichment.
- **Caching**: DeepSeek offers cache hit pricing ($0.003625/MTok for v4-flash,
  proportionally for v4-pro). LangChain handles this transparently when available.
- **Fallback strategy**: If DeepSeek is unreachable, the app should log the error
  and surface it in the UI rather than silently failing. The `is_configured()`
  pattern from TIPS Hub applies — check that the API key is set on startup.
- **Ollama Cloud alternative**: Both models are available on Ollama Cloud
  (`https://ollama.com/v1`). Set `DEEPSEEK_BASE_URL` to the Ollama endpoint and
  use your Ollama API key instead — no other changes needed.

---

## Future LLM Considerations

Alternative models evaluated but not selected for the initial build. These can
be swapped in via the `llm.py` factory by changing env vars — no code changes
needed thanks to the OpenAI-compatible API pattern.

### GLM-5.2 (Zhipu AI)

- **Pricing:** $1.40 in / $4.40 out per MTok
- **Strength:** Strong reasoning, 1M context, built-in context caching ($0.26/MTok)
- **Consideration:** Higher reasoning quality than v4-flash on complex analytical
  tasks. Registration at https://open.bigmodel.cn requires Chinese language
  navigation — not currently accessible.
- **When to consider:** If analysis quality with v4-flash is insufficient on
  complex multi-source investigations, and the Zhipu AI signup becomes accessible.

### Kimi K3 (Moonshot AI)

- **Pricing:** $3.00 in / $15.00 out per MTok (cache hits: $0.30 in)
- **Strength:** Strong reasoning, 1M context, open-source weights on HuggingFace
- **Consideration:** Same price tier as Claude Sonnet — no cost advantage. However,
  open-source weights enable self-hosting for data-sensitive deployments where
  API calls to external providers are unacceptable.
- **When to consider:** If data residency requirements mandate self-hosted LLM
  inference, Kimi K3 weights + local GPU deployment is the path.

### Claude Sonnet / Opus (Anthropic)

- **Pricing:** Sonnet $3/$15, Opus $5/$25 per MTok
- **Strength:** Proven in TIPS Hub, excellent safety judgment for ForgeChain
- **Consideration:** Highest quality option for governance verifiers. If ForgeChain
  false-positive/negative rates are unacceptable with DeepSeek v4-pro, upgrading
  the forge verifiers to Claude Opus is a one-line env var change.
- **When to consider:** If ForgeChain testing reveals safety judgment gaps in
  DeepSeek v4-pro that require Opus-tier reasoning.

---

## Setup Instructions

### 1. Clone & Virtual Environment

```bash
cd C:\Users\fokon\Documents\Fortis-Intelligence-Hub
python -m venv .venv
source .venv/Scripts/activate    # Windows Git Bash
pip install -r requirements.txt
```

### 2. SpaCy Model Download

```bash
python -m spacy download en_core_web_sm
```

### 3. MaxMind GeoLite2 Database

```bash
# Download GeoLite2-City.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# Place in data/GeoLite2-City.mmdb
# Requires free MaxMind account for license key
```

### 4. Environment Configuration

```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

### 5. Run Locally

```bash
# Option A: Flask dev server
python run.py

# Option B: Waitress (Windows production)
python run_windows.py

# Option C: With Celery (for feed monitors)
# Terminal 1: Redis
redis-server

# Terminal 2: Celery worker
celery -A app.celery_app worker --loglevel=info --pool=solo

# Terminal 3: App
python run_windows.py
```

---

## Directory Initialization

On first run, `create_app()` should:

1. Create `data/` directory if missing
2. Initialize `data/report_store.db` with schema
3. Initialize `data/forge_chain.db` with schema
4. Create `vectorstores/` directory if missing
5. Create `logs/` directory if missing
6. Verify OSINT source availability (`osint_client.is_configured()`)
7. Log available/unavailable sources to console
8. Verify ForgeChain health
9. Archive stale KB reports per retention policy

---

## Docker Setup

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m spacy download en_core_web_sm

# App code
COPY . .

# MaxMind DB (mount or copy)
# COPY GeoLite2-City.mmdb data/

EXPOSE 8080

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8080", "app.web:create_app()"]
```

---

## Minimum Viable Configuration

The app should run with zero OSINT API keys configured, with graceful degradation:

| Source          | Without API Key                                        |
|-----------------|--------------------------------------------------------|
| Twitter/X       | Disabled — "Twitter not configured" in UI              |
| Reddit          | Disabled — "Reddit not configured" in UI               |
| Telegram        | Disabled — "Telegram not configured" in UI             |
| Instagram       | Disabled — "Instagram not configured" in UI            |
| YouTube         | Disabled — "YouTube not configured" in UI              |
| Nominatim       | Available — no key needed (rate-limited)               |
| MaxMind         | Falls back to ipapi.co free tier                       |
| NewsAPI         | Disabled — "News search not configured" in UI          |
| Shodan          | Disabled — "Shodan not configured" in UI               |
| Google Geocoding| Falls back to Nominatim only                           |

Core features that work without any API keys:
- PDF/MD upload + RAG Q&A
- Manual EXIF extraction from uploaded images
- Manual coordinate entry for triangulation
- Knowledge Base management
- All export formats
- ForgeChain governance
