# Fortis Intelligence Hub — Architecture Overview

## Vision

Fortis Intelligence Hub is an OSINT-driven intelligence and analysis platform for
open-source intelligence gathering, geospatial triangulation, and analyst-grade
report generation. It adapts the proven TIPS Hub hybrid architecture — ingestion,
enrichment, governance, and export — but replaces cybersecurity threat intel with
general-purpose OSINT from social media and the open internet.

## Core Principles

1. **OSINT-first** — All intelligence sourced from publicly available information:
   social media platforms, public records, news, forums, and metadata analysis.
2. **Geospatial intelligence** — Location triangulation from OSINT metadata
   (EXIF, geotags, timezone inference, language analysis, IP geolocation) is a
   first-class feature with interactive mapping.
3. **Governance by default** — Every LLM invocation passes through ForgeChain's
   consensus gate. No ungoverned AI output reaches the analyst.
4. **Human-in-the-loop** — Automated enrichment produces drafts; analysts approve
   before any external action.
5. **Single-mode operation** — No CTI/Red Team toggle. One unified analyst mode
   with a consistent black-and-purple punk aesthetic.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FORTIS INTELLIGENCE HUB                 │
├─────────────┬──────────────┬──────────────┬─────────────────┤
│   Ingestion │  Enrichment  │   Analysis   │     Output      │
│             │              │              │                 │
│ • PDF/MD    │ • Social API │ • LLM Chains │ • PDF Export    │
│   upload    │   enrichment │(DS v4-flash)│ • Markdown      │
│ • Manual    │ • Web scrape │ • RAG Q&A    │ • STIX 2.1      │
│   entry     │ • Metadata   │ • Scenario   │ • CSV / JSON    │
│ • Batch     │   extraction │   generation │ • Google Drive  │
│   import    │ • Geo lookup │ • Synthesis  │ • Map snapshots │
│ • RSS/Feed  │ • WHOIS/DNS  │ • Knowledge  │                 │
│   monitor   │ • News crawl │   Base RAG   │                 │
└──────┬──────┴──────┬───────┴──────┬───────┴────────┬────────┘
       │             │              │                │
       ▼             ▼              ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│                     FORGECHAIN GOVERNANCE                    │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  Rule    │  │  LLM Safety  │  │  LLM Consistency      │  │
│  │ Verifier │  │  Verifier    │  │  Verifier             │  │
│  └────┬─────┘  └──────┬───────┘  └───────────┬───────────┘  │
│       └───────────────┼──────────────────────┘              │
│                 Consensus Gate (2/3)                         │
│                 Token Mint → Execute → Persist               │
└─────────────────────────────────────────────────────────────┘
       │             │              │                │
       ▼             ▼              ▼                ▼
┌─────────────────────────────────────────────────────────────┐
│                      DATA LAYER                             │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │  SQLite  │  │    FAISS     │  │   Redis (optional)    │  │
│  │ Reports  │  │  Vectorstore │  │   Task queue cache    │  │
│  │ Forge DB │  │  Knowledge   │  │                       │  │
│  └──────────┘  │  Base        │  └───────────────────────┘  │
│                └──────────────┘                              │
└─────────────────────────────────────────────────────────────┘
```

---

## What Carries Over from TIPS Hub

| Component              | TIPS Hub                        | Fortis Adaptation                         |
|------------------------|---------------------------------|-------------------------------------------|
| Web framework          | Flask + Jinja2 SPA              | Same — Flask + single `index.html`        |
| LLM orchestration      | LangChain LCEL + Claude Vertex  | LangChain LCEL + DeepSeek v4-flash (analysis) + DeepSeek v4-pro (ForgeChain) via OpenAI-compatible API |
| ForgeChain governance  | 10-step `gated_invoke()`        | Carried over unchanged                    |
| Knowledge Base         | FAISS + ReportStore             | Same — FAISS vectorstore + SQLite         |
| Export system           | PDF, Markdown, STIX, CSV, JSON  | Same + map snapshot export                |
| Auth                   | Google OAuth + role resolution  | Same — Google OAuth, simplified roles     |
| Audit logging          | JSON-structured audit trail     | Same                                      |
| Celery task queue      | Auto-TIPS webhook processing    | Adapted for feed monitoring tasks         |
| Session management     | In-memory with timeout          | Same                                      |
| PDF ingestion          | PyMuPDF → pypdf → EasyOCR      | Same 3-tier extraction                    |

## What Changes

| Component              | TIPS Hub                        | Fortis Replacement                        |
|------------------------|---------------------------------|-------------------------------------------|
| Intel source           | Recorded Future API             | OSINT client (social, web, metadata)      |
| Threat intel platform  | MISP                            | Not needed (optional future add)          |
| Jira integration       | Ticket parsing + auto-analysis  | Removed — manual or feed-based ingestion  |
| Dual mode              | CTI + Red Team                  | Single analyst mode                       |
| Product constants      | Red Hat product tiers           | Removed — domain-agnostic                 |
| Charts                 | Risk scores, severity heatmaps  | Geo heatmaps, timeline, network graphs    |
| Graph visualization    | CVE/threat actor knowledge graph| Entity relationship + geospatial graph    |
| Map feature            | None                            | Leaflet.js with OSM + geocoding           |
| UI theme               | Blue (CTI) / Red (Red Team)     | Black + purple punk (single theme)        |
| TLP classification     | Score-based TLP enforcement     | Analyst-assigned sensitivity level        |

---

## Deployment Targets

1. **Local development** — `python run.py` (Flask dev server) or `python run_windows.py` (Waitress)
2. **Containerized** — Dockerfile with multi-stage build
3. **OpenShift** — Helm chart / Kustomize overlays (mirrors TIPS Hub deploy structure)

---

## Module Map (Planned)

```
fortis-intelligence-hub/
├── run.py
├── run_windows.py
├── requirements.txt
├── .env.example
├── Dockerfile
│
├── app/
│   ├── __init__.py
│   ├── web.py                  # Flask app factory + routes
│   ├── chains.py               # LLM prompt templates (OSINT analysis)
│   ├── llm.py                  # LLM factory: DeepSeek v4-flash (analysis) + v4-pro (ForgeChain)
│   ├── osint_client.py         # OSINT aggregator client
│   ├── social_client.py        # Social media API integrations
│   ├── geo_client.py           # Geolocation + mapping services
│   ├── metadata_extractor.py   # EXIF, geotag, timezone extraction
│   ├── web_scraper.py          # News, forum, public record scraping
│   ├── export.py               # PDF/Markdown report generation
│   ├── export_ioc.py           # IOC/entity export (STIX, CSV, JSON)
│   ├── rag_store.py            # FAISS vectorstore + Knowledge Base
│   ├── report_store.py         # SQLite report persistence
│   ├── intel_graph.py          # Entity relationship graph
│   ├── charts.py               # Matplotlib chart generation
│   ├── feed_monitor.py         # RSS/social feed monitoring (Celery)
│   ├── celery_app.py           # Task queue configuration
│   ├── redis_store.py          # Feed monitor record store
│   ├── notifications.py        # Slack/email notifications
│   ├── constants.py            # Platform configs, API endpoints
│   │
│   ├── forge/                  # ForgeChain (carried over)
│   │   ├── models.py
│   │   ├── gate.py
│   │   ├── verifiers.py
│   │   ├── gated_invoke.py
│   │   ├── executor.py
│   │   ├── healer.py
│   │   ├── interpreter.py
│   │   ├── chain_store.py
│   │   ├── replay.py
│   │   ├── audit_integration.py
│   │   └── config.py
│   │
│   ├── auth/                   # Auth (carried over, simplified)
│   │   ├── config.py
│   │   ├── oauth_client.py
│   │   ├── session_manager.py
│   │   ├── decorators.py
│   │   └── audit_logger.py
│   │
│   └── utils/
│       ├── pdf_reader.py
│       ├── uploads.py
│       └── sanitizer.py        # Input sanitization utilities
│
├── templates/
│   ├── index.html              # Main SPA
│   └── welcome.html            # Landing page
│
├── static/
│   ├── css/
│   │   └── styles.css          # Black + purple punk theme
│   ├── js/
│   │   ├── app.js              # Application logic
│   │   ├── map.js              # Leaflet.js map controller
│   │   ├── chart.min.js        # Chart.js
│   │   └── cytoscape.min.js    # Graph visualization
│   └── img/
│       └── fortis-logo.svg     # Branding
│
├── tests/
├── data/
├── vectorstores/
├── logs/
└── plans/                      # Design documentation (this dir)
```
