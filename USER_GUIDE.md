# Fortis Intelligence Hub — User Guide

**Version 1.1** | **Last Updated: August 2026**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [UI Overview](#ui-overview)
4. [Core Features](#core-features)
   - [Report Ingestion](#report-ingestion)
   - [Investigation](#investigation)
   - [Geolocation](#geolocation)
   - [Q&A System](#qa-system)
   - [Feed Monitor](#feed-monitor)
   - [Scenarios](#scenarios)
   - [Batch Investigation](#batch-investigation)
   - [Entity Graphs](#entity-graphs)
   - [Knowledge Base](#knowledge-base)
   - [Export Options](#export-options)
   - [Civilian Harm Classifier](#civilian-harm-classifier)
   - [Image Analysis](#image-analysis)
   - [Wayback Machine Integration](#wayback-machine-integration)
   - [Web Intelligence](#web-intelligence)
   - [ForgeChain Governance](#forgechain-governance)
5. [Example Use Cases](#example-use-cases)
6. [Tips and Best Practices](#tips-and-best-practices)
7. [Troubleshooting](#troubleshooting)

---

## Introduction

**Fortis Intelligence Hub** is a Flask-based Open Source Intelligence (OSINT) investigation platform designed for security researchers, journalists, and analysts. With its cyberpunk-inspired black/purple interface, the platform provides comprehensive tools for digital investigations, social media analysis, geolocation, and threat intelligence gathering.

### Key Capabilities

- **Multi-platform OSINT**: Investigate across Twitter/X, Reddit, YouTube, Instagram, Mastodon, Facebook, TikTok, and Telegram
- **Domain & IP Analysis**: WHOIS, DNS, reverse lookups, historical data via Wayback Machine
- **Geolocation**: EXIF extraction, IP geolocation, clustering, triangulation
- **Image Forensics**: ELA tampering detection, steganography, reverse search, CLIP classification
- **AI-Powered Analysis**: RAG-based Q&A, entity extraction, LLM-driven insights
- **Feed Monitoring**: Background feed polling with Celery and auto-enrichment
- **Civilian Harm Detection**: Bellingcat-inspired semantic scoring for conflict zones
- **Multi-format Export**: PDF, STIX 2.1, JSON, CSV, Markdown, Google Drive
- **Governance**: ForgeChain 3-verifier consensus for all LLM-driven operations

---

## Quick Start

### Your First Investigation in 5 Minutes

**Scenario**: Investigate a Twitter/X username

1. **Navigate to Investigation**
   - Click the **Investigation** tool card in the toolbar strip at the top of the workspace

2. **Enter Your Target**
   - In the **Subject Identifier** field, type: `@example_user`
   - Leave Identifier Type on **Auto-detect** (the system recognises usernames, emails, domains, and IPs)

3. **Select Investigation Depth**
   - Choose **Standard** from the depth dropdown
   - Quick: API calls only (30-60 seconds)
   - Standard: API + web scraping (2-5 minutes)
   - Deep: All sources + metadata + entity extraction (5-15 minutes)

4. **Run Investigation**
   - Click **Investigate** at the bottom of the input panel
   - A loading indicator shows collection is in progress
   - Results appear in the right-hand results panel

5. **Review Results**
   - **Analysis tab**: LLM-generated investigation report with profile data, posts, entities, and insights
   - **Map tab**: Appears if geolocation data was found (EXIF, IP geo)
   - **Graph tab**: Entity relationship graph rendered with Cytoscape.js
   - **Civilian Harm**: If enabled, flagged content with severity scores appears in the analysis

6. **Export Your Findings**
   - Use the export bar at the bottom of the results panel
   - Click **PDF**, **MD**, **STIX**, **CSV**, **JSON**, or **Drive**

**Congratulations!** You've completed your first investigation.

---

## UI Overview

The interface is a single-page application (SPA) with no separate pages or settings screens. Everything is accessible from the main workspace.

### Top Bar

- **Logo**: Click to return to the welcome page
- **OSINT Status**: Green dot indicates OSINT services are online
- **User Info**: Your Google avatar and name (when OAuth is enabled)
- **KB**: Opens the Knowledge Base slide-in panel
- **Watch**: Opens the Feed Monitor slide-in panel to review findings
- **Sign Out**: Logs out of the current session

### Tool Cards

A horizontal strip of 8 tool cards across the top of the workspace:
- **Report Ingestion** — Upload PDF/Markdown documents
- **Investigation** — OSINT investigation of a single target
- **Geolocation** — GPS extraction, IP geolocation, map visualisation
- **Batch Investigation** — Investigate multiple targets at once
- **Feed Monitor** — Set up background monitoring
- **Scenarios** — Run analytical scenarios (Pattern of Life, Network Mapping, etc.)
- **Image Analysis** — Standalone forensics, steganography, reverse search, CLIP
- **Q&A (RAG)** — Chat with your knowledge base

Click a tool card to switch the input panel form. The active card is highlighted.

### Split Panels

- **Input Panel** (left, ~35%): Shows the form for the active tool. Submit button at the bottom.
- **Results Panel** (right, ~65%): Shows results with tabs for Analysis, Map, Graph, and Charts. Export bar at the bottom.

### Slide-in Panels

- **Watch Panel**: Opened via the Watch button in the top bar. Shows feed monitor findings with Approve and Dismiss actions.
- **Knowledge Base Panel**: Opened via the KB button. Shows uploaded documents with search, delete, toggle inclusion, rebuild index, and stats.

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Esc` | Close the Watch or Knowledge Base panel |
| `Enter` | Send message in Q&A chat |
| `Tab` | Navigate form fields (browser default) |

---

## Core Features

### Report Ingestion

Upload and analyse PDF or Markdown documents with AI-powered extraction.

#### How It Works

The system uses a 3-tier extraction pipeline:
1. **PyMuPDF**: Primary text extraction with layout preservation
2. **pypdf**: Fallback for encrypted or complex PDFs
3. **OCR**: Last resort for scanned documents or images

Extracted content is indexed into a FAISS vectorstore for semantic search and Q&A.

#### Step-by-Step

1. Click the **Report Ingestion** tool card
2. Drag files into the upload zone or click to browse
   - Supported formats: `.pdf`, `.md`, `.txt`
   - Max file size: 50 MB each
3. Optionally add comma-separated tags (e.g. `threat-intel, q3-review`)
4. Click **Ingest Reports**
5. The system extracts text, splits into chunks, and indexes into the knowledge base
6. Use the **Q&A** tool or **Knowledge Base** panel to search and query the content

#### Use Cases

- **Threat Intelligence Reports**: Extract IOCs, TTPs, attribution
- **News Articles**: Verify claims, extract dates and locations
- **Research Papers**: Summarise findings, compare methodologies
- **Legal Documents**: Search for specific clauses, entities, dates

---

### Investigation

The core OSINT feature for investigating usernames, emails, domains, and IP addresses.

#### Auto-Detection

The system automatically identifies:
- **Username**: `@username`, `username` (searches Twitter, Reddit, Instagram, etc.)
- **Email**: `user@example.com` (breach databases, social profiles)
- **Domain**: `example.com`, `www.example.com` (WHOIS, DNS, subdomains)
- **IP Address**: `8.8.8.8` (geolocation, reverse DNS, co-hosted domains)

You can also manually set the identifier type via the dropdown.

#### Investigation Depths

**Quick** (30-60 seconds)
- API calls only
- Public profile data
- Basic metadata
- Best for: Initial reconnaissance, batch investigations

**Standard** (2-5 minutes)
- API + web scraping
- Recent posts/comments (last 20-50)
- DNS/WHOIS data
- Basic entity extraction
- Best for: Most investigations

**Deep** (5-15 minutes)
- All Standard features
- Extended post history (100-500 items)
- Metadata extraction (EXIF, headers)
- Full entity graph construction
- Cross-platform correlation
- Wayback Machine historical data (for domains)
- Best for: Comprehensive dossiers, legal evidence

#### Investigation Form Options

- **Subject Identifier**: The target to investigate
- **Identifier Type**: Auto-detect or manual selection (username, email, phone, domain, name, IP, keyword)
- **Platforms**: Checkboxes for Twitter/X, Reddit, Telegram, Instagram, YouTube, Mastodon, Facebook, TikTok
- **Investigation Depth**: Quick, Standard, or Deep
- **Investigation Purpose**: Free-text field describing the scope and reason
- **Media Files**: Upload images/videos for EXIF geo extraction + image forensics + CLIP classification (run automatically alongside the investigation)
- **Search Web for Missing Intel**: Checkbox (default: on) — enables the Web Intelligence dork search pipeline

#### Platform-Specific Features

**Twitter/X**
- Profile: Bio, location, follower/following counts, join date
- Recent tweets with engagement metrics
- Account verification status
- Linked accounts via bio URLs

**Reddit**
- Karma scores (post/comment)
- Subreddit activity breakdown
- Recent posts and comments
- Account age

**Domain Investigation**
- **WHOIS**: Registrant, registrar, creation/expiration dates
- **DNS Records**: A, MX, TXT, CNAME records
- **Subdomains**: DNSdumpster enumeration
- **HTTP Headers**: Server info, security headers, cookies
- **Reverse DNS/IP**: Co-hosted domains on same IP
- **Wayback Machine**: Historical snapshots, subdomain discovery

**IP Address Investigation**
- **Geolocation**: Country, city, coordinates, ISP, ASN
- **Reverse DNS**: Hostnames pointing to this IP
- **Reverse IP**: Other domains hosted on same IP

#### Civilian Harm Analysis (Optional)

Check **Enable Civilian Harm Analysis** in the investigation form to apply Bellingcat-inspired scoring to all collected content. See the [Civilian Harm Classifier](#civilian-harm-classifier) section for details.

---

### Geolocation

Upload images or enter IP addresses for GPS coordinate extraction, geolocation, and map visualisation.

#### Input Tabs

The geolocation form has four tabs:

1. **Images**: Upload images (JPEG, PNG, TIFF) for EXIF GPS extraction
2. **Social Posts**: Paste social media URLs or text with location mentions
3. **IP Addresses**: Enter IP addresses (one per line) for geolocation lookup
4. **Manual**: Enter coordinates (lat/lng pairs) or street addresses

#### Features

- **EXIF GPS Extraction**: Pull coordinates from image metadata
- **IP Geolocation**: Geolocate IP addresses via API lookup
- **Clustering**: DBSCAN algorithm groups nearby locations
- **Triangulation**: Combine multiple partial coordinates
- **Interactive Maps**: Leaflet.js with cluster markers, fullscreen mode, heatmap layer
- **Map Snapshot**: Camera button on the map exports a PNG screenshot

#### Step-by-Step

1. Click the **Geolocation** tool card
2. Select the appropriate tab (Images, Social Posts, IP, or Manual)
3. Upload files or enter data
4. Click **Geolocate**
5. Results appear in the Analysis tab with extracted coordinates
6. The Map tab shows an interactive Leaflet map with markers and clustering
7. Use the fullscreen button on the map for detailed viewing
8. Export results via the export bar (included in PDF/MD/JSON exports)

#### Use Cases

- **Photo Verification**: Confirm claimed location of social media posts
- **Surveillance Detection**: Find patterns in movement from geotagged photos
- **Event Reconstruction**: Map out sequence of events using timestamps
- **OPSEC Audits**: Check for accidental geolocation leaks

---

### Q&A System

Ask natural language questions about uploaded documents and the knowledge base.

#### How It Works

- **RAG Architecture**: Retrieval-Augmented Generation with FAISS vectorstore
- **Semantic Search**: Finds relevant document chunks (not just keyword matching)
- **Knowledge Base Integration**: Searches across all uploaded reports and investigation results
- **Civilian Harm Context**: Automatically flags answers related to conflict/harm

#### Step-by-Step

1. Click the **Q&A (RAG)** tool card
2. The input panel shows a chat interface
3. Type your question in the chat input and press **Enter** or click the send button
4. The system retrieves relevant document chunks and generates an answer
5. Responses appear in the chat as AI messages

#### Example Queries

- "What threats are mentioned in the Q3 report?"
- "Who is the CEO of Acme Corp?"
- "When did the incident occur?"
- "List all IP addresses mentioned"
- "Summarise the key findings in under 100 words"

---

### Feed Monitor

Background monitoring of keywords, usernames, hashtags, or locations across platforms.

#### Features

- **Celery Background Polling**: Async task processing with beat scheduler
- **Flexible Intervals**: 5 minutes to 4 hours
- **Auto-Enrichment**: New posts automatically analysed with LLM
- **Civilian Harm Scoring**: All monitored content scored for sensitivity
- **Watch Panel**: Slide-in panel for reviewing findings (Approve / Dismiss)

#### Step-by-Step

1. Click the **Feed Monitor** tool card
2. Fill in the monitor form:
   - **Monitor Type**: Keyword, Username, Hashtag, or Location Radius
   - **Query**: The term to monitor (e.g. `#Kharkiv`, `@username`, `"civilian casualties"`)
   - **Platforms**: Select one or more (Twitter, Reddit, Telegram, Mastodon, Instagram, YouTube, Facebook, TikTok)
   - **Check Interval**: How often to poll (5 min to 4 hours)
   - **Alert Threshold**: All findings, High confidence only, or Geo matches only
3. Click **Start Monitor**
4. Celery beat scheduler begins background polling

#### Reviewing Findings

1. Click the **Watch** button in the top bar to open the Watch panel
2. Findings appear with platform, author, content preview, and timestamps
3. For each finding, click **Approve** to keep or **Dismiss** to discard
4. Click **Clear All Findings** to reset the panel

#### Best Practices

- **Start Broad, Then Narrow**: Begin with general keywords, refine based on results
- **Use Multiple Monitors**: Separate monitors for different aspects (locations, actors, events)
- **Balance Interval**: Too frequent = rate limits; too slow = miss time-sensitive posts
  - Breaking news: 5-10 minutes
  - General monitoring: 30-60 minutes
  - Low-priority: 120-240 minutes

---

### Scenarios

Pre-built analytical frameworks for common investigation patterns.

#### Available Scenarios

1. **Pattern of Life** — Analyses posting times, locations, language patterns to identify routines
2. **Network Mapping** — Extracts mentions, interactions, co-authors to build relationship maps
3. **Location Prediction** — Uses historical geolocation data + time-based patterns
4. **Influence Analysis** — Measures reach, engagement, amplification patterns

#### Step-by-Step

1. Click the **Scenarios** tool card
2. Select scenario type from the dropdown
3. Optionally enter a **Session Reference** (session ID from a prior investigation to use as context)
4. Optionally provide **Subject Context** (additional background about the target)
5. Optionally paste **OSINT Data** (raw data, or leave blank to pull from session/KB)
6. Click **Generate Scenario**
7. The LLM analyses the available data and produces the scenario report in the Analysis tab

---

### Batch Investigation

Investigate multiple targets simultaneously with cross-entity synthesis.

#### Step-by-Step

1. Click the **Batch Investigation** tool card
2. Enter identifiers in the text area (one per line), or upload a CSV/XLSX file
   - Mix types allowed (usernames, emails, domains, IPs)
   - Up to 100 identifiers
3. Select **Identifier Type** (Auto-detect or manual)
4. Select **Platforms** to search
5. Click **Batch Investigate**
6. Results appear in the Analysis tab with per-target summaries and cross-entity synthesis

#### Use Cases

- **Group Investigations**: Known associates, criminal networks
- **Infrastructure Mapping**: Related domains, IP ranges, server clusters
- **Comparison**: Analyse multiple accounts for similarities (sockpuppet detection)
- **Campaign Analysis**: Track multiple hashtags/topics for coordinated activity

---

### Entity Graphs

Interactive visualisation of people, places, organisations, and their relationships.

#### Features

- **Cytoscape.js**: High-performance graph rendering in the Graph tab
- **Click-to-Inspect**: Click any node to see entity details in a popup
- **Entity-Aware LLM**: AI understands graph structure for better analysis

#### Node Types

- **Person**: Blue circle (usernames, names, authors)
- **Organization**: Purple square (companies, groups)
- **Location**: Green diamond (cities, countries, addresses)
- **Domain**: Orange hexagon (websites, domains)
- **IP Address**: Red triangle (IP addresses, servers)
- **Content**: White circle (posts, documents, media)

#### Using the Graph

1. Entity graphs are automatically generated during **Standard** or **Deep** investigations
2. Click the **Graph** tab in the results panel to view
3. Navigate:
   - **Pan**: Click and drag background
   - **Zoom**: Scroll wheel
   - **Select**: Click node to see entity details
   - **Move**: Drag individual nodes to rearrange
4. The graph data is included when you export via PDF, Markdown, or JSON

#### Analysis Tips

- **Central Nodes**: Largest/most-connected = key players
- **Clusters**: Tightly connected groups = communities or campaigns
- **Bridges**: Nodes connecting clusters = information brokers
- **Isolates**: Disconnected nodes = may need further investigation

---

### Knowledge Base

Auto-indexed repository of all investigation results and uploaded documents.

#### Accessing the Knowledge Base

Click the **KB** button in the top bar to open the Knowledge Base slide-in panel.

#### Features

- **Search**: Type in the search bar to filter documents by name
- **Document List**: Shows all indexed reports with their names
- **Toggle Inclusion**: Include or exclude specific documents from Q&A searches
- **Delete**: Remove individual documents from the knowledge base
- **Rebuild Index**: Re-index all documents in the FAISS vectorstore
- **Stats**: View document count and chunk count

#### How Content Gets Indexed

- **Report Ingestion**: Uploaded PDFs and Markdown files are automatically chunked and indexed
- **Investigations**: Investigation results can be saved to the knowledge base
- All indexed content is searchable via the Q&A tool

---

### Export Options

Multiple export formats available via the export bar at the bottom of the results panel.

#### PDF Export

- Dark cyberpunk theme consistent with the UI
- Section-aware layout with auto page breaks
- TLP classification headers/footers
- Table of Contents with hyperlinks
- LLM-generated executive summary
- Embedded graphs and map data

#### Markdown Export

- Plain text with Markdown formatting
- TLP headers
- YAML frontmatter with metadata
- Easy to edit or convert to other formats

#### STIX 2.1 Export

- Industry-standard threat intelligence format
- Compatible with TAXII servers and Threat Intelligence Platforms (MISP, OpenCTI, etc.)
- Includes: observables, indicators, relationships, TTPs

#### CSV Export

- Tabular data (posts, entities, locations)
- Easy import to Excel, Google Sheets, databases

#### JSON Export

- Full investigation data (unfiltered)
- Useful for API integration, custom parsing

#### Google Drive Export

- Direct upload to Google Drive (requires OAuth configuration)
- Supports all formats (PDF, Markdown, STIX, CSV, JSON)

#### How to Export

1. Run any investigation, geolocation, or analysis
2. Results appear in the results panel
3. Click the desired format button in the export bar at the bottom:
   - **PDF** | **MD** | **STIX** | **CSV** | **JSON** | **Drive**
4. The file downloads or uploads to Drive

---

### Civilian Harm Classifier

Bellingcat-inspired methodology for detecting conflict-related content.

#### Methodology

**Semantic Similarity Scoring:**
- Uses `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` model
- Compares each post/comment against 15 harm-related reference concepts:
  - Civilian casualties and deaths from armed conflict
  - Hospital or medical facility attacked or destroyed
  - School or educational facility damaged in conflict
  - Residential buildings destroyed by shelling or airstrikes
  - Forced displacement of civilian population
  - Injuries to civilians including women and children
  - Critical infrastructure destruction affecting civilian life
  - Humanitarian crisis and civilian suffering in war zone
  - War crimes or violations of international humanitarian law
  - Deliberate targeting of civilian areas and populated zones
  - Mass graves or extrajudicial killings of civilians
  - Siege and starvation of civilian population
  - Sexual violence as weapon of war
  - Child soldiers or recruitment of minors
  - Destruction of cultural heritage sites

**Multilingual Keyword Matching:**
- Dictionaries for English, Ukrainian, Russian, Arabic, and French
- Keywords cover: airstrikes, casualties, displacement, bombing, shelling, etc.
- Weighted scoring based on severity

**Scoring Levels:**
- **Low** (0.0-0.3): General news, no harm indicators
- **Medium** (0.3-0.6): Conflict mentions, protests, non-lethal violence
- **High** (0.6-0.8): Direct harm descriptions, casualties, displacement
- **Critical** (0.8-1.0): Explicit violence, war crimes, mass casualties

#### How to Use

1. In the Investigation form, check **Enable Civilian Harm Analysis**
2. The system scores all collected posts, comments, and media
3. Results appear in the Analysis tab showing:
   - Distribution of severity levels across content
   - Flagged items sorted by score (highest first)
   - Matched concepts and keywords per item

**Environment Variable:**
- `CIVILIAN_HARM_ENABLED`: Enable/disable globally (default: `true`)
- `HARM_MODEL_NAME`: Override the sentence-transformers model (default: `paraphrase-multilingual-MiniLM-L12-v2`)

---

### Image Analysis

Four-module image forensics and intelligence pipeline.

#### Modules

**1. Reverse Image Search**
- Searches Yandex, Google Lens, and Bing using PicImageSearch (free, no API key required)
- Yandex CBIR is particularly strong for finding people and faces
- Returns matching pages with titles, URLs, and working search links you can open in a browser
- Optional TinEye API for exact-match detection (requires paid `TINEYE_API_KEY`)
- Perceptual hash cache (pHash, dHash, aHash) detects similar images across investigations

**2. Error Level Analysis (ELA)**
- Re-compresses the image at known quality and measures pixel-level differences
- Tampered regions show higher error levels (brighter in ELA output)
- Clone detection via block matching identifies copy-paste manipulations
- Metadata strip detection flags images with suspiciously absent EXIF data

**3. Steganography Detection**
- LSB (Least Significant Bit) chi-square test reveals hidden data in pixel values
- RS analysis measures statistical anomalies indicating steganographic embedding
- Sample pairs test provides a second statistical measure for confirmation

**4. CLIP Vision Classification**
- Zero-shot classification against 22 OSINT-relevant categories (military vehicles, weapons, protests, infrastructure damage, documents, surveillance equipment, etc.)
- Landmark detection against 50 locations including conflict zones (Aleppo, Mariupol, Gaza) and major cities
- Content safety screening (graphic violence, explicit content, disturbing imagery)

#### Two Ways to Use

**During Investigation:**
- Upload images via the **Media Files** field in the investigation form
- All 4 analyses run automatically alongside OSINT collection
- Results appear in the investigation report and feed into the LLM analysis context

**Standalone Analysis:**
- Click the **Image Analysis** tool card
- Drag and drop or select images (JPEG, PNG, TIFF, WebP)
- Select which modules to run (all enabled by default via checkboxes)
- Click **Analyse Images**
- Results show per image:
  - **Forensics**: Verdict (AUTHENTIC / POSSIBLY / LIKELY MANIPULATED), confidence, flags
  - **Steganography**: Verdict (NO STEGANOGRAPHY / POSSIBLE / LIKELY), confidence, estimated payload
  - **Classification**: Top-5 OSINT categories with confidence, detected landmarks, safety rating
  - **Reverse Search**: Yandex/Google Lens/Bing matches with clickable links, working search URLs, similar cached images

#### Configuration

Each module can be independently enabled/disabled via environment variables:

| Variable | Default | Description |
|---|---|---|
| `IMAGE_SEARCH_ENABLED` | `true` | Reverse image search |
| `IMAGE_FORENSICS_ENABLED` | `true` | ELA and clone detection |
| `IMAGE_STEGO_ENABLED` | `true` | Steganography detection |
| `IMAGE_VISION_ENABLED` | `true` | CLIP classification |
| `TINEYE_API_KEY` | (none) | Optional TinEye API key for reverse search |

---

### Wayback Machine Integration

Historical domain data from the Internet Archive's CDX API.

#### Features

- **Historical Snapshots**: Retrieve all archived versions of a domain
- **Subdomain Discovery**: Find subdomains from archived pages
- **No API Key Required**: Free access via CDX API

#### How It Works

When you investigate a domain with **Standard** or **Deep** depth:
1. System queries Wayback CDX API for all snapshots
2. Analyses snapshot timestamps, URLs, status codes
3. Discovers subdomains from archived internal links
4. Results are included in the LLM investigation analysis

#### Use Cases

- **Domain History**: Track ownership changes, previous content
- **Subdomain Enumeration**: Find forgotten or decommissioned subdomains
- **OPSEC Audits**: Check for historical leaks in archived pages
- **Evidence Preservation**: Verify domain existed on specific date

---

### Web Intelligence

LLM-driven dork search with a 4-phase analysis pipeline. Runs automatically during investigations when the **Search Web for Missing Intel** checkbox is enabled.

#### Architecture

**Phase 1: Gap Analysis**
- LLM reviews the investigation report and OSINT data
- Identifies intelligence gaps (platforms that returned no data, unanswered questions)
- Generates 3-5 targeted dork queries to fill those gaps

**Phase 2: Validation**
- LLM generates 3-5 dork queries to cross-reference key findings
- Queries executed via DuckDuckGo (no API key required)

**Phase 3: Synthesis**
- LLM integrates gap-fill results and validates existing data
- Rates each result: NEW_INTEL / CONFIRMED / CONTRADICTED / INCONCLUSIVE
- Assigns confidence levels: HIGH / MODERATE / LOW
- Flags HIGH and MODERATE results for deep scraping

**Phase 4: Deep Scrape** (confidence-gated)
- Only HIGH and MODERATE confidence results get full page scraping
- Uses existing web scraper with content sanitisation
- LLM enriches findings with full-page details

#### How to Use

1. In the Investigation form, ensure **Search Web for Missing Intel** is checked (default: on)
2. Run the investigation as normal
3. Web Intelligence runs automatically after the main investigation completes
4. Results appear as a "Web Intelligence" section in the investigation report
5. The section includes discovered URLs, new intelligence, and validation results

#### Security

- All 4 phases go through ForgeChain 3-verifier consensus
- Queries are sanitised (blocked operators, anti-exfiltration, 256-char limit)
- Search results undergo HTML stripping, truncation, and injection pattern scanning
- Rate limited: max 10 queries per investigation
- Feature toggle: `DORK_VALIDATION_ENABLED` (default: `true`)

---

### ForgeChain Governance

3-verifier consensus gate applied to all LLM-driven operations.

#### Verifiers

1. **Rule Verifier**: Checks against defined policies (no PII extraction, geo-restrictions, etc.)
2. **Safety Verifier**: Detects harmful intent (doxxing, harassment, illegal activity)
3. **Consistency Verifier**: Ensures request aligns with historical patterns

**Consensus Requirement:**
- All 3 verifiers must approve (unanimous) for the operation to proceed
- Any rejection blocks the operation
- Uses `deepseek-v4-pro` model for governance decisions (configurable via `DEEPSEEK_FORGE_MODEL`)

#### Audit Trail

Every ForgeChain decision is logged as a ForgeBlock in an append-only hash chain, recording:
- Timestamp
- Chain/operation type
- Verifier decisions (approve/reject with reasoning)
- Final outcome (allowed/blocked)

#### Governed Operations

ForgeChain governs all major LLM chains including:
- Investigation analysis
- Scenario generation
- Batch cross-entity synthesis
- Web Intelligence (all 4 dork phases)
- Report Q&A

---

## Example Use Cases

### Use Case 1: Investigating a Suspicious Social Media Account

**Scenario:** You've received a tip about a Twitter account spreading disinformation. You need to profile the account and assess reach.

**Steps:**
1. Click **Investigation** in the tool card strip
2. Enter `@suspicious_account` in the Subject Identifier field
3. Set Depth to **Standard**
4. Click **Investigate**
5. Review the Analysis tab for profile data, posting patterns, and engagement metrics
6. Click the **Graph** tab to see entity connections (mentioned accounts, URLs)
7. Switch to **Scenarios** and select **Influence Analysis** with the session ID from the investigation
8. Export results as PDF via the export bar

**Outcome:** Identified coordinated inauthentic behaviour. Evidence packaged for platform reporting.

---

### Use Case 2: Domain Reconnaissance for Security Assessment

**Scenario:** Assess a startup's digital footprint before acquisition.

**Steps:**
1. Click **Investigation**, enter `targetstartup.com`, set Depth to **Deep**
2. Ensure **Search Web for Missing Intel** is checked
3. Click **Investigate**
4. Review: WHOIS data, DNS records, subdomains, HTTP headers, Wayback Machine history
5. Check Web Intelligence section for dork-discovered documents or exposed endpoints
6. Export as PDF for the acquisition team

---

### Use Case 3: Monitoring a Developing Situation

**Scenario:** A natural disaster has struck. Monitor social media for casualty reports and relief needs.

**Steps:**
1. Click **Feed Monitor**
2. Create Monitor 1: Type=Keyword, Query=`"earthquake casualties"`, Platforms=Twitter+Telegram, Interval=5 min
3. Create Monitor 2: Type=Keyword, Query=`"need water" OR "food shortage"`, Platforms=Twitter+Facebook, Interval=10 min
4. Click **Start Monitor** for each
5. Click **Watch** in the top bar to review incoming findings
6. Approve critical items, dismiss noise
7. For verified reports, run full investigations on key usernames

---

### Use Case 4: Verifying Image Authenticity

**Scenario:** A social media post claims to show a bombed building, but you suspect the image is manipulated.

**Steps:**
1. Click **Image Analysis** in the tool card strip
2. Upload the image
3. Ensure all 4 module checkboxes are checked
4. Click **Analyse Images**
5. Check results:
   - **ELA**: Does the alleged bomb damage area show different error levels than surroundings?
   - **Steganography**: Any hidden data?
   - **CLIP**: What does the AI classify the scene as? Are conflict-zone landmarks detected?
   - **Reverse Search**: Has this image appeared elsewhere (earlier date = repost from different context)?

---

### Use Case 5: Batch Phishing Campaign Analysis

**Scenario:** 10 email addresses identified in a phishing campaign. Investigate all at once.

**Steps:**
1. Click **Batch Investigation**
2. Paste all 10 emails (one per line) into the text area
3. Set Identifier Type to **Auto-detect** and select relevant platforms
4. Click **Batch Investigate**
5. Review individual results and cross-entity synthesis in the Analysis tab
6. Check the Graph tab for shared connections
7. Export as STIX 2.1 for import into your Threat Intelligence Platform

---

### Use Case 6: Conflict Zone Evidence Gathering

**Scenario:** Investigate allegations of civilian harm in a conflict zone.

**Steps:**
1. Click **Investigation**
2. Enter a relevant hashtag or username
3. Set Depth to **Deep**, enable **Civilian Harm Analysis**, and check **Search Web for Missing Intel**
4. Click **Investigate**
5. Review civilian harm scores in the analysis — focus on Critical and High severity items
6. Upload any attached images via **Image Analysis** for forensics verification
7. Use **Geolocation** with geotagged media to map incident locations
8. Set up a **Feed Monitor** for ongoing tracking
9. Export the full report as PDF

---

## Tips and Best Practices

### Investigation

- **Start with Quick Depth**: Use Quick for initial triage, upgrade to Standard or Deep for high-value targets
- **Use Batch for Related Targets**: More efficient than sequential individual investigations
- **Enable Civilian Harm Selectively**: Only for conflict/crisis situations — adds processing time
- **Check the Knowledge Base First**: Before investigating, search KB for related entities to avoid duplicate work
- **Export Early**: Platform data can change or disappear (deleted posts, banned accounts)

### Geolocation

- **EXIF Isn't Always Present**: Many platforms strip GPS data on upload. Download original images when possible.
- **Combine Sources**: Use geolocation + visual landmarks + metadata for triangulation
- **Use Clustering**: Upload multiple images from the same subject to reveal location patterns

### Feed Monitor

- **Balance Interval vs. Volume**: High-volume topics need longer intervals to avoid rate limits
- **Use Specific Monitors**: Separate monitors for different aspects (locations, actors, events) are easier to triage
- **Review Regularly**: Check the Watch panel to catch critical items

### Q&A

- **Be Specific**: "What IOCs are listed in the Q3 threat report?" works better than "What does the report say?"
- **Follow Up**: The chat interface retains context from previous messages

### Export

- **TLP Classification**: Reports include TLP headers. WHITE for public, GREEN for community, AMBER for limited, RED for eyes-only.
- **STIX for TIP Integration**: Use STIX 2.1 export for automated import into threat intelligence platforms

### Security & OPSEC

- **Use VPN/Proxy**: Platform APIs and web scraping expose your IP
- **Be Aware of Rate Limits**: Deep investigations on high-volume targets may hit platform rate limits
- **Sanitise Reports**: Redact usernames and blur faces if sharing externally

---

## Troubleshooting

### Investigation Issues

**"No results found" for a valid username**
- The platform API may be down or rate-limited
- Verify the username exists by manually visiting the profile
- Try with different platform selections
- Check server logs for API errors

**Investigation takes longer than expected**
- Deep investigations can take 10-15 minutes for complex targets
- Check that Celery workers are running (required for background tasks)
- Try Quick or Standard depth instead

### Geolocation Issues

**"No GPS data found" but image should be geotagged**
- Many social media platforms strip EXIF GPS data on upload
- Try the original image file (not a screenshot or re-saved version)
- Use `exiftool` externally to verify GPS data exists in the file

**Clustering shows unexpected results**
- DBSCAN parameters may need tuning for your use case
- Upload more data points for better clustering

### Feed Monitor Issues

**Monitor stopped collecting**
- Check that Celery workers and Celery beat are running
- Platform API rate limits may have been hit — increase the polling interval
- Check server logs for connection errors

### Q&A Issues

**"No relevant documents found"**
- Ensure documents have been ingested and indexed (check KB panel for document count)
- Rephrase the question using keywords from the document
- Open the KB panel and click **Rebuild Index** to re-index all documents

### Export Issues

**PDF export fails or times out**
- Large investigations with many images can be slow to render
- Try Markdown export instead (faster, no rendering overhead)
- Check server logs for specific error messages

**STIX export missing entities**
- Some entity types don't map to STIX 2.1 objects
- Use JSON export for the complete unfiltered dataset

### General

- Check the browser console (F12 > Console) for JavaScript errors
- Check server-side logs for Python exceptions
- Ensure all required environment variables are configured (see README.md)
- Restart the Flask app and Celery workers if the system becomes unresponsive

---

## Appendix

### Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CIVILIAN_HARM_ENABLED` | `true` | Enable/disable civilian harm classifier |
| `HARM_MODEL_NAME` | `paraphrase-multilingual-MiniLM-L12-v2` | Sentence-transformers model for harm scoring |
| `DORK_VALIDATION_ENABLED` | `true` | Enable/disable Web Intelligence dork search |
| `DORK_MAX_QUERIES` | `10` | Max dork queries per investigation |
| `IMAGE_SEARCH_ENABLED` | `true` | Enable reverse image search |
| `IMAGE_FORENSICS_ENABLED` | `true` | Enable ELA and forensics |
| `IMAGE_STEGO_ENABLED` | `true` | Enable steganography detection |
| `IMAGE_VISION_ENABLED` | `true` | Enable CLIP classification |
| `TINEYE_API_KEY` | (none) | Optional TinEye API key |

For the full list of environment variables, see `README.md`.

### API Rate Limits

| Platform | Authenticated Limit | Unauthenticated Limit |
|----------|--------------------|-----------------------|
| Twitter/X | 300 req/15min | 15 req/15min |
| Reddit | 60 req/min | 10 req/min |
| YouTube | 10,000 units/day | N/A |
| Instagram | 200 req/hour | N/A |
| Mastodon | Varies by instance | Varies by instance |

### Supported File Formats

**Report Ingestion**: PDF, Markdown (.md), Plain text (.txt)
**Geolocation Images**: JPEG, PNG, TIFF, HEIC
**Image Analysis**: JPEG, PNG, TIFF, WebP, BMP
**Export**: PDF, Markdown, JSON, CSV, STIX 2.1

### TLP Classification Guidelines

- **TLP:WHITE**: Can be shared publicly, no restrictions
- **TLP:GREEN**: Share with peers and partners in the cybersecurity/OSINT community
- **TLP:AMBER**: Limited distribution, need-to-know basis only
- **TLP:RED**: Recipients only, do not share further

---

**End of User Guide**

*For deployment instructions, see `README.md`*
*Last updated: August 19, 2026*
