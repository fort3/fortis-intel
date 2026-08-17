# Fortis Intelligence Hub — User Guide

**Version 1.0** | **Last Updated: August 2026**

---

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [Core Features](#core-features)
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
   - [Wayback Machine Integration](#wayback-machine-integration)
   - [Web Intelligence](#web-intelligence)
   - [ForgeChain Governance](#forgechain-governance)
   - [Compliance Features](#compliance-features)
4. [Example Use Cases](#example-use-cases)
5. [Tips and Best Practices](#tips-and-best-practices)
6. [UI Navigation & Shortcuts](#ui-navigation--shortcuts)
7. [Troubleshooting](#troubleshooting)

---

## Introduction

**Fortis Intelligence Hub** is a Flask-based Open Source Intelligence (OSINT) investigation platform designed for security researchers, journalists, and analysts. With its cyberpunk-inspired black/purple interface, the platform provides comprehensive tools for digital investigations, social media analysis, geolocation, and threat intelligence gathering.

### Key Capabilities

- **Multi-platform OSINT**: Investigate across Twitter/X, Reddit, YouTube, Instagram, Mastodon, Facebook, TikTok, and Telegram
- **Domain & IP Analysis**: WHOIS, DNS, reverse lookups, historical data via Wayback Machine
- **Geolocation**: EXIF extraction, IP geolocation, clustering, triangulation
- **AI-Powered Analysis**: RAG-based Q&A, entity extraction, LLM-driven insights
- **Real-time Monitoring**: Background feed polling with auto-enrichment
- **Civilian Harm Detection**: Bellingcat-inspired semantic scoring for conflict zones
- **Advanced Export**: PDF, STIX 2.1, JSON, CSV, Google Drive integration
- **Governance**: ForgeChain 3-verifier consensus for sensitive operations

---

## Quick Start

### Your First Investigation in 5 Minutes

**Scenario**: Investigate a Twitter/X username

1. **Navigate to Investigation**
   - Click **Investigation** in the main navigation menu
   - The investigation form appears with a dark, cyberpunk-styled interface

2. **Enter Your Target**
   - In the **Identifier** field, type: `@example_user`
   - The system auto-detects the identifier type (username)

3. **Select Investigation Depth**
   - Choose **Standard** from the depth dropdown
   - Quick: API calls only (30-60 seconds)
   - Standard: API + web scraping (2-5 minutes)
   - Deep: All sources + metadata + entity extraction (5-15 minutes)

4. **Optional: Enable Civilian Harm Scoring**
   - Check **Enable Civilian Harm Analysis** if investigating conflict-related content
   - This applies Bellingcat methodology to flag sensitive content

5. **Run Investigation**
   - Click **Start Investigation**
   - A progress indicator shows collection status
   - Results appear in sections: Profile, Posts, Metadata, Entities

6. **Review Results**
   - **Profile Summary**: Follower count, bio, location, verification status
   - **Recent Posts**: Last 20-100 posts with timestamps and engagement
   - **Entity Graph**: Click **View Graph** to see connections
   - **Civilian Harm**: If enabled, see flagged content with severity scores

7. **Export Your Findings**
   - Click **Export** → **PDF** for a formatted report
   - Choose TLP classification (WHITE, GREEN, AMBER, RED)
   - Download includes executive summary, TOC, and dark theme styling

**Congratulations!** You've completed your first investigation.

---

## Core Features

### Report Ingestion

Upload and analyze PDF or Markdown documents with AI-powered extraction.

#### How It Works

The system uses a 3-tier extraction pipeline:
1. **PyMuPDF**: Primary text extraction with layout preservation
2. **pypdf**: Fallback for encrypted or complex PDFs
3. **OCR**: Last resort for scanned documents or images

Extracted content is indexed into a FAISS vectorstore for semantic search and Q&A.

#### Step-by-Step

1. **Navigate to Reports**
   - Click **Reports** in the main menu

2. **Upload Document**
   - Click **Upload New Report**
   - Select PDF or Markdown file (max 50MB)
   - Supported formats: `.pdf`, `.md`, `.markdown`

3. **Wait for Processing**
   - Progress bar shows extraction stages
   - Processing time: 10 seconds to 2 minutes (depends on size)

4. **Review Extraction**
   - System displays:
     - Total pages/sections extracted
     - Key entities found (people, places, organizations)
     - Summary statistics (word count, readability score)

5. **Ask Questions**
   - Navigate to **Q&A** tab
   - Type natural language questions about the document
   - Example: "What are the main findings about cybersecurity threats?"

#### Use Cases

- **Threat Intelligence Reports**: Extract IOCs, TTPs, attribution
- **News Articles**: Verify claims, extract dates and locations
- **Research Papers**: Summarize findings, compare methodologies
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

#### Platform-Specific Features

**Twitter/X**
1. Enter username: `@username` or `username`
2. Results include:
   - Profile: Bio, location, follower/following counts, join date
   - Recent tweets (with retweets, likes, replies)
   - Engagement metrics
   - Account verification status
   - Linked accounts (via bio URLs)

**Reddit**
1. Enter username: `u/username` or just `username`
2. Results include:
   - Karma scores (post/comment)
   - Subreddit activity breakdown
   - Recent posts and comments
   - Account age and cake day
   - Awarded posts

**Domain Investigation**
1. Enter domain: `example.com`
2. Results include:
   - **WHOIS**: Registrant, registrar, creation/expiration dates
   - **DNS Records**: A, MX, TXT, CNAME records
   - **Subdomains**: DNSdumpster enumeration (10-500 discovered)
   - **HTTP Headers**: Server info, security headers, cookies
   - **Reverse DNS/IP**: Co-hosted domains on same IP
   - **Wayback Machine**: Historical snapshots, content changes, subdomain discovery

**IP Address Investigation**
1. Enter IP: `8.8.8.8`
2. Results include:
   - **Geolocation**: Country, city, coordinates, ISP, ASN
   - **Reverse DNS**: Hostnames pointing to this IP
   - **Reverse IP**: Other domains hosted on same IP (co-hosting analysis)
   - **Threat Intelligence**: Blacklist status, abuse reports

#### Web Intelligence (Dork Search)

For deep web investigations, the system includes LLM-driven dork query generation.

**Phases:**
1. **Initial Dorking**: LLM generates targeted Google dork queries
2. **OSINT Collection**: DuckDuckGo scraping (no API key needed)
3. **Analysis**: Extract insights, patterns, IOCs
4. **Gap Analysis**: Identify missing information, generate follow-up queries
5. **Validation + Deep Scrape**: Re-verify findings, extract full page content

**How to Use:**
1. In the Investigation form, check **Enable Web Intelligence**
2. System automatically generates dork queries based on target
3. Circuit breaker prevents infinite loops (max 3 validation cycles)
4. Results include:
   - Discovered URLs with relevance scores
   - Extracted content snippets
   - False-positive detection log
   - LLM-synthesized insights

**Example Queries Generated:**
- Username: `"username" site:twitter.com OR site:reddit.com`
- Domain: `site:example.com filetype:pdf OR filetype:doc`
- Email: `"user@example.com" -site:example.com`

#### Civilian Harm Classifier

When investigating conflict zones or sensitive events, enable this feature for automated content flagging.

**Methodology** (based on Bellingcat research):
- Sentence-transformers semantic similarity scoring
- Multilingual keyword matching (English, Arabic, Ukrainian, Russian)
- Concept detection: violence, displacement, infrastructure damage, casualties

**Scoring Levels:**
- 🟢 **Low** (0.0-0.3): General news, no harm indicators
- 🟡 **Medium** (0.3-0.6): Conflict mentions, protests, mild violence
- 🟠 **High** (0.6-0.8): Direct harm descriptions, casualties, displacement
- 🔴 **Critical** (0.8-1.0): Explicit violence, war crimes, mass casualties

**How to Use:**
1. Check **Enable Civilian Harm Analysis** in investigation form
2. System scores all collected posts/comments/media
3. Results show:
   - **Distribution Bar**: Visual breakdown of severity levels
   - **Flagged Items**: Posts sorted by score (highest first)
   - **Concept Badges**: Tags like `violence`, `displacement`, `infrastructure`
   - **Context**: Matched keywords and semantic similarity scores

**Toggle:**
- Can be disabled via environment variable: `CIVILIAN_HARM_ENABLED=false`

---

### Geolocation

Upload images or videos for GPS coordinate extraction, IP geolocation, and map visualization.

#### Features

- **EXIF GPS Extraction**: Pull coordinates from image metadata
- **IP Geolocation**: Geolocate IP addresses from logs or screenshots
- **Clustering**: DBSCAN algorithm groups nearby locations
- **Triangulation**: Combine multiple partial coordinates
- **Video Keyframe Analysis**: Extract frames, analyze each for GPS data
- **Interactive Maps**: Leaflet.js with cluster markers, fullscreen mode

#### Step-by-Step

1. **Navigate to Geolocation**
   - Click **Geolocation** in main menu

2. **Upload Media**
   - Click **Upload Image/Video**
   - Supported formats: JPG, PNG, HEIC, MP4, MOV, AVI
   - Max file size: 100MB

3. **Automatic Processing**
   - System extracts EXIF data
   - For videos: extracts keyframes (every 30 frames)
   - GPS coordinates displayed in table

4. **Map Visualization**
   - Coordinates plotted on interactive Leaflet map
   - Cluster markers for nearby points
   - Click marker to see: timestamp, device info, altitude
   - **Fullscreen Mode**: Click fullscreen icon for detailed view

5. **Clustering Analysis**
   - System applies DBSCAN clustering
   - Shows:
     - Cluster count
     - Points per cluster
     - Centroid coordinates (average location)
   - Useful for: Identifying frequented locations, home/work detection

6. **Export**
   - Export coordinates as CSV or GeoJSON
   - Include in investigation reports automatically

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
- **Knowledge Base Integration**: Searches across all uploaded reports + investigation results
- **Civilian Harm Context**: Automatically flags answers related to conflict/harm

#### Step-by-Step

1. **Navigate to Q&A**
   - Click **Q&A** in main menu

2. **Select Document Scope** (optional)
   - **All Documents**: Searches entire knowledge base
   - **Specific Report**: Dropdown to select individual uploaded report

3. **Ask Your Question**
   - Type question in natural language
   - Examples:
     - "What threats are mentioned in the Q3 report?"
     - "Who is the CEO of Acme Corp?"
     - "When did the incident occur?"
     - "List all IP addresses mentioned"

4. **Review Answer**
   - System displays:
     - **Answer**: LLM-generated response
     - **Source**: Which document(s) the answer came from
     - **Confidence**: Similarity score (0.0-1.0)
     - **Context**: Relevant excerpts with highlighting

5. **Civilian Harm Alert** (if applicable)
   - Red banner appears if answer relates to conflict/harm
   - Shows: "This content may contain references to civilian harm or violence"

#### Advanced Queries

- **Comparison**: "How does the 2025 report differ from 2024?"
- **Summarization**: "Summarize the key findings in under 100 words"
- **Extraction**: "List all CVEs mentioned across all reports"
- **Temporal**: "What events happened between March and June 2025?"

---

### Feed Monitor

Real-time monitoring of keywords, usernames, hashtags, or topics across platforms.

#### Features

- **Celery Background Polling**: Async task processing
- **Flexible Intervals**: 5 to 240 minutes
- **Auto-Enrichment**: New posts automatically analyzed with LLM
- **Civilian Harm Scoring**: All monitored content scored for sensitivity
- **Watch Panel**: Dedicated UI for reviewing flagged items

#### Step-by-Step

1. **Navigate to Feed Monitor**
   - Click **Feed Monitor** in main menu

2. **Create New Monitor**
   - Click **+ New Monitor**
   - Fill in form:
     - **Name**: Descriptive label (e.g., "Ukraine Conflict - Kharkiv")
     - **Type**: Keyword, Username, Hashtag, or Topic
     - **Query**: The term to monitor (e.g., `#Kharkiv`, `@username`, `"civilian casualties"`)
     - **Platforms**: Select one or more (Twitter, Reddit, Telegram, etc.)
     - **Interval**: Polling frequency (default: 15 minutes)
     - **Enable Civilian Harm**: Check if monitoring conflict/sensitive topics

3. **Activate Monitor**
   - Click **Activate**
   - Celery beat scheduler starts background polling
   - Initial collection begins immediately

4. **Watch Panel**
   - New items appear in real-time (refresh every 30s)
   - Each item shows:
     - Platform icon
     - Author username
     - Content preview
     - Timestamp
     - Civilian harm score (if enabled)
     - **Action Buttons**: Dismiss, Flag, Add to Investigation

5. **Review Flagged Items**
   - Filter by severity: Critical, High, Medium, Low
   - Click item to see full content + context
   - Mark as reviewed or escalate

6. **Manage Monitors**
   - **Pause**: Temporarily stop polling (data retained)
   - **Edit**: Change interval or query
   - **Delete**: Remove monitor and all collected data

#### Best Practices

- **Start Broad, Then Narrow**: Begin with general keywords, refine based on results
- **Use Multiple Monitors**: Separate monitors for different aspects (locations, actors, events)
- **Balance Interval**: Too frequent = rate limits; too slow = miss time-sensitive posts
  - Breaking news: 5-10 minutes
  - General monitoring: 30-60 minutes
  - Low-priority: 120-240 minutes
- **Regular Review**: Check watch panel at least daily to catch critical items

---

### Scenarios

Pre-built analytical frameworks for common investigation patterns.

#### Available Scenarios

1. **Pattern of Life**
   - Analyzes posting times, locations, language patterns
   - Identifies daily routines, sleep schedules, work hours
   - Best for: Profiling suspects, OPSEC audits

2. **Network Mapping**
   - Extracts mentions, interactions, co-authors
   - Builds relationship graph
   - Best for: Uncovering networks, influence operations

3. **Location Prediction**
   - Uses historical geolocation data + time-based patterns
   - Predicts future locations or current whereabouts
   - Best for: Missing persons, surveillance planning

4. **Influence Analysis**
   - Measures reach, engagement, amplification
   - Identifies key influencers and narrative spread
   - Best for: Disinformation campaigns, propaganda detection

#### Step-by-Step

1. **Complete an Investigation First**
   - Scenarios require entity graph context
   - Run at least a **Standard** depth investigation

2. **Navigate to Scenarios**
   - Click **Scenarios** in main menu
   - Or click **Run Scenario** button on investigation results page

3. **Select Scenario Type**
   - Choose from dropdown or click pre-configured card
   - Each scenario shows: description, required data, estimated time

4. **Configure Parameters**
   - **Pattern of Life**: Select time range (7, 30, 90 days)
   - **Network Mapping**: Set relationship depth (1-3 hops)
   - **Location Prediction**: Choose prediction timeframe
   - **Influence Analysis**: Select metric (reach, engagement, sentiment)

5. **Run Analysis**
   - Click **Generate Scenario**
   - LLM analyzes entity graph + investigation data
   - Processing time: 30 seconds to 3 minutes

6. **Review Results**
   - Visual timeline for Pattern of Life
   - Interactive graph for Network Mapping
   - Heatmap for Location Prediction
   - Charts + statistics for Influence Analysis

7. **Export Scenario**
   - Click **Export Scenario**
   - Included in main investigation report automatically

---

### Batch Investigation

Investigate multiple targets simultaneously with cross-entity synthesis.

#### Features

- **Parallel Processing**: Celery workers handle multiple targets concurrently
- **Auto-Correlation**: System links related entities across targets
- **Civilian Harm Scoring**: Applies to all collected data
- **Unified Export**: Single PDF/JSON with all targets + cross-analysis

#### Step-by-Step

1. **Navigate to Batch Investigation**
   - Click **Batch** in main menu

2. **Enter Multiple Identifiers**
   - Text area appears with example format
   - Enter one identifier per line:
     ```
     @username1
     user@example.com
     example.com
     8.8.8.8
     @username2
     ```
   - Mix types allowed (usernames, emails, domains, IPs)
   - Max: 50 identifiers per batch

3. **Select Common Settings**
   - **Depth**: Applies to all targets (recommend: Quick or Standard for batches)
   - **Enable Civilian Harm**: Check if any targets are conflict-related
   - **Enable Cross-Entity Analysis**: Synthesize connections between targets

4. **Run Batch**
   - Click **Start Batch Investigation**
   - Progress bar shows: X of Y completed
   - Each target processes independently

5. **Review Results**
   - **Individual Results**: Expand each target to see full investigation
   - **Cross-Entity Synthesis**: LLM-generated analysis of connections
   - **Entity Graph**: Combined graph showing all targets + relationships
   - **Civilian Harm Summary**: Aggregated severity distribution

6. **Export**
   - Click **Export Batch Report**
   - Generates single PDF with:
     - Executive summary (cross-entity findings)
     - Individual target sections
     - Combined entity graph
     - Appendices (raw data tables)

#### Use Cases

- **Group Investigations**: Known associates, criminal networks
- **Infrastructure Mapping**: Related domains, IP ranges, server clusters
- **Comparison**: Analyze multiple accounts for similarities (sockpuppets)
- **Campaign Analysis**: Track multiple hashtags/topics for coordinated activity

---

### Entity Graphs

Interactive visualization of people, places, organizations, and their relationships.

#### Features

- **Cytoscape.js**: High-performance graph rendering
- **Click-to-Drill-Down**: Click any node to see details or launch sub-investigation
- **Entity-Aware LLM**: AI understands graph structure for better analysis
- **Export**: PNG, JSON (for external tools like Gephi)

#### Node Types

- **Person**: 🔵 Blue circle (usernames, names, authors)
- **Organization**: 🟣 Purple square (companies, groups)
- **Location**: 🟢 Green diamond (cities, countries, addresses)
- **Domain**: 🟠 Orange hexagon (websites, domains)
- **IP Address**: 🔴 Red triangle (IP addresses, servers)
- **Content**: ⚪ White circle (posts, documents, media)

#### Step-by-Step

1. **Generate Graph**
   - Automatically created during **Standard** or **Deep** investigations
   - Or click **View Graph** button on any investigation results page

2. **Navigate the Graph**
   - **Pan**: Click and drag background
   - **Zoom**: Scroll wheel or pinch gesture
   - **Select**: Click node to highlight connected edges
   - **Move Nodes**: Drag individual nodes to rearrange

3. **Node Details**
   - Click node to open details panel:
     - Entity type and name
     - Associated data (profile info, post counts, etc.)
     - Relationships (list of connected entities)
     - **Action Buttons**: 
       - **Investigate**: Launch new investigation for this entity
       - **Add to Monitor**: Create feed monitor
       - **Hide**: Remove from graph (temporary)

4. **Relationship Edges**
   - Hover over edge to see relationship type:
     - `mentions` (A mentioned B)
     - `located_in` (Person/Org in Location)
     - `owns` (Person owns Domain/Org)
     - `posted` (Person posted Content)
     - `co-hosts` (Domain co-hosts with another)

5. **Layout Options**
   - **Force-Directed**: Nodes repel, edges attract (default)
   - **Hierarchical**: Tree-like structure (good for networks)
   - **Circular**: Ring layout (good for small graphs)
   - **Grid**: Organized rows/columns

6. **Export Graph**
   - Click **Export** dropdown:
     - **PNG**: High-resolution image (for reports)
     - **JSON**: Raw graph data (for Gephi, Neo4j import)
     - **GraphML**: Standard graph format

#### Analysis Tips

- **Central Nodes**: Largest/most-connected = key players
- **Clusters**: Tightly connected groups = communities or campaigns
- **Bridges**: Nodes connecting clusters = information brokers
- **Isolates**: Disconnected nodes = may need further investigation

---

### Knowledge Base

Auto-indexed repository of all investigation results and uploaded documents.

#### Features

- **Automatic Indexing**: Every investigation + uploaded report added to FAISS vectorstore
- **Semantic Search**: Find similar entities, patterns across investigations
- **Temporal Queries**: Filter by date range
- **Federated Search**: Searches investigations + documents simultaneously

#### Step-by-Step

1. **Navigate to Knowledge Base**
   - Click **Knowledge Base** in main menu

2. **Search**
   - Enter query in search bar:
     - **Entity**: "John Doe" (finds all mentions)
     - **Topic**: "DDoS attacks" (finds related investigations)
     - **Pattern**: "Russian IPs" (finds pattern matches)
   - Click **Search**

3. **Filter Results**
   - **Type**: Investigations, Documents, Entities, Locations
   - **Date Range**: Last 7 days, 30 days, 90 days, Custom
   - **Source**: Specific platforms (Twitter, Reddit, etc.)
   - **Civilian Harm**: Filter by severity level

4. **Review Matches**
   - Each result shows:
     - Title/identifier
     - Type (investigation, document, entity)
     - Date added
     - Relevance score
     - Snippet preview
   - Click to open full investigation/document

5. **Cross-Reference**
   - Click **Find Related** on any result
   - System finds semantically similar entities across knowledge base
   - Useful for: Uncovering hidden connections, similar cases

#### Maintenance

- **Auto-Retention**: Configurable via environment variables
  - Default: 90 days for Low sensitivity, 180 days for Medium, 365+ for High
- **Manual Deletion**: 
  - Navigate to **Settings** → **Knowledge Base**
  - Click **Delete** on individual items
  - Or **Bulk Delete** by date range
- **Export Archive**:
  - Export entire knowledge base as JSON
  - For backup or migration to another instance

---

### Export Options

Multiple export formats for different use cases.

#### PDF Export

**Features:**
- Dark cyberpunk theme (consistent with UI)
- Section-aware layout (auto page breaks)
- TLP classification headers/footers
- Table of Contents with hyperlinks
- Executive Summary (LLM-generated)
- Embedded images (graphs, maps, screenshots)

**Step-by-Step:**
1. On any investigation results page, click **Export** → **PDF**
2. Configure options:
   - **TLP Classification**: WHITE (public), GREEN (community), AMBER (limited), RED (eyes only)
   - **Include Sections**: Profile, Posts, Entities, Graph, Timeline, Civilian Harm
   - **Executive Summary**: Auto-generate (LLM) or skip
3. Click **Generate PDF**
4. Download link appears (typically 2-10 MB)

#### Markdown Export

**Features:**
- Plain text with Markdown formatting
- TLP headers
- Easy to edit or convert to other formats
- Includes YAML frontmatter (metadata)

**Step-by-Step:**
1. Click **Export** → **Markdown**
2. File downloads immediately (`.md` extension)
3. Open in any text editor or Markdown viewer

#### STIX 2.1 Export

**Features:**
- Industry-standard threat intelligence format
- Compatible with TAXII servers, TIPs (Threat Intelligence Platforms)
- Includes: observables, indicators, relationships, TTPs

**Step-by-Step:**
1. Click **Export** → **STIX 2.1**
2. JSON file downloads (`.stix` or `.json` extension)
3. Import into your TIP (MISP, OpenCTI, etc.)

**STIX Objects Generated:**
- `identity`: Target entity
- `observed-data`: Social media posts, DNS records
- `indicator`: IOCs (IPs, domains, hashes)
- `relationship`: Connections between entities
- `location`: Geolocated coordinates

#### CSV Export

**Features:**
- Tabular data (posts, entities, locations)
- Easy import to Excel, Google Sheets, databases

**Step-by-Step:**
1. Click **Export** → **CSV**
2. Select data type: Posts, Entities, Locations, All
3. File downloads (`.csv` extension)

**Columns:**
- Posts: `timestamp`, `author`, `content`, `platform`, `engagement`, `civilian_harm_score`
- Entities: `name`, `type`, `platform`, `first_seen`, `relationship_count`

#### JSON Export

**Features:**
- Full investigation data (unfiltered)
- Useful for API integration, custom parsing

**Step-by-Step:**
1. Click **Export** → **JSON**
2. File downloads (`.json` extension)
3. Parse with any JSON library

#### Google Drive Export

**Features:**
- Direct upload to Google Drive (requires OAuth)
- Folder auto-creation (organized by date/target)
- All formats supported

**Step-by-Step:**
1. **First Time Setup**:
   - Click **Export** → **Google Drive**
   - Authorize Fortis to access your Drive
   - Select destination folder

2. **Subsequent Exports**:
   - Click **Export** → **Google Drive**
   - Select format (PDF, Markdown, JSON, CSV)
   - File appears in Drive within 10 seconds

---

### Civilian Harm Classifier

Bellingcat-inspired methodology for detecting conflict-related content.

#### Methodology

**Semantic Similarity Scoring:**
- Uses `sentence-transformers/all-MiniLM-L6-v2` model
- Compares each post/comment against 50+ harm-related reference sentences
- Examples:
  - "Airstrike destroyed residential building killing civilians"
  - "Children injured in shelling attack"
  - "Refugees fleeing conflict zone"

**Multilingual Keyword Matching:**
- Dictionaries for English, Arabic, Ukrainian, Russian
- Keywords: `airstrike`, `casualties`, `displaced`, `bombing`, etc.
- Weighted scoring: direct violence (1.0), infrastructure damage (0.7), displacement (0.5)

**Concept Detection:**
- Automatically tags content with concepts:
  - `violence`, `infrastructure`, `displacement`, `casualties`, `military`, `humanitarian`

#### Scoring Breakdown

**Score = (Semantic Similarity × 0.7) + (Keyword Match × 0.3)**

**Severity Levels:**
- 🟢 **Low** (0.0-0.3): General news, political discussion, no direct harm
- 🟡 **Medium** (0.3-0.6): Conflict mentions, protests, non-lethal violence
- 🟠 **High** (0.6-0.8): Direct harm descriptions, casualties, displacement
- 🔴 **Critical** (0.8-1.0): Explicit violence, war crimes, mass casualties

#### Viewing Results

**Investigation Results Page:**
1. If civilian harm analysis was enabled, see:
   - **Distribution Bar**: Visual breakdown of severity across all content
   - **Flagged Items Tab**: Posts sorted by score (Critical first)
   - **Concept Badges**: Each post shows matched concepts

2. **Filter by Severity:**
   - Click severity level (Critical, High, Medium, Low) to filter

3. **Item Details:**
   - Click post to expand:
     - Full content
     - Civilian harm score + matched keywords
     - Semantic similarity score + concept tags
     - Timestamp + platform
     - **Action Buttons**: Flag for review, Add to report, Dismiss

**Feed Monitor Watch Panel:**
- Real-time civilian harm scores for monitored content
- Auto-escalates Critical items to top of queue

#### Configuration

**Enable/Disable:**
- Environment variable: `CIVILIAN_HARM_ENABLED=true` (default)
- Set to `false` to disable globally

**Customize Thresholds:**
- Edit `config/civilian_harm_config.json`:
  ```json
  {
    "thresholds": {
      "low": 0.3,
      "medium": 0.6,
      "high": 0.8
    },
    "keywords": {
      "en": ["airstrike", "casualties", ...],
      "ar": ["غارة جوية", "ضحايا", ...],
      ...
    }
  }
  ```

---

### Wayback Machine Integration

Historical domain data from the Internet Archive's CDX API.

#### Features

- **Historical Snapshots**: Retrieve all archived versions of a domain
- **Subdomain Discovery**: Find subdomains from archived pages
- **Content Change Detection**: Track modifications over time
- **Robots.txt History**: See what was blocked/allowed historically
- **No API Key Required**: Free access via CDX API

#### How It Works

When you investigate a domain with **Standard** or **Deep** depth:
1. System queries Wayback CDX API for all snapshots
2. Analyzes snapshot timestamps, URLs, status codes
3. Identifies significant changes (layout, content, redirects)
4. Discovers subdomains from archived internal links

#### Viewing Results

**Investigation Results → Wayback Tab:**
1. **Timeline**: Visual timeline of snapshots (grouped by year/month)
2. **Snapshot Count**: Total archived versions
3. **Date Range**: First snapshot → Most recent
4. **Key Changes**: LLM-identified significant modifications
5. **Subdomains Discovered**: List of historical subdomains not in current DNS

**Snapshot Details:**
- Click any snapshot to see:
  - Capture date/time
  - HTTP status code
  - URL
  - **View Archive**: Link to Wayback Machine viewer
  - **Diff**: Compare to previous snapshot (text diff)

#### Use Cases

- **Domain History**: Track ownership changes, previous content
- **Subdomain Enumeration**: Find forgotten or decommissioned subdomains
- **OPSEC Audits**: Check for historical leaks (emails, credentials in archived pages)
- **Evidence Preservation**: Verify domain existed on specific date

---

### Web Intelligence

LLM-driven dork search with 5-phase analysis pipeline.

#### Architecture

**Phase 1: Initial Dorking**
- LLM generates targeted Google dork queries
- Examples: `site:example.com filetype:pdf`, `"username" -site:twitter.com`

**Phase 2: OSINT Collection**
- DuckDuckGo scraping (no API key required)
- Extracts: title, URL, snippet, timestamp

**Phase 3: Analysis**
- LLM analyzes results for insights
- Extracts: IOCs, patterns, anomalies

**Phase 4: Gap Analysis**
- Identifies missing information
- Generates follow-up dork queries
- Example: "No LinkedIn profile found → add `site:linkedin.com` query"

**Phase 5: Validation + Deep Scrape**
- Re-verifies findings
- Fetches full page content for high-value URLs
- Circuit breaker: max 3 validation cycles

#### Step-by-Step

1. **Enable Web Intelligence**
   - In Investigation form, check **Enable Web Intelligence**
   - Or navigate to **Web Intelligence** dedicated page

2. **Run Investigation**
   - System automatically generates dork queries
   - Progress indicator shows phases

3. **Review Results**
   - **Dork Queries**: List of generated queries with result counts
   - **Discovered URLs**: Sorted by relevance (LLM-scored)
   - **Insights**: Key findings extracted by LLM
   - **False Positive Log**: URLs marked as irrelevant

4. **Manual Refinement** (optional)
   - Click **Add Custom Dork**
   - Enter your own query
   - System re-runs analysis with additional query

5. **Deep Scrape**
   - Click **Deep Scrape** on any URL
   - Fetches full page content
   - Extracts: emails, phone numbers, social links, metadata

#### Circuit Breaker

**False Positive Detection:**
- If 70%+ of URLs in a validation cycle are irrelevant:
  - Circuit breaker activates
  - Investigation halts to prevent wasted resources
  - User prompted to refine or stop

**Max Cycles:**
- Default: 3 validation cycles
- Prevents infinite loops

---

### ForgeChain Governance

3-verifier consensus gate for sensitive operations.

#### Verifiers

1. **Rule Verifier**: Checks against defined policies (no PII extraction, geo-restrictions, etc.)
2. **Safety Verifier**: Detects harmful intent (doxxing, harassment, illegal activity)
3. **Consistency Verifier**: Ensures request aligns with historical patterns

**Consensus Requirement:**
- All 3 verifiers must approve (unanimous) for operation to proceed
- Any rejection = operation blocked

#### Elevated Authorization

For high-sensitivity cases:
- System prompts admin for manual approval
- Requires: reason, justification, approver username
- Logged with full audit trail

#### Audit Trail

**Logs Include:**
- Timestamp
- Operation type (investigation, export, deletion)
- Verifier decisions (approve/reject + reasoning)
- User who initiated
- Final outcome (allowed/blocked)
- Elevated auth details (if applicable)

#### Viewing Audit Logs

1. Navigate to **Settings** → **Governance**
2. Click **Audit Logs**
3. Filter by: date, user, operation type, outcome
4. Export as CSV for compliance reporting

#### Use Cases

- **Legal Compliance**: Prove due diligence in court
- **Internal Audits**: Track all sensitive operations
- **Policy Enforcement**: Automatically block policy violations
- **Incident Response**: Investigate unauthorized access attempts

---

### Compliance Features

GDPR, NIST CSF 2.0, and data retention management.

#### GDPR Article 17 (Right to Erasure)

**Subject Deletion Request:**
1. Navigate to **Settings** → **Compliance** → **GDPR**
2. Click **New Deletion Request**
3. Enter subject identifier (email, username, IP)
4. Click **Search Knowledge Base**
5. System finds all related data:
   - Investigation results
   - Uploaded documents
   - Entity graph nodes
   - Feed monitor data
6. Review list of data to delete
7. Click **Execute Deletion**
8. Confirmation log generated (retained for 7 years per GDPR Art. 30)

**Automated Deletion:**
- Environment variable: `GDPR_AUTO_DELETE=true`
- Deletes data automatically upon request (no review step)

#### GDPR Article 30 (Record of Processing)

**Access Processing Records:**
1. Navigate to **Settings** → **Compliance** → **Processing Records**
2. View table of all processing activities:
   - Date/time
   - Data subject (hashed)
   - Processing purpose (investigation, monitoring, etc.)
   - Legal basis (legitimate interest, consent, etc.)
   - Retention period
3. Export as CSV for DPA (Data Protection Authority) requests

#### NIST CSF 2.0 Mapping

**View Compliance Mapping:**
1. Navigate to **Settings** → **Compliance** → **NIST CSF 2.0**
2. See which platform features map to NIST functions:
   - **Identify**: Entity extraction, domain enumeration
   - **Protect**: ForgeChain governance, TLP classification
   - **Detect**: Feed monitoring, civilian harm classifier
   - **Respond**: Batch investigation, scenario analysis
   - **Recover**: Knowledge base, export/archive

#### Tiered Data Retention

**Sensitivity Levels:**
- **Low**: General OSINT (public profiles, DNS records) → 90 days
- **Medium**: Personal data (emails, locations) → 180 days
- **High**: Sensitive content (civilian harm flagged) → 365 days
- **Critical**: Legal evidence (court-ordered investigations) → Indefinite (manual deletion only)

**Configure Retention:**
1. Navigate to **Settings** → **Compliance** → **Retention**
2. Edit retention periods per sensitivity level
3. Click **Apply Changes**
4. System schedules auto-deletion via Celery beat

**Manual Override:**
- Mark specific investigations as "Legal Hold" to prevent auto-deletion

---

## Example Use Cases

### Use Case 1: Investigating a Suspicious Social Media Account

**Scenario:** You've received a tip about a Twitter account spreading disinformation about a local election. You need to profile the account, identify connections, and assess reach.

**Steps:**
1. **Navigate to Investigation**
   - Click **Investigation** in main menu

2. **Enter Target**
   - Identifier: `@suspicious_account`
   - Depth: **Standard**
   - Enable Civilian Harm: No (not conflict-related)

3. **Run Investigation**
   - Click **Start Investigation**
   - Wait 2-3 minutes for collection

4. **Analyze Profile**
   - Check: Account age, follower count, verification status
   - Red flags: Created recently, low followers but high engagement (bot activity?)

5. **Review Posts**
   - Look for: Posting frequency, hashtags used, engagement patterns
   - Findings: Posts 20+ times/day, uses identical hashtags, retweets same accounts

6. **Entity Graph**
   - Click **View Graph**
   - Identify: Frequently mentioned accounts, co-retweeted URLs
   - Findings: Small network of 5-7 accounts with mutual retweets (coordinated?)

7. **Run Scenario: Influence Analysis**
   - Click **Scenarios** → **Influence Analysis**
   - Results: Low organic reach, high bot-like amplification

8. **Export Evidence**
   - Export → **PDF** with TLP:AMBER
   - Share with election security team

**Outcome:** Identified coordinated inauthentic behavior. Evidence packaged for platform reporting.

---

### Use Case 2: Domain Reconnaissance for Security Assessment

**Scenario:** Your company is considering acquiring a small tech startup. You need to assess their digital footprint and potential security issues.

**Steps:**
1. **Navigate to Investigation**
   - Identifier: `targetstartup.com`
   - Depth: **Deep**
   - Enable Web Intelligence: Yes

2. **Run Investigation**
   - Wait 5-10 minutes for comprehensive scan

3. **Review WHOIS Data**
   - Check: Registrant (does it match company name?), creation date, expiration
   - Findings: Domain registered 3 years ago, expires in 2 months (renewal risk?)

4. **Analyze DNS Records**
   - Check: MX records (email hosting), TXT records (SPF, DKIM), nameservers
   - Findings: Using Gmail for email (no custom mail server), missing DMARC record (security gap)

5. **Subdomain Enumeration**
   - DNSdumpster found 23 subdomains
   - Wayback Machine found 8 additional historical subdomains
   - Red flags: `dev.targetstartup.com` publicly accessible, `staging.targetstartup.com` in archive

6. **HTTP Headers Analysis**
   - Check: Server version, security headers
   - Findings: Missing `X-Frame-Options`, `CSP`, `HSTS` (security hardening needed)

7. **Wayback Machine Review**
   - Click **Wayback** tab
   - Findings: Homepage completely redesigned 1 year ago, old site had exposed API docs

8. **Web Intelligence Results**
   - Dork queries found: 3 PDFs with employee emails, 1 GitHub repo with API keys (revoked? check)

9. **Export Report**
   - Export → **PDF** with TLP:RED (confidential acquisition)
   - Include recommendations: Secure staging/dev, add security headers, renew domain ASAP

**Outcome:** Security assessment completed. Identified 5 high-priority fixes before acquisition.

---

### Use Case 3: Tracking a Person of Interest Across Platforms

**Scenario:** You're investigating a subject for a missing persons case. You have a username they used on Facebook. You need to find other accounts and recent activity.

**Steps:**
1. **Initial Investigation**
   - Identifier: `missing_person_username`
   - Depth: **Deep**
   - Enable Civilian Harm: No

2. **Review Results**
   - Facebook: Last post 3 weeks ago, location tagged in City X
   - Findings: Bio mentions "Also on Twitter: @different_handle"

3. **Follow-Up Investigation**
   - Launch new investigation: `@different_handle`
   - Twitter: Last tweet 5 days ago

4. **Batch Investigation for All Aliases**
   - Navigate to **Batch Investigation**
   - Enter:
     ```
     missing_person_username
     @different_handle
     person_email@example.com
     ```
   - Enable **Cross-Entity Analysis**

5. **Review Cross-Entity Results**
   - LLM finds: All accounts mention same hometown, similar writing style, overlapping interests
   - Confirmation: Same person

6. **Geolocation Analysis**
   - Navigate to **Geolocation**
   - Upload screenshots of geotagged posts from Facebook/Twitter
   - Extract GPS coordinates
   - Map shows: Last known locations in City X

7. **Pattern of Life Scenario**
   - Click **Scenarios** → **Pattern of Life**
   - Results: Usually posts between 8-10 PM, active on weekends, frequents coffee shop in downtown City X

8. **Feed Monitor Setup**
   - Create monitor for all aliases
   - Interval: 15 minutes (time-sensitive case)
   - Get real-time alerts for new posts

9. **Share with Authorities**
   - Export → **PDF** with timeline, map, screenshots
   - TLP:AMBER (share with law enforcement)

**Outcome:** Provided investigators with last known locations and activity patterns. Subject found safe 2 days later.

---

### Use Case 4: Monitoring a Developing Situation (Feed Monitor)

**Scenario:** A natural disaster has struck a region. You're monitoring social media for casualty reports, relief needs, and misinformation.

**Steps:**
1. **Navigate to Feed Monitor**
   - Click **Feed Monitor**

2. **Create Multiple Monitors**
   - Monitor 1:
     - Name: "Earthquake - Casualty Reports"
     - Type: Keyword
     - Query: `"earthquake casualties" OR "deaths" OR "injured"`
     - Platforms: Twitter, Telegram, Reddit
     - Interval: 5 minutes (breaking situation)
     - Enable Civilian Harm: Yes

   - Monitor 2:
     - Name: "Earthquake - Relief Needs"
     - Type: Keyword
     - Query: `"need water" OR "food shortage" OR "medical supplies"`
     - Platforms: Twitter, Facebook, Telegram
     - Interval: 10 minutes

   - Monitor 3:
     - Name: "Earthquake - Misinformation"
     - Type: Keyword
     - Query: `"fake news" OR "hoax" OR "debunk" earthquake`
     - Platforms: Twitter, Reddit
     - Interval: 15 minutes

3. **Activate All Monitors**
   - Click **Activate** on each
   - Celery workers begin polling

4. **Watch Panel Review**
   - Navigate to **Watch Panel**
   - Filter by **Critical** civilian harm first
   - Items appear in real-time

5. **Triage Incoming Posts**
   - **Critical Items**: Reports of casualties, collapsed buildings
     - Action: Flag for humanitarian orgs, verify with geolocation
   - **High Items**: Relief needs, supply requests
     - Action: Forward to NGOs, add to situation report
   - **Medium Items**: General updates, traffic conditions
     - Action: Review periodically

6. **Verify Claims with Geolocation**
   - For posts claiming "building collapsed at [location]":
     - Right-click → **Add to Investigation**
     - Upload attached images to **Geolocation**
     - Extract GPS, verify claimed location matches

7. **Daily Situation Report**
   - End of each day: Export monitor data
   - Export → **CSV** (all posts from last 24h)
   - Analyze in spreadsheet: post volume over time, top keywords, verified casualties

8. **Adjust Monitors**
   - After 48 hours, reduce intervals (situation stabilizing):
     - Casualties: 15 minutes
     - Relief: 30 minutes
     - Misinformation: 60 minutes

**Outcome:** Real-time monitoring enabled rapid response. 200+ verified reports forwarded to relief organizations.

---

### Use Case 5: Analyzing a Conflict Zone for Civilian Harm

**Scenario:** You're investigating allegations of civilian harm in an active conflict zone. You need to collect evidence, geolocate incidents, and produce a report for human rights investigators.

**Steps:**
1. **Navigate to Investigation**
   - Identifier: `#ConflictZoneName` (hashtag)
   - Depth: **Deep**
   - Enable Civilian Harm: **Yes**
   - Enable Web Intelligence: Yes

2. **Run Investigation**
   - Wait 10-15 minutes (deep scan with LLM analysis)

3. **Review Civilian Harm Results**
   - Click **Civilian Harm** tab
   - Distribution: 15% Critical, 30% High, 40% Medium, 15% Low
   - Filter: **Critical**

4. **Analyze Critical Items**
   - Post 1: "Airstrike hit residential building, 20+ casualties"
     - Civilian harm score: 0.92
     - Concepts: `violence`, `casualties`, `infrastructure`
     - Screenshot attached
   - Post 2: "Children injured in shelling attack on school"
     - Score: 0.89
     - Concepts: `violence`, `casualties`

5. **Geolocate Incidents**
   - Right-click Post 1 → **Extract Media**
   - Upload screenshot to **Geolocation**
   - No GPS data in image (EXIF stripped)
   - Use visual landmarks + Web Intelligence:
     - LLM generates dork: `"building name" city conflict`
     - Find match: Building is City Hall in Town X
     - Manually add coordinates to map

6. **Cross-Reference Claims**
   - Navigate to **Q&A**
   - Ask: "Are there other reports of airstrikes on Town X on [date]?"
   - System searches knowledge base
   - Finds: 3 additional posts mentioning Town X, same date

7. **Create Evidence Package**
   - Navigate to **Batch Investigation**
   - Enter all related usernames/hashtags
   - Export → **PDF** with TLP:RED
   - Include:
     - Timeline of events
     - Geolocation map with incident markers
     - Screenshots with civilian harm scores
     - Concept tags and keywords
     - Cross-referenced claims

8. **Feed Monitor for Ongoing Monitoring**
   - Create monitor: Keyword = "Town X"
   - Enable Civilian Harm
   - Interval: 10 minutes
   - Alert investigators to new reports

9. **GDPR Compliance** (if publishing)
   - Blur faces in screenshots
   - Redact usernames (replace with "Source A", "Source B")
   - Navigate to **Settings** → **Compliance**
   - Log processing activity for GDPR Art. 30

**Outcome:** Evidence package submitted to human rights organization. Geolocated 5 incidents with corroborating social media posts. Ongoing monitoring active.

---

### Use Case 6: Verifying Claims in a Document

**Scenario:** You've received a PDF report claiming XYZ Corp was hacked, with 10,000 customer records leaked. You need to verify claims before publishing a news article.

**Steps:**
1. **Upload Document**
   - Navigate to **Reports**
   - Click **Upload New Report**
   - Select PDF file: `XYZ_Corp_Breach_Report.pdf`
   - Wait for processing (30 seconds)

2. **Ask Verification Questions**
   - Navigate to **Q&A**
   - Select document: `XYZ_Corp_Breach_Report.pdf`
   - Questions:
     - Q: "When did the breach allegedly occur?"
       - A: "According to the report, March 15, 2025"
     - Q: "What evidence is provided for the 10,000 records claim?"
       - A: "The report cites a sample of 100 records, extrapolated to 10,000 based on file size"
     - Q: "Are there any screenshots or proof?"
       - A: "Yes, screenshot on page 5 shows leaked database table"

3. **Extract Claims to Verify**
   - Claim 1: Breach on March 15, 2025
   - Claim 2: 10,000 records leaked
   - Claim 3: Data includes names, emails, passwords (hashed)

4. **Investigate XYZ Corp Domain**
   - Navigate to **Investigation**
   - Identifier: `xyzcorp.com`
   - Depth: **Standard**
   - Enable Web Intelligence: Yes

5. **Check for Breach Mentions**
   - Web Intelligence finds:
     - Dork: `"XYZ Corp" breach 2025`
     - Results: 2 forum posts discussing breach, 1 Pastebin link
   - Navigate to Pastebin link → Sample data matches screenshot in PDF

6. **Verify Timeline**
   - Check domain's Twitter: `@XYZCorp`
   - Search posts for March 15-20, 2025
   - Finding: March 17 post: "We are investigating reports of unauthorized access"
   - Confirms timeline (breach on 15th, disclosure on 17th)

7. **Verify Record Count**
   - Q&A system: "Is there independent verification of the 10,000 number?"
   - Answer: "No, only the report's extrapolation"
   - Red flag: Unverified claim

8. **Cross-Reference with Knowledge Base**
   - Navigate to **Knowledge Base**
   - Search: "XYZ Corp breach"
   - Finds: 1 previous investigation from 2024 (unrelated incident)

9. **Produce Verification Summary**
   - Verified: Breach occurred (confirmed by company statement + sample data)
   - Verified: Timing (March 15, disclosed March 17)
   - Unverified: Exact record count (10,000 is estimate, not confirmed)
   - Verified: Data types (names, emails, hashed passwords in sample)

10. **Document Findings**
    - Export Q&A session → **Markdown**
    - Include in article as "verification methodology"

**Outcome:** Published article with accurate claims. Noted that exact record count is unconfirmed.

---

### Use Case 7: IP Address Investigation

**Scenario:** Your IDS flagged an IP address (203.0.113.45) making suspicious API calls. You need to investigate the IP's origin, associated domains, and threat intelligence.

**Steps:**
1. **Navigate to Investigation**
   - Identifier: `203.0.113.45`
   - Depth: **Standard**

2. **Review Geolocation**
   - Country: Example Country
   - City: Example City
   - ISP: Example Hosting Ltd.
   - ASN: AS12345
   - Coordinates: 40.7128° N, 74.0060° W

3. **Reverse DNS**
   - Hostname: `vps-12345.examplehosting.com`
   - Indicates: Virtual private server (shared hosting)

4. **Reverse IP (Co-hosted Domains)**
   - System finds 47 other domains on same IP
   - Domains:
     - `legitimate-site1.com` (clean)
     - `phishing-example.net` (suspicious TLD)
     - `malware-test.org` (high-risk name)
   - Red flag: Shared hosting with known malicious domains

5. **Web Intelligence**
   - Dork: `"203.0.113.45" malware OR blacklist OR abuse`
   - Finds: 1 forum post mentioning IP in botnet list (6 months ago)

6. **Check Knowledge Base**
   - Search: `203.0.113.45`
   - Finding: IP appeared in previous investigation (DDoS attack, 8 months ago)

7. **Threat Intelligence Export**
   - Export → **STIX 2.1**
   - Indicator object includes:
     - IP address
     - ASN
     - Co-hosted domains
     - Historical incidents
   - Import into TIP for alerting

8. **Block IP + Monitor**
   - Add IP to firewall blocklist
   - Create Feed Monitor:
     - Name: "IP 203.0.113.45 - Monitor Mentions"
     - Type: Keyword
     - Query: `203.0.113.45`
     - Platforms: Twitter, Pastebin (via web intel)
     - Interval: 60 minutes

**Outcome:** IP confirmed as high-risk. Blocked at firewall. Monitoring for future activity.

---

### Use Case 8: Batch Investigation for Multiple Targets

**Scenario:** You've identified 10 email addresses in a phishing campaign. You need to investigate all addresses for OSINT footprints and identify connections.

**Steps:**
1. **Navigate to Batch Investigation**
   - Click **Batch** in main menu

2. **Enter Email Addresses**
   - Paste list (one per line):
     ```
     phisher1@example.com
     phisher2@example.com
     phisher3@differentdomain.com
     ...
     phisher10@example.com
     ```

3. **Configure Settings**
   - Depth: **Quick** (10 targets = use faster depth)
   - Enable Civilian Harm: No
   - Enable Cross-Entity Analysis: **Yes**

4. **Run Batch**
   - Click **Start Batch Investigation**
   - Progress: 1 of 10 completed... 5 of 10... 10 of 10
   - Total time: 8 minutes (parallel processing)

5. **Review Individual Results**
   - `phisher1@example.com`:
     - Found: GitHub profile (username: phisher1_dev)
     - Twitter: @phisher1
   - `phisher3@differentdomain.com`:
     - Found: LinkedIn profile (different name, but email in contact info)

6. **Cross-Entity Analysis**
   - Click **Cross-Entity Synthesis** tab
   - LLM findings:
     - "7 of 10 emails share domain: example.com"
     - "3 subjects have GitHub accounts with similar project names"
     - "2 subjects follow each other on Twitter"
     - "All LinkedIn profiles created within 2-month window (likely fake)"

7. **Entity Graph**
   - Click **View Combined Graph**
   - Visual shows:
     - Central node: `example.com` domain
     - 7 email nodes connected to domain
     - GitHub accounts clustered (similar projects)
     - Twitter mutual follows

8. **Export Batch Report**
   - Export → **PDF**
   - Sections:
     - Executive Summary (cross-entity findings)
     - Individual profiles (1 page each)
     - Combined entity graph
     - Appendix: Raw data table

9. **Add to TIP**
   - Export → **STIX 2.1**
   - Import into TIP
   - Create alert rule: Flag emails from `@example.com` domain

**Outcome:** Identified phishing campaign infrastructure. 7 of 10 emails linked to same domain. Report shared with SOC.

---

## Tips and Best Practices

### Investigation Best Practices

1. **Start with Quick Depth for Exploration**
   - Use **Quick** to rapidly assess multiple targets
   - Upgrade to **Standard** or **Deep** only for high-value targets
   - Saves time and API quota

2. **Use Batch for Related Targets**
   - Investigating multiple aliases? Use **Batch** with cross-entity analysis
   - More efficient than sequential individual investigations

3. **Enable Civilian Harm Selectively**
   - Only enable for conflict/crisis situations
   - Adds ~20% processing time due to LLM scoring

4. **Leverage Knowledge Base for Historical Context**
   - Before investigating, search Knowledge Base for related entities
   - Avoid duplicate work, find connections faster

5. **Export Early, Export Often**
   - Export results immediately after investigation
   - Platform data can change or disappear (deleted posts, banned accounts)

### Geolocation Tips

1. **EXIF Data Isn't Always Reliable**
   - Many platforms strip GPS data (Twitter, Instagram, Facebook)
   - Download original images when possible (via DMs, direct links)

2. **Combine Multiple Sources**
   - Use geolocation + visual landmarks + metadata
   - Triangulate: If image has no GPS, analyze shadows, buildings, license plates

3. **Cluster Analysis for Pattern Detection**
   - Upload multiple images from same subject
   - Clustering reveals: home location, work location, frequent spots

### Feed Monitor Optimization

1. **Balance Interval vs. Data Volume**
   - High-volume topics (trending hashtags): 30-60 min intervals
   - Low-volume topics (niche keywords): 10-15 min intervals
   - Adjust based on Watch Panel queue size

2. **Use Multiple Specific Monitors Instead of One Broad Monitor**
   - Bad: Single monitor with `"conflict"`
   - Good: Separate monitors for `"Airstrike"`, `"Casualties"`, `"Displacement"`
   - Easier to triage and prioritize

3. **Regularly Archive and Clear Watch Panel**
   - Export reviewed items as CSV weekly
   - Dismiss non-actionable items
   - Keeps queue manageable

### Q&A System Optimization

1. **Be Specific in Questions**
   - Vague: "What does the report say?"
   - Better: "What IOCs are listed in the Q3 threat report?"

2. **Use Follow-Up Questions**
   - System retains context from previous question
   - Example chain:
     - Q1: "Who is the CEO of Acme Corp?"
     - Q2: "What is their background?" (refers to CEO from Q1)

3. **Cross-Reference Multiple Documents**
   - Select "All Documents" scope
   - Ask: "How do the 2024 and 2025 reports differ in threat assessment?"

### Export Best Practices

1. **Choose TLP Classification Carefully**
   - **TLP:WHITE**: Public info, safe to share widely
   - **TLP:GREEN**: Community (industry peers, trusted partners)
   - **TLP:AMBER**: Limited distribution (need-to-know basis)
   - **TLP:RED**: Eyes-only (recipient only, no further sharing)

2. **Include Executive Summary for Leadership**
   - Non-technical stakeholders need high-level findings
   - LLM-generated summaries are concise and actionable

3. **Use STIX for TIP Integration**
   - Automate export → import workflow
   - Enables alerting, correlation, threat hunting

### Security & OPSEC

1. **Use VPN or Proxy for Sensitive Investigations**
   - Platform APIs and web scraping expose your IP
   - Protect your identity and location

2. **Be Aware of Rate Limits**
   - Twitter: 300 requests/15 min (authenticated)
   - Reddit: 60 requests/min
   - Deep investigations may hit limits → use delays or proxies

3. **Don't Over-Investigate**
   - Excessive profile views can alert target (LinkedIn "Who Viewed Your Profile")
   - Use stealth methods: web scraping vs. direct API (where possible)

4. **Sanitize Exported Reports**
   - If sharing externally, redact your infrastructure (IP addresses, API keys in logs)
   - Blur faces in screenshots to protect identities

### Performance Optimization

1. **Clean Up Knowledge Base Regularly**
   - Old investigations slow down Q&A semantic search
   - Delete or archive investigations older than retention period

2. **Use Celery Workers for Large Batches**
   - Default: 4 workers
   - For 20+ target batches, increase workers: `CELERY_WORKERS=8`

3. **Monitor Disk Space**
   - Uploaded PDFs, FAISS vectorstores, media files consume disk
   - Archive to Google Drive or external storage monthly

---

## UI Navigation & Shortcuts

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + K` | Global search (jump to investigation, report, entity) |
| `Ctrl + N` | New investigation |
| `Ctrl + U` | Upload report |
| `Ctrl + E` | Export current view |
| `Ctrl + F` | Find in page (browser default) |
| `Esc` | Close modal/dialog |
| `Tab` | Navigate form fields |
| `Enter` | Submit active form |

### UI Tips

1. **Dark Theme Optimization**
   - Interface uses black (#000) background + neon purple (#9D4EDD) accents
   - Reduce screen brightness for comfortable extended use
   - Or switch to light theme: **Settings** → **Theme** → **Light**

2. **Collapsible Sections**
   - Long investigation results have collapsible sections
   - Click section header to expand/collapse
   - Collapse unused sections to focus on key data

3. **Breadcrumb Navigation**
   - Top of every page shows: Home > Investigation > Results
   - Click any breadcrumb to navigate back

4. **Quick Actions Menu**
   - Right-click any entity (username, domain, IP) for quick actions:
     - Investigate
     - Add to Monitor
     - Copy to Clipboard
     - View in Graph

5. **Notifications**
   - Bell icon (top-right) shows:
     - Investigation complete
     - Feed monitor critical items
     - Export ready for download
   - Click notification to jump to relevant page

6. **Responsive Design**
   - Platform works on mobile/tablet (limited features)
   - For best experience: Desktop with 1920x1080 or higher resolution

---

## Troubleshooting

### Investigation Issues

**Problem: "No results found" for valid username**

**Cause**: Platform API down, rate limit, or username doesn't exist on searched platforms

**Solution**:
1. Check platform status pages (Twitter Status, Reddit Status)
2. Verify username exists by manually visiting profile
3. Try again with different platform selection
4. Check logs: **Settings** → **Logs** → `investigation_errors.log`

---

**Problem: Investigation stuck at "Collecting data..." for 10+ minutes**

**Cause**: Celery worker crashed, network timeout, or large dataset

**Solution**:
1. Check Celery worker status: **Settings** → **System** → **Workers**
2. Restart worker: Click **Restart Worker**
3. Re-run investigation with **Quick** depth instead of **Deep**

---

**Problem: Civilian Harm scores seem inaccurate**

**Cause**: Model needs retraining on new conflict/harm language, or keywords outdated

**Solution**:
1. Check version: **Settings** → **Civilian Harm** → **Model Version**
2. Update keywords: Edit `config/civilian_harm_config.json`
3. Retrain model: `python scripts/retrain_civilian_harm.py` (requires admin)

---

### Geolocation Issues

**Problem: "No GPS data found" but image is geotagged**

**Cause**: EXIF data stripped by platform, or non-standard GPS tag format

**Solution**:
1. Use `exiftool` externally to verify GPS data exists
2. Try uploading original image (not screenshot)
3. If downloaded from social media, request original via DM

---

**Problem: Clustering shows single cluster when locations are far apart**

**Cause**: DBSCAN epsilon parameter too large

**Solution**:
1. Navigate to **Geolocation** → **Settings** (gear icon)
2. Reduce `eps` parameter (default: 0.5 km → try 0.2 km)
3. Recompute clusters

---

### Feed Monitor Issues

**Problem: Monitor stopped polling**

**Cause**: Celery beat scheduler stopped, or API rate limit exceeded

**Solution**:
1. Check scheduler: **Settings** → **System** → **Celery Beat**
2. Restart beat: Click **Restart Beat**
3. Check monitor interval: If too frequent, increase interval to avoid rate limits

---

**Problem: Too many irrelevant posts in Watch Panel**

**Cause**: Keywords too broad, or hashtag used for multiple topics

**Solution**:
1. Edit monitor: Add exclusion keywords
   - Example: Monitor `"conflict"` but exclude `"movie conflict"`, `"work conflict"`
2. Use AND logic: `"conflict" AND "military"` (stricter matching)
3. Enable Civilian Harm filter: Only show Medium+ scores

---

### Q&A System Issues

**Problem: "No relevant documents found" when document exists**

**Cause**: FAISS vectorstore not updated, or query semantically mismatched

**Solution**:
1. Re-index document: **Reports** → Select document → **Re-index**
2. Rephrase question (use keywords from document)
3. Check document upload status: **Reports** → Status column should be "Indexed"

---

**Problem: Answers cite wrong document**

**Cause**: Multiple documents with similar content, vectorstore confusion

**Solution**:
1. Use **Specific Report** scope instead of **All Documents**
2. Check document metadata: **Reports** → Click document → **Metadata**
3. Re-upload with unique title (helps LLM distinguish)

---

### Export Issues

**Problem: PDF export fails with "Generation timeout"**

**Cause**: Too many images/graphs, or large investigation dataset

**Solution**:
1. Deselect some sections: Uncheck **Graphs** or **Timeline** (heavy rendering)
2. Export as Markdown instead (faster, no rendering)
3. Increase timeout: **Settings** → **Export** → **PDF Timeout** (default: 60s → 120s)

---

**Problem: STIX export missing entities**

**Cause**: Entity type not supported in STIX 2.1, or relationship too weak

**Solution**:
1. Check STIX spec: Some entity types (e.g., "concept") don't map to STIX objects
2. Export as JSON instead (full data, no filtering)
3. Manually convert JSON to STIX using external tool

---

### Performance Issues

**Problem: Platform slow after 100+ investigations**

**Cause**: Knowledge base vectorstore too large, slowing semantic search

**Solution**:
1. Archive old investigations: **Settings** → **Knowledge Base** → **Archive**
2. Delete investigations older than retention period: **Compliance** → **Retention** → **Run Cleanup**
3. Increase server resources (RAM, CPU)

---

**Problem: Batch investigation times out after 20 minutes**

**Cause**: Too many targets, or targets with large datasets

**Solution**:
1. Reduce batch size (10-20 targets max)
2. Use **Quick** depth instead of **Standard**
3. Increase Celery worker count: `CELERY_WORKERS=8` (env var)

---

### ForgeChain Governance Issues

**Problem: "Operation blocked by verifiers" but request seems legitimate**

**Cause**: Overly strict rules, or false positive in safety verifier

**Solution**:
1. Check audit log: **Settings** → **Governance** → **Audit Logs**
2. Review verifier reasoning: See which verifier rejected and why
3. Request elevated authorization: **Governance** → **Request Override**
4. Adjust rules: **Settings** → **Governance** → **Rules** (admin only)

---

### Compliance Issues

**Problem: GDPR deletion request fails**

**Cause**: Data locked by legal hold, or entity not found

**Solution**:
1. Check legal holds: **Compliance** → **Legal Holds**
2. Verify identifier: Search Knowledge Base to confirm data exists
3. Manual deletion: Contact admin to force delete (bypasses holds)

---

### General Troubleshooting Steps

1. **Check System Status**
   - **Settings** → **System** → **Health Check**
   - Green = all services running
   - Red = service down (click for details)

2. **Review Logs**
   - **Settings** → **Logs**
   - Filter by: timestamp, log level (ERROR, WARNING, INFO)
   - Download full log for support tickets

3. **Restart Services**
   - **Settings** → **System** → **Restart Services**
   - Restarts: Flask app, Celery workers, Celery beat

4. **Clear Cache**
   - **Settings** → **System** → **Clear Cache**
   - Clears: Redis cache, browser cache (cookies retained)

5. **Contact Support**
   - If issue persists, export logs: **Settings** → **Logs** → **Export**
   - File support ticket with: error message, steps to reproduce, exported logs

---

## Appendix

### Environment Variables Reference

- `CIVILIAN_HARM_ENABLED`: Enable/disable civilian harm classifier (default: `true`)
- `GDPR_AUTO_DELETE`: Auto-execute deletion requests without review (default: `false`)
- `CELERY_WORKERS`: Number of Celery workers for parallel processing (default: `4`)
- `WAYBACK_ENABLED`: Enable Wayback Machine integration (default: `true`)
- `WEB_INTEL_ENABLED`: Enable Web Intelligence dork search (default: `true`)
- `FORGE_CHAIN_ENABLED`: Enable ForgeChain governance (default: `true`)

### API Rate Limits

| Platform | Authenticated Limit | Unauthenticated Limit |
|----------|--------------------|-----------------------|
| Twitter/X | 300 req/15min | 15 req/15min |
| Reddit | 60 req/min | 10 req/min |
| YouTube | 10,000 units/day | N/A |
| Instagram | 200 req/hour | N/A |
| Mastodon | Varies by instance | Varies by instance |

### Supported File Formats

**Reports**: PDF, Markdown (.md, .markdown)  
**Geolocation**: JPG, PNG, HEIC, MP4, MOV, AVI  
**Export**: PDF, Markdown, JSON, CSV, STIX 2.1, GraphML

### TLP Classification Guidelines

- **TLP:WHITE**: Can be shared publicly, no restrictions
- **TLP:GREEN**: Share with peers and partners in the cybersecurity/OSINT community
- **TLP:AMBER**: Limited distribution, need-to-know basis only, no public disclosure
- **TLP:RED**: Recipients only, do not share further (eyes-only)

---

**End of User Guide**

*For technical documentation, see `DEPLOYMENT.md` and `API_REFERENCE.md`*  
*For developer documentation, see `CONTRIBUTING.md`*  
*Last updated: August 17, 2026*
