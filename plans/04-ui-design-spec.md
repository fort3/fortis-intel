# Fortis Intelligence Hub — UI/UX Design Specification

## Theme: Black & Purple Punk

Single theme — no light/dark toggle. The aesthetic is dark, bold, and utilitarian
with punk-inspired accents. Think neon-on-black terminal meets investigator's
war room.

---

## Color Palette

### Primary Colors

| Role              | Hex       | Usage                                            |
|-------------------|-----------|--------------------------------------------------|
| Background (deep) | `#0a0a0f` | Page background, main canvas                     |
| Background (card) | `#12121a` | Card backgrounds, panels, modals                 |
| Background (elev) | `#1a1a28` | Elevated elements, hover states, active cards     |
| Surface           | `#222233` | Input fields, dropdowns, table rows               |
| Border            | `#2a2a3d` | Card borders, dividers, subtle separators         |
| Border (active)   | `#6b3fa0` | Active/focused element borders                    |

### Accent Colors

| Role              | Hex       | Usage                                            |
|-------------------|-----------|--------------------------------------------------|
| Purple (primary)  | `#9b59b6` | Primary buttons, active tabs, links               |
| Purple (bright)   | `#bb6bd9` | Hover states, highlighted text, active indicators |
| Purple (neon)     | `#d946ef` | Critical alerts, punk accent glows                |
| Purple (dark)     | `#6b3fa0` | Button pressed states, selected items             |
| Purple (subtle)   | `#2d1f4e` | Purple-tinted backgrounds, tag backgrounds        |

### Text Colors

| Role              | Hex       | Usage                                            |
|-------------------|-----------|--------------------------------------------------|
| Text (primary)    | `#e8e6f0` | Main body text, headings                          |
| Text (secondary)  | `#9a97a8` | Subtitles, timestamps, metadata                   |
| Text (muted)      | `#5c5a6a` | Placeholders, disabled text                       |
| Text (bright)     | `#ffffff` | Button labels, critical emphasis                   |

### Semantic Colors

| Role              | Hex       | Usage                                            |
|-------------------|-----------|--------------------------------------------------|
| Success           | `#22c55e` | Confirmed locations, verified data                |
| Warning           | `#f59e0b` | Low confidence, unverified sources                |
| Danger            | `#ef4444` | High sensitivity, blocked by ForgeChain           |
| Info              | `#8b5cf6` | Informational badges, geo confidence rings        |

### Map Accent Colors

| Role              | Hex       | Usage                                            |
|-------------------|-----------|--------------------------------------------------|
| Marker (primary)  | `#9b59b6` | Primary location markers                          |
| Marker (alt)      | `#bb6bd9` | Alternate/secondary locations                     |
| Heatmap (low)     | `#2d1f4e` | Low density                                       |
| Heatmap (mid)     | `#9b59b6` | Medium density                                    |
| Heatmap (high)    | `#d946ef` | High density / high confidence                    |
| Radius circle     | `#9b59b620`| Confidence radius (20% opacity fill)             |
| Triangulation line| `#d946ef` | Lines connecting triangulation points             |

---

## Typography

| Element           | Font                         | Size   | Weight | Case       |
|-------------------|------------------------------|--------|--------|------------|
| H1 (page title)   | `'JetBrains Mono', monospace`| 28px   | 700    | UPPERCASE  |
| H2 (section)      | `'JetBrains Mono', monospace`| 20px   | 600    | UPPERCASE  |
| H3 (card title)   | `'Inter', sans-serif`        | 16px   | 600    | Normal     |
| Body text          | `'Inter', sans-serif`        | 14px   | 400    | Normal     |
| Monospace/code     | `'JetBrains Mono', monospace`| 13px   | 400    | Normal     |
| Button label       | `'Inter', sans-serif`        | 13px   | 600    | UPPERCASE  |
| Badge/tag          | `'JetBrains Mono', monospace`| 11px   | 500    | UPPERCASE  |
| Timestamp          | `'JetBrains Mono', monospace`| 12px   | 400    | Normal     |

**Punk accents:**
- Section headers use a subtle `text-shadow: 0 0 20px #9b59b640` glow
- Active elements get a `box-shadow: 0 0 12px #d946ef40` neon glow
- Card borders use a `1px solid #2a2a3d` with `hover: 1px solid #6b3fa0`

---

## Layout Structure

```
┌──────────────────────────────────────────────────────────────┐
│  ▌ FORTIS INTELLIGENCE HUB              [user] [KB] [Watch] │  ← Top bar
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │  TOOL CARDS (horizontally scrollable or grid)           │ │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌─────┐ │ │
│  │  │Ingest│ │Invest│ │ Geo  │ │Batch │ │Monit │ │ Q&A │ │ │
│  │  │      │ │igate │ │      │ │      │ │ or   │ │     │ │ │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └─────┘ │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                              │
│  ┌───────────────────────┬──────────────────────────────────┐│
│  │   INPUT PANEL         │   RESULTS PANEL                  ││
│  │                       │                                  ││
│  │  [active tool form]   │  ┌────────────────────────────┐  ││
│  │                       │  │  Analysis output           │  ││
│  │  Subject: ________    │  │  (rendered markdown)       │  ││
│  │  Platforms: [x][x][]  │  │                            │  ││
│  │  Depth: [standard ▾]  │  │                            │  ││
│  │                       │  ├────────────────────────────┤  ││
│  │  [  INVESTIGATE  ]    │  │  MAP VIEW                  │  ││
│  │                       │  │  ┌──────────────────────┐  │  ││
│  │                       │  │  │                      │  │  ││
│  │                       │  │  │   Leaflet.js map     │  │  ││
│  │                       │  │  │   with markers,      │  │  ││
│  │                       │  │  │   heatmap, radius    │  │  ││
│  │                       │  │  │                      │  │  ││
│  │                       │  │  └──────────────────────┘  │  ││
│  │                       │  ├────────────────────────────┤  ││
│  │                       │  │  ENTITY GRAPH              │  ││
│  │                       │  │  (Cytoscape.js)            │  ││
│  │                       │  ├────────────────────────────┤  ││
│  │                       │  │  CHARTS                    │  ││
│  │                       │  │  (Chart.js)                │  ││
│  │                       │  ├────────────────────────────┤  ││
│  │                       │  │  EXPORT BAR                │  ││
│  │                       │  │  [PDF] [MD] [STIX] [CSV]   │  ││
│  │                       │  │  [JSON] [Drive]            │  ││
│  └───────────────────────┴──────────────────────────────────┘│
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

---

## Tool Cards

Each tool card is a clickable tile that loads its form into the Input Panel.

### 1. Report Ingestion

- Upload PDF or Markdown file
- Drag-and-drop zone with purple accent border
- File type indicator and size display
- After upload: text preview + option to "Enrich with OSINT"

### 2. Investigation

- **Subject identifier** — text input (username, email, phone, domain, name)
- **Identifier type** — auto-detected with manual override dropdown
- **Platforms** — checkbox grid of configured platforms (grayed out if not configured)
- **Depth** — dropdown: Quick (API only), Standard (API + web), Deep (all sources)
- **Focus areas** — optional multi-select: Geolocation, Connections, Timeline, Content
- **Submit button**: `INVESTIGATE`

### 3. Geolocation / Triangulate

- **Data input methods** (tabs):
  - **Images** — multi-file upload for EXIF extraction
  - **Social posts** — paste URLs or content with metadata
  - **IP addresses** — paste list of IPs
  - **Locations** — manual coordinate/address entries
- **Map preview** — inline Leaflet map showing entered points in real-time
- **Submit button**: `TRIANGULATE`

### 4. Batch Investigation

- **Identifiers** — textarea (one per line) or CSV/XLSX upload
- **Identifier type** — dropdown (auto-detect, username, email, domain, phone)
- **Platforms** — checkbox grid
- **Submit button**: `BATCH INVESTIGATE`

### 5. Feed Monitor

- **Monitor type** — dropdown: Keyword, Username, Hashtag, Location radius
- **Query** — text input
- **Platforms** — checkbox grid
- **Interval** — dropdown: 5min, 15min, 30min, 1hr, 4hr
- **Alert threshold** — dropdown: All findings, High confidence only, Geo matches only
- **Submit button**: `START MONITOR`
- **Active monitors list** — below the form, showing status, last poll, finding count

### 6. Q&A (RAG)

- Chat interface against uploaded documents
- Text input with send button
- Chat history displayed in results panel
- KB context indicator showing when KB data augments the response

---

## Results Panel Components

### Analysis Output

- Rendered markdown with syntax highlighting
- Sensitivity level badge (color-coded):
  - `PUBLIC` — green badge
  - `INTERNAL` — blue/purple badge
  - `RESTRICTED` — amber badge
  - `CONFIDENTIAL` — red badge
- Source attribution tags (which platforms contributed)
- Collapsible sections for long reports

### Map View

- **Library**: Leaflet.js with OpenStreetMap tiles
- **Map tile style**: Dark theme (CartoDB Dark Matter or Stadia Dark)
- **Features**:
  - Purple markers for data points (custom SVG markers matching theme)
  - Pulsing circle for primary triangulated location
  - Dashed confidence radius circle (purple, 20% opacity fill)
  - Connecting lines between triangulation source points (neon purple)
  - Heatmap overlay for density visualization
  - Timeline slider for temporal location data
  - Cluster groups for dense marker areas
  - Popup cards on marker click: source, confidence, timestamp
- **Controls**:
  - Zoom, pan, fullscreen toggle
  - Layer toggle: markers, heatmap, radius, connections
  - Export map as PNG snapshot
  - Center on triangulated location

### Entity Graph

- **Library**: Cytoscape.js (carried over from TIPS Hub)
- **Node types & colors**:
  - Person: `#9b59b6` (purple)
  - Organization: `#8b5cf6` (violet)
  - Location: `#22c55e` (green)
  - Account/Profile: `#bb6bd9` (light purple)
  - Domain/IP: `#6b3fa0` (dark purple)
  - Event: `#f59e0b` (amber)
- **Edge types**: associated_with, located_at, posted_from, linked_to, alias_of
- **Interactions**: click node for detail panel, drag to rearrange, zoom, filter by type
- **Layout**: COSE (compound spring embedder) default, switchable to concentric/grid

### Charts

- **Library**: Chart.js (client-side) + Matplotlib (server-side for PDF)
- **Chart types for investigations**:
  - Platform source distribution (doughnut)
  - Confidence score breakdown (horizontal bar)
  - Activity timeline (line chart with time axis)
  - Location frequency (bar chart)
  - Entity type distribution (doughnut)
- **Theme**: All charts use purple gradient palette on dark backgrounds

### Export Bar

- Horizontal button row below results
- Buttons: `PDF`, `MARKDOWN`, `STIX`, `CSV`, `JSON`, `DRIVE`
- Each button shows a brief loading state then triggers download
- Drive upload shows confirmation with link

---

## Watch Panel (Feed Monitor Review)

Slides in from the right (same pattern as TIPS Hub Watch Mode).

```
┌─────────────────────────────────┐
│  WATCH — FEED MONITOR           │
│  [3 pending] [auto-refresh: ON] │
├─────────────────────────────────┤
│                                 │
│  ┌─────────────────────────────┐│
│  │ ● KEYWORD: "subject name"  ││
│  │   Platform: Twitter         ││
│  │   Found: 2 min ago          ││
│  │   Confidence: HIGH          ││
│  │                             ││
│  │   "Post content preview..." ││
│  │                             ││
│  │   📍 Location: detected     ││
│  │   [View on Map]             ││
│  │                             ││
│  │   [APPROVE]  [DISMISS]      ││
│  └─────────────────────────────┘│
│                                 │
│  ┌─────────────────────────────┐│
│  │ ● USERNAME: @handle         ││
│  │   ...                       ││
│  └─────────────────────────────┘│
└─────────────────────────────────┘
```

---

## Knowledge Base Panel

Slides in from the right. Same functionality as TIPS Hub.

- Report list with search/filter
- Toggle reports in/out of KB
- Delete reports
- Rebuild KB button
- Stats: total reports, in-KB count, chunk count, retention info

---

## Punk Design Elements

### Glitch/Noise Effects (Subtle)

- Page title has a subtle CSS `text-shadow` flicker on load (one-time, 0.5s)
- Card borders get a brief `#d946ef` flash on new data arrival
- Loading states use a purple scanline animation instead of a spinner

### Borders & Cards

- All cards: `border: 1px solid #2a2a3d`, `border-radius: 4px` (sharp, not rounded)
- Active/selected cards: `border-color: #6b3fa0`, `box-shadow: 0 0 12px #d946ef30`
- No drop shadows on inactive cards — flat and utilitarian

### Buttons

- Primary: `background: #9b59b6`, `color: #fff`, uppercase, `letter-spacing: 1px`
- Primary hover: `background: #bb6bd9`, `box-shadow: 0 0 16px #d946ef40`
- Secondary: `background: transparent`, `border: 1px solid #9b59b6`, `color: #9b59b6`
- Danger: `background: #ef4444`
- Disabled: `opacity: 0.4`, `cursor: not-allowed`

### Scrollbars

- Custom webkit scrollbars: thin, `#2a2a3d` track, `#6b3fa0` thumb
- Firefox: `scrollbar-color: #6b3fa0 #12121a`

### Inputs

- `background: #1a1a28`, `border: 1px solid #2a2a3d`, `color: #e8e6f0`
- Focus: `border-color: #9b59b6`, `box-shadow: 0 0 8px #9b59b630`
- Placeholder: `color: #5c5a6a`

---

## Responsive Behavior

- **Desktop (>1200px)**: Full layout as shown above, side-by-side input/results
- **Tablet (768-1200px)**: Stacked layout — input panel on top, results below
- **Mobile (<768px)**: Single column, collapsible tool cards, map fills width

---

## Accessibility

- All interactive elements keyboard-navigable
- ARIA labels on icon-only buttons
- Color contrast ratios meet WCAG AA on dark backgrounds
- Map markers have distinct shapes in addition to colors
- Screen reader support for analysis text (semantic HTML headings)
