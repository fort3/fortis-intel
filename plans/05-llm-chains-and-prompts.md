# Fortis Intelligence Hub — LLM Chains & Prompt Architecture

## Overview

Fortis uses LangChain LCEL chains with a single-provider DeepSeek stack:
- **DeepSeek v4-flash** for all analysis chains — ultra-low cost ($0.14/$0.28
  per MTok) with strong reasoning and 1M context window
- **DeepSeek v4-pro** for ForgeChain governance verifiers — higher reasoning
  quality ($0.435/$0.87 per MTok) for safety-critical judgment

Both accessed via OpenAI-compatible API through `ChatOpenAI` from
`langchain-openai` — one provider, one API key.

Since there is no dual-mode (CTI/Red Team), all chains use a single analyst
persona with consistent temperature and framing.

---

## LLM Configuration

### Instances

| Instance          | Provider   | Model              | Temperature | Max Tokens | Purpose                     |
|-------------------|------------|---------------------|-------------|------------|-----------------------------|
| `_analyst_llm`    | DeepSeek   | deepseek-v4-flash  | 0.2         | 8192       | All analysis chains         |
| `_batch_llm`      | DeepSeek   | deepseek-v4-flash  | 0.1         | 2048       | Per-entity batch items      |
| `_forge_safety`   | DeepSeek   | deepseek-v4-pro    | 0.2         | 2048       | ForgeChain safety verifier  |
| `_forge_consist`  | DeepSeek   | deepseek-v4-pro    | 0.1         | 2048       | ForgeChain consistency      |

All instances use `ChatOpenAI` from `langchain-openai` with `base_url` set to
`https://api.deepseek.com/v1`. Single provider, single API key — no provider-specific
SDKs needed.

---

## Chain Inventory

### 1. Investigation Chain (`get_investigation_chain()`)

**Input variables:** `osint_data`, `geo_data`, `entity_graph_context`, `subject_identifier`, `identifier_type`, `kb_context`

**System prompt:**

```
You are an OSINT intelligence analyst. Your role is to synthesize open-source 
intelligence findings into clear, actionable intelligence reports.

You work exclusively with publicly available information gathered from social 
media, public records, news sources, and metadata analysis. You do not speculate 
beyond what the data supports. When evidence is thin, you say so.

For every claim, cite the source platform and data type (e.g., "Twitter geotag", 
"EXIF metadata", "posting pattern analysis"). Distinguish between confirmed facts 
(direct data), correlated findings (multiple sources align), and inferences 
(analytical judgment from patterns).

GEOLOCATION ANALYSIS:
When geospatial data is present, provide:
- Primary assessed location with confidence level and methodology
- Supporting evidence (which data points contributed)
- Contradictory indicators if any
- Temporal dimension: is this a current location, historical, or pattern-based?

SENSITIVITY CLASSIFICATION:
Recommend a sensitivity level for this report:
- PUBLIC: No personally identifiable information, general trends only
- INTERNAL: Contains identifying details, for organizational use
- RESTRICTED: Contains sensitive location or behavioral patterns
- CONFIDENTIAL: Contains information that could endanger if disclosed
```

**Report structure:**

```
## Executive Summary
## Subject Profile
## OSINT Source Analysis
## Geolocation Assessment
## Digital Footprint
## Entity Relationships
## Timeline of Activity
## Confidence Assessment
## Intelligence Gaps
## Recommendations
```

---

### 2. Enrichment Chain (`get_enrichment_chain()`)

**Input variables:** `document_text`, `extracted_entities`, `osint_data`, `geo_data`, `kb_context`

**Purpose:** Enrich an ingested document with OSINT findings.

**System prompt:**

```
You are an OSINT analyst enriching an existing intelligence report or document 
with additional open-source intelligence gathered from social media and public 
internet sources.

Your task is to:
1. Identify key entities, claims, and locations in the original document
2. Cross-reference with OSINT findings provided
3. Confirm, contradict, or expand on the document's assertions
4. Add geolocation context where available
5. Flag any claims that could not be verified through OSINT

Do NOT rewrite the original document. Produce a structured enrichment report 
that supplements it. Reference specific sections of the original where your 
findings apply.
```

**Report structure:**

```
## Enrichment Summary
## Confirmed Assertions
## Contradicted or Questionable Claims
## New Intelligence (not in original)
## Geolocation Enrichment
## Entity Cross-References
## Source Reliability Assessment
## Gaps Remaining
```

---

### 3. Geolocation Chain (`get_geolocation_chain()`)

**Input variables:** `geo_points`, `triangulation_result`, `metadata_summary`, `subject_context`

**Purpose:** Analyze and narrate geolocation findings.

**System prompt:**

```
You are a geospatial intelligence analyst specializing in location determination 
from open-source data. You receive multiple geolocation data points from 
different sources (EXIF, social media geotags, IP addresses, timezone analysis, 
language analysis, check-ins) and a computed triangulation result.

Your task is to:
1. Assess the reliability of each data source
2. Explain the triangulation methodology and its confidence level
3. Identify the most probable location(s) and why
4. Flag inconsistencies between data points
5. Provide temporal analysis if timestamps are available (location over time)
6. Suggest additional data that would improve confidence

CONFIDENCE SCALE:
- HIGH (>0.8): Multiple independent exact sources agree
- MODERATE (0.5-0.8): Some exact sources, corroborated by inferred data
- LOW (0.3-0.5): Primarily inferred data, few exact points
- SPECULATIVE (<0.3): Single source or highly uncertain inference

Never overstate confidence. A single geotag from a social post is not 
"confirmed" — it could be spoofed, VPN-routed, or from a shared device.
```

**Report structure:**

```
## Location Assessment
## Primary Location Analysis
## Alternate Locations
## Data Source Reliability
## Temporal Movement Pattern
## Methodology Notes
## Confidence Statement
## Recommendations for Improved Accuracy
```

---

### 4. Batch Synthesis Chain (`get_batch_synthesis_chain()`)

**Input variables:** `per_entity_summaries`, `aggregate_osint`, `cross_entity_relationships`, `geo_aggregate`

**Purpose:** Synthesize findings across multiple investigated entities.

**Report structure:**

```
## Batch Investigation Summary
## Cross-Entity Relationships
## Geographic Clustering
## Common Patterns
## Platform Distribution Analysis
## Notable Findings
## Per-Entity Key Takeaways
## Intelligence Gaps
## Recommendations
```

---

### 5. Batch Item Chain (`get_batch_item_chain()`)

**Input variables:** `osint_data`, `geo_data`, `subject_identifier`, `identifier_type`

**Purpose:** Quick per-entity analysis in batch processing (lower token budget).

**Output:** Concise single-entity summary (500-800 words).

---

### 6. RAG Chain (`get_rag_chain()`)

**Input variables:** `question`, `context`, `kb_context`

**Purpose:** Answer questions about uploaded documents, augmented with KB context.

**System prompt:**

```
You are an OSINT analyst answering questions about intelligence documents. Use 
the provided document context and knowledge base context to answer accurately.

If the answer is not in the provided context, say so. Do not fabricate information.
When citing, reference the document section or KB source.
```

---

### 7. Monitor Alert Chain (`get_monitor_alert_chain()`)

**Input variables:** `new_content`, `monitor_config`, `historical_context`

**Purpose:** Analyze new findings from feed monitors. Lightweight — runs frequently.

**System prompt:**

```
You are an OSINT monitoring analyst. A configured monitor has detected new content 
matching the watch criteria. Produce a brief assessment:

1. Relevance: How relevant is this to the monitored subject/topic? (HIGH/MEDIUM/LOW)
2. Key finding: What is the most important takeaway?
3. Location: Any geolocation indicators?
4. Action: Does this warrant immediate analyst attention?

Keep your assessment under 200 words. This is a triage, not a full investigation.
```

---

### 8. Scenario Chain (`get_scenario_chain()`)

**Input variables:** `osint_data`, `subject_context`, `scenario_type`, `kb_context`

**Purpose:** Generate intelligence scenarios based on OSINT patterns.

**Scenario types:**
- `pattern_of_life` — Daily/weekly behavioral patterns from posting data
- `network_mapping` — Social graph and connection analysis
- `location_prediction` — Probable future locations based on patterns
- `influence_analysis` — Reach, engagement patterns, influence networks

**Report structure varies by scenario type.**

---

## Prompt Design Principles

### Consistent across all chains:

1. **Source attribution required** — Every claim must cite the source platform and data type
2. **Confidence explicit** — Never present inferences as facts
3. **No fabrication** — If OSINT data is insufficient, state the gap
4. **Public data only** — Never suggest or imply accessing private/protected data
5. **Sensitivity awareness** — Recommend appropriate classification level
6. **Temporal context** — Distinguish current vs. historical vs. pattern-based findings
7. **Markdown formatting** — Use `##` headers, `**bold**` emphasis, `-` bullet lists,
   `code` for identifiers

### ForgeChain integration:

All chains are invoked via `gated_invoke()`. The ForgeChain rule verifier is
adapted for OSINT context:
- Blocks queries targeting minors (unless elevated authorization documented)
- Blocks queries that appear to be stalking/harassment in nature
- Validates that the analyst has documented the purpose of the investigation
- Validates identifier format before expensive API calls
