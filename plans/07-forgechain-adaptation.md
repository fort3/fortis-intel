# Fortis Intelligence Hub — ForgeChain Adaptation

## Overview

ForgeChain is carried over from TIPS Hub with minimal changes. The 10-step
`gated_invoke()` pipeline, consensus gate, token system, and persistence layer
remain identical. Only the rule verifier's domain-specific policies are adapted
for OSINT context.

---

## What Stays Unchanged

| Component            | File                   | Changes |
|----------------------|------------------------|---------|
| `gated_invoke()`     | `forge/gated_invoke.py`| None — same 10-step pipeline |
| `ForgeGate`          | `forge/gate.py`        | None — same 2/3 consensus logic |
| `LLMSafetyVerifier`  | `forge/verifiers.py`   | Model changed: DeepSeek v4-pro (was Claude Opus) |
| `LLMConsistencyVerifier`| `forge/verifiers.py` | Model changed: DeepSeek v4-pro (was Claude Opus) |
| `ForgeBlock`         | `forge/models.py`      | None — same blockchain-like model |
| `ForgeToken`         | `forge/models.py`      | None — same single-use token |
| `ForgeChainSession`  | `forge/models.py`      | None — same session model |
| `executor.py`        | `forge/executor.py`    | None — same token-gated execution |
| `healer.py`          | `forge/healer.py`      | None — same healing strategies |
| `interpreter.py`     | `forge/interpreter.py` | Minor — new endpoint names |
| `chain_store.py`     | `forge/chain_store.py` | None — same SQLite + Fernet |
| `replay.py`          | `forge/replay.py`      | None — same forensic replay |
| `audit_integration.py`| `forge/audit_integration.py`| None — same bridge |
| `config.py`          | `forge/config.py`      | None — same env config |

---

## What Changes: Rule Verifier

The `RuleVerifier` in `forge/verifiers.py` is the only component that needs
OSINT-specific policy adaptations.

### Carried Over Rules (Unchanged)

1. **Prompt injection detection** — 13 regex patterns including leetspeak normalization
2. **Unicode homoglyph detection** — NFKC normalization
3. **Sensitive data scanning** — Credit cards, SSN, API keys, etc.
4. **Input length limits** — `FORGE_MAX_PROMPT_LENGTH=50000`
5. **Trusted keys concept** — Certain keys (osint_data, context, geo_data) get
   lightweight pattern check instead of full injection scan

### New OSINT-Specific Rules

#### a. Minor Protection

```python
MINOR_INDICATORS = [
    r'\b(minor|child|juvenile|underage|kid|teen(?:ager)?)\b',
    r'\bage\s*(?::|is|=)\s*(?:[1-9]|1[0-7])\b',
    r'\b(?:school|elementary|middle\s+school|high\s+school)\s+student\b',
]

def _check_minor_protection(self, chain_input):
    """Block investigations targeting minors unless elevated auth present."""
    text = self._extract_scannable_text(chain_input)
    for pattern in MINOR_INDICATORS:
        if re.search(pattern, text, re.IGNORECASE):
            if not chain_input.get('elevated_authorization'):
                return VerifierVote(
                    approved=False,
                    reason="Investigation appears to target a minor. "
                           "Elevated authorization required.",
                    confidence=0.9,
                    policy_veto=True
                )
    return None  # no concern
```

#### b. Harassment / Stalking Detection

```python
HARASSMENT_INDICATORS = [
    r'\b(?:stalk|harass|track\s+(?:their|her|his)\s+movements?)\b',
    r'\b(?:find\s+(?:their|her|his)\s+(?:home|address|where\s+they\s+live))\b',
    r'\b(?:real\s+(?:name|identity)\s+(?:of|for)\s+(?:a|an)\s+anonymous)\b',
    r'\b(?:dox|doxx|expose\s+(?:their|her|his)\s+identity)\b',
]

def _check_harassment_intent(self, chain_input):
    """Flag potential harassment/stalking queries for elevated review."""
    text = self._extract_scannable_text(chain_input)
    for pattern in HARASSMENT_INDICATORS:
        if re.search(pattern, text, re.IGNORECASE):
            return VerifierVote(
                approved=False,
                reason="Query contains indicators of potential harassment or "
                       "stalking intent. Review and document legitimate purpose.",
                confidence=0.7,
                policy_veto=False  # soft deny, LLM verifiers can override
            )
    return None
```

#### c. Investigation Purpose Validation

```python
def _check_investigation_purpose(self, chain_input, endpoint):
    """Ensure investigation endpoints include a documented purpose."""
    if endpoint in ('/investigate', '/triangulate', '/batch-investigate'):
        purpose = chain_input.get('investigation_purpose', '')
        if not purpose or len(purpose.strip()) < 10:
            return VerifierVote(
                approved=False,
                reason="Investigation purpose must be documented (min 10 chars).",
                confidence=0.95,
                policy_veto=True
            )
    return None
```

#### d. Platform-Specific Rate Awareness

```python
def _check_rate_awareness(self, chain_input):
    """Warn (soft) when querying many platforms simultaneously."""
    platforms = chain_input.get('platforms', [])
    if len(platforms) > 5:
        return VerifierVote(
            approved=True,  # allowed but flagged
            reason=f"Querying {len(platforms)} platforms simultaneously. "
                   "Consider narrowing scope for efficiency.",
            confidence=0.5,
            policy_veto=False
        )
    return None
```

#### e. Identifier Format Validation

```python
IDENTIFIER_PATTERNS = {
    'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'phone': r'^\+?[1-9]\d{6,14}$',
    'domain': r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$',
    'ip': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
    'username': r'^@?[a-zA-Z0-9._-]{1,100}$',
}

def _check_identifier_format(self, chain_input):
    """Validate identifier format before expensive API calls."""
    identifier = chain_input.get('subject_identifier', '')
    id_type = chain_input.get('identifier_type', '')
    
    if id_type in IDENTIFIER_PATTERNS:
        if not re.match(IDENTIFIER_PATTERNS[id_type], identifier):
            return VerifierVote(
                approved=False,
                reason=f"Invalid {id_type} format: '{identifier}'",
                confidence=0.95,
                policy_veto=True
            )
    return None
```

### Updated Endpoint Whitelist

```python
FORTIS_ENDPOINTS = {
    '/ask',
    '/investigate',
    '/triangulate',
    '/batch-investigate',
    '/enrich',
    '/scenario',
    '/monitor/create',
    '/export/pdf',
    '/export/markdown',
    '/export/stix',
    '/export/csv',
    '/export/json',
    '/export/drive',
}
```

### Updated Trusted Keys

```python
FORTIS_TRUSTED_KEYS = {
    'osint_data',       # OSINT API response data (large, structured)
    'context',          # RAG context from vectorstore
    'kb_context',       # Knowledge Base context
    'geo_data',         # Geolocation data points
    'entity_graph_context',  # Graph summary for LLM
    'document_text',    # Uploaded document text
    'metadata_summary', # Extracted metadata
}
```

---

## Interpreter Adaptation

The `interpreter.py` module extracts intent from chain inputs. For Fortis,
the intent categories change:

### TIPS Hub Intent Categories
```
cve_analysis, malware_research, incident_investigation, supply_chain_analysis,
batch_analysis, trend_report, product_intelligence, rag_query, scenario,
engagement, product_analysis
```

### Fortis Intent Categories
```
subject_investigation, geolocation_triangulation, batch_investigation,
document_enrichment, osint_search, rag_query, scenario_analysis,
feed_monitoring, entity_mapping
```

---

## Audit Events

ForgeChain audit events via `audit_integration.py` remain the same event types:

| Event                   | When                                           |
|-------------------------|-------------------------------------------------|
| `FORGE_EXECUTED`        | Chain approved and executed successfully        |
| `FORGE_REFUSED`         | Soft deny — query flagged but not hard-blocked  |
| `FORGE_BLOCKED`         | Hard deny — policy violation detected           |
| `FORGE_HEALING`         | Blocked query underwent healing attempt         |
| `FORGE_TOKEN_MINTED`    | Execution token created for approved chain      |
| `FORGE_TOKEN_CONSUMED`  | Token used to execute chain                     |
| `FORGE_REPLAY_ACCESS`   | Forensic replay accessed for a session          |

New Fortis-specific metadata in audit events:
- `platforms_queried` — which OSINT platforms were involved
- `geo_data_collected` — whether geolocation data was gathered
- `subject_identifier_hash` — SHA-256 hash of the investigated subject
- `investigation_purpose` — analyst-stated purpose (from ForgeChain input)

---

## ForgeChain Health Endpoint

`GET /forge/health` returns the same stats as TIPS Hub:

```json
{
  "total_blocks": 1247,
  "executed": 1180,
  "refused": 42,
  "blocked": 25,
  "sessions": 89,
  "uptime_hours": 720,
  "healing_attempts": 12,
  "healing_success_rate": 0.58
}
```
