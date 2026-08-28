"""Lightweight intent extraction for ForgeChain -- no LLM call needed.

Fortis Intelligence Hub validates and routes inputs through its endpoints,
so the interpreter just packages that routing as structured intent data.
"""

CHAIN_DESCRIPTIONS = {
    # Investigation chains
    "osint_subject_investigation": "OSINT subject investigation across social platforms",
    "osint_geolocation_triangulation": "Geolocation triangulation from multi-source indicators",
    "osint_batch_investigation": "Batch OSINT investigation across multiple identifiers",
    # Enrichment and search
    "osint_document_enrichment": "Document enrichment with OSINT context and entity extraction",
    "osint_osint_search": "General OSINT search and intelligence gathering",
    "osint_rag_query": "RAG-based Q&A over ingested knowledge base and documents",
    # Analysis
    "osint_scenario_analysis": "Scenario analysis from behavioral patterns and OSINT data",
    "osint_feed_monitoring": "Real-time feed monitoring rule creation and management",
    "osint_entity_mapping": "Entity relationship mapping and social graph analysis",
    # Web intelligence (dork search)
    "dork_collection_chain": "Initial collection — generates dork queries for pre-OSINT web discovery",
    "dork_gap_analysis_chain": "Gap analysis — identifies missing intelligence for web search",
    "dork_validation_chain": "Validation query generation — cross-references findings via web search",
    "dork_synthesis_chain": "Web search synthesis — integrates search results into investigation",
    "dork_deep_synthesis_chain": "Deep synthesis — enriches findings with full-page scraped content",
    "report_consolidation_chain": "Report consolidation — merges initial analysis with web intelligence into unified brief",
    "competing_hypotheses_chain": "Competing hypotheses (ACH) — generates alternative explanations to counter confirmation bias",
    "report_refinement_chain": "Report refinement — produces analyst-ready brief from raw report + integrity results",
    "chat_intent_chain": "Chat intent classifier — routes user messages to appropriate OSINT pipeline",
    # Image analysis (no LLM chains — these are local processing modules)
    "image_reverse_search": "Reverse image search via TinEye API and perceptual hash cache",
    "image_forensics_ela": "Error Level Analysis and clone detection for image tampering assessment",
    "image_steganography": "LSB, RS analysis, and sample pairs steganography detection",
    "image_clip_vision": "CLIP zero-shot classification, landmark detection, and content safety",
    "image_deepseek_vision": "DeepSeek Vision AI scene description, object identification, text extraction, and OSINT assessment",
    "vision_geolocation": "AI vision-based geolocation — two-pass clue extraction with country feature cross-referencing, Overpass spatial verification, and multi-round refinement",
    "geoclip_locator": "GeoCLIP local GPS prediction — contrastive learning model predicts coordinates from images without API calls",
    "geo_features": "Country visual feature database — bollards, sign systems, road markings, license plates for 30+ countries",
    "overpass_client": "OpenStreetMap Overpass API — spatial context queries for nearby streets, POIs, landmarks, admin boundaries",
    "url_endpoint_fuzzing": "URL endpoint fuzzing for domain recon — probes common paths to discover exposed endpoints (elevated authorization required)",
    # Attribution and deanonymization modules
    "breach_client": "HaveIBeenPwned + LeakCheck credential exposure lookup — breach history, paste mentions, password reuse detection",
    "username_enum": "Broad username enumeration — Sherlock-style HTTP probing across 80+ platforms (developer, gaming, security, social, commerce)",
    "email_accounts": "Email-to-accounts resolution — discovers which services an email is registered on (Holehe-style service detection)",
    "recursive_pivot": "Recursive pivot engine — auto-investigates discovered emails, domains, and usernames from profile data (depth-limited, 2-hop max)",
    "attribution_chain": "Attribution chain scoring — confidence-scored identity links from seed to discovered identities (CONFIRMED/STRONG/MODERATE/CIRCUMSTANTIAL)",
}

ENDPOINT_REQUIRED_KEYS = {
    "/ask": {"question"},
    "/investigate": {"subject_identifier", "identifier_type"},
    "/triangulate": {"geo_points"},
    "/batch-investigate": {"per_entity_summaries"},
    "/enrich": {"document_text"},
    "/scenario": {"scenario_type", "osint_data"},
    "/monitor/create": {"monitor_type", "query"},
    "/export/pdf": {"session_id"},
    "/export/markdown": {"session_id"},
    "/export/stix": {"session_id"},
    "/export/csv": {"session_id"},
    "/export/json": {"session_id"},
    "/analyze-image": {"images"},
    "/export/drive": {"session_id"},
}

# Endpoint to intent category mapping
ENDPOINT_INTENT_MAP = {
    "/ask": "rag_query",
    "/investigate": "subject_investigation",
    "/triangulate": "geolocation_triangulation",
    "/batch-investigate": "batch_investigation",
    "/enrich": "document_enrichment",
    "/scenario": "scenario_analysis",
    "/monitor/create": "feed_monitoring",
}


def interpret(
    endpoint: str,
    mode: str,
    chain_name: str,
    chain_input_keys: list[str],
) -> dict:
    return {
        "action": "invoke_chain",
        "endpoint": endpoint,
        "mode": mode,
        "chain_name": chain_name,
        "input_keys": sorted(chain_input_keys),
        "intent_summary": CHAIN_DESCRIPTIONS.get(chain_name, f"Chain invocation: {chain_name}"),
        "intent_category": ENDPOINT_INTENT_MAP.get(endpoint, "osint_search"),
    }
