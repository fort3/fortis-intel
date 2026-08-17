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
    "dork_gap_analysis_chain": "Gap analysis — identifies missing intelligence for web search",
    "dork_validation_chain": "Validation query generation — cross-references findings via web search",
    "dork_synthesis_chain": "Web search synthesis — integrates search results into investigation",
    "dork_deep_synthesis_chain": "Deep synthesis — enriches findings with full-page scraped content",
}

ENDPOINT_REQUIRED_KEYS = {
    "/ask": {"context", "question"},
    "/investigate": {"identifier", "identifier_type"},
    "/triangulate": {"identifiers"},
    "/batch-investigate": {"identifiers"},
    "/enrich": {"context", "document_text"},
    "/scenario": {"context", "scenario_type"},
    "/monitor/create": {"monitor_type", "query"},
    "/export/pdf": {"session_id"},
    "/export/markdown": {"session_id"},
    "/export/stix": {"session_id"},
    "/export/csv": {"session_id"},
    "/export/json": {"session_id"},
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
