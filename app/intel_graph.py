"""Knowledge graph builder for Fortis Intelligence Hub OSINT investigations.

Constructs a NetworkX directed graph from OSINT investigation findings
and extracted entities. Zero LLM cost -- all entities and relationships
are parsed from structured data.

Node types: person, organization, location, account, domain, event, media
Edge types: associated_with, located_at, posted_from, linked_to,
            alias_of, member_of, mentioned_by
"""

import time
from collections import defaultdict

import networkx as nx


# ── Node type colors (for Cytoscape rendering) ────────────────────────

NODE_COLORS = {
    "person": "#9b59b6",
    "organization": "#8b5cf6",
    "location": "#22c55e",
    "account": "#bb6bd9",
    "domain": "#6b3fa0",
    "event": "#f59e0b",
    "media": "#d946ef",
}

EDGE_TYPES = {
    "associated_with",
    "located_at",
    "posted_from",
    "linked_to",
    "alias_of",
    "member_of",
    "mentioned_by",
}


# ── Graph construction ────────────────────────────────────────────────


def build_investigation_graph(findings: list[dict]) -> nx.DiGraph:
    """Build a knowledge graph from OSINT investigation results.

    Each finding is expected to have:
        - source / platform: where the data came from
        - entities: list of extracted entities (optional)
        - relationships: list of relationship dicts (optional)
        - query / subject: what was investigated

    Args:
        findings: List of investigation finding dicts.

    Returns:
        A NetworkX DiGraph with typed nodes and labeled edges.
    """
    g = nx.DiGraph()
    if not findings:
        return g

    for finding in findings:
        # Add platform/source node
        platform = finding.get("platform") or finding.get("source") or "unknown"
        platform_nid = f"platform:{platform}"
        if platform_nid not in g:
            g.add_node(platform_nid, type="platform", label=platform)

        # Add subject node if present
        subject = finding.get("subject") or finding.get("query") or ""
        subject_type = finding.get("subject_type", "person")
        if subject:
            subject_nid = _make_node_id(subject_type, subject)
            if subject_nid not in g:
                g.add_node(subject_nid, type=subject_type, label=subject)
            g.add_edge(platform_nid, subject_nid, relationship="mentioned_by")

        # Process embedded entities
        for entity in finding.get("entities", []):
            _add_entity_node(g, entity, platform_nid)

        # Process embedded relationships
        for rel in finding.get("relationships", []):
            _add_relationship_edge(g, rel)

    return g


def build_entity_graph(entities: list[dict]) -> nx.DiGraph:
    """Build a knowledge graph from a flat list of extracted entities.

    Each entity is expected to have:
        - type: person, organization, location, account, domain, event, media
        - name / value: entity identifier
        - Optional: platform, source, confidence, location, relationships

    Args:
        entities: List of entity dicts.

    Returns:
        A NetworkX DiGraph with typed nodes and labeled edges.
    """
    g = nx.DiGraph()
    if not entities:
        return g

    for entity in entities:
        etype = (entity.get("type") or "unknown").lower()
        ename = entity.get("name") or entity.get("value") or ""
        if not ename:
            continue

        nid = _make_node_id(etype, ename)
        attrs = {
            "type": etype,
            "label": ename,
            "confidence": entity.get("confidence", 0),
            "source": entity.get("source", ""),
            "platform": entity.get("platform", ""),
        }
        # Carry through optional metadata
        for key in ("url", "display_name", "country", "latitude",
                     "longitude", "description", "first_seen", "last_seen"):
            val = entity.get(key)
            if val is not None:
                attrs[key] = val

        if entity.get("aliases"):
            aliases = entity["aliases"]
            if isinstance(aliases, list):
                attrs["aliases"] = ", ".join(aliases[:10])
            else:
                attrs["aliases"] = str(aliases)

        g.add_node(nid, **attrs)

        # Location edge
        location = entity.get("location")
        if location and etype != "location":
            loc_nid = _make_node_id("location", location)
            if loc_nid not in g:
                g.add_node(loc_nid, type="location", label=location)
            g.add_edge(nid, loc_nid, relationship="located_at")

        # Platform edge
        platform = entity.get("platform")
        if platform:
            plat_nid = f"platform:{platform}"
            if plat_nid not in g:
                g.add_node(plat_nid, type="platform", label=platform)
            g.add_edge(nid, plat_nid, relationship="posted_from")

        # Explicit relationships
        for rel in entity.get("relationships", []):
            _add_relationship_edge(g, rel, source_override=nid)

        # Alias edges
        for alias in (entity.get("aliases") or []):
            if isinstance(alias, str) and alias:
                alias_nid = _make_node_id(etype, alias)
                if alias_nid not in g:
                    g.add_node(alias_nid, type=etype, label=alias,
                               is_alias=True)
                g.add_edge(nid, alias_nid, relationship="alias_of")

    return g


def _make_node_id(entity_type: str, name: str) -> str:
    """Create a deterministic node ID from type and name."""
    clean = name.strip().lower().replace(" ", "_")[:80]
    return f"{entity_type}:{clean}"


def _add_entity_node(g: nx.DiGraph, entity: dict, platform_nid: str):
    """Add an entity node from a finding and link to its platform."""
    etype = (entity.get("type") or "unknown").lower()
    ename = entity.get("name") or entity.get("value") or ""
    if not ename:
        return

    nid = _make_node_id(etype, ename)
    attrs = {
        "type": etype,
        "label": ename,
        "confidence": entity.get("confidence", 0),
        "source": entity.get("source", ""),
    }
    for key in ("url", "location", "platform", "description"):
        val = entity.get(key)
        if val is not None:
            attrs[key] = val

    g.add_node(nid, **attrs)
    g.add_edge(platform_nid, nid, relationship="mentioned_by")

    # Location sub-edge
    loc = entity.get("location")
    if loc and etype != "location":
        loc_nid = _make_node_id("location", loc)
        if loc_nid not in g:
            g.add_node(loc_nid, type="location", label=loc)
        g.add_edge(nid, loc_nid, relationship="located_at")


def _add_relationship_edge(g: nx.DiGraph, rel: dict,
                           source_override: str | None = None):
    """Add an edge from a relationship dict.

    Expected keys: source_type, source_name, target_type, target_name,
                   relationship_type
    """
    rel_type = rel.get("relationship_type", "associated_with")

    source_nid = source_override
    if not source_nid:
        stype = (rel.get("source_type") or "unknown").lower()
        sname = rel.get("source_name") or rel.get("source_value") or ""
        if not sname:
            return
        source_nid = _make_node_id(stype, sname)
        if source_nid not in g:
            g.add_node(source_nid, type=stype, label=sname)

    ttype = (rel.get("target_type") or "unknown").lower()
    tname = rel.get("target_name") or rel.get("target_value") or ""
    if not tname:
        return
    target_nid = _make_node_id(ttype, tname)
    if target_nid not in g:
        g.add_node(target_nid, type=ttype, label=tname)

    g.add_edge(source_nid, target_nid, relationship=rel_type)


# ── Correlation queries (OSINT-adapted) ────────────────────────────────


def get_shared_connections(graph: nx.DiGraph) -> list[dict]:
    """Entities connected to multiple other entities (hub nodes).

    Finds nodes with high degree centrality -- useful for identifying
    key persons, organizations, or accounts in an investigation.
    """
    results = []
    for nid, attrs in graph.nodes(data=True):
        ntype = attrs.get("type", "")
        if ntype in ("platform",):
            continue
        in_deg = graph.in_degree(nid)
        out_deg = graph.out_degree(nid)
        total = in_deg + out_deg
        if total >= 3:
            connections = set()
            for pred in graph.predecessors(nid):
                connections.add(graph.nodes[pred].get("label", pred))
            for succ in graph.successors(nid):
                connections.add(graph.nodes[succ].get("label", succ))
            results.append({
                "node_id": nid,
                "connection_count": total,
                "connections": sorted(connections)[:10],
                **attrs,
            })
    return sorted(results, key=lambda x: x["connection_count"], reverse=True)


def get_location_clusters(graph: nx.DiGraph) -> list[dict]:
    """Locations with multiple entities associated.

    Returns location nodes and all entities linked to them,
    useful for geographic pattern analysis.
    """
    results = []
    for nid, attrs in graph.nodes(data=True):
        if attrs.get("type") != "location":
            continue
        entities = []
        for pred in graph.predecessors(nid):
            pred_attrs = graph.nodes[pred]
            if graph[pred][nid].get("relationship") == "located_at":
                entities.append({
                    "node_id": pred,
                    "type": pred_attrs.get("type", "unknown"),
                    "label": pred_attrs.get("label", pred),
                })
        if len(entities) >= 2:
            results.append({
                "node_id": nid,
                "location": attrs.get("label", nid),
                "entity_count": len(entities),
                "entities": entities,
                **attrs,
            })
    return sorted(results, key=lambda x: x["entity_count"], reverse=True)


def get_activity_overlap(graph: nx.DiGraph) -> list[dict]:
    """Entities that appear across multiple platforms/sources.

    Identifies accounts or persons seen on different platforms,
    suggesting cross-platform activity patterns.
    """
    results = []
    for nid, attrs in graph.nodes(data=True):
        ntype = attrs.get("type", "")
        if ntype not in ("person", "account", "organization"):
            continue
        platforms = set()
        for neighbor in list(graph.successors(nid)) + list(graph.predecessors(nid)):
            n_attrs = graph.nodes[neighbor]
            if n_attrs.get("type") == "platform":
                platforms.add(n_attrs.get("label", neighbor))
            # Also check platform attribute on connected nodes
            plat = n_attrs.get("platform")
            if plat:
                platforms.add(plat)
        # Check own platform attribute
        own_plat = attrs.get("platform")
        if own_plat:
            platforms.add(own_plat)

        if len(platforms) >= 2:
            results.append({
                "node_id": nid,
                "platform_count": len(platforms),
                "platforms": sorted(platforms),
                **attrs,
            })
    return sorted(results, key=lambda x: x["platform_count"], reverse=True)


def get_entity_neighborhood(graph: nx.DiGraph, entity_type: str,
                            entity_name: str) -> nx.DiGraph:
    """2-hop subgraph around a specific entity node."""
    nid = _make_node_id(entity_type, entity_name)
    if nid not in graph:
        return nx.DiGraph()
    nodes = {nid}
    for neighbor in list(graph.successors(nid)) + list(graph.predecessors(nid)):
        nodes.add(neighbor)
        for hop2 in list(graph.successors(neighbor)) + list(graph.predecessors(neighbor)):
            nodes.add(hop2)
    return graph.subgraph(nodes).copy()


# ── Export ─────────────────────────────────────────────────────────────


def graph_to_cytoscape_json(graph: nx.DiGraph, max_nodes: int = 300) -> dict:
    """Export graph to Cytoscape.js JSON format.

    Priority-based truncation when graph exceeds max_nodes:
    persons > organizations > accounts > locations > remaining.
    """
    if graph.number_of_nodes() == 0:
        return {"nodes": [], "edges": []}

    if graph.number_of_nodes() <= max_nodes:
        included = set(graph.nodes())
    else:
        included: set[str] = set()
        by_type: dict[str, list] = defaultdict(list)
        for nid, attrs in graph.nodes(data=True):
            by_type[attrs.get("type", "other")].append((nid, attrs))

        # Priority order for inclusion
        priority_types = [
            "person", "organization", "account", "location",
            "domain", "event", "media", "platform",
        ]
        for node_type in priority_types:
            entries = by_type.get(node_type, [])
            entries.sort(key=lambda x: x[1].get("confidence", 0), reverse=True)
            for nid, _ in entries:
                if len(included) >= max_nodes:
                    break
                included.add(nid)

        # Fill remaining with other types
        for node_type, entries in by_type.items():
            if node_type in priority_types:
                continue
            for nid, _ in entries:
                if len(included) >= max_nodes:
                    break
                included.add(nid)

    nodes = []
    for nid in included:
        attrs = dict(graph.nodes[nid])
        data = {"id": nid, **attrs}
        # Add color hint for rendering
        data["color"] = NODE_COLORS.get(attrs.get("type", ""), "#9b59b6")
        # Serialize list-like attributes
        if isinstance(data.get("aliases"), list):
            data["aliases"] = ", ".join(data["aliases"][:5])
        nodes.append({"data": data})

    edges = []
    for u, v, attrs in graph.edges(data=True):
        if u in included and v in included:
            edges.append({"data": {
                "id": f"e_{u}_{v}",
                "source": u,
                "target": v,
                "relationship": attrs.get("relationship", ""),
            }})

    return {"nodes": nodes, "edges": edges}


def graph_summary(graph: nx.DiGraph) -> str:
    """Text summary of graph structure (brief)."""
    if graph.number_of_nodes() == 0:
        return ""

    type_counts = defaultdict(int)
    for _, attrs in graph.nodes(data=True):
        type_counts[attrs.get("type", "other")] += 1

    parts = ["=== Investigation Graph Summary ==="]
    type_strs = [f"{c} {t.replace('_', ' ')}s" for t, c in
                 sorted(type_counts.items(), key=lambda x: -x[1])]
    parts.append(f"Nodes: {graph.number_of_nodes()} ({', '.join(type_strs)})")
    parts.append(f"Edges: {graph.number_of_edges()}")

    shared = get_shared_connections(graph)
    if shared:
        hubs = ", ".join(f"{s['label']} ({s['connection_count']} links)"
                         for s in shared[:5])
        parts.append(f"Hub entities: {hubs}")

    clusters = get_location_clusters(graph)
    if clusters:
        locs = ", ".join(f"{c['location']} ({c['entity_count']} entities)"
                         for c in clusters[:3])
        parts.append(f"Location clusters: {locs}")

    overlap = get_activity_overlap(graph)
    if overlap:
        cross = ", ".join(
            f"{o['label']} ({', '.join(o['platforms'])})"
            for o in overlap[:3]
        )
        parts.append(f"Cross-platform activity: {cross}")

    return "\n".join(parts)


def graph_context(graph: nx.DiGraph, max_chars: int = 6000) -> str:
    """Token-efficient, prioritized context from the knowledge graph.

    Generates a deduplicated summary for LLM consumption by traversing
    graph nodes and edges. Budget-aware output capped at max_chars.
    """
    if graph.number_of_nodes() == 0:
        return ""

    parts: list[str] = ["=== OSINT Investigation Graph ==="]
    used = len(parts[0])

    type_counts = defaultdict(int)
    for _, attrs in graph.nodes(data=True):
        type_counts[attrs.get("type", "other")] += 1
    type_strs = [f"{c} {t.replace('_', ' ')}s" for t, c in
                 sorted(type_counts.items(), key=lambda x: -x[1])]
    header = (f"Graph: {graph.number_of_nodes()} nodes "
              f"({', '.join(type_strs)}), "
              f"{graph.number_of_edges()} edges")
    parts.append(header)
    used += len(header)

    def _budget_ok(text: str) -> bool:
        nonlocal used
        if used + len(text) > max_chars:
            return False
        used += len(text)
        return True

    # Hub entities (high connectivity)
    shared = get_shared_connections(graph)
    if shared:
        section = ["\n--- Key Hub Entities ---"]
        for s in shared[:8]:
            line = (f"  {s.get('type', '?').title()} \"{s['label']}\": "
                    f"{s['connection_count']} connections "
                    f"(conf: {s.get('confidence', '?')})")
            conns = s.get("connections", [])
            if conns:
                line += f" -> {', '.join(conns[:5])}"
            section.append(line)
        block = "\n".join(section)
        if _budget_ok(block):
            parts.append(block)

    # Location clusters
    clusters = get_location_clusters(graph)
    if clusters:
        section = ["\n--- Geographic Clusters ---"]
        for c in clusters[:6]:
            entity_strs = [f"{e['type']}:{e['label']}" for e in c["entities"][:5]]
            line = (f"  {c['location']}: {c['entity_count']} entities "
                    f"({', '.join(entity_strs)})")
            section.append(line)
        block = "\n".join(section)
        if _budget_ok(block):
            parts.append(block)

    # Cross-platform activity
    overlap = get_activity_overlap(graph)
    if overlap:
        section = ["\n--- Cross-Platform Activity ---"]
        for o in overlap[:6]:
            line = (f"  {o.get('type', '?').title()} \"{o['label']}\": "
                    f"seen on {', '.join(o['platforms'])}")
            section.append(line)
        block = "\n".join(section)
        if _budget_ok(block):
            parts.append(block)

    # Per-type entity digest
    for etype in ("person", "organization", "account", "domain"):
        type_nodes = [(nid, attrs) for nid, attrs in graph.nodes(data=True)
                      if attrs.get("type") == etype]
        if not type_nodes:
            continue
        section = [f"\n--- {etype.title()}s ({len(type_nodes)}) ---"]
        # Sort by confidence descending
        type_nodes.sort(key=lambda x: x[1].get("confidence", 0), reverse=True)
        for nid, attrs in type_nodes[:10]:
            extras = []
            if attrs.get("platform"):
                extras.append(f"platform: {attrs['platform']}")
            if attrs.get("location"):
                extras.append(f"location: {attrs['location']}")
            if attrs.get("aliases"):
                extras.append(f"aliases: {attrs['aliases']}")
            extras_str = f" [{', '.join(extras)}]" if extras else ""
            line = (f"  {attrs.get('label', nid)} "
                    f"(conf: {attrs.get('confidence', '?')}){extras_str}")
            section.append(line)
        block = "\n".join(section)
        if _budget_ok(block):
            parts.append(block)

    # Relationship summary
    rel_counts: Counter = defaultdict(int)
    for _, _, attrs in graph.edges(data=True):
        rel_counts[attrs.get("relationship", "unknown")] += 1
    if rel_counts:
        section = ["\n--- Relationship Summary ---"]
        for rtype, count in sorted(rel_counts.items(), key=lambda x: -x[1]):
            section.append(f"  {rtype}: {count}")
        block = "\n".join(section)
        if _budget_ok(block):
            parts.append(block)

    return "\n".join(parts)


# ── Graph caching ─────────────────────────────────────────────────────

_graph_cache: dict[str, tuple[float, nx.DiGraph]] = {}
_GRAPH_CACHE_TTL = 900  # 15 minutes
_MAX_CACHED_GRAPHS = 10


def cache_graph(graph: nx.DiGraph, cache_key: str) -> str:
    """Cache a graph and return its cache key.

    Args:
        graph: The graph to cache.
        cache_key: A unique key (e.g. investigation ID or query hash).

    Returns:
        The cache key for later retrieval.
    """
    _graph_cache[cache_key] = (time.time(), graph)
    if len(_graph_cache) > _MAX_CACHED_GRAPHS:
        oldest = min(_graph_cache, key=lambda k: _graph_cache[k][0])
        del _graph_cache[oldest]
    return cache_key


def get_cached_graph(key: str) -> nx.DiGraph | None:
    """Retrieve a cached graph if still valid (within TTL)."""
    entry = _graph_cache.get(key)
    if not entry:
        return None
    ts, graph = entry
    if time.time() - ts > _GRAPH_CACHE_TTL:
        del _graph_cache[key]
        return None
    return graph
