"""Chart generation for Fortis Intelligence Hub reports using matplotlib.

Produces OSINT-relevant visualizations as base64 PNG images for PDF embedding:
- Platform source distribution (doughnut)
- Activity timeline (line chart)
- Entity type distribution (doughnut)
- Confidence score breakdown (horizontal bar)
- Location frequency (bar chart)
- Geo heatmap data generation (for Leaflet)
"""

import base64
import io
from collections import Counter
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np


# Purple gradient palette matching the Fortis theme
PURPLE_PALETTE = ["#2d1f4e", "#6b3fa0", "#9b59b6", "#bb6bd9", "#d946ef"]

# Extended palette for charts needing more colors
EXTENDED_PALETTE = [
    "#9b59b6", "#6b3fa0", "#bb6bd9", "#d946ef", "#2d1f4e",
    "#8b5cf6", "#a78bfa", "#c084fc", "#7c3aed", "#5b21b6",
]

# Entity type colors (matching intel_graph node colors)
ENTITY_COLORS = {
    "person": "#9b59b6",
    "organization": "#8b5cf6",
    "location": "#22c55e",
    "account": "#bb6bd9",
    "domain": "#6b3fa0",
    "event": "#f59e0b",
    "media": "#d946ef",
}

# Dark background for all charts
CHART_BG = "#0a0a0f"
CHART_TEXT = "#e0e0e0"
CHART_GRID = "#1a1a2e"
CHART_ACCENT = "#9b59b6"

# Confidence level labels and ranges
CONFIDENCE_LEVELS = [
    ("Very High", 80, 100),
    ("High", 60, 79),
    ("Medium", 40, 59),
    ("Low", 20, 39),
    ("Very Low", 0, 19),
]

CONFIDENCE_COLORS = ["#22c55e", "#6b3fa0", "#9b59b6", "#bb6bd9", "#d946ef"]


def _fig_to_b64(fig) -> str:
    """Convert a matplotlib figure to a base64 PNG data URI."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=120, bbox_inches="tight",
                facecolor=CHART_BG, edgecolor="none")
    plt.close(fig)
    buf.seek(0)
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def _apply_dark_style(ax, title: str):
    """Apply dark theme styling to an axis."""
    ax.set_facecolor(CHART_BG)
    ax.set_title(title, fontsize=10, fontweight="bold", color=CHART_TEXT, pad=10)
    ax.tick_params(labelsize=8, colors=CHART_TEXT)
    for spine in ax.spines.values():
        spine.set_color(CHART_GRID)
    ax.grid(True, color=CHART_GRID, alpha=0.3, linewidth=0.5)


# -- Platform Source Distribution (Doughnut) ----------------------------

def chart_platform_distribution(findings: list[dict]) -> str | None:
    """Doughnut chart showing which platforms contributed OSINT data.

    Args:
        findings: List of finding dicts, each with a 'platform' or 'source' key.

    Returns:
        Base64 data URI of the chart PNG, or None if no data.
    """
    counts = Counter()
    for f in findings:
        platform = f.get("platform") or f.get("source") or "Unknown"
        counts[platform] += 1

    if not counts:
        return None

    labels = list(counts.keys())
    sizes = list(counts.values())
    colors = [EXTENDED_PALETTE[i % len(EXTENDED_PALETTE)] for i in range(len(labels))]

    fig, ax = plt.subplots(figsize=(5, 3.5))
    fig.patch.set_facecolor(CHART_BG)
    wedges, texts, autotexts = ax.pie(
        sizes, labels=labels, colors=colors, autopct="%1.0f%%",
        startangle=90, pctdistance=0.75,
        textprops={"fontsize": 8, "color": CHART_TEXT},
    )
    for t in autotexts:
        t.set_fontsize(8)
        t.set_fontweight("bold")
        t.set_color("#ffffff")
    centre = plt.Circle((0, 0), 0.5, fc=CHART_BG)
    ax.add_patch(centre)
    total = sum(sizes)
    ax.text(0, 0, str(total), ha="center", va="center",
            fontsize=14, fontweight="bold", color=CHART_TEXT)
    ax.set_title("Platform Sources", fontsize=10, fontweight="bold", color=CHART_TEXT)
    return _fig_to_b64(fig)


# -- Activity Timeline (Line Chart) ------------------------------------

def chart_activity_timeline(findings: list[dict]) -> str | None:
    """Line chart showing activity over time.

    Args:
        findings: List of finding dicts, each with a 'timestamp' or 'date' key
                  (ISO format string or datetime).

    Returns:
        Base64 data URI of the chart PNG, or None if no data.
    """
    dates = []
    for f in findings:
        raw = f.get("timestamp") or f.get("date") or f.get("created_at")
        if not raw:
            continue
        if isinstance(raw, datetime):
            dates.append(raw)
        elif isinstance(raw, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
                        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    dates.append(datetime.strptime(raw[:len(fmt)], fmt))
                    break
                except ValueError:
                    continue

    if len(dates) < 2:
        return None

    dates.sort()
    # Bucket by day
    day_counts: Counter = Counter()
    for d in dates:
        day_counts[d.strftime("%Y-%m-%d")] += 1

    sorted_days = sorted(day_counts.keys())
    x_vals = [datetime.strptime(d, "%Y-%m-%d") for d in sorted_days]
    y_vals = [day_counts[d] for d in sorted_days]

    fig, ax = plt.subplots(figsize=(6, 3.5))
    fig.patch.set_facecolor(CHART_BG)
    ax.set_facecolor(CHART_BG)

    ax.fill_between(x_vals, y_vals, alpha=0.15, color=CHART_ACCENT)
    ax.plot(x_vals, y_vals, color=CHART_ACCENT, linewidth=2, marker="o", markersize=4)

    ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
    ax.xaxis.set_major_locator(mdates.AutoDateLocator(minticks=3, maxticks=8))
    fig.autofmt_xdate(rotation=30)

    _apply_dark_style(ax, "Activity Timeline")
    ax.set_xlabel("Date", fontsize=8, color=CHART_TEXT)
    ax.set_ylabel("Events", fontsize=8, color=CHART_TEXT)
    return _fig_to_b64(fig)


# -- Entity Type Distribution (Doughnut) --------------------------------

def chart_entity_type_distribution(entities: list[dict]) -> str | None:
    """Doughnut chart showing entity type breakdown.

    Args:
        entities: List of entity dicts, each with a 'type' key.

    Returns:
        Base64 data URI of the chart PNG, or None if no data.
    """
    counts = Counter()
    for e in entities:
        etype = (e.get("type") or "unknown").lower()
        counts[etype] += 1

    if not counts:
        return None

    labels = list(counts.keys())
    sizes = list(counts.values())
    colors = [ENTITY_COLORS.get(l, CHART_ACCENT) for l in labels]
    display_labels = [l.replace("_", " ").title() for l in labels]

    fig, ax = plt.subplots(figsize=(5, 3.5))
    fig.patch.set_facecolor(CHART_BG)
    wedges, texts, autotexts = ax.pie(
        sizes, labels=display_labels, colors=colors, autopct="%1.0f%%",
        startangle=90, pctdistance=0.75,
        textprops={"fontsize": 8, "color": CHART_TEXT},
    )
    for t in autotexts:
        t.set_fontsize(8)
        t.set_fontweight("bold")
        t.set_color("#ffffff")
    centre = plt.Circle((0, 0), 0.5, fc=CHART_BG)
    ax.add_patch(centre)
    total = sum(sizes)
    ax.text(0, 0, str(total), ha="center", va="center",
            fontsize=14, fontweight="bold", color=CHART_TEXT)
    ax.set_title("Entity Types", fontsize=10, fontweight="bold", color=CHART_TEXT)
    return _fig_to_b64(fig)


# -- Confidence Score Breakdown (Horizontal Bar) -------------------------

def chart_confidence_breakdown(entities: list[dict]) -> str | None:
    """Horizontal bar chart showing confidence score distribution.

    Args:
        entities: List of entity dicts, each with a 'confidence' key (0-100).

    Returns:
        Base64 data URI of the chart PNG, or None if no data.
    """
    buckets = {label: 0 for label, _, _ in CONFIDENCE_LEVELS}
    for e in entities:
        score = e.get("confidence", 0)
        try:
            score = int(score)
        except (ValueError, TypeError):
            score = 0
        for label, lo, hi in CONFIDENCE_LEVELS:
            if lo <= score <= hi:
                buckets[label] += 1
                break

    labels = [label for label, _, _ in CONFIDENCE_LEVELS]
    values = [buckets[l] for l in labels]

    if not any(v > 0 for v in values):
        return None

    fig, ax = plt.subplots(figsize=(5, 3))
    fig.patch.set_facecolor(CHART_BG)
    ax.set_facecolor(CHART_BG)

    y_pos = range(len(labels))
    bars = ax.barh(y_pos, values, color=CONFIDENCE_COLORS,
                   edgecolor=CHART_BG, linewidth=0.5, height=0.6)
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels, fontsize=8, color=CHART_TEXT)

    for bar, count in zip(bars, values):
        if count > 0:
            ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height() / 2,
                    str(count), ha="left", va="center", fontsize=8,
                    fontweight="bold", color=CHART_TEXT)

    _apply_dark_style(ax, "Confidence Score Distribution")
    ax.set_xlabel("Entity Count", fontsize=8, color=CHART_TEXT)
    ax.invert_yaxis()
    return _fig_to_b64(fig)


# -- Location Frequency (Bar Chart) -------------------------------------

def chart_location_frequency(entities: list[dict], top_n: int = 10) -> str | None:
    """Bar chart of most frequently referenced locations.

    Args:
        entities: List of entity dicts. Uses 'location' field, or entities
                  whose type is 'location' use their name/value.
        top_n: Maximum number of locations to show.

    Returns:
        Base64 data URI of the chart PNG, or None if no data.
    """
    counts = Counter()
    for e in entities:
        loc = e.get("location") or ""
        if not loc and (e.get("type") or "").lower() == "location":
            loc = e.get("name") or e.get("value") or ""
        if loc:
            counts[loc] += 1

    if not counts:
        return None

    top = counts.most_common(top_n)
    labels = [item[0] for item in top]
    values = [item[1] for item in top]

    # Generate gradient colors
    n = len(labels)
    colors = []
    for i in range(n):
        idx = int(i / max(n - 1, 1) * (len(PURPLE_PALETTE) - 1))
        colors.append(PURPLE_PALETTE[idx])

    fig, ax = plt.subplots(figsize=(5, max(2.5, n * 0.4)))
    fig.patch.set_facecolor(CHART_BG)
    ax.set_facecolor(CHART_BG)

    y_pos = range(len(labels))
    bars = ax.barh(y_pos, values, color=colors,
                   edgecolor=CHART_BG, linewidth=0.5, height=0.6)
    ax.set_yticks(list(y_pos))
    ax.set_yticklabels(labels, fontsize=8, color=CHART_TEXT)

    for bar, count in zip(bars, values):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height() / 2,
                str(count), ha="left", va="center", fontsize=8,
                fontweight="bold", color=CHART_TEXT)

    _apply_dark_style(ax, "Top Locations")
    ax.set_xlabel("Mentions", fontsize=8, color=CHART_TEXT)
    ax.invert_yaxis()
    return _fig_to_b64(fig)


# -- Geo Heatmap Data Generation (for Leaflet) --------------------------

def generate_geo_heatmap_data(entities: list[dict]) -> list[dict]:
    """Generate heatmap point data suitable for Leaflet.heat.

    Does NOT produce a matplotlib chart. Instead returns a list of
    [lat, lng, intensity] suitable for L.heatLayer().

    Args:
        entities: List of entity dicts with latitude/longitude fields.

    Returns:
        List of dicts with {lat, lng, intensity, label}.
    """
    points = []
    location_counts: Counter = Counter()

    for e in entities:
        lat = e.get("latitude")
        lng = e.get("longitude")
        if lat is None or lng is None:
            continue
        try:
            lat = float(lat)
            lng = float(lng)
        except (ValueError, TypeError):
            continue

        label = e.get("name") or e.get("value") or e.get("location") or ""
        location_counts[f"{lat},{lng}"] += 1

        points.append({
            "lat": lat,
            "lng": lng,
            "intensity": 1.0,
            "label": label,
        })

    # Adjust intensity based on co-location density
    for point in points:
        key = f"{point['lat']},{point['lng']}"
        count = location_counts[key]
        point["intensity"] = min(1.0, 0.3 + (count * 0.15))

    return points


# -- Entity Relationship Graph (server-side) ------------------------------

GRAPH_NODE_COLORS = {
    "person": "#9b59b6",
    "organization": "#8b5cf6",
    "location": "#22c55e",
    "account": "#bb6bd9",
    "domain": "#6b3fa0",
    "event": "#f59e0b",
    "media": "#d946ef",
    "ip": "#6366f1",
    "email": "#ec4899",
    "platform": "#14b8a6",
    "threat_actor": "#ef4444",
}


def chart_entity_graph(entity_graph: dict, width: int = 8, height: int = 6) -> str | None:
    """Render Cytoscape-format entity graph as a PNG using networkx + matplotlib.

    Args:
        entity_graph: Cytoscape.js JSON dict with 'nodes' and 'edges' lists.
        width: Figure width in inches.
        height: Figure height in inches.

    Returns:
        Base64 PNG data URI, or None if graph is empty.
    """
    nodes = entity_graph.get("nodes", [])
    edges = entity_graph.get("edges", [])
    if not nodes:
        return None

    try:
        import networkx as nx
    except ImportError:
        return None

    G = nx.DiGraph()
    node_colors = []
    node_sizes = []
    labels = {}

    for n in nodes[:80]:
        data = n.get("data", {})
        nid = data.get("id", "")
        if not nid:
            continue
        ntype = data.get("type", "default")
        label = data.get("label", nid)
        G.add_node(nid)
        node_colors.append(GRAPH_NODE_COLORS.get(ntype, "#9b59b6"))
        node_sizes.append(350 if ntype in ("person", "organization") else 200)
        labels[nid] = label[:18] + "..." if len(label) > 18 else label

    for e in edges[:120]:
        data = e.get("data", {})
        src = data.get("source", "")
        tgt = data.get("target", "")
        if src in G and tgt in G:
            G.add_edge(src, tgt, label=data.get("label", ""))

    if len(G.nodes) == 0:
        return None

    fig, ax = plt.subplots(figsize=(width, height), facecolor=CHART_BG)
    ax.set_facecolor(CHART_BG)
    ax.set_title("Entity Relationship Graph", fontsize=11, fontweight="bold",
                 color=CHART_TEXT, pad=12)

    try:
        pos = nx.spring_layout(G, k=2.5, iterations=60, seed=42)
    except Exception:
        pos = nx.circular_layout(G)

    nx.draw_networkx_edges(
        G, pos, ax=ax, edge_color=(0.608, 0.349, 0.714, 0.35),
        arrows=True, arrowsize=10, width=0.8,
        connectionstyle="arc3,rad=0.1",
    )

    ordered_nodes = list(G.nodes())
    colors_ordered = [node_colors[list(G.nodes()).index(n)] if n in list(G.nodes()) else "#9b59b6"
                      for n in ordered_nodes]
    sizes_ordered = [node_sizes[list(G.nodes()).index(n)] if n in list(G.nodes()) else 200
                     for n in ordered_nodes]

    nx.draw_networkx_nodes(
        G, pos, ax=ax, nodelist=ordered_nodes,
        node_color=colors_ordered, node_size=sizes_ordered,
        edgecolors="#1a1a2e", linewidths=1.0,
    )

    nx.draw_networkx_labels(
        G, pos, ax=ax, labels=labels,
        font_size=6, font_color="#e0e0e0", font_weight="bold",
    )

    edge_labels = {(u, v): d.get("label", "")[:12]
                   for u, v, d in G.edges(data=True) if d.get("label")}
    if edge_labels:
        nx.draw_networkx_edge_labels(
            G, pos, ax=ax, edge_labels=edge_labels,
            font_size=5, font_color="#9a97a8",
        )

    ax.axis("off")
    fig.tight_layout(pad=0.5)
    return _fig_to_b64(fig)


# -- Aggregate Chart Generation ------------------------------------------

def generate_investigation_charts(findings: list[dict],
                                  entities: list[dict]) -> dict:
    """Generate all OSINT charts for an investigation report.

    Args:
        findings: List of raw finding dicts (with platform, timestamp, etc.)
        entities: List of extracted entity dicts

    Returns:
        dict: chart_name -> base64 PNG data URI
    """
    charts = {}

    result = chart_platform_distribution(findings)
    if result:
        charts["platform_sources"] = result

    result = chart_activity_timeline(findings)
    if result:
        charts["activity_timeline"] = result

    result = chart_entity_type_distribution(entities)
    if result:
        charts["entity_types"] = result

    result = chart_confidence_breakdown(entities)
    if result:
        charts["confidence_breakdown"] = result

    result = chart_location_frequency(entities)
    if result:
        charts["top_locations"] = result

    return charts
