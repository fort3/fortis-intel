"""PDF and Markdown export for Fortis Intelligence Hub OSINT reports using PyMuPDF.

Landscape layout matching the welcome page design: deep purple-black gradient,
HUD SVG overlay, card-based sections with subtle borders, purple accent headings.
"""

import base64
import io
import re
from datetime import datetime, timezone
from html import escape as html_escape
from pathlib import Path

import pymupdf as fitz
import markdown
from PIL import Image


_APP_DIR = Path(__file__).resolve().parent
_FAVICON_PATH = _APP_DIR / "data" / "favicon.ico"
_HUD_SVG_PATH = _APP_DIR.parent / "static" / "img" / "bg-hud.svg"
_logo_b64: str | None = None
_hud_png_cache: dict[str, bytes] = {}

SENSITIVITY_COLORS_RGB = {
    "PUBLIC": (0.133, 0.545, 0.133),
    "INTERNAL": (0.608, 0.349, 0.714),
    "RESTRICTED": (1.0, 0.655, 0.149),
    "CONFIDENTIAL": (0.827, 0.184, 0.184),
}

SENSITIVITY_COLORS_HEX = {
    "PUBLIC": "#228B22",
    "INTERNAL": "#9b59b6",
    "RESTRICTED": "#ffa726",
    "CONFIDENTIAL": "#d32f2f",
}

SENSITIVITY_DESCRIPTIONS = {
    "PUBLIC": "Unrestricted - May be shared publicly without limitation.",
    "INTERNAL": "Internal Use Only - Do not distribute outside the organization.",
    "RESTRICTED": "Restricted - Share only with authorized personnel on a need-to-know basis.",
    "CONFIDENTIAL": "Confidential - Eyes only. Named recipients only. Do NOT share.",
}

# Exact welcome page CSS variables
BG_DEEP = "#08081a"
CARD_BG = "#10101e"
BORDER = "#2a2a3d"
BORDER_ACTIVE = "#6b3fa0"
PURPLE_BRIGHT = "#bb6bd9"
PURPLE_NEON = "#d946ef"
PURPLE_DARK = "#6b3fa0"
PURPLE_SUBTLE = "#2d1f4e"
TEXT_PRIMARY = "#e8e6f0"
TEXT_SECONDARY = "#9a97a8"
TEXT_MUTED = "#5c5a6a"
TEXT_BRIGHT = "#ffffff"

# Landscape US Letter dimensions
PAGE_W = 792
PAGE_H = 612


def _get_logo_b64() -> str:
    global _logo_b64
    if _logo_b64 is not None:
        return _logo_b64
    try:
        img = Image.open(_FAVICON_PATH)
        img = img.resize((48, 48), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        _logo_b64 = base64.b64encode(buf.getvalue()).decode()
    except Exception:
        _logo_b64 = ""
    return _logo_b64


def _get_hud_png(width: int, height: int) -> bytes | None:
    global _hud_png_cache
    key = f"{width}x{height}"
    if key in _hud_png_cache:
        return _hud_png_cache[key] if _hud_png_cache[key] else None
    try:
        if not _HUD_SVG_PATH.exists():
            _hud_png_cache[key] = b""
            return None
        svg_data = _HUD_SVG_PATH.read_bytes()
        svg_doc = fitz.open(stream=svg_data, filetype="svg")
        page = svg_doc[0]
        mat = fitz.Matrix(width / page.rect.width, height / page.rect.height)
        pix = page.get_pixmap(matrix=mat, alpha=True)
        _hud_png_cache[key] = pix.tobytes("png")
        svg_doc.close()
        return _hud_png_cache[key]
    except Exception:
        _hud_png_cache[key] = b""
        return None


def _extract_report_name(session_id: str) -> str:
    if not session_id:
        return "N/A"
    parts = session_id.split("_", 1)
    name = parts[1] if len(parts) > 1 else session_id
    return re.sub(r"\.pdf$", "", name).replace("_", " ")


def _normalize_section_headers(text: str) -> str:
    text = re.sub(r'={3,}\s*(.+?)\s*={3,}', r'## \1', text)
    text = re.sub(r'^\s*={3,}\s*$', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\s*[-]{3,}\s*$', '---', text, flags=re.MULTILINE)
    return text


def _paint_gradient_bg(page, mediabox):
    w = mediabox.width
    h = mediabox.height
    bands = 40
    band_h = h / bands

    colors = [
        (0.051, 0.020, 0.125),  # #0d0520
        (0.039, 0.024, 0.106),
        (0.031, 0.031, 0.094),  # #080818
        (0.027, 0.027, 0.098),
        (0.024, 0.024, 0.102),  # #06061a
        (0.035, 0.016, 0.118),
        (0.039, 0.012, 0.125),  # #0a0320
    ]

    for i in range(bands):
        t = i / max(bands - 1, 1)
        idx = t * (len(colors) - 1)
        lo = int(idx)
        hi = min(lo + 1, len(colors) - 1)
        frac = idx - lo
        r = colors[lo][0] + (colors[hi][0] - colors[lo][0]) * frac
        g = colors[lo][1] + (colors[hi][1] - colors[lo][1]) * frac
        b = colors[lo][2] + (colors[hi][2] - colors[lo][2]) * frac
        y0 = i * band_h
        y1 = y0 + band_h + 0.5
        page.draw_rect(fitz.Rect(0, y0, w, y1), color=None, fill=(r, g, b), overlay=False)


def _overlay_hud(page, mediabox):
    hud_png = _get_hud_png(int(mediabox.width), int(mediabox.height))
    if not hud_png:
        return
    try:
        page.insert_image(
            mediabox,
            stream=hud_png,
            overlay=False,
            keep_proportion=False,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# HTML section builders
# ---------------------------------------------------------------------------

def _build_geo_summary_html(map_data: dict | None) -> str:
    if not map_data:
        return ""
    markers = map_data.get("markers", [])
    if not markers:
        return ""

    source_labels = {
        "exif": "EXIF GPS", "video_exif": "Video EXIF",
        "video_landmark": "Video Landmark", "nlp_mention": "NLP Location",
        "geotag": "Social Geotag", "ip": "IP Geolocation",
        "ip_geolocation": "IP Geolocation", "geocoding": "Geocoded",
        "osint": "OSINT", "mention": "Mention",
    }

    rows = ""
    for m in markers[:20]:
        lat = m.get("lat", 0)
        lng = m.get("lng", 0)
        label = html_escape(str(m.get("label", ""))[:40]) or "&mdash;"
        src = m.get("source_type", "osint")
        src_label = source_labels.get(src, src.replace("_", " ").title())
        conf = m.get("confidence", 0)
        conf_pct = f"{conf * 100:.0f}%" if isinstance(conf, (int, float)) else str(conf)
        desc = html_escape(str(m.get("description", ""))[:60])
        rows += (
            f'<tr>'
            f'<td>{label}</td>'
            f'<td class="mono">{lat:.5f}, {lng:.5f}</td>'
            f'<td><span class="src-badge">{html_escape(src_label)}</span></td>'
            f'<td>{conf_pct}</td>'
            f'<td class="desc-cell">{desc}</td>'
            f'</tr>'
        )

    tri = map_data.get("triangulation")
    tri_html = ""
    if tri and tri.get("center"):
        c = tri["center"]
        clat = c.get("lat", c[0] if isinstance(c, list) else 0)
        clng = c.get("lng", c[1] if isinstance(c, list) else 0)
        method = tri.get("method", "weighted centroid").replace("_", " ")
        conf = tri.get("confidence", 0)
        radius = tri.get("confidence_radius", 0)
        tri_html = (
            f'<div class="tri-box">'
            f'<span class="tri-label">TRIANGULATED CENTER</span> '
            f'{clat:.5f}, {clng:.5f} &nbsp;|&nbsp; '
            f'Method: {html_escape(method)} &nbsp;|&nbsp; '
            f'Radius: {radius:.0f}m &nbsp;|&nbsp; '
            f'Confidence: {conf * 100:.0f}%'
            f'</div>'
        )

    return (
        f'<div class="section">'
        f'<div class="section-header">'
        f'<h2 class="section-title">Geospatial Data Points</h2>'
        f'<div class="section-rule"></div>'
        f'</div>'
        f'{tri_html}'
        f'<table>'
        f'<tr><th>Label</th><th>Coordinates</th><th>Source</th><th>Conf.</th><th>Details</th></tr>'
        f'{rows}'
        f'</table>'
        f'</div>'
    )


def _build_chart_html(charts: dict) -> str:
    if not charts:
        return ""
    items = list(charts.items())
    rows_html = ""
    for i in range(0, len(items), 3):
        row_items = items[i:i + 3]
        cells = ""
        for name, b64_uri in row_items:
            label = html_escape(name.replace("_", " ").title())
            if not isinstance(b64_uri, str) or not b64_uri.startswith("data:image/"):
                continue
            cells += (
                f'<td class="chart-cell">'
                f'<div class="chart-label">{label}</div>'
                f'<img src="{html_escape(b64_uri)}" class="chart-img">'
                f'</td>'
            )
        while len(row_items) < 3:
            cells += '<td class="chart-cell"></td>'
            row_items.append(None)
        rows_html += f"<tr>{cells}</tr>"
    return (
        f'<div class="section">'
        f'<div class="section-header">'
        f'<h2 class="section-title">Visual Analytics</h2>'
        f'<div class="section-rule"></div>'
        f'</div>'
        f'<table class="chart-grid">{rows_html}</table>'
        f'</div>'
    )


def _build_map_html(map_snapshot_b64: str | None) -> str:
    if not map_snapshot_b64:
        return ""
    if not map_snapshot_b64.startswith("data:image/"):
        map_snapshot_b64 = f"data:image/png;base64,{map_snapshot_b64}"
    return (
        f'<div class="section" style="text-align:center;">'
        f'<div class="section-header">'
        f'<h2 class="section-title">Geographic Overview</h2>'
        f'<div class="section-rule"></div>'
        f'</div>'
        f'<div class="media-frame">'
        f'<img src="{html_escape(map_snapshot_b64)}" class="media-img">'
        f'</div>'
        f'</div>'
    )


def _build_graph_html(graph_b64: str | None) -> str:
    if not graph_b64:
        return ""
    if not graph_b64.startswith("data:image/"):
        graph_b64 = f"data:image/png;base64,{graph_b64}"
    return (
        f'<div class="section" style="text-align:center;">'
        f'<div class="section-header">'
        f'<h2 class="section-title">Entity Relationship Graph</h2>'
        f'<div class="section-rule"></div>'
        f'</div>'
        f'<div class="media-frame">'
        f'<img src="{html_escape(graph_b64)}" class="media-img">'
        f'</div>'
        f'</div>'
    )


def _build_title_page_html(
    title: str,
    session_id: str,
    sensitivity_level: str,
    timestamp: str,
) -> str:
    logo_b64 = _get_logo_b64()
    logo_html = (
        f'<img src="data:image/png;base64,{logo_b64}" class="title-logo">'
        if logo_b64 else ""
    )
    report_name = html_escape(_extract_report_name(session_id))
    title_escaped = html_escape(title)
    sens_color = SENSITIVITY_COLORS_HEX.get(sensitivity_level, PURPLE_BRIGHT)
    sens_desc = html_escape(
        SENSITIVITY_DESCRIPTIONS.get(sensitivity_level, "")
    )

    tlp_label, tlp_color = _TLP_MAP.get(
        sensitivity_level, ("TLP:AMBER", "#f59e0b")
    )

    return f"""
<div class="title-page">
    <div class="title-card">
        {logo_html}
        <div class="title-brand">FORTIS INTELLIGENCE HUB</div>
        <div class="title-divider"></div>
        <div class="title-main">{title_escaped}</div>
        <div class="title-subtitle">OSINT INVESTIGATION REPORT</div>
        <table class="title-meta-table">
            <tr><td class="meta-key">Generated</td><td class="meta-val">{timestamp}</td></tr>
            <tr><td class="meta-key">Source</td><td class="meta-val">{report_name}</td></tr>
            <tr><td class="meta-key">Platform</td><td class="meta-val">Fortis Intelligence Hub</td></tr>
            <tr><td class="meta-key">Classification</td><td class="meta-val"><span class="title-sens-inline" style="color:{sens_color};">{sensitivity_level}</span></td></tr>
            <tr><td class="meta-key">TLP</td><td class="meta-val"><span class="title-sens-inline" style="color:{tlp_color};">{tlp_label}</span></td></tr>
        </table>
        <div class="title-sens-footer">{sens_desc}</div>
    </div>
</div>
"""


_GEO_KEYS = {"geolocation assessment", "geolocation", "geographic overview"}
_ENTITY_KEYS = {"entity relationships", "entity relationship graph"}
_SOURCE_KEYS = {"osint source analysis", "source analysis"}

_TLP_MAP = {
    "PUBLIC": ("TLP:CLEAR", "#22c55e"),
    "INTERNAL": ("TLP:AMBER", "#f59e0b"),
    "RESTRICTED": ("TLP:AMBER+STRICT", "#f97316"),
    "CONFIDENTIAL": ("TLP:RED", "#ef4444"),
}


def _parse_sections(content: str) -> list[tuple[str, str]]:
    """Split markdown content at ## boundaries into (heading, body) pairs."""
    content = _normalize_section_headers(content)
    sens_pattern = r'^#\s*(PUBLIC|INTERNAL|RESTRICTED|CONFIDENTIAL)\s*\n+'
    content = re.sub(sens_pattern, '', content, count=1,
                     flags=re.IGNORECASE | re.MULTILINE)

    parts = re.split(r'^(##\s+.+)$', content, flags=re.MULTILINE)
    sections: list[tuple[str, str]] = []

    if parts[0].strip():
        sections.append(("", parts[0].strip()))

    for i in range(1, len(parts), 2):
        heading = re.sub(r'^##\s+', '', parts[i]).strip()
        body = parts[i + 1].strip() if i + 1 < len(parts) else ""
        sections.append((heading, body))

    return sections


def _build_section_html(heading: str, body_md: str, section_num: int,
                        is_executive: bool = False) -> str:
    """Render a report section as HTML with PyMuPDF-compatible CSS."""
    body_html = markdown.markdown(body_md, extensions=["tables", "fenced_code"])
    heading_escaped = html_escape(heading)
    num_str = f"{section_num:02d}" if section_num > 0 else ""

    if is_executive:
        return (
            f'<div class="section exec-section">'
            f'<div class="section-header">'
            f'<div class="exec-label">KEY FINDINGS</div>'
            f'<div class="section-num-line">'
            f'<span class="section-num">{num_str}</span>'
            f'</div>'
            f'<h2 class="section-title exec-title">{heading_escaped}</h2>'
            f'<div class="exec-rule"></div>'
            f'</div>'
            f'<div class="exec-body">{body_html}</div>'
            f'</div>'
        )

    return (
        f'<div class="section">'
        f'<div class="section-header">'
        f'<div class="section-num-line">'
        f'<span class="section-num">{num_str}</span>'
        f'</div>'
        f'<h2 class="section-title">{heading_escaped}</h2>'
        f'<div class="section-rule"></div>'
        f'</div>'
        f'{body_html}'
        f'</div>'
    )


def _build_toc_html(sections: list[tuple[str, str]]) -> str:
    """Build a table-of-contents using a simple table layout."""
    if len(sections) < 3:
        return ""
    rows = ""
    num = 0
    for heading, _ in sections:
        if not heading:
            continue
        num += 1
        rows += (
            f'<tr>'
            f'<td class="toc-num">{num:02d}</td>'
            f'<td class="toc-text">{html_escape(heading)}</td>'
            f'</tr>'
        )
    return (
        f'<div class="toc-section">'
        f'<h2 class="toc-heading">CONTENTS</h2>'
        f'<div class="toc-rule"></div>'
        f'<table class="toc-table">{rows}</table>'
        f'</div>'
    )


def _build_tlp_bar(sensitivity_level: str) -> str:
    """Build a full-width TLP classification bar."""
    tlp_label, tlp_color = _TLP_MAP.get(
        sensitivity_level, ("TLP:AMBER", "#f59e0b")
    )
    sens_color = SENSITIVITY_COLORS_HEX.get(sensitivity_level, PURPLE_BRIGHT)
    return (
        f'<div class="tlp-bar">'
        f'<table class="tlp-table">'
        f'<tr>'
        f'<td class="tlp-left" style="color:{tlp_color};">{tlp_label}</td>'
        f'<td class="tlp-right" style="color:{sens_color};">{sensitivity_level}</td>'
        f'</tr>'
        f'</table>'
        f'</div>'
    )


def _build_html(content: str, title: str, session_id: str,
                charts: dict | None = None,
                map_snapshot_b64: str | None = None,
                map_data: dict | None = None,
                entity_graph_b64: str | None = None,
                sensitivity_level: str = "INTERNAL") -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    title_page = _build_title_page_html(
        title, session_id, sensitivity_level, timestamp,
    )

    tlp_bar = _build_tlp_bar(sensitivity_level)
    map_section = _build_map_html(map_snapshot_b64)
    geo_summary = _build_geo_summary_html(map_data)
    graph_section = _build_graph_html(entity_graph_b64)
    chart_section = _build_chart_html(charts) if charts else ""

    sections = _parse_sections(content)
    toc_html = _build_toc_html(sections)

    body_parts: list[str] = [tlp_bar, toc_html]

    geo_placed = False
    graph_placed = False
    charts_placed = False
    section_num = 0

    for heading, body_md in sections:
        if not heading and not body_md:
            continue

        key = heading.lower().strip()
        is_exec = key in ("executive summary", "enrichment summary")

        if not heading:
            body_html = markdown.markdown(
                body_md, extensions=["tables", "fenced_code"],
            )
            body_parts.append(f'<div class="section">{body_html}</div>')
            continue

        section_num += 1
        body_parts.append(
            _build_section_html(heading, body_md, section_num, is_exec)
        )

        if key in _GEO_KEYS and not geo_placed:
            if map_section:
                body_parts.append(map_section)
            if geo_summary:
                body_parts.append(geo_summary)
            geo_placed = True

        if key in _ENTITY_KEYS and not graph_placed:
            if graph_section:
                body_parts.append(graph_section)
            graph_placed = True

        if key in _SOURCE_KEYS and not charts_placed:
            if chart_section:
                body_parts.append(chart_section)
            charts_placed = True

    if not geo_placed and (map_section or geo_summary):
        body_parts.append(map_section)
        body_parts.append(geo_summary)
    if not graph_placed and graph_section:
        body_parts.append(graph_section)
    if not charts_placed and chart_section:
        body_parts.append(chart_section)

    body_content = "\n".join(body_parts)

    return f"""<!DOCTYPE html>
<html>
<head>
<style>
@page {{
    size: {PAGE_W}pt {PAGE_H}pt;
    margin: 0;
}}

/* ================================================================
   BASE — PyMuPDF Story supports CSS2 only: no border-radius,
   no rgba(), no inline-block, no flexbox/grid.  All solid colors,
   block layout, borders for separation.
   ================================================================ */

body {{
    font-family: Helvetica, Arial, sans-serif;
    font-size: 9pt;
    line-height: 1.6;
    color: {TEXT_PRIMARY};
    background: transparent;
    margin: 0;
    padding: 0;
}}

/* ========== TITLE PAGE ========== */

.title-page {{
    page-break-after: always;
    min-height: 500px;
    text-align: center;
    padding: 80px 100px 40px 100px;
}}
.title-card {{
    background: {CARD_BG};
    border: 1px solid {BORDER};
    padding: 50px 40px 30px 40px;
    margin-top: 30px;
}}
.title-logo {{
    width: 48px;
    height: 48px;
    margin-bottom: 14px;
}}
.title-brand {{
    font-size: 12pt;
    font-weight: 700;
    color: {PURPLE_BRIGHT};
    letter-spacing: 6px;
    margin-bottom: 6px;
}}
.title-divider {{
    width: 80px;
    height: 1px;
    background: {PURPLE_DARK};
    margin: 14px auto;
}}
.title-main {{
    font-size: 18pt;
    font-weight: 700;
    color: {TEXT_BRIGHT};
    margin: 18px 0 4px 0;
    line-height: 1.25;
}}
.title-subtitle {{
    font-size: 7.5pt;
    font-weight: 700;
    color: {TEXT_SECONDARY};
    letter-spacing: 3px;
    margin-bottom: 24px;
}}
.title-meta-table {{
    margin: 14px auto;
    border-collapse: collapse;
    width: auto;
}}
.title-meta-table td {{
    padding: 3px 10px;
    font-size: 7.5pt;
    border: none;
}}
.meta-key {{
    color: {TEXT_MUTED};
    text-align: right;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
.meta-val {{
    color: {TEXT_SECONDARY};
    text-align: left;
}}
.title-sens-inline {{
    font-weight: 700;
    letter-spacing: 2px;
    font-size: 7.5pt;
}}
.title-sens-footer {{
    font-size: 6.5pt;
    color: {TEXT_MUTED};
    margin-top: 14px;
    padding-top: 8px;
    border-top: 1px solid {BORDER};
}}

/* ========== TLP CLASSIFICATION BAR ========== */

.tlp-bar {{
    border-bottom: 1px solid {BORDER};
    padding: 3px 0;
    margin-bottom: 12px;
}}
.tlp-table {{
    width: 100%;
    border-collapse: collapse;
}}
.tlp-table td {{
    padding: 2px 4px;
    font-size: 7pt;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    border: none;
}}
.tlp-left {{
    text-align: left;
}}
.tlp-right {{
    text-align: right;
}}

/* ========== TABLE OF CONTENTS ========== */

.toc-section {{
    padding: 20px 0 10px 0;
    page-break-after: always;
}}
.toc-heading {{
    font-size: 11pt;
    font-weight: 700;
    color: {PURPLE_BRIGHT};
    letter-spacing: 3px;
    text-transform: uppercase;
    margin: 0 0 4px 0;
}}
.toc-rule {{
    height: 1px;
    background: {PURPLE_DARK};
    margin-bottom: 10px;
}}
.toc-table {{
    width: 100%;
    border-collapse: collapse;
}}
.toc-table td {{
    padding: 5px 6px;
    border-bottom: 1px solid {BORDER};
    font-size: 8.5pt;
}}
.toc-num {{
    width: 30px;
    color: {PURPLE_BRIGHT};
    font-weight: 700;
    font-size: 7.5pt;
    font-family: "Courier New", Courier, monospace;
}}
.toc-text {{
    color: {TEXT_PRIMARY};
}}

/* ========== REPORT SECTIONS ========== */

.section {{
    background: #181830;
    border: 1px solid {BORDER};
    padding: 20px 26px;
    margin: 8px 0;
    page-break-inside: auto;
}}
.section-header {{
    page-break-inside: avoid;
    page-break-after: avoid;
}}
.section-num-line {{
    margin-bottom: 2px;
    page-break-after: avoid;
}}
.section-num {{
    font-family: "Courier New", Courier, monospace;
    font-size: 7pt;
    font-weight: 700;
    color: {PURPLE_DARK};
    letter-spacing: 1px;
}}
.section-title {{
    font-size: 11pt;
    font-weight: 700;
    color: {PURPLE_BRIGHT};
    text-transform: uppercase;
    letter-spacing: 1px;
    margin: 0 0 2px 0;
    page-break-after: avoid;
}}
.section-rule {{
    height: 1px;
    background: {BORDER};
    margin: 6px 0 12px 0;
    page-break-after: avoid;
}}

/* ========== EXECUTIVE SUMMARY ========== */

.exec-section {{
    border-left: 3px solid {PURPLE_DARK};
}}
.exec-label {{
    font-size: 6pt;
    font-weight: 700;
    color: {PURPLE_BRIGHT};
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 4px;
    padding: 2px 0;
    border-bottom: 1px solid {PURPLE_DARK};
    width: 100px;
}}
.exec-title {{
    font-size: 11pt;
    color: {TEXT_BRIGHT};
    page-break-after: avoid;
}}
.exec-rule {{
    height: 1px;
    background: {PURPLE_DARK};
    margin: 4px 0 12px 0;
    page-break-after: avoid;
}}
.exec-body {{
    font-size: 9.5pt;
    line-height: 1.7;
}}
.exec-body p {{
    color: #f0eef5;
}}

/* ========== CONTENT TYPOGRAPHY ========== */

h1 {{
    font-size: 11pt;
    color: {PURPLE_BRIGHT};
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 12px;
    margin-bottom: 6px;
    page-break-after: avoid;
}}
h2 {{
    font-size: 11pt;
    color: {PURPLE_BRIGHT};
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 10px;
    margin-bottom: 5px;
    page-break-after: avoid;
}}
h3 {{
    font-size: 10pt;
    color: {TEXT_BRIGHT};
    font-weight: 700;
    margin-top: 10px;
    margin-bottom: 4px;
    page-break-after: avoid;
}}
h4 {{
    font-size: 9.5pt;
    color: {TEXT_BRIGHT};
    font-weight: 700;
    margin-top: 8px;
    margin-bottom: 3px;
    page-break-after: avoid;
}}
p {{
    margin: 4px 0;
    color: {TEXT_PRIMARY};
    orphans: 3;
    widows: 3;
}}
ul, ol {{
    padding-left: 16px;
    margin: 4px 0;
    color: {TEXT_PRIMARY};
}}
li {{
    margin: 2px 0;
    color: {TEXT_PRIMARY};
    line-height: 1.5;
    orphans: 2;
    widows: 2;
}}
strong {{
    color: {TEXT_BRIGHT};
}}
em {{
    color: {TEXT_SECONDARY};
    font-style: italic;
}}
a {{
    color: {PURPLE_BRIGHT};
    text-decoration: none;
}}
blockquote {{
    background: {CARD_BG};
    border-left: 2px solid {PURPLE_DARK};
    padding: 6px 12px;
    margin: 6px 0;
    color: #ccc8d4;
    font-size: 8.5pt;
}}
code {{
    background: {PURPLE_SUBTLE};
    color: {PURPLE_BRIGHT};
    padding: 1px 3px;
    font-family: "Courier New", Courier, monospace;
    font-size: 8pt;
}}
pre {{
    background: {CARD_BG};
    border: 1px solid {BORDER};
    padding: 6px 10px;
    font-size: 7.5pt;
    margin: 5px 0;
    color: {TEXT_PRIMARY};
}}
pre code {{
    background: none;
    padding: 0;
}}
hr {{
    border: none;
    border-top: 1px solid {BORDER};
    margin: 8px 0;
}}

/* ========== TABLES ========== */

table {{
    border-collapse: collapse;
    width: 100%;
    margin: 6px 0;
    font-size: 8pt;
}}
th {{
    background: {PURPLE_SUBTLE};
    color: {TEXT_BRIGHT};
    padding: 5px 8px;
    text-align: left;
    font-weight: 700;
    font-size: 7pt;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid {PURPLE_DARK};
}}
td {{
    padding: 4px 8px;
    border-bottom: 1px solid {BORDER};
    color: {TEXT_PRIMARY};
}}
.mono {{
    font-family: "Courier New", Courier, monospace;
    font-size: 7.5pt;
    color: {TEXT_PRIMARY};
}}
.desc-cell {{
    color: {TEXT_MUTED};
    font-size: 7pt;
}}
.src-badge {{
    background: {PURPLE_DARK};
    color: {TEXT_BRIGHT};
    padding: 1px 6px;
    font-size: 6.5pt;
    font-weight: 700;
}}
.tri-box {{
    background: {PURPLE_SUBTLE};
    padding: 5px 10px;
    margin-bottom: 8px;
    font-size: 7.5pt;
    color: {TEXT_PRIMARY};
}}
.tri-label {{
    font-weight: 700;
    color: {PURPLE_BRIGHT};
    letter-spacing: 1px;
    font-size: 7pt;
}}

/* ========== CHARTS ========== */

.chart-grid {{
    width: 100%;
    border-collapse: collapse;
    border: none;
}}
.chart-grid td {{
    border: none;
}}
.chart-cell {{
    padding: 6px;
    text-align: center;
    vertical-align: top;
    width: 33%;
}}
.chart-label {{
    font-size: 7pt;
    font-weight: 700;
    color: {TEXT_MUTED};
    margin-bottom: 3px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.chart-img {{
    width: 200px;
}}

/* ========== MAP / GRAPH ========== */

.media-frame {{
    margin: 6px auto;
}}
.media-img {{
    width: 88%;
    border: 1px solid {BORDER};
}}
</style>
</head>
<body>

{title_page}

{body_content}

</body>
</html>"""


def generate_markdown(content: str, title: str, session_id: str,
                      sensitivity_level: str = "INTERNAL") -> bytes:
    session_ref = session_id
    if session_ref:
        parts = session_ref.split("_", 1)
        session_ref = parts[1] if len(parts) > 1 else session_ref
        session_ref = re.sub(r"\.pdf$", "", session_ref).replace("_", " ")
    else:
        session_ref = "N/A"

    sens = (sensitivity_level or "INTERNAL").upper()
    tlp_label, _ = _TLP_MAP.get(sens, ("TLP:AMBER", "#f59e0b"))

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md_lines = [
        f"# {title}", "",
        f"> **{tlp_label}** | Classification: **{sens}**", "",
        "---", "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Platform** | Fortis Intelligence Hub |",
        f"| **Generated** | {timestamp} |",
        f"| **Source** | {session_ref} |",
        f"| **Classification** | {sens} ({tlp_label}) |",
        "", "---", "",
        content,
        "", "---", "",
        f"*Generated by Fortis Intelligence Hub | {tlp_label} | {timestamp}*",
    ]
    return "\n".join(md_lines).encode("utf-8")


def generate_pdf(content: str, title: str, session_id: str,
                 charts: dict | None = None,
                 sensitivity_level: str | None = None,
                 map_snapshot_b64: str | None = None,
                 map_data: dict | None = None,
                 entity_graph_b64: str | None = None) -> bytes:
    if sensitivity_level:
        sensitivity_level = sensitivity_level.upper()
    else:
        sens_pattern = r'^#\s*(PUBLIC|INTERNAL|RESTRICTED|CONFIDENTIAL)\s*\n+'
        sens_match = re.match(sens_pattern, content, re.IGNORECASE | re.MULTILINE)
        if sens_match:
            sensitivity_level = sens_match.group(1).upper()
        else:
            sensitivity_level = "INTERNAL"

    sens_color_rgb = SENSITIVITY_COLORS_RGB.get(
        sensitivity_level, SENSITIVITY_COLORS_RGB["INTERNAL"]
    )

    full_html = _build_html(
        content, title, session_id,
        charts=charts,
        map_snapshot_b64=map_snapshot_b64,
        map_data=map_data,
        entity_graph_b64=entity_graph_b64,
        sensitivity_level=sensitivity_level,
    )

    mediabox = fitz.Rect(0, 0, PAGE_W, PAGE_H)
    content_rect = fitz.Rect(48, 48, PAGE_W - 48, PAGE_H - 52)

    buf = io.BytesIO()
    writer = fitz.DocumentWriter(buf)
    story = fitz.Story(html=full_html)

    more = True
    page_count = 0
    while more and page_count < 50:
        dev = writer.begin_page(mediabox)
        more, _ = story.place(content_rect)
        story.draw(dev)
        writer.end_page()
        page_count += 1

    writer.close()
    raw_pdf = buf.getvalue()

    doc = fitz.open(stream=raw_pdf, filetype="pdf")
    total = len(doc)

    accent_rgb = (0.733, 0.420, 0.851)  # #bb6bd9
    border_rgb = (0.165, 0.165, 0.239)  # #2a2a3d
    text_muted_rgb = (0.361, 0.353, 0.416)  # #5c5a6a

    for i, page in enumerate(doc):
        # Order matters: with overlay=False each call prepends behind
        # existing content. Call HUD first, then gradient, so the final
        # layer order is: gradient (back) → HUD → text (front).
        _overlay_hud(page, mediabox)
        _paint_gradient_bg(page, mediabox)

        if i == 0:
            continue

        # Footer line
        footer_y = PAGE_H - 30
        page.draw_line(
            fitz.Point(48, footer_y),
            fitz.Point(PAGE_W - 48, footer_y),
            color=border_rgb,
            width=0.3,
        )
        page.insert_text(
            fitz.Point(48, footer_y + 12),
            "FORTIS INTELLIGENCE HUB",
            fontsize=5.5,
            color=accent_rgb,
        )
        mid_x = PAGE_W / 2 - 20
        page.insert_text(
            fitz.Point(mid_x, footer_y + 12),
            sensitivity_level,
            fontsize=5.5,
            color=sens_color_rgb,
        )
        page.insert_text(
            fitz.Point(PAGE_W - 48 - 50, footer_y + 12),
            f"Page {i + 1} of {total}",
            fontsize=5.5,
            color=text_muted_rgb,
        )

    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes
