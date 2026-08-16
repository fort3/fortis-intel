"""PDF and Markdown export for Fortis Intelligence Hub OSINT reports using PyMuPDF.

Dark cyberpunk theme matching the app's visual design. Reports include:
- Branded title page with sensitivity classification
- Analysis content with proper dark-theme contrast
- Inline map snapshots and entity relationship graphs
- Visual analytics charts in 2-column layout
- Sensitivity banners and branded footers
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


_FAVICON_PATH = Path(__file__).resolve().parent / "data" / "favicon.ico"
_logo_b64: str | None = None

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

# Theme colors matching the app's CSS variables
BG_DEEP = "#08081a"
BG_CARD = "#10101e"
BG_ELEVATED = "#1a1a28"
SURFACE = "#222233"
BORDER = "#2a2a3d"
PURPLE_PRIMARY = "#9b59b6"
PURPLE_BRIGHT = "#bb6bd9"
PURPLE_NEON = "#d946ef"
PURPLE_DARK = "#6b3fa0"
PURPLE_SUBTLE = "#2d1f4e"
TEXT_PRIMARY = "#e8e6f0"
TEXT_SECONDARY = "#9a97a8"
TEXT_MUTED = "#5c5a6a"
TEXT_BRIGHT = "#ffffff"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
DANGER = "#ef4444"


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


def _build_geo_summary_html(map_data: dict | None) -> str:
    """Build a tabular summary of geospatial data points."""
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
        label = html_escape(str(m.get("label", ""))[:40]) or "—"
        src = m.get("source_type", "osint")
        src_label = source_labels.get(src, src.replace("_", " ").title())
        conf = m.get("confidence", 0)
        conf_pct = f"{conf * 100:.0f}%" if isinstance(conf, (int, float)) else str(conf)
        desc = html_escape(str(m.get("description", ""))[:50])
        rows += (
            f'<tr>'
            f'<td>{label}</td>'
            f'<td>{lat:.5f}, {lng:.5f}</td>'
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
        f'<div class="section-block">'
        f'<h2>Geospatial Data Points</h2>'
        f'{tri_html}'
        f'<table class="data-table">'
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
    for i in range(0, len(items), 2):
        row_items = items[i:i + 2]
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
        if len(row_items) == 1:
            cells += '<td class="chart-cell"></td>'
        rows_html += f"<tr>{cells}</tr>"

    return (
        f'<div class="section-block">'
        f'<h2>Visual Analytics</h2>'
        f'<table class="chart-grid">{rows_html}</table>'
        f'</div>'
    )


def _build_map_html(map_snapshot_b64: str | None) -> str:
    if not map_snapshot_b64:
        return ""
    if not map_snapshot_b64.startswith("data:image/"):
        map_snapshot_b64 = f"data:image/png;base64,{map_snapshot_b64}"
    return (
        f'<div class="section-block">'
        f'<h2>Geographic Overview</h2>'
        f'<div class="map-frame">'
        f'<img src="{html_escape(map_snapshot_b64)}" class="map-img">'
        f'</div>'
        f'</div>'
    )


def _build_graph_html(graph_b64: str | None) -> str:
    if not graph_b64:
        return ""
    if not graph_b64.startswith("data:image/"):
        graph_b64 = f"data:image/png;base64,{graph_b64}"
    return (
        f'<div class="section-block">'
        f'<h2>Entity Relationship Graph</h2>'
        f'<div class="graph-frame">'
        f'<img src="{html_escape(graph_b64)}" class="graph-img">'
        f'</div>'
        f'</div>'
    )


def _build_title_page_html(
    title: str,
    session_id: str,
    sensitivity_level: str,
    timestamp: str,
) -> str:
    """Build a full-page title/cover page."""
    logo_b64 = _get_logo_b64()
    logo_html = (
        f'<img src="data:image/png;base64,{logo_b64}" class="title-logo">'
        if logo_b64 else ""
    )
    report_name = html_escape(_extract_report_name(session_id))
    title_escaped = html_escape(title)
    sens_color = SENSITIVITY_COLORS_HEX.get(sensitivity_level, PURPLE_PRIMARY)
    sens_desc = html_escape(
        SENSITIVITY_DESCRIPTIONS.get(sensitivity_level, "")
    )

    return f"""
<div class="title-page">
    <div class="title-top-bar"></div>
    <div class="title-content">
        {logo_html}
        <div class="title-brand">FORTIS INTELLIGENCE HUB</div>
        <div class="title-divider"></div>
        <div class="title-main">{title_escaped}</div>
        <div class="title-subtitle">OSINT INVESTIGATION REPORT</div>
        <div class="title-meta">
            <table class="title-meta-table">
                <tr><td class="meta-key">Generated</td><td class="meta-val">{timestamp}</td></tr>
                <tr><td class="meta-key">Source</td><td class="meta-val">{report_name}</td></tr>
                <tr><td class="meta-key">Platform</td><td class="meta-val">Fortis Intelligence Hub</td></tr>
            </table>
        </div>
        <div class="title-sens-badge" style="background:{sens_color};">
            {sensitivity_level}
        </div>
        <div class="title-sens-desc">{sens_desc}</div>
    </div>
    <div class="title-footer">
        <div class="title-footer-line"></div>
        <div class="title-footer-text">FORTIS INTELLIGENCE HUB &mdash; CLASSIFIED REPORT</div>
    </div>
</div>
"""


def _build_html(content: str, title: str, session_id: str,
                charts: dict | None = None,
                map_snapshot_b64: str | None = None,
                map_data: dict | None = None,
                entity_graph_b64: str | None = None,
                sensitivity_level: str = "INTERNAL") -> str:
    """Build dark-themed HTML for PDF rendering with title page and inline visuals."""
    sens_pattern = r'^#\s*(PUBLIC|INTERNAL|RESTRICTED|CONFIDENTIAL)\s*\n+'
    content = re.sub(sens_pattern, '', content, count=1,
                     flags=re.IGNORECASE | re.MULTILINE)
    content = _normalize_section_headers(content)
    body_html = markdown.markdown(
        content, extensions=["tables", "fenced_code"],
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sens_color = SENSITIVITY_COLORS_HEX.get(sensitivity_level, PURPLE_PRIMARY)

    title_page = _build_title_page_html(
        title, session_id, sensitivity_level, timestamp,
    )
    map_section = _build_map_html(map_snapshot_b64)
    geo_summary = _build_geo_summary_html(map_data)
    graph_section = _build_graph_html(entity_graph_b64)
    chart_section = _build_chart_html(charts) if charts else ""

    return f"""<!DOCTYPE html>
<html>
<head>
<style>
@page {{
    margin: 0;
}}
body {{
    font-family: Helvetica, Arial, sans-serif;
    font-size: 9.5pt;
    line-height: 1.6;
    color: {TEXT_PRIMARY};
    background: {BG_DEEP};
    margin: 0;
    padding: 0;
}}

/* ========== TITLE PAGE ========== */
.title-page {{
    page-break-after: always;
    min-height: 700px;
    text-align: center;
    padding: 40px 60px;
    position: relative;
}}
.title-top-bar {{
    width: 100%;
    height: 4px;
    background: {PURPLE_NEON};
    margin-bottom: 80px;
}}
.title-content {{
    margin-top: 40px;
}}
.title-logo {{
    width: 64px;
    height: 64px;
    margin-bottom: 16px;
}}
.title-brand {{
    font-size: 11pt;
    font-weight: 700;
    color: {PURPLE_BRIGHT};
    letter-spacing: 4px;
    margin-bottom: 10px;
}}
.title-divider {{
    width: 80px;
    height: 2px;
    background: {PURPLE_NEON};
    margin: 16px auto;
}}
.title-main {{
    font-size: 22pt;
    font-weight: 700;
    color: {TEXT_BRIGHT};
    margin: 20px 0 8px 0;
    line-height: 1.2;
}}
.title-subtitle {{
    font-size: 10pt;
    font-weight: 700;
    color: {PURPLE_PRIMARY};
    letter-spacing: 3px;
    margin-bottom: 40px;
}}
.title-meta {{
    margin: 30px auto;
    max-width: 300px;
}}
.title-meta-table {{
    width: 100%;
    border-collapse: collapse;
}}
.title-meta-table td {{
    padding: 4px 8px;
    font-size: 8.5pt;
    border: none;
}}
.meta-key {{
    color: {TEXT_MUTED};
    text-align: right;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    width: 40%;
}}
.meta-val {{
    color: {TEXT_SECONDARY};
    text-align: left;
}}
.title-sens-badge {{
    display: inline-block;
    padding: 6px 24px;
    font-size: 10pt;
    font-weight: 700;
    color: {TEXT_BRIGHT};
    letter-spacing: 2px;
    margin: 20px auto 8px auto;
}}
.title-sens-desc {{
    font-size: 7.5pt;
    color: {TEXT_MUTED};
    max-width: 400px;
    margin: 0 auto;
}}
.title-footer {{
    position: absolute;
    bottom: 30px;
    left: 60px;
    right: 60px;
    text-align: center;
}}
.title-footer-line {{
    width: 100%;
    height: 1px;
    background: {BORDER};
    margin-bottom: 8px;
}}
.title-footer-text {{
    font-size: 7pt;
    color: {TEXT_MUTED};
    letter-spacing: 2px;
}}

/* ========== CONTENT PAGES ========== */
.content-header {{
    border-bottom: 2px solid {PURPLE_PRIMARY};
    padding-bottom: 8px;
    margin-bottom: 16px;
}}
.content-brand {{
    font-size: 7pt;
    font-weight: 700;
    color: {PURPLE_PRIMARY};
    letter-spacing: 2px;
    text-transform: uppercase;
}}
.content-title {{
    font-size: 13pt;
    font-weight: 700;
    color: {TEXT_BRIGHT};
    margin: 4px 0 0 0;
}}

.section-block {{
    margin: 16px 0;
    padding: 12px 14px;
    background: {BG_CARD};
    border: 1px solid {BORDER};
    border-left: 3px solid {PURPLE_PRIMARY};
}}

h1 {{
    font-size: 13pt;
    color: {PURPLE_BRIGHT};
    border-bottom: 2px solid {PURPLE_DARK};
    padding-bottom: 4px;
    margin-top: 22px;
    margin-bottom: 10px;
    font-weight: 700;
    page-break-after: avoid;
}}
h2 {{
    font-size: 11pt;
    color: {PURPLE_BRIGHT};
    font-weight: 700;
    margin-top: 16px;
    margin-bottom: 8px;
    border-bottom: 1px solid {BORDER};
    padding-bottom: 3px;
    page-break-after: avoid;
}}
h3 {{
    font-size: 10pt;
    color: {TEXT_BRIGHT};
    font-weight: 700;
    margin-top: 12px;
    margin-bottom: 6px;
    page-break-after: avoid;
}}
p {{
    margin: 6px 0;
    color: {TEXT_PRIMARY};
}}
ul, ol {{
    padding-left: 22px;
    margin: 6px 0;
    color: {TEXT_PRIMARY};
}}
li {{
    margin: 3px 0;
}}
strong {{
    color: {TEXT_BRIGHT};
}}
em {{
    color: {PURPLE_BRIGHT};
}}
a {{
    color: {PURPLE_BRIGHT};
}}
code {{
    background: {PURPLE_SUBTLE};
    color: {PURPLE_BRIGHT};
    padding: 1px 4px;
    font-family: "Courier New", Courier, monospace;
    font-size: 8.5pt;
}}
pre {{
    background: {BG_ELEVATED};
    border-left: 3px solid {PURPLE_PRIMARY};
    padding: 10px;
    font-size: 8pt;
    margin: 8px 0;
    color: {TEXT_PRIMARY};
}}
pre code {{
    background: none;
    padding: 0;
}}
hr {{
    border: none;
    border-top: 1px solid {BORDER};
    margin: 14px 0;
}}

/* Tables */
table {{
    border-collapse: collapse;
    width: 100%;
    margin: 10px 0;
    font-size: 8.5pt;
}}
th {{
    background: {PURPLE_SUBTLE};
    color: {TEXT_BRIGHT};
    padding: 6px 8px;
    text-align: left;
    font-weight: 700;
    border-bottom: 2px solid {PURPLE_PRIMARY};
    font-size: 8pt;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
td {{
    padding: 5px 8px;
    border-bottom: 1px solid {BORDER};
    color: {TEXT_PRIMARY};
}}
tr:nth-child(even) td {{
    background: {BG_CARD};
}}

.data-table {{
    margin: 8px 0;
}}
.data-table th {{
    background: {PURPLE_SUBTLE};
}}
.desc-cell {{
    color: {TEXT_SECONDARY};
    font-size: 7.5pt;
}}
.src-badge {{
    display: inline-block;
    background: {PURPLE_DARK};
    color: {TEXT_BRIGHT};
    padding: 1px 6px;
    font-size: 7pt;
    font-weight: 700;
    letter-spacing: 0.3px;
}}

.tri-box {{
    background: {PURPLE_SUBTLE};
    border: 1px solid {PURPLE_DARK};
    padding: 6px 10px;
    margin-bottom: 8px;
    font-size: 8pt;
    color: {TEXT_PRIMARY};
}}
.tri-label {{
    font-weight: 700;
    color: {PURPLE_NEON};
    letter-spacing: 1px;
    font-size: 7.5pt;
}}

/* Charts */
.chart-grid {{
    width: 100%;
    border-collapse: collapse;
}}
.chart-cell {{
    padding: 6px;
    text-align: center;
    vertical-align: top;
    width: 50%;
}}
.chart-label {{
    font-size: 7.5pt;
    font-weight: 700;
    color: {TEXT_SECONDARY};
    margin-bottom: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}}
.chart-img {{
    width: 240px;
    max-width: 100%;
}}

/* Map & Graph */
.map-frame, .graph-frame {{
    background: {BG_ELEVATED};
    border: 1px solid {BORDER};
    padding: 8px;
    text-align: center;
    margin: 6px 0;
}}
.map-img {{
    width: 100%;
    max-width: 500px;
}}
.graph-img {{
    width: 100%;
    max-width: 500px;
}}

/* Sensitivity indicator */
.sens-strip {{
    width: 100%;
    height: 3px;
    margin-bottom: 12px;
}}
</style>
</head>
<body>

{title_page}

<div class="content-header">
    <div class="content-brand">FORTIS INTELLIGENCE HUB</div>
    <div class="content-title">{html_escape(title)}</div>
</div>
<div class="sens-strip" style="background:{sens_color};"></div>

{map_section}

{geo_summary}

{graph_section}

{chart_section}

{body_html}

</body>
</html>"""


def generate_markdown(content: str, title: str, session_id: str) -> bytes:
    session_ref = session_id
    if session_ref:
        parts = session_ref.split("_", 1)
        session_ref = parts[1] if len(parts) > 1 else session_ref
        session_ref = re.sub(r"\.pdf$", "", session_ref).replace("_", " ")
    else:
        session_ref = "N/A"

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    md_lines = [
        f"# {title}",
        "",
        "---",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Platform** | Fortis Intelligence Hub |",
        f"| **Generated** | {timestamp} |",
        f"| **Source** | {session_ref} |",
        "",
        "---",
        "",
        content,
    ]
    return "\n".join(md_lines).encode("utf-8")


def generate_pdf(content: str, title: str, session_id: str,
                 charts: dict | None = None,
                 sensitivity_level: str | None = None,
                 map_snapshot_b64: str | None = None,
                 map_data: dict | None = None,
                 entity_graph_b64: str | None = None) -> bytes:
    """Generate a dark-themed PDF report with title page and inline visuals."""
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

    buf = io.BytesIO()
    writer = fitz.DocumentWriter(buf)
    story = fitz.Story(html=full_html)

    mediabox = fitz.Rect(0, 0, 612, 792)
    content_rect = fitz.Rect(54, 54, 558, 720)

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

    bg_color_rgb = (0.031, 0.031, 0.102)  # #08081a
    accent_rgb = (0.608, 0.349, 0.714)    # #9b59b6
    border_rgb = (0.165, 0.165, 0.239)    # #2a2a3d
    text_muted_rgb = (0.361, 0.353, 0.416)
    text_secondary_rgb = (0.604, 0.592, 0.659)

    for i, page in enumerate(doc):
        # Dark background fill for every page
        page.draw_rect(
            mediabox,
            color=None,
            fill=bg_color_rgb,
            overlay=False,
        )

        if i == 0:
            # Title page — neon accent line at top
            page.draw_rect(
                fitz.Rect(54, 54, 558, 58),
                color=None,
                fill=(0.851, 0.275, 0.937),  # #d946ef neon
            )
            continue

        # Content pages — header line + sensitivity strip
        page.draw_rect(
            fitz.Rect(54, 38, 558, 40),
            color=None,
            fill=accent_rgb,
        )
        # Sensitivity micro-badge top-right
        page.insert_text(
            fitz.Point(480, 35),
            sensitivity_level,
            fontsize=6,
            color=sens_color_rgb,
            fontname="helv",
        )

        # Footer
        page.draw_line(
            fitz.Point(54, 738),
            fitz.Point(558, 738),
            color=border_rgb,
            width=0.5,
        )
        page.insert_text(
            fitz.Point(54, 752),
            f"FORTIS INTELLIGENCE HUB",
            fontsize=6,
            color=accent_rgb,
        )
        page.insert_text(
            fitz.Point(250, 752),
            f"—  {sensitivity_level}  —",
            fontsize=6,
            color=sens_color_rgb,
        )
        page.insert_text(
            fitz.Point(500, 752),
            f"Page {i + 1} of {total}",
            fontsize=6,
            color=text_muted_rgb,
        )

    pdf_bytes = doc.tobytes()
    doc.close()
    return pdf_bytes
