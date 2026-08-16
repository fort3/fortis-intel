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
        f'<div class="card">'
        f'<h3 class="card-title">Geospatial Data Points</h3>'
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
        f'<div class="card">'
        f'<h3 class="card-title">Visual Analytics</h3>'
        f'<table class="chart-grid">{rows_html}</table>'
        f'</div>'
    )


def _build_map_html(map_snapshot_b64: str | None) -> str:
    if not map_snapshot_b64:
        return ""
    if not map_snapshot_b64.startswith("data:image/"):
        map_snapshot_b64 = f"data:image/png;base64,{map_snapshot_b64}"
    return (
        f'<div class="card media-card">'
        f'<h3 class="card-title">Geographic Overview</h3>'
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
        f'<div class="card media-card">'
        f'<h3 class="card-title">Entity Relationship Graph</h3>'
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
        </table>
        <div class="title-sens-footer">{sens_desc}</div>
    </div>
</div>
"""


def _build_html(content: str, title: str, session_id: str,
                charts: dict | None = None,
                map_snapshot_b64: str | None = None,
                map_data: dict | None = None,
                entity_graph_b64: str | None = None,
                sensitivity_level: str = "INTERNAL") -> str:
    sens_pattern = r'^#\s*(PUBLIC|INTERNAL|RESTRICTED|CONFIDENTIAL)\s*\n+'
    content = re.sub(sens_pattern, '', content, count=1,
                     flags=re.IGNORECASE | re.MULTILINE)
    content = _normalize_section_headers(content)
    body_html = markdown.markdown(
        content, extensions=["tables", "fenced_code"],
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

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
    size: {PAGE_W}pt {PAGE_H}pt;
    margin: 0;
}}
body {{
    font-family: Helvetica, Arial, sans-serif;
    font-size: 9pt;
    line-height: 1.55;
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
    padding: 60px 100px;
}}
.title-card {{
    background: {CARD_BG};
    border: 1px solid {BORDER};
    border-radius: 6px;
    padding: 50px 40px 30px 40px;
    margin-top: 40px;
}}
.title-logo {{
    width: 56px;
    height: 56px;
    margin-bottom: 16px;
}}
.title-brand {{
    font-size: 13pt;
    font-weight: 700;
    color: {PURPLE_BRIGHT};
    letter-spacing: 6px;
    margin-bottom: 8px;
}}
.title-divider {{
    width: 80px;
    height: 1px;
    background: {PURPLE_DARK};
    margin: 16px auto;
}}
.title-main {{
    font-size: 20pt;
    font-weight: 700;
    color: {TEXT_BRIGHT};
    margin: 20px 0 6px 0;
    line-height: 1.2;
}}
.title-subtitle {{
    font-size: 8pt;
    font-weight: 700;
    color: {TEXT_SECONDARY};
    letter-spacing: 3px;
    margin-bottom: 30px;
}}
.title-meta-table {{
    margin: 16px auto;
    border-collapse: collapse;
    width: auto;
}}
.title-meta-table td {{
    padding: 3px 10px;
    font-size: 8pt;
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
    font-size: 8pt;
}}
.title-sens-footer {{
    font-size: 7pt;
    color: {TEXT_MUTED};
    margin-top: 16px;
    padding-top: 10px;
    border-top: 1px solid {BORDER};
}}

/* ========== CARDS (welcome-capability style) ========== */
.card {{
    background: {CARD_BG};
    border: 1px solid {BORDER};
    border-radius: 4px;
    padding: 16px 20px;
    margin: 12px 0;
}}
.card-title {{
    font-size: 9pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: {PURPLE_BRIGHT};
    margin: 0 0 10px 0;
}}
.media-card {{
    text-align: center;
    padding: 16px;
}}
.body-card {{
    padding: 20px 28px;
}}

/* ========== CONTENT TYPOGRAPHY ========== */
h1 {{
    font-size: 12pt;
    color: {PURPLE_BRIGHT};
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 18px;
    margin-bottom: 8px;
    page-break-after: avoid;
}}
h2 {{
    font-size: 10pt;
    color: {PURPLE_BRIGHT};
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 14px;
    margin-bottom: 6px;
    page-break-after: avoid;
}}
h3 {{
    font-size: 9.5pt;
    color: {TEXT_BRIGHT};
    font-weight: 700;
    margin-top: 10px;
    margin-bottom: 5px;
    page-break-after: avoid;
}}
p {{
    margin: 5px 0;
    color: {TEXT_SECONDARY};
}}
ul, ol {{
    padding-left: 20px;
    margin: 5px 0;
    color: {TEXT_SECONDARY};
}}
li {{
    margin: 2px 0;
    color: {TEXT_SECONDARY};
}}
strong {{
    color: {TEXT_PRIMARY};
}}
em {{
    color: {TEXT_SECONDARY};
    font-style: italic;
}}
a {{
    color: {PURPLE_BRIGHT};
}}
code {{
    background: {PURPLE_SUBTLE};
    color: {PURPLE_BRIGHT};
    padding: 1px 4px;
    font-family: "Courier New", Courier, monospace;
    font-size: 8pt;
    border-radius: 3px;
}}
pre {{
    background: {CARD_BG};
    border: 1px solid {BORDER};
    padding: 8px 10px;
    font-size: 7.5pt;
    margin: 6px 0;
    color: {TEXT_PRIMARY};
    border-radius: 4px;
}}
pre code {{
    background: none;
    padding: 0;
}}
hr {{
    border: none;
    border-top: 1px solid {BORDER};
    margin: 12px 0;
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
    border-bottom: 1px solid {BORDER};
}}
td {{
    padding: 4px 8px;
    border-bottom: 1px solid {BORDER};
    color: {TEXT_SECONDARY};
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
    display: inline-block;
    background: {PURPLE_DARK};
    color: {TEXT_BRIGHT};
    padding: 1px 6px;
    font-size: 6.5pt;
    font-weight: 700;
    border-radius: 3px;
}}
.tri-box {{
    background: {PURPLE_SUBTLE};
    padding: 5px 10px;
    margin-bottom: 8px;
    font-size: 7.5pt;
    color: {TEXT_PRIMARY};
    border-radius: 4px;
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
    max-width: 95%;
    border-radius: 4px;
}}

/* ========== MAP & GRAPH ========== */
.media-frame {{
    margin: 6px auto;
}}
.media-img {{
    width: 88%;
    max-width: 620px;
    border-radius: 4px;
    border: 1px solid {BORDER};
}}
</style>
</head>
<body>

{title_page}

{map_section}

{geo_summary}

{graph_section}

{chart_section}

<div class="card body-card">
{body_html}
</div>

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
        f"# {title}", "",
        "---", "",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Platform** | Fortis Intelligence Hub |",
        f"| **Generated** | {timestamp} |",
        f"| **Source** | {session_ref} |",
        "", "---", "",
        content,
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
    content_rect = fitz.Rect(48, 44, PAGE_W - 48, PAGE_H - 48)

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
