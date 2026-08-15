"""PDF and Markdown export for Fortis Intelligence Hub OSINT reports using PyMuPDF."""

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

# Sensitivity level color mapping (RGB tuples for PyMuPDF)
SENSITIVITY_COLORS_RGB = {
    "PUBLIC": (0.133, 0.545, 0.133),          # green  #228B22
    "INTERNAL": (0.608, 0.349, 0.714),        # purple #9b59b6
    "RESTRICTED": (1.0, 0.655, 0.149),        # amber  #ffa726
    "CONFIDENTIAL": (0.827, 0.184, 0.184),    # red    #d32f2f
}

SENSITIVITY_DESCRIPTIONS = {
    "PUBLIC": "Unrestricted - May be shared publicly without limitation.",
    "INTERNAL": "Internal Use Only - Do not distribute outside the organization.",
    "RESTRICTED": "Restricted - Share only with authorized personnel on a need-to-know basis.",
    "CONFIDENTIAL": "Confidential - Eyes only. Named recipients only. Do NOT share.",
}

# Single purple accent for all reports
ACCENT = "#9b59b6"
ACCENT_LIGHT = "#f3e8fa"
HEADER_BG = "#2d1f4e"


def _get_logo_b64() -> str:
    """Convert favicon.ico to a base64 PNG data URI, cached after first call."""
    global _logo_b64
    if _logo_b64 is not None:
        return _logo_b64

    try:
        img = Image.open(_FAVICON_PATH)
        img = img.resize((28, 28), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        _logo_b64 = base64.b64encode(buf.getvalue()).decode()
    except Exception:
        _logo_b64 = ""

    return _logo_b64


def _extract_report_name(session_id: str) -> str:
    """Extract human-readable report name from session ID."""
    if not session_id:
        return "N/A"
    parts = session_id.split("_", 1)
    name = parts[1] if len(parts) > 1 else session_id
    return re.sub(r"\.pdf$", "", name).replace("_", " ")


def _normalize_section_headers(text: str) -> str:
    """Convert decorated section headers to markdown ## headers."""
    text = re.sub(r'={3,}\s*(.+?)\s*={3,}', r'## \1', text)
    text = re.sub(r'^\s*={3,}\s*$', '', text, flags=re.MULTILINE)
    text = re.sub(r'^\s*[-]{3,}\s*$', '---', text, flags=re.MULTILINE)
    return text


def _build_chart_html(charts: dict) -> str:
    """Build HTML table grid for chart images (2x2 layout)."""
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
                f'<td style="padding:6px; text-align:center; vertical-align:top; width:50%;">'
                f'<div style="font-size:8pt; font-weight:700; color:#555555; margin-bottom:4px;">{label}</div>'
                f'<img src="{html_escape(b64_uri)}" width="240">'
                f'</td>'
            )
        if len(row_items) == 1:
            cells += '<td style="padding:6px;"></td>'
        rows_html += f"<tr>{cells}</tr>"

    return (
        '<div style="margin: 14px 0;">'
        '<div style="font-size:10pt; font-weight:700; color:#333333; margin-bottom:8px;">'
        'Visual Analytics</div>'
        f'<table style="width:100%; border-collapse:collapse;">{rows_html}</table>'
        '</div>'
    )


def _build_map_html(map_snapshot_b64: str | None) -> str:
    """Build HTML block for an embedded map snapshot PNG."""
    if not map_snapshot_b64:
        return ""

    # Accept raw base64 or full data URI
    if not map_snapshot_b64.startswith("data:image/"):
        map_snapshot_b64 = f"data:image/png;base64,{map_snapshot_b64}"

    return (
        '<div style="margin: 14px 0;">'
        '<div style="font-size:10pt; font-weight:700; color:#333333; margin-bottom:8px;">'
        'Geographic Overview</div>'
        f'<img src="{html_escape(map_snapshot_b64)}" style="width:100%; max-width:500px;">'
        '</div>'
    )


def _build_html(content: str, title: str, session_id: str,
                charts: dict | None = None,
                map_snapshot_b64: str | None = None) -> str:
    """Convert raw AI text to a styled HTML document for PDF rendering.

    Uses minimal CSS that PyMuPDF Story renders reliably.
    """
    # Remove any sensitivity header from content before processing
    sens_pattern = r'^#\s*(PUBLIC|INTERNAL|RESTRICTED|CONFIDENTIAL)\s*\n+'
    content = re.sub(sens_pattern, '', content, count=1, flags=re.IGNORECASE | re.MULTILINE)

    content = _normalize_section_headers(content)
    body_html = markdown.markdown(
        content,
        extensions=["tables", "fenced_code"],
    )

    accent = ACCENT
    accent_light = ACCENT_LIGHT
    header_bg = HEADER_BG

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report_name = html_escape(_extract_report_name(session_id))
    title_escaped = html_escape(title)

    logo_b64 = _get_logo_b64()
    logo_html = (
        f'<img src="data:image/png;base64,{logo_b64}" width="28" height="28">'
        if logo_b64 else ""
    )

    chart_section = _build_chart_html(charts) if charts else ""
    map_section = _build_map_html(map_snapshot_b64)

    return f"""<!DOCTYPE html>
<html>
<head>
<style>
body {{
    font-family: Helvetica, Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.55;
    color: #222222;
    margin: 0;
    padding: 0;
}}
.header-table {{
    width: 100%;
    border-bottom: 3px solid {accent};
    margin: 0 0 18px 0;
    padding-bottom: 12px;
    page-break-after: avoid;
}}
.header-table td {{
    vertical-align: top;
    border: none;
    padding: 2px 0;
}}
.logo-cell {{
    width: 36px;
    padding-right: 10px;
}}
.brand {{
    font-size: 8pt;
    font-weight: 700;
    color: {accent};
    letter-spacing: 1.5px;
    text-transform: uppercase;
}}
.report-title {{
    font-size: 16pt;
    font-weight: 700;
    color: {header_bg};
    margin: 4px 0;
}}
.mode-badge {{
    font-size: 8pt;
    font-weight: 700;
    color: {accent};
    letter-spacing: 1px;
}}
.meta-line {{
    font-size: 8pt;
    color: #666666;
    margin-top: 4px;
}}
h1 {{
    font-size: 14pt;
    color: {header_bg};
    border-bottom: 2px solid {accent};
    padding-bottom: 4px;
    margin-top: 20px;
    margin-bottom: 10px;
    font-weight: 700;
    page-break-after: avoid;
}}
h2 {{
    font-size: 11.5pt;
    color: {header_bg};
    font-weight: 700;
    margin-top: 16px;
    margin-bottom: 8px;
    border-bottom: 1px solid #cccccc;
    padding-bottom: 2px;
    page-break-after: avoid;
}}
h3 {{
    font-size: 10.5pt;
    color: {header_bg};
    font-weight: 700;
    margin-top: 12px;
    margin-bottom: 6px;
    page-break-after: avoid;
}}
p {{
    margin: 6px 0;
}}
ul, ol {{
    padding-left: 22px;
    margin: 6px 0;
}}
li {{
    margin: 3px 0;
}}
code {{
    background: {accent_light};
    color: {header_bg};
    padding: 1px 4px;
    font-family: "Courier New", Courier, monospace;
    font-size: 9pt;
}}
pre {{
    background: #f5f5f5;
    border-left: 3px solid {accent};
    padding: 10px;
    font-size: 8.5pt;
    margin: 8px 0;
}}
pre code {{
    background: none;
    padding: 0;
}}
table {{
    border-collapse: collapse;
    width: 100%;
    margin: 10px 0;
    font-size: 9pt;
}}
th {{
    background: #ffffff;
    color: {header_bg};
    padding: 6px 10px;
    text-align: left;
    font-weight: 700;
    border-bottom: 2px solid {accent};
}}
td {{
    padding: 5px 10px;
    border-bottom: 1px solid #dddddd;
}}
strong {{
    color: #111111;
}}
hr {{
    border: none;
    border-top: 1px solid #cccccc;
    margin: 14px 0;
}}
</style>
</head>
<body>

<table class="header-table">
<tr>
    <td class="logo-cell">{logo_html}</td>
    <td>
        <div class="brand">Fortis Intelligence Hub</div>
        <div class="report-title">{title_escaped}</div>
        <div class="mode-badge">OSINT INVESTIGATION REPORT</div>
        <div class="meta-line">Generated: {timestamp} &nbsp;|&nbsp; Source: {report_name}</div>
    </td>
</tr>
</table>

{chart_section}

{map_section}

{body_html}

</body>
</html>"""


def generate_markdown(content: str, title: str, session_id: str) -> bytes:
    """Convert raw AI analysis text to a Markdown report.

    Args:
        content: Raw AI response text
        title: Report title
        session_id: Session identifier for metadata

    Returns:
        UTF-8 encoded Markdown bytes
    """
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
                 map_snapshot_b64: str | None = None) -> bytes:
    """Convert raw AI analysis text to a styled PDF report.

    Args:
        content: Raw AI response text
        title: Report title
        session_id: For metadata header
        charts: Optional dict of chart_name -> base64 PNG data URI
        sensitivity_level: Sensitivity classification (PUBLIC, INTERNAL,
                          RESTRICTED, CONFIDENTIAL). Defaults to INTERNAL.
        map_snapshot_b64: Optional base64-encoded PNG of a map snapshot
                         to embed in the report.

    Returns:
        PDF file contents as bytes
    """
    # Determine sensitivity level
    if sensitivity_level:
        sensitivity_level = sensitivity_level.upper()
    else:
        # Try to extract from content header
        sens_pattern = r'^#\s*(PUBLIC|INTERNAL|RESTRICTED|CONFIDENTIAL)\s*\n+'
        sens_match = re.match(sens_pattern, content, re.IGNORECASE | re.MULTILINE)
        if sens_match:
            sensitivity_level = sens_match.group(1).upper()
        else:
            sensitivity_level = "INTERNAL"

    sens_color_rgb = SENSITIVITY_COLORS_RGB.get(sensitivity_level, SENSITIVITY_COLORS_RGB["INTERNAL"])
    sens_description = SENSITIVITY_DESCRIPTIONS.get(sensitivity_level, "Unknown sensitivity level")

    full_html = _build_html(content, title, session_id,
                            charts=charts,
                            map_snapshot_b64=map_snapshot_b64)

    buf = io.BytesIO()
    writer = fitz.DocumentWriter(buf)
    story = fitz.Story(html=full_html)

    mediabox = fitz.Rect(0, 0, 612, 792)
    content_rect = fitz.Rect(54, 126, 558, 720)

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
    accent_color = (0.608, 0.349, 0.714)  # Purple accent #9b59b6
    footer_color = (0.45, 0.50, 0.55)
    total = len(doc)

    for i, page in enumerate(doc):
        # Draw sensitivity banner on page 1 only
        if i == 0:
            # Sensitivity colored banner
            page.draw_rect(
                fitz.Rect(54, 54, 558, 76),
                color=None,
                fill=sens_color_rgb,
            )
            # Sensitivity text centered
            sens_text = sensitivity_level
            text_width = len(sens_text) * 6
            center_x = 306 - (text_width / 2)
            page.insert_text(
                fitz.Point(center_x, 68),
                sens_text,
                fontsize=11,
                color=(1, 1, 1),
                fontname="helv",
            )

            # Sensitivity guidelines box
            page.draw_rect(
                fitz.Rect(54, 78, 57, 104),
                color=None,
                fill=sens_color_rgb,
            )
            page.draw_rect(
                fitz.Rect(57, 78, 558, 104),
                color=None,
                fill=(0.976, 0.976, 0.976),
            )
            page.insert_text(
                fitz.Point(60, 88),
                f"Handling: {sens_description}",
                fontsize=8.5,
                color=(0.4, 0.4, 0.4),
            )

        # Footer line and text on all pages
        page.draw_line(
            fitz.Point(54, 744),
            fitz.Point(558, 744),
            color=(0.82, 0.82, 0.82),
            width=0.5,
        )
        page.insert_text(
            fitz.Point(54, 756),
            f"Fortis Intelligence Hub — {sensitivity_level}",
            fontsize=7,
            color=accent_color,
        )
        page.insert_text(
            fitz.Point(510, 756),
            f"Page {i + 1} of {total}",
            fontsize=7,
            color=footer_color,
        )

    pdf_bytes = doc.tobytes()
    doc.close()

    return pdf_bytes
