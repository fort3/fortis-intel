"""Security sanitisation layer for dork queries and search results.

Blocks dangerous Google operators, anti-exfiltration patterns, and scans
incoming web content for prompt-injection before it reaches the LLM.
"""

import re
import logging
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Allowed / blocked dork operators
# ---------------------------------------------------------------------------

ALLOWED_OPERATORS = {"site:", "intitle:", "inurl:", "filetype:"}
BLOCKED_OPERATORS = {"cache:", "link:", "related:", "info:", "inanchor:"}

MAX_QUERY_LENGTH = 256

# ---------------------------------------------------------------------------
# Anti-exfiltration patterns
# ---------------------------------------------------------------------------

_EMBEDDED_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_LONG_HEX_RE = re.compile(r"[0-9a-f]{32,}", re.IGNORECASE)
_SHELL_DANGEROUS_RE = re.compile(r"[;&`]")


def sanitize_dork_query(query: str) -> tuple[str, list[str]]:
    """Validate and sanitise a dork query string.

    Returns ``(cleaned_query, warnings)`` where *cleaned_query* is empty
    when the query should be dropped entirely.
    """
    warnings: list[str] = []

    if len(query) > MAX_QUERY_LENGTH:
        warnings.append(f"Query too long ({len(query)} chars, max {MAX_QUERY_LENGTH})")
        return "", warnings

    lowered = query.lower()

    for op in BLOCKED_OPERATORS:
        if op in lowered:
            warnings.append(f"Blocked operator: {op}")
            return "", warnings

    if _EMBEDDED_URL_RE.search(query):
        warnings.append("Embedded URL detected")
        return "", warnings

    if _BASE64_RE.search(query):
        warnings.append("Possible base64 payload detected")
        return "", warnings

    if _LONG_HEX_RE.search(query):
        warnings.append("Long hex string detected")
        return "", warnings

    if _SHELL_DANGEROUS_RE.search(query):
        warnings.append("Dangerous shell character detected")
        return "", warnings

    return query.strip(), warnings


# ---------------------------------------------------------------------------
# Result sanitisation
# ---------------------------------------------------------------------------

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_LOCALHOST_RE = re.compile(
    r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
    re.IGNORECASE,
)

SNIPPET_MAX_CHARS = 300
MAX_RESULTS = 10


def sanitize_search_results(
    results: list[dict[str, Any]],
    max_results: int = MAX_RESULTS,
) -> str:
    """Sanitise raw search results into a numbered text block safe for LLM input.

    Strips HTML, truncates snippets, blocks internal URLs, and scans for
    prompt-injection patterns using the same regex set as ForgeChain verifiers.
    """
    from app.forge.verifiers import INJECTION_PATTERNS

    sanitised_lines: list[str] = []
    count = 0

    for r in results:
        if count >= max_results:
            break

        url = r.get("url", "")
        if _LOCALHOST_RE.search(url):
            log.debug("Blocked internal URL: %s", url)
            continue

        title = _HTML_TAG_RE.sub("", r.get("title", "")).strip()
        snippet = _HTML_TAG_RE.sub("", r.get("snippet", "")).strip()

        if len(snippet) > SNIPPET_MAX_CHARS:
            snippet = snippet[:SNIPPET_MAX_CHARS] + "..."

        for pattern in INJECTION_PATTERNS:
            if pattern.search(title):
                title = "[Content filtered]"
                break
        for pattern in INJECTION_PATTERNS:
            if pattern.search(snippet):
                snippet = "[Content filtered]"
                break

        count += 1
        sanitised_lines.append(
            f"[{count}] {title}\n    URL: {url}\n    {snippet}"
        )

    if not sanitised_lines:
        return "No results found."

    return "\n\n".join(sanitised_lines)


def sanitize_scraped_content(raw_html: str, max_chars: int = 2000) -> str:
    """Strip scripts/styles, HTML tags, and injection patterns from scraped page content."""
    from app.forge.verifiers import INJECTION_PATTERNS

    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", raw_html, flags=re.DOTALL | re.IGNORECASE)
    text = _HTML_TAG_RE.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) > max_chars:
        text = text[:max_chars] + "..."

    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            text = pattern.sub("[filtered]", text)

    return text
