"""Post-generation grounding verifier.

Compares claims in LLM-generated reports against the input OSINT data
to detect hallucinated or ungrounded statements.

Runs AFTER LLM generation (unlike the ForgeGate verifiers which run before).
Uses the same sentence-transformers model as the civilian harm classifier
to avoid loading a second copy.
"""

import logging
import re
import threading
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

GROUNDED_THRESHOLD = 0.45
WEAKLY_GROUNDED_THRESHOLD = 0.25
WELL_GROUNDED_RATIO = 0.7
PARTIALLY_GROUNDED_RATIO = 0.4

# Structural / filler sentences to skip during claim extraction
_STRUCTURAL_PREFIXES = [
    "in summary",
    "in conclusion",
    "based on the above",
    "based on the data",
    "based on the findings",
    "based on the analysis",
    "based on available",
    "as mentioned",
    "as noted",
    "as described",
    "as outlined",
    "as discussed",
    "the following",
    "overall",
    "to summarize",
    "to conclude",
    "it is worth noting",
    "it should be noted",
    "note that",
    "please note",
    "see below",
    "see above",
    "further investigation",
    "additional research",
    "more information",
    "no data available",
    "no information available",
    "no relevant data",
]

# Regex for sentences that are headers, transitions, or structural
_STRUCTURAL_RE = re.compile(
    r"^(\s*#{1,6}\s|[-*]\s*$|\d+\.\s*$|\*\*.*\*\*\s*$)",
    re.MULTILINE,
)

# Regex to detect factual content (names, numbers, dates, URLs, platform refs)
_FACTUAL_INDICATORS = re.compile(
    r"(\b\d{4}\b"                           # years
    r"|\b\d+[.,]?\d*\s*%"                   # percentages
    r"|\b\d{1,3}([.,]\d{3})*\b"            # large numbers
    r"|\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)+\b"  # proper names (two+ capitalized words)
    r"|@\w+"                                 # handles
    r"|https?://\S+"                         # URLs
    r"|\b(?:twitter|facebook|instagram|linkedin|telegram|reddit|github|tiktok|x\.com)\b"  # platforms
    r"|\b(?:HIGH|MODERATE|LOW|CRITICAL|CONFIRMED|CONTRADICTED|NEW)\b"  # confidence/verdict markers
    r"|\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b"  # dates
    r"|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"  # IP addresses
    r")",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Model singleton — shares the sentence-transformers model with civilian_harm
# ---------------------------------------------------------------------------

_model = None
_model_lock = threading.Lock()
_model_available = True


def _get_model():
    """Lazy-load the sentence-transformers model.

    Attempts to reuse the model from the civilian harm classifier first.
    Falls back to loading its own instance if the classifier is unavailable.
    """
    global _model, _model_available

    if _model is not None or not _model_available:
        return _model

    with _model_lock:
        if _model is not None or not _model_available:
            return _model

        # Try to reuse the civilian harm classifier's model
        try:
            from app.civilian_harm import get_civilian_harm_classifier
            classifier = get_civilian_harm_classifier()
            classifier._load_model()
            if classifier._model is not None:
                _model = classifier._model
                log.info("Grounding verifier: reusing civilian harm model")
                return _model
        except Exception as exc:
            log.debug("Could not reuse civilian harm model: %s", exc)

        # Fall back to loading our own instance
        retries = 2
        for attempt in range(retries + 1):
            try:
                from sentence_transformers import SentenceTransformer
                from app.civilian_harm import HARM_MODEL_NAME
                log.info("Grounding verifier: loading model %s [attempt %d/%d]",
                         HARM_MODEL_NAME, attempt + 1, retries + 1)
                _model = SentenceTransformer(HARM_MODEL_NAME)
                log.info("Grounding verifier: model loaded")
                break
            except Exception as exc:
                if attempt < retries:
                    log.warning("Grounding verifier load attempt %d failed, retrying: %s",
                                attempt + 1, exc)
                    import time
                    time.sleep(2)
                else:
                    log.warning(
                        "Grounding verifier model unavailable after %d attempts: %s. "
                        "Ensure 'transformers' and 'torch' are installed: "
                        "pip install transformers torch sentence-transformers",
                        retries + 1, exc,
                    )
                    _model_available = False

        return _model


# ---------------------------------------------------------------------------
# Claim extraction
# ---------------------------------------------------------------------------

def _split_into_sentences(text: str) -> list[str]:
    """Split text into sentences using a simple regex-based approach."""
    # Remove markdown headers (keep the text after #)
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    # Remove markdown bold/italic markers
    text = re.sub(r"\*{1,3}([^*]+)\*{1,3}", r"\1", text)
    # Remove markdown bullet points at the start of lines
    text = re.sub(r"^[-*+]\s+", "", text, flags=re.MULTILINE)
    # Remove numbered list markers
    text = re.sub(r"^\d+\.\s+", "", text, flags=re.MULTILINE)

    # Split on sentence boundaries
    raw_sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z])", text)

    sentences = []
    for s in raw_sentences:
        s = s.strip()
        # Also split on newlines that separate distinct statements
        for sub in s.split("\n"):
            sub = sub.strip()
            if sub:
                sentences.append(sub)

    return sentences


def _is_structural(sentence: str) -> bool:
    """Check if a sentence is structural/filler rather than a factual claim."""
    lower = sentence.lower().strip()

    # Too short to be a meaningful claim
    if len(lower) < 15:
        return True

    # Starts with a structural prefix
    for prefix in _STRUCTURAL_PREFIXES:
        if lower.startswith(prefix):
            return True

    # Is a header line
    if _STRUCTURAL_RE.match(sentence):
        return True

    # Lines that are just labels (e.g., "Executive Summary", "Key Findings")
    if re.match(r"^[A-Z][a-z]+(\s[A-Z&][a-z]*)*\s*:?\s*$", sentence.strip()):
        return True

    return False


def _is_factual(sentence: str) -> bool:
    """Check if a sentence contains factual content worth verifying."""
    return bool(_FACTUAL_INDICATORS.search(sentence))


def extract_claims(report_text: str) -> list[str]:
    """Extract verifiable factual claims from a report.

    Skips structural sentences, headers, transitions, and
    focuses on statements containing names, dates, numbers,
    platform references, or other factual indicators.
    """
    sentences = _split_into_sentences(report_text)
    claims = []
    for s in sentences:
        if _is_structural(s):
            continue
        if _is_factual(s):
            claims.append(s)
    return claims


# ---------------------------------------------------------------------------
# Context chunking
# ---------------------------------------------------------------------------

def _chunk_context(context: str, chunk_size: int = 300, overlap: int = 50) -> list[str]:
    """Split OSINT context into overlapping chunks for comparison."""
    if not context:
        return []

    words = context.split()
    if len(words) <= chunk_size:
        return [context]

    chunks = []
    start = 0
    while start < len(words):
        end = min(start + chunk_size, len(words))
        chunk = " ".join(words[start:end])
        if chunk.strip():
            chunks.append(chunk)
        start += chunk_size - overlap

    return chunks


# ---------------------------------------------------------------------------
# Main verification function
# ---------------------------------------------------------------------------

def verify_grounding(report_text: str, osint_context: str) -> dict:
    """Verify that report claims are grounded in OSINT data.

    Computes semantic similarity between each extracted claim and
    the input OSINT context chunks to detect potential hallucinations.

    Args:
        report_text: The LLM-generated report text.
        osint_context: The raw OSINT data that was fed to the LLM.

    Returns:
        Dictionary with grounding analysis results:
        - grounded_ratio: float 0.0-1.0
        - total_claims: int
        - grounded_claims: int
        - weakly_grounded_claims: int
        - ungrounded_claims: int
        - ungrounded_details: list of dicts with claim, max_similarity, closest_source
        - verdict: WELL_GROUNDED | PARTIALLY_GROUNDED | POORLY_GROUNDED
        - warnings: list of str
    """
    result = {
        "grounded_ratio": 1.0,
        "total_claims": 0,
        "grounded_claims": 0,
        "weakly_grounded_claims": 0,
        "ungrounded_claims": 0,
        "ungrounded_details": [],
        "verdict": "WELL_GROUNDED",
        "warnings": [],
    }

    # Extract claims from the report
    claims = extract_claims(report_text)
    if not claims:
        result["warnings"].append("No verifiable claims extracted from report.")
        return result

    result["total_claims"] = len(claims)

    # Check model availability
    model = _get_model()
    if model is None:
        result["warnings"].append(
            "Sentence-transformers model unavailable; grounding check skipped."
        )
        result["verdict"] = "SKIPPED"
        result["grounded_ratio"] = 0.0
        result["grounded_claims"] = 0
        return result

    # Chunk the OSINT context
    chunks = _chunk_context(osint_context)
    if not chunks:
        result["warnings"].append("No OSINT context provided for grounding check.")
        result["verdict"] = "POORLY_GROUNDED"
        result["grounded_ratio"] = 0.0
        result["ungrounded_claims"] = len(claims)
        return result

    try:
        import numpy as np

        # Encode all claims and context chunks
        claim_embeddings = model.encode(claims, normalize_embeddings=True)
        chunk_embeddings = model.encode(chunks, normalize_embeddings=True)

        # Compute similarity matrix: claims x chunks
        similarity_matrix = np.dot(claim_embeddings, chunk_embeddings.T)

        grounded = 0
        weakly_grounded = 0
        ungrounded = 0
        ungrounded_details = []

        for i, claim in enumerate(claims):
            max_sim = float(similarity_matrix[i].max())
            best_chunk_idx = int(similarity_matrix[i].argmax())

            if max_sim >= GROUNDED_THRESHOLD:
                grounded += 1
            elif max_sim >= WEAKLY_GROUNDED_THRESHOLD:
                weakly_grounded += 1
            else:
                ungrounded += 1
                # Truncate the closest source for readability
                closest = chunks[best_chunk_idx]
                if len(closest) > 200:
                    closest = closest[:200] + "..."
                ungrounded_details.append({
                    "claim": claim[:300],
                    "max_similarity": round(max_sim, 3),
                    "closest_source": closest,
                })

        result["grounded_claims"] = grounded
        result["weakly_grounded_claims"] = weakly_grounded
        result["ungrounded_claims"] = ungrounded
        result["ungrounded_details"] = ungrounded_details[:20]  # cap for response size

        # Grounded ratio: fully grounded + half credit for weakly grounded
        effective_grounded = grounded + (weakly_grounded * 0.5)
        result["grounded_ratio"] = round(
            effective_grounded / len(claims), 3
        ) if claims else 1.0

        # Determine verdict
        if result["grounded_ratio"] >= WELL_GROUNDED_RATIO:
            result["verdict"] = "WELL_GROUNDED"
        elif result["grounded_ratio"] >= PARTIALLY_GROUNDED_RATIO:
            result["verdict"] = "PARTIALLY_GROUNDED"
        else:
            result["verdict"] = "POORLY_GROUNDED"

        # Add warnings for notable findings
        if ungrounded > 0:
            result["warnings"].append(
                f"{ungrounded} claim(s) could not be traced to OSINT source data."
            )
        if result["verdict"] == "POORLY_GROUNDED":
            result["warnings"].append(
                "Report has low grounding in source data. "
                "Review flagged claims for potential hallucinations."
            )

    except Exception as exc:
        log.warning("Grounding verification failed: %s", exc)
        result["warnings"].append(f"Grounding check error: {str(exc)[:200]}")
        result["verdict"] = "UNKNOWN"
        result["grounded_ratio"] = 0.0
        result["grounded_claims"] = 0

    return result


# ---------------------------------------------------------------------------
# Field-level fact verification (A2)
# ---------------------------------------------------------------------------

_FACT_EXTRACTORS = {
    "date": re.compile(
        r"\b(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})\b"
    ),
    "ip": re.compile(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    ),
    "email": re.compile(
        r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
    ),
    "handle": re.compile(r"(?<!\w)@([a-zA-Z0-9_]{2,30})\b"),
    "url": re.compile(r"(https?://[^\s)<>\"]+)"),
    "percentage": re.compile(r"\b(\d+(?:\.\d+)?)\s*%"),
    "year": re.compile(r"\b((?:19|20)\d{2})\b"),
    "ipv4_port": re.compile(
        r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})\b"
    ),
    "domain": re.compile(
        r"\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"\.(?:com|org|net|io|co|gov|edu|info|xyz|me|dev|app|uk|de|ru|cn|"
        r"biz|tech|online|site|shop|club|top))\b"
    ),
}


def _extract_facts(text: str) -> list[dict]:
    """Extract typed factual tokens from text."""
    facts = []
    seen = set()
    for fact_type, pattern in _FACT_EXTRACTORS.items():
        for m in pattern.finditer(text):
            val = m.group(1) if m.lastindex else m.group(0)
            key = (fact_type, val.lower())
            if key not in seen:
                seen.add(key)
                facts.append({
                    "type": fact_type,
                    "value": val,
                    "position": m.start(),
                })
    return facts


def verify_facts(report_text: str, osint_context: str) -> dict:
    """Cross-check specific facts in the report against raw OSINT data.

    Unlike semantic grounding (which measures overall similarity), this
    performs exact/normalised matching of concrete data points — dates,
    IPs, emails, handles, URLs, domains — to catch fabricated specifics
    that semantic similarity might miss.

    Returns:
        confirmed: facts found in source data
        unconfirmed: facts NOT found in source data (potential hallucinations)
        accuracy_ratio: confirmed / total
    """
    report_facts = _extract_facts(report_text)
    if not report_facts:
        return {
            "confirmed": [],
            "unconfirmed": [],
            "total_facts": 0,
            "accuracy_ratio": 1.0,
            "verdict": "NO_FACTS",
        }

    context_lower = osint_context.lower()
    context_facts_set = set()
    for fact_type, pattern in _FACT_EXTRACTORS.items():
        for m in pattern.finditer(osint_context):
            val = m.group(1) if m.lastindex else m.group(0)
            context_facts_set.add((fact_type, val.lower()))

    confirmed = []
    unconfirmed = []

    for fact in report_facts:
        key = (fact["type"], fact["value"].lower())
        if key in context_facts_set or fact["value"].lower() in context_lower:
            confirmed.append(fact)
        else:
            unconfirmed.append(fact)

    total = len(report_facts)
    ratio = len(confirmed) / total if total > 0 else 1.0

    if ratio >= 0.85:
        verdict = "ACCURATE"
    elif ratio >= 0.6:
        verdict = "PARTIALLY_ACCURATE"
    else:
        verdict = "LOW_ACCURACY"

    return {
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
        "total_facts": total,
        "confirmed_count": len(confirmed),
        "unconfirmed_count": len(unconfirmed),
        "accuracy_ratio": round(ratio, 3),
        "verdict": verdict,
    }
