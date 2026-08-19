"""Self-consistency check for LLM-generated OSINT reports.

Runs the investigation chain multiple times and identifies claims that
are unstable across runs — i.e., the LLM produces contradictory or
absent statements depending on sampling.  Stable claims are more
trustworthy; unstable claims warrant analyst review.

Exports:
    run_self_consistency_check  -- main entry point
    SELF_CONSISTENCY_ENABLED    -- feature toggle (env var)
"""

import logging
import os
import re
from typing import Any

log = logging.getLogger(__name__)

SELF_CONSISTENCY_ENABLED: bool = os.environ.get(
    "SELF_CONSISTENCY_ENABLED", "false"
).lower() in ("true", "1", "yes")

SELF_CONSISTENCY_RUNS: int = int(os.environ.get("SELF_CONSISTENCY_RUNS", "3"))

_FILLER_PATTERNS = re.compile(
    r"^(#{1,4}\s|---|\*\*\*|>|in summary|based on|overall|"
    r"as noted|as mentioned|the following|this section)\b",
    re.IGNORECASE,
)

_model = None
_model_lock = None


def _get_model():
    """Lazy-load sentence-transformers model (shared with civilian_harm)."""
    global _model
    if _model is not None:
        return _model
    try:
        from app.civilian_harm import get_civilian_harm_classifier
        classifier = get_civilian_harm_classifier()
        _model = classifier._model
        return _model
    except Exception:
        pass
    try:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")
        return _model
    except Exception as exc:
        log.error("Could not load sentence-transformers model: %s", exc)
        return None


def _extract_claims(text: str) -> list[str]:
    """Extract factual claim sentences from a report."""
    sentences = re.split(r"(?<=[.!?])\s+", text)
    claims = []
    for s in sentences:
        s = s.strip()
        if len(s) < 20 or len(s) > 500:
            continue
        if _FILLER_PATTERNS.match(s):
            continue
        if s.startswith("#") or s.startswith("|") or s.startswith("-"):
            continue
        claims.append(s)
    return claims


def run_self_consistency_check(
    chain,
    chain_input: dict[str, Any],
    primary_output: str,
    gated_invoke_fn=None,
    gated_invoke_kwargs: dict | None = None,
    num_runs: int | None = None,
) -> dict[str, Any]:
    """Run the chain multiple times and compare outputs for consistency.

    Parameters
    ----------
    chain:
        The LangChain chain to invoke.
    chain_input:
        Input dict for the chain.
    primary_output:
        The initial report already generated (counted as run 1).
    gated_invoke_fn:
        If provided, use this function instead of chain.invoke().
    gated_invoke_kwargs:
        Extra kwargs to pass to gated_invoke_fn.
    num_runs:
        Total number of runs (including the primary).  Defaults to
        ``SELF_CONSISTENCY_RUNS`` env var.

    Returns
    -------
    dict with keys:
        - ``consistency_ratio``: 0.0-1.0
        - ``stable_claims``: int
        - ``unstable_claims``: int
        - ``total_claims``: int
        - ``unstable_details``: list of {claim, appearances, total_runs}
        - ``verdict``: CONSISTENT | MOSTLY_CONSISTENT | INCONSISTENT
        - ``runs_completed``: int
    """
    runs = num_runs or SELF_CONSISTENCY_RUNS
    if runs < 2:
        runs = 2

    model = _get_model()
    if model is None:
        return {
            "consistency_ratio": 1.0,
            "stable_claims": 0,
            "unstable_claims": 0,
            "total_claims": 0,
            "unstable_details": [],
            "verdict": "CONSISTENT",
            "runs_completed": 1,
            "error": "Sentence-transformers model unavailable",
        }

    outputs = [primary_output]

    for i in range(runs - 1):
        try:
            if gated_invoke_fn:
                kwargs = dict(gated_invoke_kwargs or {})
                result = gated_invoke_fn(chain, chain_input, **kwargs)
                if hasattr(result, "success") and not result.success:
                    continue
                text = result.content if hasattr(result, "content") else str(result)
            else:
                raw = chain.invoke(chain_input)
                text = raw.content if hasattr(raw, "content") else str(raw)
            outputs.append(text)
        except Exception as exc:
            log.warning("Self-consistency run %d failed: %s", i + 2, exc)

    if len(outputs) < 2:
        return {
            "consistency_ratio": 1.0,
            "stable_claims": 0,
            "unstable_claims": 0,
            "total_claims": 0,
            "unstable_details": [],
            "verdict": "CONSISTENT",
            "runs_completed": len(outputs),
            "error": "Not enough runs completed",
        }

    primary_claims = _extract_claims(primary_output)
    if not primary_claims:
        return {
            "consistency_ratio": 1.0,
            "stable_claims": 0,
            "unstable_claims": 0,
            "total_claims": 0,
            "unstable_details": [],
            "verdict": "CONSISTENT",
            "runs_completed": len(outputs),
        }

    import numpy as np

    primary_embeddings = model.encode(primary_claims)

    other_texts = outputs[1:]
    other_claims_list = [_extract_claims(t) for t in other_texts]
    other_embeddings_list = [
        model.encode(claims) if claims else np.array([])
        for claims in other_claims_list
    ]

    similarity_threshold = 0.65
    stable_claims = []
    unstable_claims = []

    for idx, claim in enumerate(primary_claims):
        claim_embedding = primary_embeddings[idx].reshape(1, -1)
        appearances = 1

        for other_embeddings in other_embeddings_list:
            if len(other_embeddings) == 0:
                continue
            similarities = np.dot(other_embeddings, claim_embedding.T).flatten()
            if np.max(similarities) >= similarity_threshold:
                appearances += 1

        if appearances >= len(outputs) * 0.66:
            stable_claims.append(claim)
        else:
            unstable_claims.append({
                "claim": claim,
                "appearances": appearances,
                "total_runs": len(outputs),
            })

    total = len(primary_claims)
    stable_count = len(stable_claims)
    unstable_count = len(unstable_claims)
    ratio = stable_count / total if total > 0 else 1.0

    if ratio >= 0.8:
        verdict = "CONSISTENT"
    elif ratio >= 0.5:
        verdict = "MOSTLY_CONSISTENT"
    else:
        verdict = "INCONSISTENT"

    log.info(
        "Self-consistency: %s (%.0f%% stable, %d/%d claims, %d runs)",
        verdict, ratio * 100, stable_count, total, len(outputs),
    )

    return {
        "consistency_ratio": round(ratio, 2),
        "stable_claims": stable_count,
        "unstable_claims": unstable_count,
        "total_claims": total,
        "unstable_details": unstable_claims[:15],
        "verdict": verdict,
        "runs_completed": len(outputs),
    }
