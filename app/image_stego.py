"""Steganography detection module for Fortis Intelligence Hub.

Three complementary steganalysis methods -- LSB chi-square, RS analysis,
and Sample Pairs -- estimate whether an image carries a hidden payload.
Uses NumPy for array ops and Pillow for image decoding.
"""

import base64, io, logging, math, os
from typing import Any, Dict

import numpy as np
from PIL import Image

log = logging.getLogger(__name__)

IMAGE_STEGO_ENABLED = os.getenv(
    "IMAGE_STEGO_ENABLED", "true"
).lower() in ("1", "true", "yes")

_CHI_P_THRESHOLD = 0.05
_RS_EMBED_THRESHOLD = 0.05
_SP_EMBED_THRESHOLD = 0.05


def _chi_square_p(observed: np.ndarray, expected: np.ndarray) -> float:
    """Approximate chi-square p-value via Wilson-Hilferty (no scipy)."""
    mask = expected > 0
    chi2 = float(np.sum((observed[mask] - expected[mask]) ** 2 / expected[mask]))
    df = int(mask.sum()) - 1
    if df <= 0:
        return 1.0
    # Wilson-Hilferty approximation: Z ~ N(0,1)
    z = ((chi2 / df) ** (1 / 3) - (1 - 2 / (9 * df))) / math.sqrt(2 / (9 * df))
    # Survival function of standard normal via erfc
    p = 0.5 * math.erfc(z / math.sqrt(2))
    return max(0.0, min(1.0, p))

def _lsb_plane_image_b64(channel: np.ndarray) -> str:
    """Return a base64-encoded PNG of the LSB plane."""
    plane = ((channel & 1) * 255).astype(np.uint8)
    img = Image.fromarray(plane, mode="L")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")

def _lsb_analysis(pixels: np.ndarray) -> Dict[str, Any]:
    """Analyse the LSB plane of each colour channel with chi-square test."""
    results: Dict[str, Any] = {"channels": {}}
    suspicious = False

    for idx, name in enumerate(("R", "G", "B")):
        ch = pixels[:, :, idx]
        ratio = float(np.mean(ch & 1))
        flat = ch.flatten()
        pairs = flat >> 1
        bins = int(pairs.max()) + 1
        observed = np.bincount(flat, minlength=bins * 2).astype(float)
        expected = np.zeros_like(observed)  # each pair (2k,2k+1) splits evenly
        for k in range(bins):
            total = observed[2 * k] + observed[2 * k + 1] if 2 * k + 1 < len(observed) else observed[2 * k]
            expected[2 * k] = total / 2
            if 2 * k + 1 < len(expected):
                expected[2 * k + 1] = total / 2

        p_val = _chi_square_p(observed, expected)
        if p_val < _CHI_P_THRESHOLD:
            suspicious = True

        results["channels"][name] = {
            "lsb_ratio": round(ratio, 6),
            "chi_square_p_value": round(p_val, 6),
        }

    results["lsb_visual_b64"] = _lsb_plane_image_b64(pixels[:, :, 1])
    results["suspicious"] = suspicious
    return results

def _rs_analysis(pixels: np.ndarray, group_size: int = 4) -> Dict[str, Any]:
    """Regular-Singular steganalysis on the red channel."""
    ch = pixels[:, :, 0].astype(np.int16).flatten()
    n = (len(ch) // group_size) * group_size
    ch = ch[:n]
    groups = ch.reshape(-1, group_size)

    def _discrimination(g: np.ndarray) -> np.ndarray:
        return np.sum(np.abs(np.diff(g, axis=1)), axis=1).astype(float)

    def _flip_positive(g: np.ndarray) -> np.ndarray:
        flipped = g.copy()
        flipped[:, ::2] = flipped[:, ::2] ^ 1  # flip LSB of even-indexed
        return flipped

    def _flip_negative(g: np.ndarray) -> np.ndarray:
        flipped = g.copy()
        flipped[:, 1::2] = flipped[:, 1::2] ^ 1  # flip LSB of odd-indexed
        return flipped

    d_orig = _discrimination(groups)
    d_pos = _discrimination(_flip_positive(groups))
    d_neg = _discrimination(_flip_negative(groups))

    total = float(len(groups))
    r_p = float(np.sum(d_pos > d_orig)) / total
    s_p = float(np.sum(d_pos < d_orig)) / total
    r_n = float(np.sum(d_neg > d_orig)) / total
    s_n = float(np.sum(d_neg < d_orig)) / total

    d0, d1 = r_p - s_p, r_n - s_n
    denom = d0 + d1
    if abs(denom) < 1e-12:
        est = 0.0
    else:
        est = abs(d0 - d1) / denom
    est = max(0.0, min(1.0, est))

    return {
        "r_positive": round(r_p, 6),
        "s_positive": round(s_p, 6),
        "r_negative": round(r_n, 6),
        "s_negative": round(s_n, 6),
        "rs_ratio": round(r_p / s_p if s_p > 0 else 0.0, 4),
        "estimated_embedding_rate": round(est, 6),
        "suspicious": bool(est > _RS_EMBED_THRESHOLD),
    }

def _sample_pairs_analysis(pixels: np.ndarray) -> Dict[str, Any]:
    """Simplified Sample-Pairs steganalysis on the blue channel."""
    ch = pixels[:, :, 2].astype(np.int16).flatten()
    if len(ch) < 4:
        return {"sp_estimate": 0.0, "suspicious": False}

    n = (len(ch) // 2) * 2
    u = ch[:n:2]
    v = ch[1:n:2]

    same_bucket = (u >> 1) == (v >> 1)
    close = np.abs(u - v) <= 1
    w = close & same_bucket
    y = close & ~same_bucket

    w_count, y_count = float(np.sum(w)), float(np.sum(y))
    if (w_count + y_count) < 1:
        est = 0.0
    else:
        est = abs(w_count - y_count) / (w_count + y_count)
    est = max(0.0, min(1.0, est))

    return {
        "sp_estimate": round(est, 6),
        "suspicious": bool(est > _SP_EMBED_THRESHOLD),
    }

def detect_steganography(
    image_bytes: bytes,
    filename: str | None = None,
) -> Dict[str, Any]:
    """Run all steganalysis methods on *image_bytes* and return a verdict.

    Returns a dict with keys: lsb_analysis, rs_analysis, sample_pairs,
    overall_verdict, confidence, estimated_payload_percent.
    """
    if not IMAGE_STEGO_ENABLED:
        return {
            "lsb_analysis": {},
            "rs_analysis": {},
            "sample_pairs": {},
            "overall_verdict": "DISABLED",
            "confidence": 0.0,
            "estimated_payload_percent": 0.0,
        }

    tag = filename or "unknown"
    log.info("Running steganography detection on %s (%d bytes)", tag, len(image_bytes))

    img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    pixels = np.array(img)

    lsb = _lsb_analysis(pixels)
    rs = _rs_analysis(pixels)
    sp = _sample_pairs_analysis(pixels)

    # --- Verdict logic ---
    flags = sum([lsb["suspicious"], rs["suspicious"], sp["suspicious"]])

    if flags >= 2:
        verdict = "STEGANOGRAPHY_LIKELY"
    elif flags == 1:
        verdict = "STEGANOGRAPHY_POSSIBLE"
    else:
        verdict = "NO_STEGANOGRAPHY_DETECTED"

    # Confidence: weighted combination of method signals
    embed_rates = [
        rs["estimated_embedding_rate"],
        sp["sp_estimate"],
    ]
    # Add LSB deviation from 0.5 as a signal (max across channels)
    lsb_dev = max(
        abs(ch["lsb_ratio"] - 0.5) for ch in lsb["channels"].values()
    )
    embed_rates.append(min(lsb_dev * 4, 1.0))  # scale deviation

    avg_rate = sum(embed_rates) / len(embed_rates)
    confidence = min(1.0, avg_rate * 2) if flags else avg_rate * 0.5
    confidence = round(max(0.0, min(1.0, confidence)), 4)

    payload_pct = round(rs["estimated_embedding_rate"] * 100, 2)

    log.info("Stego result for %s: %s (confidence=%.2f)", tag, verdict, confidence)

    return {
        "lsb_analysis": lsb,
        "rs_analysis": rs,
        "sample_pairs": sp,
        "overall_verdict": verdict,
        "confidence": confidence,
        "estimated_payload_percent": payload_pct,
    }
