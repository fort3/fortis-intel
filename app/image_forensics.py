"""Image forensics module for Fortis Intelligence Hub.

ELA, metadata-stripping detection, and block-hash clone detection using
only Pillow and the standard library (no numpy).
"""

import base64
import hashlib
import io
import logging
import math
import os
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image, ImageChops
from PIL.ExifTags import TAGS as EXIF_TAGS

log = logging.getLogger(__name__)

IMAGE_FORENSICS_ENABLED = os.getenv(
    "IMAGE_FORENSICS_ENABLED", "true"
).lower() in ("1", "true", "yes")

_ELA_QUALITY = 90
_ELA_SCALE = 15
_ELA_THRESHOLD = 40  # per-pixel brightness threshold for "suspicious"
_ELA_MEAN_LIKELY = 15
_ELA_MEAN_POSSIBLY = 8

_CLONE_BLOCK = 16
_CLONE_MIN_DISTANCE = 32  # min pixel distance to count as a "clone"

_EDITING_SOFTWARE_KEYWORDS = [
    "photoshop", "gimp", "lightroom", "affinity", "paint.net",
    "snapseed", "pixlr", "canva", "capture one", "darktable",
    "adobe", "corel", "picasa", "fotoforensics",
]


def _ela_analysis(img: Image.Image) -> Dict[str, Any]:
    """Re-save as JPEG and measure per-pixel error."""
    original = img.convert("RGB")

    buf = io.BytesIO()
    original.save(buf, format="JPEG", quality=_ELA_QUALITY)
    buf.seek(0)
    resaved = Image.open(buf).convert("RGB")

    diff = ImageChops.difference(original, resaved)

    # Scale for visibility
    ela_img = diff.point(lambda px: min(px * _ELA_SCALE, 255))

    # Compute statistics from the raw diff
    pixels = list(diff.getdata())  # list of (R, G, B)
    n = len(pixels)
    if n == 0:
        return {
            "mean_error": 0.0, "max_error": 0, "std_dev": 0.0,
            "suspicious_percentage": 0.0,
            "verdict": "NO_MANIPULATION_DETECTED", "ela_image_b64": "",
        }

    brightnesses = [(r + g + b) / 3.0 for r, g, b in pixels]
    mean_err = sum(brightnesses) / n
    max_err = max(brightnesses)
    variance = sum((b - mean_err) ** 2 for b in brightnesses) / n
    std_dev = math.sqrt(variance)
    suspicious_count = sum(1 for b in brightnesses if b > _ELA_THRESHOLD)
    suspicious_pct = (suspicious_count / n) * 100.0

    if mean_err > _ELA_MEAN_LIKELY:
        verdict = "LIKELY_MANIPULATED"
    elif mean_err > _ELA_MEAN_POSSIBLY:
        verdict = "POSSIBLY_MANIPULATED"
    else:
        verdict = "NO_MANIPULATION_DETECTED"

    # Encode ELA visualisation as base64 PNG
    ela_buf = io.BytesIO()
    ela_img.save(ela_buf, format="PNG")
    ela_b64 = base64.b64encode(ela_buf.getvalue()).decode("ascii")

    return {
        "mean_error": round(mean_err, 2),
        "max_error": round(max_err, 2),
        "std_dev": round(std_dev, 2),
        "suspicious_percentage": round(suspicious_pct, 2),
        "verdict": verdict,
        "ela_image_b64": ela_b64,
    }


def _metadata_analysis(
    img: Image.Image, filename: Optional[str] = None,
) -> Dict[str, Any]:
    """Check EXIF presence, editing software, and date consistency."""
    exif_present = False
    editing_software: Optional[str] = None
    date_mismatch = False
    stripped = False

    exif_data: Dict[str, Any] = {}
    raw_exif = img.getexif()
    if raw_exif:
        exif_present = True
        for tag_id, value in raw_exif.items():
            tag_name = EXIF_TAGS.get(tag_id, str(tag_id))
            try:
                exif_data[tag_name] = str(value)
            except Exception:
                exif_data[tag_name] = repr(value)

    # Detect editing software
    software_val = exif_data.get("Software", "") or ""
    processing_val = exif_data.get("ProcessingSoftware", "") or ""
    combined = (software_val + " " + processing_val).lower()
    for kw in _EDITING_SOFTWARE_KEYWORDS:
        if kw in combined:
            editing_software = software_val or processing_val
            break

    # Date mismatch between DateTimeOriginal and DateTimeDigitized / DateTime
    dt_original = exif_data.get("DateTimeOriginal")
    dt_digitized = exif_data.get("DateTimeDigitized")
    dt_modified = exif_data.get("DateTime")
    dates = [d for d in (dt_original, dt_digitized, dt_modified) if d]
    if len(set(dates)) > 1:
        date_mismatch = True

    # A JPEG with zero EXIF is suspicious (cameras always embed EXIF)
    fmt = (img.format or "").upper()
    if not filename:
        filename = ""
    is_jpeg = fmt in ("JPEG", "JPG") or filename.lower().endswith(
        (".jpg", ".jpeg")
    )
    if is_jpeg and not exif_present:
        stripped = True

    return {
        "exif_present": exif_present,
        "editing_software": editing_software,
        "date_mismatch": date_mismatch,
        "stripped": stripped,
    }


def _clone_detection(img: Image.Image) -> Dict[str, Any]:
    """Simplified copy-move forgery detection via block hashing."""
    grey = img.convert("L")
    w, h = grey.size

    if w < _CLONE_BLOCK * 2 or h < _CLONE_BLOCK * 2:
        return {"clone_regions_found": 0, "verdict": "NO_CLONING_DETECTED"}

    block_hashes: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
    pixels = list(grey.getdata())

    step = _CLONE_BLOCK  # non-overlapping blocks for speed
    for by in range(0, h - _CLONE_BLOCK + 1, step):
        for bx in range(0, w - _CLONE_BLOCK + 1, step):
            # Extract block bytes
            block_bytes = bytearray()
            for row in range(by, by + _CLONE_BLOCK):
                offset = row * w + bx
                for c in range(_CLONE_BLOCK):
                    block_bytes.append(pixels[offset + c])
            digest = hashlib.md5(bytes(block_bytes)).hexdigest()
            block_hashes[digest].append((bx, by))

    clone_count = 0
    for positions in block_hashes.values():
        if len(positions) < 2:
            continue
        # Check spatial distance between matching blocks
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                dx = abs(positions[i][0] - positions[j][0])
                dy = abs(positions[i][1] - positions[j][1])
                if math.hypot(dx, dy) >= _CLONE_MIN_DISTANCE:
                    clone_count += 1

    verdict = "CLONING_DETECTED" if clone_count > 0 else "NO_CLONING_DETECTED"
    return {"clone_regions_found": clone_count, "verdict": verdict}


def analyze_image_forensics(
    image_bytes: bytes, filename: Optional[str] = None,
) -> Dict[str, Any]:
    """Run all forensic analyses and return aggregated results."""
    if not IMAGE_FORENSICS_ENABLED:
        return {
            "ela": {}, "metadata": {}, "clone_detection": {},
            "overall_verdict": "DISABLED",
            "confidence": 0.0, "flags": ["Image forensics disabled"],
        }

    try:
        img = Image.open(io.BytesIO(image_bytes))
    except Exception as exc:
        log.warning("image_forensics: cannot open image: %s", exc)
        return {
            "ela": {}, "metadata": {}, "clone_detection": {},
            "overall_verdict": "ERROR",
            "confidence": 0.0, "flags": [f"Cannot open image: {exc}"],
        }

    ela = _ela_analysis(img)
    metadata = _metadata_analysis(img, filename)
    clones = _clone_detection(img)

    # ---- aggregate verdict & confidence ----
    flags: List[str] = []
    score = 0.0  # 0-1 confidence that the image has been manipulated

    # ELA contribution (up to 0.45)
    if ela["verdict"] == "LIKELY_MANIPULATED":
        score += 0.45
        flags.append("High ELA error indicates likely manipulation")
    elif ela["verdict"] == "POSSIBLY_MANIPULATED":
        score += 0.25
        flags.append("Moderate ELA error suggests possible manipulation")

    # Metadata contribution (up to 0.30)
    if metadata["stripped"]:
        score += 0.15
        flags.append("EXIF metadata stripped from JPEG")
    if metadata["editing_software"]:
        score += 0.10
        flags.append(f"Editing software detected: {metadata['editing_software']}")
    if metadata["date_mismatch"]:
        score += 0.05
        flags.append("EXIF date fields are inconsistent")

    # Clone contribution (up to 0.25)
    if clones["verdict"] == "CLONING_DETECTED":
        score += 0.25
        flags.append(
            f"Clone regions detected: {clones['clone_regions_found']} matches"
        )

    score = min(score, 1.0)

    if score >= 0.55:
        overall = "LIKELY_MANIPULATED"
    elif score >= 0.25:
        overall = "POSSIBLY_MANIPULATED"
    else:
        overall = "AUTHENTIC"

    return {
        "ela": ela,
        "metadata": metadata,
        "clone_detection": clones,
        "overall_verdict": overall,
        "confidence": round(score, 2),
        "flags": flags,
    }
