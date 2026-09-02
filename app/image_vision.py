"""Zero-shot image classification using CLIP for Fortis Intelligence Hub.

Uses sentence-transformers' CLIP model to perform zero-shot image
classification, landmark detection, and content safety checks on images
flowing through OSINT investigations.

Architecture: CLIP (clip-ViT-B-32) via sentence-transformers encodes both
images and text labels into a shared embedding space, enabling zero-shot
classification by cosine similarity without any task-specific training.

The model (~340 MB) is lazy-loaded on first use and cached globally.
"""

import io
import logging
import os
import threading
from typing import Any

log = logging.getLogger(__name__)

IMAGE_VISION_ENABLED = os.getenv("IMAGE_VISION_ENABLED", "true").lower() in (
    "1", "true", "yes",
)
CLIP_MODEL_NAME = os.getenv("CLIP_MODEL_NAME", "clip-ViT-B-32")

# ---------------------------------------------------------------------------
# Default OSINT category labels for zero-shot classification
# ---------------------------------------------------------------------------
OSINT_CATEGORIES = [
    "military vehicle", "military personnel", "weapon",
    "explosion or fire", "damaged building", "protest or demonstration",
    "surveillance equipment", "document or ID card", "map or satellite imagery",
    "civilian crowd", "refugee or displaced persons", "checkpoint or roadblock",
    "naval vessel", "aircraft", "infrastructure damage",
    "flag or insignia", "graffiti or street art", "natural landscape",
    "urban cityscape", "indoor scene", "portrait photo", "screenshot",
]

# ---------------------------------------------------------------------------
# Landmark / location labels for geo-hint detection
# ---------------------------------------------------------------------------
LANDMARK_LABELS = [
    # Major monuments & landmarks
    "Eiffel Tower in Paris", "Statue of Liberty in New York",
    "Big Ben in London", "Colosseum in Rome", "Taj Mahal in India",
    "Great Wall of China", "Sydney Opera House", "Christ the Redeemer in Rio",
    "Kremlin in Moscow", "Burj Khalifa in Dubai",
    "Brandenburg Gate in Berlin", "Acropolis in Athens",
    "Pyramids of Giza in Egypt", "Machu Picchu in Peru",
    "Hagia Sophia in Istanbul", "Tower Bridge in London",
    "Golden Gate Bridge in San Francisco", "White House in Washington DC",
    "Sagrada Familia in Barcelona", "St. Basil's Cathedral in Moscow",
    # Conflict-relevant locations
    "Aleppo old city in Syria", "Mariupol city in Ukraine",
    "Kabul city in Afghanistan", "Baghdad city in Iraq",
    "Gaza city in Palestine", "Kharkiv city in Ukraine",
    "Mosul city in Iraq", "Tripoli city in Libya",
    "Sana'a city in Yemen", "Mogadishu city in Somalia",
    # Major cities
    "Tokyo city skyline", "Beijing city skyline",
    "Lagos city in Nigeria", "Mumbai city in India",
    "Mexico City skyline", "Jakarta city in Indonesia",
    "Nairobi city in Kenya", "Kyiv city in Ukraine",
    "Tehran city in Iran", "Ankara city in Turkey",
    # Geographic features
    "Sahara desert landscape", "Amazon rainforest",
    "Arctic or Antarctic ice", "Mediterranean coastline",
    "Himalayan mountains", "African savanna",
    "Middle Eastern desert", "Southeast Asian jungle",
    "European countryside", "Central Asian steppe",
]

# ---------------------------------------------------------------------------
# Safety labels for content moderation
# ---------------------------------------------------------------------------
SAFETY_LABELS = [
    "graphic violence or gore",
    "explicit sexual content",
    "disturbing or distressing imagery",
    "safe and appropriate content",
]

_SAFETY_THRESHOLD = 0.25
_LANDMARK_THRESHOLD = 0.24
_TOP_K = 5


# ---------------------------------------------------------------------------
# Thread-safe CLIP model wrapper
# ---------------------------------------------------------------------------
class _CLIPModel:
    """Lazy-loaded, thread-safe singleton wrapper around a CLIP model."""

    def __init__(self, model_name: str | None = None):
        self._model_name = model_name or CLIP_MODEL_NAME
        self._model = None
        self._lock = threading.Lock()
        self._available = True

    # -- loading -----------------------------------------------------------

    def _load(self):
        if self._model is not None or not self._available:
            return
        with self._lock:
            if self._model is not None or not self._available:
                return
            retries = 2
            for attempt in range(retries + 1):
                try:
                    from sentence_transformers import SentenceTransformer

                    log.info(
                        "Loading CLIP model: %s (~340 MB on first download) [attempt %d/%d]",
                        self._model_name, attempt + 1, retries + 1,
                    )
                    self._model = SentenceTransformer(self._model_name)
                    log.info("CLIP model ready: %s", self._model_name)
                    return
                except Exception as exc:
                    if attempt < retries:
                        log.warning("CLIP model load attempt %d failed, retrying: %s", attempt + 1, exc)
                        import time
                        time.sleep(2)
                    else:
                        log.warning(
                            "CLIP model unavailable after %d attempts: %s. "
                            "Ensure 'transformers' and 'torch' are installed: "
                            "pip install transformers torch sentence-transformers",
                            retries + 1, exc,
                        )
                        self._available = False

    # -- encoding ----------------------------------------------------------

    def encode_image(self, image_bytes: bytes):
        """Return a normalised embedding vector for *image_bytes*."""
        self._load()
        if self._model is None:
            return None
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        return self._model.encode(img, normalize_embeddings=True)

    def encode_texts(self, texts: list[str]):
        """Return normalised embedding vectors for a list of text labels."""
        self._load()
        if self._model is None:
            return None
        return self._model.encode(texts, normalize_embeddings=True)

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def name(self) -> str:
        return self._model_name


# Module-level singleton
_clip: _CLIPModel | None = None
_clip_lock = threading.Lock()


def _get_clip() -> _CLIPModel:
    global _clip
    if _clip is None:
        with _clip_lock:
            if _clip is None:
                _clip = _CLIPModel()
    return _clip


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_image(
    image_bytes: bytes,
    categories: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Zero-shot classify *image_bytes* against text category labels.

    Returns the top-5 categories sorted by descending confidence.
    """
    import numpy as np

    clip = _get_clip()
    labels = categories or OSINT_CATEGORIES

    img_emb = clip.encode_image(image_bytes)
    if img_emb is None:
        return []

    txt_emb = clip.encode_texts(labels)
    if txt_emb is None:
        return []

    sims = np.dot(img_emb, txt_emb.T)
    top_idx = sims.argsort()[-_TOP_K:][::-1]

    return [
        {"category": labels[i], "confidence": round(float(sims[i]), 4)}
        for i in top_idx
    ]


def detect_landmarks(image_bytes: bytes) -> list[dict[str, Any]]:
    """Compare *image_bytes* against known landmarks / locations.

    Returns landmarks whose confidence exceeds the detection threshold.
    """
    import numpy as np

    clip = _get_clip()

    img_emb = clip.encode_image(image_bytes)
    if img_emb is None:
        return []

    txt_emb = clip.encode_texts(LANDMARK_LABELS)
    if txt_emb is None:
        return []

    sims = np.dot(img_emb, txt_emb.T)
    matches = [
        {"name": LANDMARK_LABELS[i], "confidence": round(float(sims[i]), 4)}
        for i in sims.argsort()[::-1]
        if sims[i] >= _LANDMARK_THRESHOLD
    ]
    return matches[:_TOP_K]


def check_content_safety(image_bytes: bytes) -> dict[str, Any]:
    """Score *image_bytes* against safety categories.

    Returns the dominant safety classification and its score.
    """
    import numpy as np

    clip = _get_clip()

    img_emb = clip.encode_image(image_bytes)
    if img_emb is None:
        return {"classification": "unknown", "score": 0.0}

    txt_emb = clip.encode_texts(SAFETY_LABELS)
    if txt_emb is None:
        return {"classification": "unknown", "score": 0.0}

    sims = np.dot(img_emb, txt_emb.T)
    best_idx = int(np.argmax(sims))
    best_score = float(sims[best_idx])

    # If the best match is the safe-content label, report safe
    if best_idx == len(SAFETY_LABELS) - 1:
        return {"classification": "safe", "score": round(best_score, 4)}

    # Unsafe category dominates only if it clears the threshold
    if best_score >= _SAFETY_THRESHOLD:
        return {
            "classification": SAFETY_LABELS[best_idx],
            "score": round(best_score, 4),
        }

    return {"classification": "safe", "score": round(float(sims[-1]), 4)}


def analyze_image(
    image_bytes: bytes,
    filename: str | None = None,
    custom_categories: list[str] | None = None,
) -> dict[str, Any]:
    """Run full CLIP analysis: classification + landmarks + safety.

    Returns a dict with keys ``classifications``, ``landmarks``,
    ``safety``, and ``model``.
    """
    if not IMAGE_VISION_ENABLED:
        return {
            "classifications": [],
            "landmarks": [],
            "safety": {"classification": "unknown", "score": 0.0},
            "model": _get_clip().name,
            "enabled": False,
        }

    log.info(
        "Analyzing image%s with CLIP",
        f" ({filename})" if filename else "",
    )

    classifications = classify_image(image_bytes, categories=custom_categories)
    landmarks = detect_landmarks(image_bytes)
    safety = check_content_safety(image_bytes)

    return {
        "classifications": classifications,
        "landmarks": landmarks,
        "safety": safety,
        "model": _get_clip().name,
    }
