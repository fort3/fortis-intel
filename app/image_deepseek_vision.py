"""DeepSeek Vision API integration for Fortis Intelligence Hub.

Uses deepseek-v4-flash-vision-exp to provide contextual image understanding
beyond what CLIP zero-shot classification offers. The model sees the actual
image and returns free-form descriptions, object identification, text
extraction, and OSINT-relevant observations.

Uses the OpenAI-compatible API — same base URL and API key as the text LLM.
"""

import base64
import io
import logging
import os
from typing import Any

log = logging.getLogger(__name__)

DEEPSEEK_VISION_ENABLED = os.getenv("DEEPSEEK_VISION_ENABLED", "true").lower() in (
    "1", "true", "yes",
)
DEEPSEEK_VISION_MODEL = os.getenv(
    "DEEPSEEK_VISION_MODEL", "deepseek-v4-flash-vision-exp",
)
_BASE_URL = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    try:
        from openai import OpenAI

        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            print("[DEEPSEEK VISION] DEEPSEEK_API_KEY not set — Vision disabled")
            log.warning("DEEPSEEK_API_KEY not set — DeepSeek Vision disabled")
            return None
        _client = OpenAI(api_key=api_key, base_url=_BASE_URL)
        return _client
    except Exception as exc:
        log.warning("Failed to initialise DeepSeek Vision client: %s", exc)
        return None


def _encode_image(image_bytes: bytes) -> tuple[str, str]:
    """Return (base64_data, media_type) for image bytes."""
    from PIL import Image

    img = Image.open(io.BytesIO(image_bytes))
    fmt = (img.format or "JPEG").upper()
    media_map = {
        "JPEG": "image/jpeg",
        "JPG": "image/jpeg",
        "PNG": "image/png",
        "GIF": "image/gif",
        "WEBP": "image/webp",
        "TIFF": "image/tiff",
        "BMP": "image/bmp",
    }
    media_type = media_map.get(fmt, "image/jpeg")

    if fmt not in ("JPEG", "PNG", "GIF", "WEBP"):
        buf = io.BytesIO()
        img.convert("RGB").save(buf, format="JPEG", quality=90)
        image_bytes = buf.getvalue()
        media_type = "image/jpeg"

    b64 = base64.b64encode(image_bytes).decode("utf-8")
    return b64, media_type


def _call_vision(
    image_bytes: bytes,
    prompt: str,
    detail: str = "auto",
    max_tokens: int = 1024,
) -> str | None:
    """Send a single image + text prompt to DeepSeek Vision. Returns the response text.

    Raises on API errors so callers can surface the message.
    Returns ``None`` only when the client cannot be initialised.
    """
    client = _get_client()
    if client is None:
        return None

    b64, media_type = _encode_image(image_bytes)
    data_url = f"data:{media_type};base64,{b64}"

    response = client.chat.completions.create(
        model=DEEPSEEK_VISION_MODEL,
        messages=[{
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {
                    "type": "image_url",
                    "image_url": {"url": data_url, "detail": detail},
                },
            ],
        }],
        max_tokens=max_tokens,
        temperature=0.2,
    )
    return response.choices[0].message.content


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_OSINT_PROMPT = """You are an OSINT image analyst for an intelligence platform.
Analyse this image and provide a structured assessment:

1. **Scene Description**: What is depicted — location type, environment, time of day, weather if visible.
2. **Objects & Entities**: Vehicles, weapons, equipment, infrastructure, people (count, clothing, uniforms, insignia — no facial recognition).
3. **Text & Signage**: Any visible text, signs, banners, watermarks, license plates, labels — transcribe exactly.
4. **Location Clues**: Architectural style, vegetation, road markings, utility poles, language on signs, terrain — anything that could narrow geographic location.
5. **Temporal Clues**: Shadows, lighting, seasonal indicators, visible dates or timestamps.
6. **OSINT Relevance**: Assessment of intelligence value — conflict indicators, civilian impact, infrastructure status, military activity.

Be factual and precise. Do not speculate beyond what is visible. If something is unclear, say so."""

_FORENSICS_PROMPT = """You are a digital forensics analyst. This image shows an Error Level Analysis (ELA) heatmap overlaid on the original image. Bright areas indicate regions with different compression levels, which may suggest manipulation.

Analyse the ELA result:
1. Which regions show high error levels (bright areas)?
2. Do these regions correspond to objects that may have been inserted, removed, or altered?
3. Is the pattern consistent with normal JPEG artefacts or does it suggest deliberate editing?
4. What is your overall assessment of the image's authenticity?

Be precise about spatial locations in the image."""

_KEYFRAME_PROMPT = """You are a geolocation analyst examining a video keyframe.
Identify any clues that could help determine where this video was filmed:

1. **Visible text**: Signs, banners, store names, license plates — transcribe exactly, note the language.
2. **Architecture**: Building styles, construction materials, roof types, road infrastructure.
3. **Vegetation & terrain**: Plant species, landscape type, season indicators.
4. **Vehicles & infrastructure**: Car makes/models common to specific regions, road markings, power lines, traffic signs.
5. **Cultural markers**: Clothing styles, flags, scripts, commercial brands.
6. **Other clues**: Sun position, shadow angles, weather conditions.

Report only what you can see. If uncertain, express your confidence level."""


def describe_image(
    image_bytes: bytes,
    filename: str | None = None,
    context: str | None = None,
) -> dict[str, Any]:
    """Full OSINT-oriented image description via DeepSeek Vision.

    Returns a dict with ``description``, ``model``, and ``enabled`` keys.
    """
    if not DEEPSEEK_VISION_ENABLED:
        return {
            "description": None,
            "model": DEEPSEEK_VISION_MODEL,
            "enabled": False,
        }

    log.info(
        "Analysing image%s with DeepSeek Vision",
        f" ({filename})" if filename else "",
    )

    prompt = _OSINT_PROMPT
    if context:
        prompt += f"\n\nAdditional investigation context: {context}"

    error = None
    try:
        description = _call_vision(image_bytes, prompt, detail="auto", max_tokens=4096)
    except Exception as exc:
        log.error("DeepSeek Vision describe_image failed: %s", exc)
        description = None
        error = f"{type(exc).__name__}: {exc}"

    result = {
        "description": description,
        "model": DEEPSEEK_VISION_MODEL,
        "enabled": True,
    }
    if error:
        result["error"] = error
    return result


def interpret_forensics(
    ela_image_bytes: bytes,
    filename: str | None = None,
) -> dict[str, Any]:
    """Interpret an ELA forensics visualization with DeepSeek Vision."""
    if not DEEPSEEK_VISION_ENABLED:
        return {"interpretation": None, "model": DEEPSEEK_VISION_MODEL, "enabled": False}

    log.info(
        "Interpreting ELA%s with DeepSeek Vision",
        f" for {filename}" if filename else "",
    )

    try:
        interpretation = _call_vision(
            ela_image_bytes, _FORENSICS_PROMPT, detail="high", max_tokens=4096,
        )
    except Exception as exc:
        log.error("DeepSeek Vision interpret_forensics failed: %s", exc)
        interpretation = None
    return {
        "interpretation": interpretation,
        "model": DEEPSEEK_VISION_MODEL,
        "enabled": True,
    }


def analyse_keyframe(
    frame_bytes: bytes,
    video_context: str | None = None,
) -> dict[str, Any]:
    """Analyse a video keyframe for geolocation clues."""
    if not DEEPSEEK_VISION_ENABLED:
        return {"analysis": None, "model": DEEPSEEK_VISION_MODEL, "enabled": False}

    prompt = _KEYFRAME_PROMPT
    if video_context:
        prompt += f"\n\nVideo source context: {video_context}"

    try:
        analysis = _call_vision(frame_bytes, prompt, detail="auto", max_tokens=4096)
    except Exception as exc:
        log.error("DeepSeek Vision analyse_keyframe failed: %s", exc)
        analysis = None
    return {
        "analysis": analysis,
        "model": DEEPSEEK_VISION_MODEL,
        "enabled": True,
    }
