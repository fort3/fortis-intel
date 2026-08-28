"""GeoCLIP image geolocation for Fortis Intelligence Hub.

Uses the GeoCLIP model (MIT license) to predict GPS coordinates directly
from images. Returns ranked location predictions with probabilities.

GeoCLIP encodes images and GPS coordinates into a shared embedding space
using contrastive learning, then retrieves the closest GPS points from
a built-in gallery. No API calls needed — runs entirely locally.

Install: pip install geoclip
"""

import io
import logging
import os
import threading
from typing import Any

log = logging.getLogger(__name__)

GEOCLIP_ENABLED = os.getenv("GEOCLIP_ENABLED", "true").lower() in ("1", "true", "yes")
GEOCLIP_TOP_K = int(os.getenv("GEOCLIP_TOP_K", "5"))
GEOCLIP_MIN_PROB = float(os.getenv("GEOCLIP_MIN_PROB", "0.01"))

_model = None
_model_lock = threading.Lock()
_available = True


def _get_model():
    """Lazy-load the GeoCLIP model singleton."""
    global _model, _available
    if _model is not None:
        return _model
    if not _available:
        return None

    with _model_lock:
        if _model is not None:
            return _model
        if not _available:
            return None

        try:
            from geoclip import GeoCLIP
            log.info("Loading GeoCLIP model (~1.5 GB on first download)")
            _model = GeoCLIP()
            log.info("GeoCLIP model loaded successfully")
            return _model
        except ImportError:
            log.info("geoclip not installed — GeoCLIP geolocation disabled (pip install geoclip)")
            _available = False
            return None
        except Exception as exc:
            log.warning("GeoCLIP model failed to load: %s", exc)
            _available = False
            return None


def predict_location(
    image_bytes: bytes,
    top_k: int | None = None,
    filename: str | None = None,
) -> dict[str, Any]:
    """Predict GPS coordinates from an image using GeoCLIP.

    Returns a dict with ``predictions`` (list of lat/lon/probability),
    ``geo_points`` (ready for the map pipeline), and metadata.
    """
    if not GEOCLIP_ENABLED:
        return {"enabled": False, "predictions": [], "geo_points": []}

    model = _get_model()
    if model is None:
        return {"enabled": False, "available": False, "predictions": [], "geo_points": []}

    top_k = top_k or GEOCLIP_TOP_K

    try:
        import tempfile
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes))
        if img.mode != "RGB":
            img = img.convert("RGB")

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            img.save(tmp, format="JPEG", quality=90)
            tmp_path = tmp.name

        try:
            top_pred_gps, top_pred_prob = model.predict(tmp_path, top_k=top_k)
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        predictions = []
        geo_points = []

        for i in range(len(top_pred_gps)):
            lat = float(top_pred_gps[i][0])
            lon = float(top_pred_gps[i][1])
            prob = float(top_pred_prob[i])

            predictions.append({
                "lat": lat,
                "lon": lon,
                "probability": round(prob, 4),
                "rank": i + 1,
            })

            if prob >= GEOCLIP_MIN_PROB:
                confidence = _prob_to_confidence(prob, i)
                geo_points.append({
                    "lat": lat,
                    "lon": lon,
                    "source": "geoclip",
                    "confidence": round(confidence, 2),
                    "label": f"GeoCLIP #{i+1} (p={prob:.2%})",
                    "method": "geoclip_embedding",
                    "geoclip_probability": prob,
                    "geoclip_rank": i + 1,
                })

        log.info(
            "GeoCLIP prediction%s: top=(%0.4f, %0.4f) p=%0.3f, %d points above threshold",
            f" for {filename}" if filename else "",
            predictions[0]["lat"] if predictions else 0,
            predictions[0]["lon"] if predictions else 0,
            predictions[0]["probability"] if predictions else 0,
            len(geo_points),
        )

        return {
            "enabled": True,
            "available": True,
            "predictions": predictions,
            "geo_points": geo_points,
        }

    except Exception as exc:
        log.warning("GeoCLIP prediction failed: %s", exc)
        return {"enabled": True, "available": True, "predictions": [], "geo_points": [], "error": str(exc)}


def _prob_to_confidence(prob: float, rank: int) -> float:
    """Convert GeoCLIP probability + rank to a pipeline confidence score.

    GeoCLIP probabilities are relative to the gallery, not absolute.
    A top-1 prediction with p=0.15 is quite strong; p=0.02 is weak.
    """
    if rank == 0:
        if prob >= 0.20:
            return min(0.80, 0.50 + prob)
        elif prob >= 0.10:
            return 0.45 + prob * 1.5
        elif prob >= 0.05:
            return 0.35 + prob * 2.0
        else:
            return max(0.20, prob * 5.0)
    elif rank == 1:
        return max(0.15, min(0.55, prob * 4.0))
    else:
        return max(0.10, min(0.40, prob * 3.0))


def reverse_geocode_predictions(predictions: list[dict]) -> list[dict]:
    """Add human-readable place names to GeoCLIP predictions via GeoClient."""
    if not predictions:
        return predictions

    try:
        from app.geo_client import GeoClient
        geo = GeoClient()
    except Exception:
        return predictions

    for pred in predictions[:3]:
        try:
            from geopy.geocoders import Nominatim
            geolocator = Nominatim(user_agent="fortis-intelligence-hub")
            location = geolocator.reverse(
                f"{pred['lat']}, {pred['lon']}",
                language="en",
                timeout=5,
            )
            if location and location.address:
                pred["address"] = location.address
                parts = location.address.split(", ")
                pred["place_name"] = parts[0] if parts else ""
                pred["country"] = parts[-1] if len(parts) > 1 else ""
        except Exception:
            pass

    return predictions
