"""Bellingcat-inspired civilian harm classifier for Fortis Intelligence Hub.

Replicates the core methodology from Bellingcat's June 2026 research:
semantic similarity scoring (their #1 predictive feature) combined with
multilingual conflict keyword density to produce a 0-1 harm likelihood
score for any text content flowing through investigations.

Architecture: sentence-transformers (multilingual) + keyword scoring
→ composite harm score → classification (CRITICAL/HIGH/MODERATE/LOW/NONE).

Reference: https://www.bellingcat.com/resources/2026/06/25/
how-to-use-ai-to-help-find-civilian-harm/
"""

import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

CIVILIAN_HARM_ENABLED = os.getenv("CIVILIAN_HARM_ENABLED", "true").lower() in ("1", "true", "yes")
HARM_MODEL_NAME = os.getenv(
    "HARM_MODEL_NAME", "paraphrase-multilingual-MiniLM-L12-v2"
)

HARM_CONCEPTS = [
    "civilian casualties and deaths from armed conflict",
    "hospital or medical facility attacked or destroyed",
    "school or educational facility damaged in conflict",
    "residential buildings destroyed by shelling or airstrikes",
    "forced displacement of civilian population",
    "injuries to civilians including women and children",
    "critical infrastructure destruction affecting civilian life",
    "humanitarian crisis and civilian suffering in war zone",
    "war crimes or violations of international humanitarian law",
    "deliberate targeting of civilian areas and populated zones",
    "mass graves or extrajudicial killings of civilians",
    "siege and starvation of civilian population",
    "sexual violence as weapon of war",
    "child soldiers or recruitment of minors",
    "destruction of cultural heritage sites",
]

CONFLICT_KEYWORDS = {
    "en": [
        "casualties", "killed", "wounded", "injured", "dead", "shelling",
        "airstrike", "bombing", "explosion", "missile", "rocket", "artillery",
        "attack", "destruction", "destroyed", "damage", "fire",
        "evacuation", "displaced", "refugees", "humanitarian", "crisis",
        "hospital", "school", "residential", "civilian", "children",
        "infrastructure", "rescue", "emergency", "victims", "debris",
        "crater", "ruins", "collapse", "trapped", "survivor",
        "massacre", "genocide", "atrocity", "torture", "execution",
        "siege", "blockade", "famine", "starvation", "cluster munition",
        "landmine", "chemical weapon", "white phosphorus",
    ],
    "uk": [
        "загиблі", "поранені", "обстріл", "ракета", "вибух", "бомбардування",
        "руйнування", "евакуація", "біженці", "лікарня", "школа", "житловий",
        "цивільні", "діти", "інфраструктура", "рятувальники", "жертви",
        "уламки", "воронка", "завали", "постраждалі", "удар", "масове вбивство",
        "геноцид", "тортури", "страта", "облога", "голод",
    ],
    "ru": [
        "погибшие", "раненые", "обстрел", "ракета", "взрыв", "бомбардировка",
        "разрушение", "эвакуация", "беженцы", "больница", "школа", "жилой",
        "гражданские", "дети", "инфраструктура", "спасатели", "жертвы",
        "обломки", "воронка", "завалы", "пострадавшие", "удар", "массовое убийство",
        "геноцид", "пытки", "казнь", "осада", "голод",
    ],
    "ar": [
        "ضحايا", "قتلى", "جرحى", "قصف", "صاروخ", "انفجار", "تفجير",
        "دمار", "إجلاء", "لاجئين", "مستشفى", "مدرسة", "سكني",
        "مدنيين", "أطفال", "بنية تحتية", "إنقاذ", "مجزرة",
        "إبادة", "تعذيب", "إعدام", "حصار", "مجاعة",
    ],
    "fr": [
        "victimes", "tués", "blessés", "bombardement", "missile",
        "explosion", "destruction", "évacuation", "réfugiés",
        "hôpital", "école", "civil", "enfants", "infrastructure",
        "massacre", "génocide", "torture", "siège", "famine",
    ],
}

_ALL_KEYWORDS: set[str] = set()
for _kws in CONFLICT_KEYWORDS.values():
    _ALL_KEYWORDS.update(w.lower() for w in _kws)


@dataclass
class HarmScore:
    """Civilian harm classification result for a text item."""
    score: float = 0.0
    semantic_similarity: float = 0.0
    keyword_density: float = 0.0
    keyword_count: int = 0
    classification: str = "NONE"
    matched_concepts: list[str] = field(default_factory=list)
    matched_keywords: list[str] = field(default_factory=list)
    language: str = ""


def _classify(score: float) -> str:
    if score >= 0.75:
        return "CRITICAL"
    if score >= 0.55:
        return "HIGH"
    if score >= 0.35:
        return "MODERATE"
    if score >= 0.15:
        return "LOW"
    return "NONE"


class CivilianHarmClassifier:
    """Scores text content for civilian harm likelihood using semantic
    similarity (Bellingcat's strongest predictive feature) combined with
    multilingual keyword density."""

    def __init__(self, model_name: str | None = None):
        self._model_name = model_name or HARM_MODEL_NAME
        self._model = None
        self._concept_embeddings = None
        self._lock = threading.Lock()
        self._available = True

    def _load_model(self):
        if self._model is not None or not self._available:
            return
        with self._lock:
            if self._model is not None or not self._available:
                return
            retries = 2
            for attempt in range(retries + 1):
                try:
                    from sentence_transformers import SentenceTransformer
                    log.info("Loading civilian harm model: %s [attempt %d/%d]",
                             self._model_name, attempt + 1, retries + 1)
                    self._model = SentenceTransformer(self._model_name)
                    self._concept_embeddings = self._model.encode(
                        HARM_CONCEPTS, normalize_embeddings=True,
                    )
                    log.info(
                        "CivilianHarmClassifier ready — %d concepts encoded",
                        len(HARM_CONCEPTS),
                    )
                    return
                except Exception as exc:
                    if attempt < retries:
                        log.warning("Civilian harm model load attempt %d failed, retrying: %s",
                                    attempt + 1, exc)
                        import time
                        time.sleep(2)
                    else:
                        log.warning(
                            "Civilian harm model unavailable after %d attempts: %s. "
                            "Ensure 'transformers' and 'torch' are installed: "
                            "pip install transformers torch sentence-transformers",
                            retries + 1, exc,
                        )
                        self._available = False

    def _semantic_score(self, text: str) -> tuple[float, list[str]]:
        """Compute semantic similarity between text and harm concepts."""
        self._load_model()
        if self._model is None or self._concept_embeddings is None:
            return 0.0, []
        try:
            import numpy as np
            text_emb = self._model.encode([text], normalize_embeddings=True)
            sims = np.dot(text_emb, self._concept_embeddings.T)[0]

            top_idx = sims.argsort()[-3:][::-1]
            top_concepts = [
                HARM_CONCEPTS[i] for i in top_idx if sims[i] > 0.2
            ]
            max_sim = float(sims.max())
            avg_top3 = float(sims[top_idx].mean())
            blended = 0.6 * max_sim + 0.4 * avg_top3
            return blended, top_concepts
        except Exception as exc:
            log.warning("Semantic scoring failed: %s", exc)
            return 0.0, []

    @staticmethod
    def _keyword_score(text: str) -> tuple[float, int, list[str]]:
        """Score text by conflict keyword density."""
        words = text.lower().split()
        if not words:
            return 0.0, 0, []

        matched = [w for w in words if w in _ALL_KEYWORDS]

        text_lower = text.lower()
        for kws in CONFLICT_KEYWORDS.values():
            for kw in kws:
                if " " in kw and kw.lower() in text_lower and kw not in matched:
                    matched.append(kw)

        unique = list(dict.fromkeys(matched))
        density = min(len(matched) / len(words) * 5.0, 1.0)
        return density, len(unique), unique[:15]

    def score_text(self, text: str, language: str = "") -> HarmScore:
        """Score a single text for civilian harm likelihood."""
        if not text or len(text.strip()) < 10:
            return HarmScore()

        scoring_text = text[:1500]

        sem_score, concepts = self._semantic_score(scoring_text)
        kw_density, kw_count, kw_matched = self._keyword_score(scoring_text)

        composite = 0.7 * sem_score + 0.3 * kw_density
        composite = min(max(composite, 0.0), 1.0)

        return HarmScore(
            score=round(composite, 3),
            semantic_similarity=round(sem_score, 3),
            keyword_density=round(kw_density, 3),
            keyword_count=kw_count,
            classification=_classify(composite),
            matched_concepts=concepts,
            matched_keywords=kw_matched,
            language=language,
        )

    def score_batch(
        self,
        items: list[dict[str, Any]],
        text_key: str = "content",
    ) -> list[dict[str, Any]]:
        """Score a list of dicts, adding ``harm_score`` to each."""
        results = []
        for item in items:
            text = str(item.get(text_key, "") or "")
            lang = item.get("language", "") if isinstance(item, dict) else ""
            harm = self.score_text(text, language=lang)
            enriched = dict(item)
            enriched["harm_score"] = {
                "score": harm.score,
                "classification": harm.classification,
                "semantic_similarity": harm.semantic_similarity,
                "keyword_count": harm.keyword_count,
                "matched_concepts": harm.matched_concepts[:3],
                "matched_keywords": harm.matched_keywords[:5],
            }
            results.append(enriched)
        return results

    def summarize(self, scored_items: list[dict[str, Any]]) -> dict[str, Any]:
        """Aggregate harm scores across a batch of scored items."""
        scores = [
            it.get("harm_score", {}).get("score", 0) for it in scored_items
        ]
        classifications = [
            it.get("harm_score", {}).get("classification", "NONE")
            for it in scored_items
        ]
        if not scores:
            return {
                "total_scored": 0,
                "distribution": {},
                "flagged_count": 0,
                "flagged": [],
            }

        distribution: dict[str, int] = {}
        for cls in ("CRITICAL", "HIGH", "MODERATE", "LOW", "NONE"):
            n = classifications.count(cls)
            if n:
                distribution[cls] = n

        flagged = [
            it for it in scored_items
            if it.get("harm_score", {}).get("score", 0) >= 0.35
        ]
        flagged.sort(
            key=lambda x: x.get("harm_score", {}).get("score", 0),
            reverse=True,
        )

        return {
            "total_scored": len(scores),
            "average_score": round(sum(scores) / len(scores), 3),
            "max_score": round(max(scores), 3),
            "distribution": distribution,
            "flagged_count": len(flagged),
            "flagged": flagged[:25],
        }


_classifier: CivilianHarmClassifier | None = None


def get_civilian_harm_classifier() -> CivilianHarmClassifier:
    """Singleton factory for the civilian harm classifier."""
    global _classifier
    if _classifier is None:
        _classifier = CivilianHarmClassifier()
    return _classifier
