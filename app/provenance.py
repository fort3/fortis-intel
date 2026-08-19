"""Provenance tracking for Fortis Intelligence Hub.

Maintains a chain-of-custody record for each investigation, tracking
how data flows from raw OSINT collection through analysis to final
report.  Each step is timestamped and attributed.

The provenance trail is built incrementally during the investigation
pipeline and attached to the final response so analysts can trace any
claim back to its source.

Exports:
    ProvenanceTrail  -- builder class
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)


class ProvenanceTrail:
    """Incremental provenance builder for a single investigation run."""

    def __init__(self, subject: str, identifier_type: str):
        self._subject = subject
        self._type = identifier_type
        self._steps: list[dict[str, Any]] = []
        self._created = datetime.now(tz=timezone.utc)

    def record(
        self,
        stage: str,
        action: str,
        source: str = "",
        detail: str = "",
        item_count: int = 0,
        data_hash: str = "",
    ) -> None:
        """Record a provenance step.

        Parameters
        ----------
        stage:
            Pipeline phase (e.g. "osint_collection", "llm_analysis",
            "web_intelligence", "grounding_verification").
        action:
            What happened (e.g. "Queried Twitter API", "Ran investigation
            chain via ForgeChain").
        source:
            System/module that performed the action.
        detail:
            Brief human-readable summary of result.
        item_count:
            Number of items produced by this step.
        data_hash:
            Optional SHA-256 hash of output data for tamper detection.
        """
        self._steps.append({
            "step": len(self._steps) + 1,
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "stage": stage,
            "action": action,
            "source": source,
            "detail": detail,
            "item_count": item_count,
            "data_hash": data_hash,
        })

    def record_collection(
        self,
        platforms: list[str],
        findings_summary: dict[str, int],
    ) -> None:
        """Record the OSINT data collection phase."""
        total = sum(findings_summary.values())
        parts = [f"{k}: {v}" for k, v in findings_summary.items() if v > 0]
        self.record(
            stage="osint_collection",
            action=f"Queried {len(platforms)} platforms: {', '.join(platforms)}",
            source="osint_client",
            detail=f"Collected {total} items ({', '.join(parts)})",
            item_count=total,
        )

    def record_analysis(
        self,
        chain_name: str,
        analysis_text: str,
        forgechain_block_id: str = "",
    ) -> None:
        """Record LLM analysis step with content hash."""
        text_hash = hashlib.sha256(analysis_text.encode()).hexdigest()[:16]
        self.record(
            stage="llm_analysis",
            action=f"Ran {chain_name}",
            source="forgechain" if forgechain_block_id else "direct",
            detail=f"Generated {len(analysis_text)} chars, "
                   f"block_id={forgechain_block_id or 'n/a'}",
            data_hash=text_hash,
        )

    def record_verification(
        self,
        verification_type: str,
        verdict: str,
        detail: str = "",
    ) -> None:
        """Record a verification/audit step."""
        self.record(
            stage="verification",
            action=verification_type,
            source=verification_type.lower().replace(" ", "_"),
            detail=f"{verdict}: {detail}" if detail else verdict,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise the full provenance trail."""
        return {
            "subject": self._subject,
            "identifier_type": self._type,
            "created": self._created.isoformat(),
            "total_steps": len(self._steps),
            "steps": self._steps,
        }
