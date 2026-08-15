"""Forensic replay logic for ForgeChain sessions."""

from typing import Optional

from app.forge.chain_store import get_chain_store


def get_session_replay(
    session_id: str,
    endpoint_filter: Optional[str] = None,
    outcome_filter: Optional[str] = None,
) -> Optional[dict]:
    """Build a forensic replay response for a session.

    Returns block history with hashes and verifier votes,
    but intentionally excludes input_snapshot and raw LLM output
    to prevent data leakage.
    """
    store = get_chain_store()
    session = store.load_session(session_id)

    if session is None:
        return None

    is_valid, error = session.verify_integrity()

    blocks = session.blocks
    if endpoint_filter:
        blocks = [b for b in blocks if b.endpoint == endpoint_filter]
    if outcome_filter:
        blocks = [b for b in blocks if b.gate_outcome == outcome_filter]

    return {
        "session_id": session_id,
        "chain_integrity": is_valid,
        "integrity_error": error,
        "block_count": len(blocks),
        "total_blocks_in_session": len(session.blocks),
        "blocks": [
            {
                "block_id": b.block_id,
                "sequence_num": b.sequence_num,
                "timestamp": b.timestamp,
                "endpoint": b.endpoint,
                "mode": b.mode,
                "chain_name": b.chain_name,
                "gate_outcome": b.gate_outcome,
                "verifier_votes": b.verifier_attestations,
                "prompt_hash": b.prompt_hash,
                "execution_result_hash": b.execution_result_hash,
                "execution_time_ms": b.execution_time_ms,
                "block_hash": b.block_hash,
                "previous_hash": b.previous_hash,
                "user_hash": b.user_hash,
                "error_message": b.error_message,
            }
            for b in blocks
        ],
    }
