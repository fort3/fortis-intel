"""Bridge ForgeChain events to the Fortis Intelligence Hub audit logger."""

from app.forge.models import ForgeBlock, ForgeToken


class ForgeAuditBridge:
    def __init__(self):
        from app.auth.audit_logger import get_audit_logger
        self._logger = get_audit_logger()

    def log_forge_event(self, block: ForgeBlock) -> None:
        event_type = f"FORGE_{block.gate_outcome.upper()}"
        self._logger._log_event(event_type, None, {
            "block_id": block.block_id,
            "session_id": block.session_id,
            "endpoint": block.endpoint,
            "mode": block.mode,
            "chain_name": block.chain_name,
            "gate_outcome": block.gate_outcome,
            "user_hash": block.user_hash,
            "prompt_hash": block.prompt_hash,
            "verifier_count": len(block.verifier_attestations),
            "approvals": sum(1 for v in block.verifier_attestations if v.get("approved")),
            "execution_time_ms": block.execution_time_ms,
        })

    def log_forge_healing(self, block_id: str, session_id: str, strategy: str, success: bool) -> None:
        self._logger._log_event("FORGE_HEALING", None, {
            "block_id": block_id,
            "session_id": session_id,
            "strategy": strategy,
            "success": success,
        })

    def log_forge_token_minted(self, token: ForgeToken, block_id: str) -> None:
        self._logger._log_event("FORGE_TOKEN_MINTED", None, {
            "token_id": token.token_id,
            "block_id": block_id,
            "intent_scope": token.intent_scope,
            "ttl_seconds": round(token.expires_at - token.created_at, 1),
        })

    def log_forge_token_consumed(self, token: ForgeToken) -> None:
        self._logger._log_event("FORGE_TOKEN_CONSUMED", None, {
            "token_id": token.token_id,
            "block_id": token.block_id,
        })

    def log_forge_replay_access(self, session_id: str, user_hash: str) -> None:
        self._logger._log_event("FORGE_REPLAY_ACCESS", None, {
            "session_id": session_id,
            "user_hash": user_hash,
        })


_forge_audit = None


def get_forge_audit() -> ForgeAuditBridge:
    global _forge_audit
    if _forge_audit is None:
        _forge_audit = ForgeAuditBridge()
    return _forge_audit
