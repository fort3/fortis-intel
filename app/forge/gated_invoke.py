"""Main ForgeChain wrapper for LangChain .invoke() calls."""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from app.forge.config import FORGE_ENABLED, FORGE_HEALING_ENABLED, FORGE_SESSION_KEY_BYTES
from app.forge.models import ForgeBlock, ForgeChainSession


@dataclass
class GatedInvokeResult:
    success: bool
    content: Optional[str]
    gate_outcome: str
    block_id: str
    reason: Optional[str]
    execution_time_ms: Optional[float]


def gated_invoke(
    chain,
    chain_input: dict,
    *,
    chain_name: str,
    endpoint: str,
    mode: str,
    session_id: str,
    user_hash: str,
    trusted_keys: set | None = None,
) -> GatedInvokeResult:
    """Wrap a LangChain chain.invoke() call with ForgeChain governance.

    If FORGE_ENABLED is False, bypasses all governance and calls chain.invoke() directly.
    """
    if not FORGE_ENABLED:
        result = chain.invoke(chain_input)
        content = result.content if hasattr(result, "content") else str(result)
        return GatedInvokeResult(
            success=True,
            content=content,
            gate_outcome="bypassed",
            block_id="none",
            reason=None,
            execution_time_ms=None,
        )

    block_id = uuid.uuid4().hex

    try:
        return _run_pipeline(
            chain, chain_input,
            chain_name=chain_name,
            endpoint=endpoint,
            mode=mode,
            session_id=session_id,
            user_hash=user_hash,
            block_id=block_id,
            trusted_keys=trusted_keys,
        )
    except Exception as exc:
        _persist_error_block(
            block_id=block_id,
            session_id=session_id,
            endpoint=endpoint,
            mode=mode,
            chain_name=chain_name,
            chain_input=chain_input,
            user_hash=user_hash,
            error=exc,
        )
        raise


def _run_pipeline(
    chain,
    chain_input: dict,
    *,
    chain_name: str,
    endpoint: str,
    mode: str,
    session_id: str,
    user_hash: str,
    block_id: str,
    trusted_keys: set | None = None,
) -> GatedInvokeResult:
    from app.forge.chain_store import get_chain_store
    from app.forge.interpreter import interpret
    from app.forge.gate import forge_gate
    from app.forge.executor import execute_with_token
    from app.forge.healer import attempt_healing
    from app.forge.audit_integration import get_forge_audit

    store = get_chain_store()
    audit = get_forge_audit()

    # 1. Get or create session
    forge_session = store.load_session(session_id)
    if forge_session is None:
        forge_session = ForgeChainSession(
            session_id=session_id,
            session_key=ForgeChainSession.generate_session_key(FORGE_SESSION_KEY_BYTES),
        )
        store.save_session(forge_session)

    # 2. Interpret intent (no LLM call)
    parsed_intent = interpret(
        endpoint=endpoint,
        mode=mode,
        chain_name=chain_name,
        chain_input_keys=list(chain_input.keys()),
    )

    # 3. Compute prompt hash and invariants
    prompt_hash = ForgeBlock.hash_input(chain_input)
    invariants = [
        f"mode_is_{mode}",
        f"chain_is_{chain_name}",
        f"endpoint_is_{endpoint}",
        "session_valid",
        f"input_keys_{','.join(sorted(chain_input.keys()))}",
    ]

    # 4. Run Forge Gate
    gate_outcome, attestations, token = forge_gate(
        parsed_intent, chain_input, session_id, mode, block_id, trusted_keys
    )

    # 5. Build the block
    now = datetime.now(timezone.utc).isoformat()
    previous_hash = forge_session.get_latest_hash()
    block_hash = ForgeBlock.compute_hash(block_id, previous_hash, prompt_hash, now)
    signature = ForgeBlock.sign(block_hash, forge_session.session_key)

    block = ForgeBlock(
        block_id=block_id,
        session_id=session_id,
        endpoint=endpoint,
        mode=mode,
        chain_name=chain_name,
        timestamp=now,
        parsed_intent=parsed_intent,
        prompt_hash=prompt_hash,
        input_snapshot=chain_input,
        invariants=invariants,
        verifier_attestations=attestations,
        gate_outcome=gate_outcome,
        previous_hash=previous_hash,
        block_hash=block_hash,
        signature=signature,
        user_hash=user_hash,
    )

    # 6. Execute if approved
    exec_content = None
    exec_time = None

    if gate_outcome == "executed" and token is not None:
        audit.log_forge_token_minted(token, block_id)
        exec_result = execute_with_token(token, chain, chain_input)
        audit.log_forge_token_consumed(token)
        block.token_id = token.token_id
        block.execution_result_hash = exec_result.result_hash
        block.execution_time_ms = exec_result.execution_time_ms
        exec_content = exec_result.content
        exec_time = exec_result.execution_time_ms

    elif gate_outcome == "blocked" and FORGE_HEALING_ENABLED:
        healed, healed_outcome, healed_attestations, healed_exec = attempt_healing(
            parsed_intent, chain_input, session_id, mode, block_id, chain, attestations,
            trusted_keys=trusted_keys
        )
        if healed and healed_exec is not None:
            block.gate_outcome = healed_outcome or "executed_healed"
            block.verifier_attestations = healed_attestations
            block.execution_result_hash = healed_exec.result_hash
            block.execution_time_ms = healed_exec.execution_time_ms
            exec_content = healed_exec.content
            exec_time = healed_exec.execution_time_ms
            gate_outcome = block.gate_outcome
            audit.log_forge_healing(block_id, session_id, "recovery", True)
        else:
            audit.log_forge_healing(block_id, session_id, "recovery", False)

    # 7. Recompute hash/signature AFTER execution fields are set (tamper-evident chain)
    block.block_hash = ForgeBlock.compute_hash(
        block_id,
        previous_hash,
        prompt_hash,
        now,
        execution_result_hash=block.execution_result_hash or "",
        token_id=block.token_id or "",
        execution_time_ms=block.execution_time_ms or 0.0
    )
    block.signature = ForgeBlock.sign(block.block_hash, forge_session.session_key)

    # 8. Persist
    forge_session.append_block(block)
    store.append_block(block)

    # 9. Audit
    audit.log_forge_event(block)

    # 10. Build result
    success = exec_content is not None
    reason = None
    if not success:
        refusal_votes = [
            a for a in attestations if not a.get("approved")
        ]
        if refusal_votes:
            reason = refusal_votes[0].get("reason", "Blocked by governance")
        else:
            reason = "Blocked by governance"

    return GatedInvokeResult(
        success=success,
        content=exec_content,
        gate_outcome=gate_outcome,
        block_id=block_id,
        reason=reason,
        execution_time_ms=exec_time,
    )


def _persist_error_block(
    *,
    block_id: str,
    session_id: str,
    endpoint: str,
    mode: str,
    chain_name: str,
    chain_input: dict,
    user_hash: str,
    error: Exception,
) -> None:
    """Best-effort persist an error block."""
    try:
        from app.forge.chain_store import get_chain_store
        from app.forge.audit_integration import get_forge_audit

        store = get_chain_store()
        audit = get_forge_audit()

        now = datetime.now(timezone.utc).isoformat()
        prompt_hash = ForgeBlock.hash_input(chain_input)

        forge_session = store.load_session(session_id)
        if forge_session is None:
            return

        previous_hash = forge_session.get_latest_hash()
        block_hash = ForgeBlock.compute_hash(block_id, previous_hash, prompt_hash, now)
        signature = ForgeBlock.sign(block_hash, forge_session.session_key)

        block = ForgeBlock(
            block_id=block_id,
            session_id=session_id,
            endpoint=endpoint,
            mode=mode,
            chain_name=chain_name,
            timestamp=now,
            parsed_intent={"action": "error", "chain_name": chain_name},
            prompt_hash=prompt_hash,
            input_snapshot={},
            invariants=[],
            verifier_attestations=[],
            gate_outcome="error",
            previous_hash=previous_hash,
            block_hash=block_hash,
            signature=signature,
            user_hash=user_hash,
            error_message=str(error)[:500],
        )
        forge_session.append_block(block)
        store.append_block(block)
        audit.log_forge_event(block)
    except Exception:
        pass
