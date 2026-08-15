"""ForgeGate: 3-verifier consensus logic for Fortis Intelligence Hub."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from typing import Optional

from app.forge.config import (
    FORGE_CONSENSUS_THRESHOLD,
    FORGE_LLM_VERIFIER_TIMEOUT,
    FORGE_SAFETY_VETO_THRESHOLD,
    FORGE_TOKEN_TTL_SECONDS,
)
from app.forge.models import ForgeToken
from app.forge.verifiers import (
    RuleVerifier,
    LLMSafetyVerifier,
    LLMConsistencyVerifier,
    VerifierVote,
)


_rule_verifier = RuleVerifier()
_safety_verifier = LLMSafetyVerifier()
_consistency_verifier = LLMConsistencyVerifier()


def forge_gate(
    parsed_intent: dict,
    chain_input: dict,
    session_id: str,
    mode: str,
    block_id: str,
    trusted_keys: set | None = None,
) -> tuple[str, list[dict], Optional[ForgeToken]]:
    """Run the 3-verifier consensus gate.

    Returns:
        (gate_outcome, attestations, token_or_none)
        gate_outcome is one of: "executed", "refused", "blocked"
    """
    rule_vote = _rule_verifier.verify(parsed_intent, chain_input, session_id, mode, trusted_keys)
    attestations = [asdict(rule_vote)]

    if rule_vote.policy_veto:
        return "refused", attestations, None

    llm_votes = _run_llm_verifiers(parsed_intent, chain_input, session_id, mode)
    attestations.extend([asdict(v) for v in llm_votes])

    for vote in llm_votes:
        if (vote.verifier_id == "llm_safety_verifier"
                and not vote.approved
                and vote.confidence >= FORGE_SAFETY_VETO_THRESHOLD):
            return "refused", attestations, None

    approvals = sum(1 for v in [rule_vote] + llm_votes if v.approved)

    if approvals >= FORGE_CONSENSUS_THRESHOLD:
        chain_name = parsed_intent.get("chain_name", "unknown")
        token = ForgeToken.mint(
            block_id=block_id,
            intent_scope=f"{chain_name}:invoke",
            ttl_seconds=FORGE_TOKEN_TTL_SECONDS,
        )
        return "executed", attestations, token

    return "blocked", attestations, None


def _run_llm_verifiers(
    parsed_intent: dict,
    chain_input: dict,
    session_id: str,
    mode: str,
) -> list[VerifierVote]:
    """Run both LLM verifiers concurrently."""
    votes: list[VerifierVote] = []

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(
                _safety_verifier.verify, parsed_intent, chain_input, session_id, mode
            ): "safety",
            executor.submit(
                _consistency_verifier.verify, parsed_intent, chain_input, session_id, mode
            ): "consistency",
        }

        try:
            for future in as_completed(futures, timeout=FORGE_LLM_VERIFIER_TIMEOUT + 5):
                try:
                    vote = future.result(timeout=FORGE_LLM_VERIFIER_TIMEOUT)
                    votes.append(vote)
                except Exception as e:
                    verifier_name = futures[future]
                    votes.append(VerifierVote(
                        verifier_id=f"llm_{verifier_name}_verifier",
                        approved=True,
                        reason=f"Verifier unavailable (fail-open): {str(e)[:200]}",
                        confidence=0.1,
                    ))
        except TimeoutError:
            collected = {futures[f] for f in futures if f.done()}
            for future, name in futures.items():
                if not future.done():
                    future.cancel()
                    votes.append(VerifierVote(
                        verifier_id=f"llm_{name}_verifier",
                        approved=True,
                        reason=f"Verifier timed out after {FORGE_LLM_VERIFIER_TIMEOUT}s (fail-open)",
                        confidence=0.1,
                    ))

    return votes
