"""Fork healing for ForgeChain -- recovery on low consensus."""

from typing import Optional

from app.forge.gate import forge_gate
from app.forge.executor import execute_with_token, ExecutionResult
from app.forge.verifiers import VerifierVote


def attempt_healing(
    parsed_intent: dict,
    chain_input: dict,
    session_id: str,
    mode: str,
    block_id: str,
    chain,
    original_votes: list[dict],
    trusted_keys: set | None = None,
) -> tuple[bool, Optional[str], list[dict], Optional[ExecutionResult]]:
    """Try recovery strategies when consensus is low.

    Args:
        trusted_keys: Keys that should skip injection scanning (passed to forge_gate)

    Returns:
        (healed, gate_outcome, attestations, execution_result)
    """
    strategies = [
        _strategy_truncate_context,
        _strategy_verifier_retry,
    ]

    for strategy_fn in strategies:
        mutated_input = strategy_fn(chain_input, parsed_intent)
        if mutated_input is None:
            continue

        # Pass trusted_keys through to forge_gate for consistent validation
        outcome, attestations, token = forge_gate(
            parsed_intent, mutated_input, session_id, mode, block_id,
            trusted_keys=trusted_keys
        )

        if outcome == "executed" and token is not None:
            exec_result = execute_with_token(token, chain, mutated_input)
            return True, "executed_healed", attestations, exec_result

    return False, None, [], None


def _strategy_truncate_context(chain_input: dict, parsed_intent: dict) -> Optional[dict]:
    """Truncate context if it exceeds 20K chars."""
    context = chain_input.get("context", "")
    if len(context) <= 20_000:
        return None

    mutated = dict(chain_input)
    mutated["context"] = context[:20_000]
    return mutated


def _strategy_verifier_retry(chain_input: dict, parsed_intent: dict) -> Optional[dict]:
    """Simply re-submit the same input (LLM verifiers may produce different results)."""
    return dict(chain_input)
