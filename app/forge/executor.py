"""Token-gated chain execution for ForgeChain."""

import hashlib
import time

from app.forge.models import ForgeToken


class ExecutionResult:
    __slots__ = ("content", "result_hash", "execution_time_ms")

    def __init__(self, content: str, result_hash: str, execution_time_ms: float):
        self.content = content
        self.result_hash = result_hash
        self.execution_time_ms = execution_time_ms


def execute_with_token(token: ForgeToken, chain, chain_input: dict) -> ExecutionResult:
    """Execute a LangChain chain only if the ForgeToken is valid.

    Consumes the token after execution. Raises RuntimeError if token
    is invalid or already consumed.
    """
    if not token.is_valid():
        raise RuntimeError(f"ForgeToken {token.token_id} is invalid or expired")

    token.consume()

    start = time.time()
    result = chain.invoke(chain_input)
    elapsed_ms = (time.time() - start) * 1000

    content = result.content if hasattr(result, "content") else str(result)
    result_hash = hashlib.sha256(content.encode()).hexdigest()

    return ExecutionResult(
        content=content,
        result_hash=result_hash,
        execution_time_ms=elapsed_ms,
    )
