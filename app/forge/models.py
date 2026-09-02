"""ForgeChain data models: ForgeBlock, ForgeChainSession, ForgeToken."""

import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ForgeBlock:
    block_id: str
    session_id: str
    endpoint: str
    mode: str
    chain_name: str
    timestamp: str
    parsed_intent: dict
    prompt_hash: str
    input_snapshot: dict
    invariants: list[str]
    verifier_attestations: list[dict]
    gate_outcome: str
    previous_hash: str
    block_hash: str
    signature: str
    user_hash: str
    token_id: Optional[str] = None
    execution_result_hash: Optional[str] = None
    execution_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    sequence_num: int = 0

    @staticmethod
    def compute_hash(
        block_id: str,
        previous_hash: str,
        prompt_hash: str,
        timestamp: str,
        execution_result_hash: str = "",
        token_id: str = "",
        execution_time_ms: float = 0.0
    ) -> str:
        """Compute tamper-evident hash including execution results.

        Including execution results in the hash ensures the entire block
        (pre-execution AND post-execution data) is covered by the hash chain,
        preventing modification of LLM outputs without detection.
        """
        payload = (
            f"{block_id}:{previous_hash}:{prompt_hash}:{timestamp}:"
            f"{execution_result_hash}:{token_id}:{execution_time_ms}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def sign(block_hash: str, session_key: bytes) -> str:
        return hmac.new(session_key, block_hash.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def hash_input(chain_input: dict) -> str:
        serialized = json.dumps(chain_input, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ForgeBlock":
        return cls(**data)


@dataclass
class ForgeChainSession:
    session_id: str
    session_key: bytes
    blocks: list[ForgeBlock] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @staticmethod
    def generate_session_key(nbytes: int = 32) -> bytes:
        return secrets.token_bytes(nbytes)

    def append_block(self, block: ForgeBlock) -> None:
        """Thread-safe block appending with chain integrity validation."""
        with self._lock:
            # Validate chain linkage
            if self.blocks:
                expected_prev = self.blocks[-1].block_hash
                if block.previous_hash != expected_prev:
                    raise ValueError(
                        f"Block previous_hash mismatch: expected {expected_prev}, got {block.previous_hash}"
                    )

            # Assign sequence number
            block.sequence_num = len(self.blocks)

            # Append to chain
            self.blocks.append(block)

    def verify_integrity(self) -> tuple[bool, Optional[str]]:
        for i, block in enumerate(self.blocks):
            expected_hash = ForgeBlock.compute_hash(
                block.block_id, block.previous_hash, block.prompt_hash, block.timestamp,
                execution_result_hash=block.execution_result_hash or "",
                token_id=block.token_id or "",
                execution_time_ms=block.execution_time_ms or 0.0,
            )
            if not hmac.compare_digest(block.block_hash, expected_hash):
                return False, f"Block {i} hash mismatch"

            expected_sig = ForgeBlock.sign(block.block_hash, self.session_key)
            if not hmac.compare_digest(block.signature, expected_sig):
                return False, f"Block {i} signature mismatch"

            if i > 0 and block.previous_hash != self.blocks[i - 1].block_hash:
                return False, f"Block {i} chain link broken"
            elif i == 0 and block.previous_hash != "genesis":
                return False, f"Genesis block has wrong previous_hash"

        return True, None

    def get_latest_hash(self) -> str:
        if self.blocks:
            return self.blocks[-1].block_hash
        return "genesis"


@dataclass
class ForgeToken:
    token_id: str
    block_id: str
    intent_scope: str
    created_at: float
    expires_at: float
    consumed: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    @classmethod
    def mint(cls, block_id: str, intent_scope: str, ttl_seconds: int = 60) -> "ForgeToken":
        now = time.time()
        return cls(
            token_id=uuid.uuid4().hex,
            block_id=block_id,
            intent_scope=intent_scope,
            created_at=now,
            expires_at=now + ttl_seconds,
        )

    def is_valid(self) -> bool:
        return not self.consumed and time.time() < self.expires_at

    def consume(self) -> None:
        with self._lock:
            if self.consumed:
                raise RuntimeError("Token already consumed")
            self.consumed = True
