"""SQLite persistence for ForgeChain sessions and blocks."""

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

from app.forge.models import ForgeBlock, ForgeChainSession


def _derive_fernet_key(secret: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(secret.encode()))


_SALT_FILE = ".forge_salt"


class ChainStore:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._fernet: Optional[Fernet] = None

    def _get_salt(self) -> bytes:
        salt_path = Path(self.db_path).parent / _SALT_FILE
        if salt_path.exists():
            return salt_path.read_bytes()
        salt = os.urandom(16)
        salt_path.parent.mkdir(parents=True, exist_ok=True)
        salt_path.write_bytes(salt)
        return salt

    def _get_fernet(self) -> Fernet:
        if self._fernet is None:
            secret = os.getenv("SESSION_SECRET_KEY", "")
            if not secret:
                raise RuntimeError(
                    "SESSION_SECRET_KEY environment variable is required for ForgeChain encryption. "
                    "Set it in your .env file."
                )
            self._fernet = Fernet(_derive_fernet_key(secret, self._get_salt()))
        return self._fernet

    def initialize(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS forge_sessions (
                    session_id TEXT PRIMARY KEY,
                    session_key_encrypted TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_activity TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS forge_blocks (
                    block_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    sequence_num INTEGER NOT NULL,
                    endpoint TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    chain_name TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    parsed_intent TEXT NOT NULL,
                    prompt_hash TEXT NOT NULL,
                    input_snapshot TEXT NOT NULL,
                    invariants TEXT NOT NULL,
                    verifier_attestations TEXT NOT NULL,
                    gate_outcome TEXT NOT NULL,
                    token_id TEXT,
                    execution_result_hash TEXT,
                    previous_hash TEXT NOT NULL,
                    block_hash TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    user_hash TEXT NOT NULL,
                    execution_time_ms REAL,
                    error_message TEXT,
                    FOREIGN KEY (session_id) REFERENCES forge_sessions(session_id)
                );
                CREATE INDEX IF NOT EXISTS idx_blocks_session
                    ON forge_blocks(session_id, sequence_num);
                CREATE INDEX IF NOT EXISTS idx_blocks_outcome
                    ON forge_blocks(gate_outcome);
                CREATE INDEX IF NOT EXISTS idx_blocks_timestamp
                    ON forge_blocks(timestamp);
            """)

    def _encrypt_key(self, session_key: bytes) -> str:
        return self._get_fernet().encrypt(session_key).decode()

    def _decrypt_key(self, encrypted: str) -> bytes:
        return self._get_fernet().decrypt(encrypted.encode())

    def save_session(self, session: ForgeChainSession) -> None:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        encrypted_key = self._encrypt_key(session.session_key)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO forge_sessions (session_id, session_key_encrypted, created_at, last_activity)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(session_id) DO UPDATE SET last_activity = ?""",
                (session.session_id, encrypted_key, session.created_at, now, now),
            )

    def load_session(self, session_id: str) -> Optional[ForgeChainSession]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM forge_sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if not row:
                return None

            session_key = self._decrypt_key(row["session_key_encrypted"])
            session = ForgeChainSession(
                session_id=session_id,
                session_key=session_key,
                created_at=row["created_at"],
            )

            block_rows = conn.execute(
                "SELECT * FROM forge_blocks WHERE session_id = ? ORDER BY sequence_num",
                (session_id,),
            ).fetchall()

            for br in block_rows:
                block = ForgeBlock(
                    block_id=br["block_id"],
                    session_id=br["session_id"],
                    endpoint=br["endpoint"],
                    mode=br["mode"],
                    chain_name=br["chain_name"],
                    timestamp=br["timestamp"],
                    parsed_intent=json.loads(br["parsed_intent"]),
                    prompt_hash=br["prompt_hash"],
                    input_snapshot=json.loads(br["input_snapshot"]),
                    invariants=json.loads(br["invariants"]),
                    verifier_attestations=json.loads(br["verifier_attestations"]),
                    gate_outcome=br["gate_outcome"],
                    previous_hash=br["previous_hash"],
                    block_hash=br["block_hash"],
                    signature=br["signature"],
                    user_hash=br["user_hash"],
                    token_id=br["token_id"],
                    execution_result_hash=br["execution_result_hash"],
                    execution_time_ms=br["execution_time_ms"],
                    error_message=br["error_message"],
                    sequence_num=br["sequence_num"],
                )
                session.blocks.append(block)

            return session

    def append_block(self, block: ForgeBlock) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO forge_blocks (
                    block_id, session_id, sequence_num, endpoint, mode, chain_name,
                    timestamp, parsed_intent, prompt_hash, input_snapshot, invariants,
                    verifier_attestations, gate_outcome, token_id, execution_result_hash,
                    previous_hash, block_hash, signature, user_hash, execution_time_ms,
                    error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    block.block_id, block.session_id, block.sequence_num,
                    block.endpoint, block.mode, block.chain_name, block.timestamp,
                    json.dumps(block.parsed_intent), block.prompt_hash,
                    json.dumps(block.input_snapshot), json.dumps(block.invariants),
                    json.dumps(block.verifier_attestations), block.gate_outcome,
                    block.token_id, block.execution_result_hash, block.previous_hash,
                    block.block_hash, block.signature, block.user_hash,
                    block.execution_time_ms, block.error_message,
                ),
            )
            conn.execute(
                "UPDATE forge_sessions SET last_activity = ? WHERE session_id = ?",
                (block.timestamp, block.session_id),
            )

    def get_session_blocks(
        self,
        session_id: str,
        endpoint: Optional[str] = None,
        outcome: Optional[str] = None,
    ) -> list[ForgeBlock]:
        query = "SELECT * FROM forge_blocks WHERE session_id = ?"
        params: list = [session_id]
        if endpoint:
            query += " AND endpoint = ?"
            params.append(endpoint)
        if outcome:
            query += " AND gate_outcome = ?"
            params.append(outcome)
        query += " ORDER BY sequence_num"

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(query, params).fetchall()
            return [
                ForgeBlock(
                    block_id=r["block_id"],
                    session_id=r["session_id"],
                    endpoint=r["endpoint"],
                    mode=r["mode"],
                    chain_name=r["chain_name"],
                    timestamp=r["timestamp"],
                    parsed_intent=json.loads(r["parsed_intent"]),
                    prompt_hash=r["prompt_hash"],
                    input_snapshot=json.loads(r["input_snapshot"]),
                    invariants=json.loads(r["invariants"]),
                    verifier_attestations=json.loads(r["verifier_attestations"]),
                    gate_outcome=r["gate_outcome"],
                    previous_hash=r["previous_hash"],
                    block_hash=r["block_hash"],
                    signature=r["signature"],
                    user_hash=r["user_hash"],
                    token_id=r["token_id"],
                    execution_result_hash=r["execution_result_hash"],
                    execution_time_ms=r["execution_time_ms"],
                    error_message=r["error_message"],
                    sequence_num=r["sequence_num"],
                )
                for r in rows
            ]

    def get_stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total_sessions = conn.execute("SELECT COUNT(*) FROM forge_sessions").fetchone()[0]
            total_blocks = conn.execute("SELECT COUNT(*) FROM forge_blocks").fetchone()[0]
            last_ts = conn.execute(
                "SELECT MAX(timestamp) FROM forge_blocks"
            ).fetchone()[0]
            return {
                "total_sessions": total_sessions,
                "total_blocks": total_blocks,
                "last_block_timestamp": last_ts,
            }


_chain_store = None


def get_chain_store() -> ChainStore:
    global _chain_store
    if _chain_store is None:
        from app.forge.config import FORGE_DB_PATH
        _chain_store = ChainStore(FORGE_DB_PATH)
        _chain_store.initialize()
    return _chain_store
