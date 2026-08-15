"""ForgeChain governance configuration."""

import os
from dotenv import load_dotenv

load_dotenv()

FORGE_ENABLED = os.getenv("FORGE_ENABLED", "true").lower() == "true"
FORGE_DB_PATH = os.getenv("FORGE_DB_PATH", "data/forge_chain.db")
FORGE_TOKEN_TTL_SECONDS = int(os.getenv("FORGE_TOKEN_TTL_SECONDS", "60"))
FORGE_MAX_PROMPT_LENGTH = int(os.getenv("FORGE_MAX_PROMPT_LENGTH", "50000"))
FORGE_CONSENSUS_THRESHOLD = int(os.getenv("FORGE_CONSENSUS_THRESHOLD", "2"))
FORGE_HEALING_ENABLED = os.getenv("FORGE_HEALING_ENABLED", "true").lower() == "true"
FORGE_SESSION_KEY_BYTES = int(os.getenv("FORGE_SESSION_KEY_BYTES", "32"))
FORGE_LLM_VERIFIER_TIMEOUT = int(os.getenv("FORGE_LLM_VERIFIER_TIMEOUT", "15"))
FORGE_LLM_MODEL = os.getenv("FORGE_LLM_MODEL", "deepseek-v4-pro")
FORGE_SAFETY_VETO_THRESHOLD = float(os.getenv("FORGE_SAFETY_VETO_THRESHOLD", "0.95"))
