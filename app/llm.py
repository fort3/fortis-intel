"""Centralized LLM configuration for Fortis Intelligence Hub.

Single provider: DeepSeek via OpenAI-compatible API.
- deepseek-v4-flash: all analysis chains (investigation, enrichment, geo, scenario, RAG)
- deepseek-v4-pro: ForgeChain governance verifiers (safety + consistency)
"""

import os
from langchain_openai import ChatOpenAI

_analyst_llm = None
_batch_llm = None
_forge_safety_llm = None
_forge_consistency_llm = None

_BASE_URL = "https://api.deepseek.com/v1"


def _get_api_key():
    key = os.getenv("DEEPSEEK_API_KEY")
    if not key:
        raise RuntimeError(
            "DEEPSEEK_API_KEY not set. Register at https://platform.deepseek.com"
        )
    return key


def get_analyst_llm():
    """DeepSeek v4-flash for all analysis chains."""
    global _analyst_llm
    if _analyst_llm is None:
        _analyst_llm = ChatOpenAI(
            model=os.getenv("DEEPSEEK_ANALYSIS_MODEL", "deepseek-v4-flash"),
            api_key=_get_api_key(),
            base_url=os.getenv("DEEPSEEK_BASE_URL", _BASE_URL),
            temperature=0.2,
            max_tokens=8192,
        )
    return _analyst_llm


def get_batch_llm():
    """DeepSeek v4-flash at lower temperature for per-entity batch items."""
    global _batch_llm
    if _batch_llm is None:
        _batch_llm = ChatOpenAI(
            model=os.getenv("DEEPSEEK_ANALYSIS_MODEL", "deepseek-v4-flash"),
            api_key=_get_api_key(),
            base_url=os.getenv("DEEPSEEK_BASE_URL", _BASE_URL),
            temperature=0.1,
            max_tokens=2048,
        )
    return _batch_llm


def get_forge_safety_llm():
    """DeepSeek v4-pro for ForgeChain safety verification."""
    global _forge_safety_llm
    if _forge_safety_llm is None:
        _forge_safety_llm = ChatOpenAI(
            model=os.getenv("DEEPSEEK_FORGE_MODEL", "deepseek-v4-pro"),
            api_key=_get_api_key(),
            base_url=os.getenv("DEEPSEEK_BASE_URL", _BASE_URL),
            temperature=0.2,
            max_tokens=2048,
        )
    return _forge_safety_llm


def get_forge_consistency_llm():
    """DeepSeek v4-pro for ForgeChain consistency verification."""
    global _forge_consistency_llm
    if _forge_consistency_llm is None:
        _forge_consistency_llm = ChatOpenAI(
            model=os.getenv("DEEPSEEK_FORGE_MODEL", "deepseek-v4-pro"),
            api_key=_get_api_key(),
            base_url=os.getenv("DEEPSEEK_BASE_URL", _BASE_URL),
            temperature=0.1,
            max_tokens=2048,
        )
    return _forge_consistency_llm


def is_configured():
    """Check if LLM is configured."""
    return bool(os.getenv("DEEPSEEK_API_KEY"))
