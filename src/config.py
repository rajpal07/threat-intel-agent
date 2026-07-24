"""Central configuration: env loading, API keys, LLM provider factory.

Reads from a local .env for development and falls back to Streamlit
`st.secrets` when deployed to Streamlit Community Cloud. Nothing here raises
on a missing key — absence is reported as a capability the app degrades around.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()  # local .env; no-op on Streamlit Cloud where secrets are injected

# --- paths ---
ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"
FIXTURES_DIR = DATA_DIR / "fixtures"
CACHE_DB = ROOT / ".cache" / "http_cache.db"
CHECKPOINT_DB = ROOT / ".cache" / "checkpoints.db"
MITRE_FILE = DATA_DIR / "mitre_attack_trimmed.json"


def _get(name: str, default: str | None = None) -> str | None:
    """Env first, then st.secrets (guarded so tests work without Streamlit)."""
    val = os.getenv(name)
    if val not in (None, ""):
        return val
    try:
        import streamlit as st  # local import: not required for tests/CLI

        if name in st.secrets:
            return str(st.secrets[name])
    except Exception:
        pass
    return default


# --- threat-intel API keys (any may be None → source reports "unavailable") ---
API_KEYS: dict[str, str | None] = {
    "virustotal": _get("VIRUSTOTAL_API_KEY"),
    "abuseipdb": _get("ABUSEIPDB_API_KEY"),
    "otx": _get("OTX_API_KEY"),
    "nvd": _get("NVD_API_KEY"),
    "shodan": _get("SHODAN_API_KEY"),
}


def demo_mode() -> bool:
    return (_get("DEMO_MODE", "false") or "false").strip().lower() in ("1", "true", "yes")


def has_key(source: str) -> bool:
    return bool(API_KEYS.get(source))


# --- LLM factory ------------------------------------------------------------
@lru_cache(maxsize=4)
def make_llm(temperature: float = 0.0):
    """Return a LangChain chat model. Groq by default; Ollama Cloud optional.

    Both providers are free-tier. Structured output (.with_structured_output)
    is used by the router, so the model must support tool/function calling.
    """
    provider = (_get("LLM_PROVIDER", "groq") or "groq").strip().lower()

    if provider == "ollama":
        # Ollama Cloud: OpenAI-compatible chat via langchain-ollama.
        from langchain_ollama import ChatOllama

        return ChatOllama(
            model=_get("OLLAMA_MODEL", "gpt-oss:120b"),
            base_url=_get("OLLAMA_HOST", "https://ollama.com"),
            client_kwargs={"headers": {"Authorization": f"Bearer {_get('OLLAMA_API_KEY', '')}"}},
            temperature=temperature,
        )

    # default: Groq
    from langchain_groq import ChatGroq

    return ChatGroq(
        model=_get("GROQ_MODEL", "llama-3.3-70b-versatile"),
        api_key=_get("GROQ_API_KEY"),
        temperature=temperature,
        max_retries=2,
    )


def llm_available() -> bool:
    provider = (_get("LLM_PROVIDER", "groq") or "groq").strip().lower()
    return bool(_get("OLLAMA_API_KEY")) if provider == "ollama" else bool(_get("GROQ_API_KEY"))
