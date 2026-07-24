"""Structured logging + token/cost accounting (observability & cost bonuses)."""
from __future__ import annotations

import logging
import sys

import structlog

# Approx Groq pricing (USD per 1M tokens) for common free-tier models.
# Used only for the in-app cost estimate; not billed here.
_PRICE_PER_M = {
    "llama-3.3-70b-versatile": (0.59, 0.79),
    "llama-3.1-8b-instant": (0.05, 0.08),
    "openai/gpt-oss-120b": (0.15, 0.60),
    "gpt-oss:120b": (0.0, 0.0),  # Ollama Cloud free
}
_DEFAULT_PRICE = (0.59, 0.79)

_configured = False


def configure(level: int = logging.INFO) -> None:
    global _configured
    if _configured:
        return
    logging.basicConfig(format="%(message)s", stream=sys.stderr, level=level)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        cache_logger_on_first_use=True,
    )
    _configured = True


def get_logger(name: str = "agent"):
    configure()
    return structlog.get_logger(name)


def estimate_cost(tokens_in: int, tokens_out: int, model: str = "") -> float:
    pin, pout = _PRICE_PER_M.get(model, _DEFAULT_PRICE)
    return round(tokens_in / 1e6 * pin + tokens_out / 1e6 * pout, 6)


def tokens_from_response(response) -> tuple[int, int]:
    """Pull (input, output) token counts from a LangChain AIMessage."""
    meta = getattr(response, "usage_metadata", None) or {}
    if meta:
        return int(meta.get("input_tokens", 0)), int(meta.get("output_tokens", 0))
    rmeta = getattr(response, "response_metadata", None) or {}
    usage = rmeta.get("token_usage") or rmeta.get("usage") or {}
    return int(usage.get("prompt_tokens", 0)), int(usage.get("completion_tokens", 0))
