"""Pydantic models shared across the agent, tools, and UI."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

EntityType = Literal["ip", "domain", "hash", "actor", "product", "cve", "url"]
Intent = Literal["ioc_lookup", "actor_profile", "exposure_check", "pivot", "out_of_scope"]
ToolStatus = Literal["ok", "error", "rate_limited", "no_data", "unavailable"]
Confidence = Literal["high", "medium", "low"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Entity(BaseModel):
    value: str
    type: EntityType


class RouteResult(BaseModel):
    """Structured output of LLM call 1 (route_and_resolve)."""

    standalone_query: str = Field(description="Latest message rewritten to stand alone")
    intent: Intent
    entities: list[Entity] = Field(default_factory=list)
    reasoning: str = Field(default="", max_length=400)


class ToolResult(BaseModel):
    source: str
    status: ToolStatus
    data: Optional[dict[str, Any]] = None
    fetched_at: datetime = Field(default_factory=_utcnow)
    cached: bool = False
    endpoint: str = ""
    error: str = ""
    suspicion_flags: list[str] = Field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.status == "ok" and bool(self.data)


class Finding(BaseModel):
    claim: str
    sources: list[str] = Field(default_factory=list)
    confidence: Confidence = "medium"


class ApiCall(BaseModel):
    source: str
    endpoint: str
    status: ToolStatus
    cached: bool = False
    ms: float = 0.0


class TurnTrace(BaseModel):
    node_timings: dict[str, float] = Field(default_factory=dict)
    api_calls: list[ApiCall] = Field(default_factory=list)
    tokens_in: int = 0
    tokens_out: int = 0
    injection_flags: list[str] = Field(default_factory=list)
    blocked: bool = False
    intent: str = ""
