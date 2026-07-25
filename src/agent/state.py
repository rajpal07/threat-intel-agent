"""LangGraph state definition."""
from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class AgentState(TypedDict, total=False):
    # conversation history (persisted by the checkpointer, thread_id per session)
    messages: Annotated[list[BaseMessage], add_messages]

    # per-turn working fields (overwritten each turn)
    route: dict[str, Any]          # RouteResult.model_dump()
    tool_results: list[dict]       # [ToolResult.model_dump(), ...]
    answer: str
    confidence: str                # band: high|medium|low
    confidence_score: int          # 0..100
    confidence_rationale: str
    verdict: str                   # Malicious | Benign | Exposed | Profiled | ...
    confidence_report: dict[str, Any]  # ConfidenceReport.model_dump()
    trace: dict[str, Any]          # TurnTrace.model_dump()
