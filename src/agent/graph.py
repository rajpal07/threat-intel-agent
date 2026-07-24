"""Assemble the LangGraph state machine and expose a per-turn runner."""
from __future__ import annotations

import sqlite3
from typing import Any

from langchain_core.messages import HumanMessage
from langgraph.graph import END, START, StateGraph

from ..config import CHECKPOINT_DB
from . import nodes
from .state import AgentState


def make_checkpointer():
    """SQLite-backed checkpointer; falls back to in-memory if the file can't open."""
    try:
        from langgraph.checkpoint.sqlite import SqliteSaver

        CHECKPOINT_DB.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(CHECKPOINT_DB), check_same_thread=False)
        return SqliteSaver(conn)
    except Exception:
        from langgraph.checkpoint.memory import MemorySaver

        return MemorySaver()


def build_graph(checkpointer=None):
    g = StateGraph(AgentState)
    g.add_node("input_guard", nodes.input_guard)
    g.add_node("route_and_resolve", nodes.route_and_resolve)
    g.add_node("tool_executor", nodes.tool_executor)
    g.add_node("sanitize_evidence", nodes.sanitize_evidence)
    g.add_node("grounding_synthesis", nodes.grounding_synthesis)
    g.add_node("confidence_scorer", nodes.confidence_scorer)
    g.add_node("scope_reply", nodes.scope_reply)
    g.add_node("error_reply", nodes.error_reply)

    g.add_edge(START, "input_guard")
    g.add_conditional_edges("input_guard", nodes.after_guard,
                            {"end": END, "route": "route_and_resolve"})
    g.add_conditional_edges("route_and_resolve", nodes.after_router,
                            {"scope": "scope_reply", "tools": "tool_executor"})
    g.add_conditional_edges("tool_executor", nodes.after_tools,
                            {"sanitize": "sanitize_evidence", "error": "error_reply"})
    g.add_edge("sanitize_evidence", "grounding_synthesis")
    g.add_edge("grounding_synthesis", "confidence_scorer")
    g.add_edge("confidence_scorer", END)
    g.add_edge("scope_reply", END)
    g.add_edge("error_reply", END)

    return g.compile(checkpointer=checkpointer)


def run_turn(app, user_text: str, thread_id: str) -> dict[str, Any]:
    """Invoke one turn; returns the full resulting state. Never raises."""
    cfg = {"configurable": {"thread_id": thread_id}}
    try:
        return app.invoke({"messages": [HumanMessage(user_text)]}, cfg)
    except Exception as exc:  # last-resort guard: the app must not crash the UI
        from ..observability import get_logger

        get_logger("graph").error("turn_crashed", error=str(exc))
        return {
            "answer": f"Something went wrong while processing that request "
                      f"({type(exc).__name__}). Please try rephrasing or retry shortly.",
            "confidence": "low", "confidence_rationale": "", "tool_results": [],
            "trace": {"intent": "error", "node_timings": {}, "api_calls": [],
                      "tokens_in": 0, "tokens_out": 0, "injection_flags": [], "blocked": False},
        }
