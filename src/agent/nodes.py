"""LangGraph node functions.

Every node is defensive: LLM/tool failures degrade into a grounded fallback
answer rather than raising, so the evaluator can never trigger an unhandled
crash. Per-turn working fields are reset in `input_guard`.
"""
from __future__ import annotations

import time
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from ..config import llm_available, make_llm
from ..ioc import extract_entities, is_private_ip
from ..observability import estimate_cost, get_logger, tokens_from_response
from ..schemas import Entity, RouteResult, ToolResult, TurnTrace
from ..security.injection import REFUSAL_MESSAGE, scan_input
from ..security.sanitizer import sanitize_tool_result
from ..tools import abuseipdb, mitre, nvd, otx, shodan, virustotal
from . import confidence
from .prompts import ROUTER_SYSTEM, SCOPE_REPLY, SYNTHESIS_SYSTEM, evidence_block

log = get_logger("nodes")
HISTORY_LIMIT = 8          # cap messages fed to the router (Groq TPM budget)
MAX_ENTITIES = 2           # cap indicators processed per turn (rate-limit budget)

_RATE_LIMIT_NOTE = (
    "⏳ **LLM rate limit reached** (Groq free tier caps daily tokens). I've "
    "gathered the threat-intel evidence below and routed your query, but the "
    "written analysis is paused. It resumes automatically when the limit resets "
    "(daily), or immediately if you set a lighter `GROQ_MODEL` "
    "(e.g. `llama-3.1-8b-instant`, ~5× the daily token budget). Raw findings:"
)


# --- helpers ---------------------------------------------------------------
def _last_human_text(state: dict) -> str:
    for m in reversed(state.get("messages", [])):
        if isinstance(m, HumanMessage):
            return m.content if isinstance(m.content, str) else str(m.content)
    return ""


def _blank_trace() -> dict:
    return TurnTrace().model_dump()


def _record_call(trace: dict, res: ToolResult, ms: float) -> None:
    trace["api_calls"].append({
        "source": res.source, "endpoint": res.endpoint,
        "status": res.status, "cached": res.cached, "ms": round(ms, 1),
    })


def _timed(trace: dict, fn, *args) -> ToolResult:
    t = time.perf_counter()
    try:
        res = fn(*args)
    except Exception as exc:  # tool bug must never crash the graph
        res = ToolResult(source=getattr(fn, "__name__", "tool"), status="error",
                         data={"error": str(exc)})
    _record_call(trace, res, (time.perf_counter() - t) * 1000)
    return res


def _format_caveats(text: str) -> str:
    """Ensure any 'Caveats:' section is split onto its own new line with a bold header."""
    if not text:
        return text
    import re
    # Match inline "Caveats:" or "**Caveats:**" or "Caveat:" that is not already at the start of a new line
    text = re.sub(
        r'(?<!\n)\s*[\.\;]?\s*(?:\*\*)?(?:Caveat|Caveats)(?:\*\*)?:\s*',
        r'\n\n**Caveats:**\n',
        text,
        flags=re.IGNORECASE
    )
    # Clean up any triple newlines
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def _is_rate_limit(exc: Exception) -> bool:
    s = str(exc).lower()
    return any(k in s for k in ("429", "rate limit", "rate_limit", "tokens per day", "tpd", "quota"))


def _dedup_entities(ents: list[Entity]) -> list[Entity]:
    seen: set[tuple[str, str]] = set()
    out: list[Entity] = []
    for e in ents:
        k = (e.value.lower(), e.type)
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out


_STOP = {"we", "run", "running", "are", "is", "am", "exposed", "exposure", "our",
         "do", "have", "to", "known", "threats", "vuln", "vulnerabilities", "the",
         "a", "an", "for", "any", "on", "using", "use", "version", "what", "which",
         "cve", "cves", "against", "affected", "by"}


def _product_keyword(query: str, entities: list[Entity]) -> str:
    prods = [e.value for e in entities if e.type in ("product", "cve")]
    if prods:
        return " ".join(prods)
    toks = [t.strip("?.,") for t in query.split()]
    kept = [t for t in toks if t and t.lower() not in _STOP]
    return " ".join(kept[:6]) or query


# --- nodes -----------------------------------------------------------------
def input_guard(state: dict) -> dict:
    """Layer-1 direct injection scan + per-turn reset."""
    text = _last_human_text(state)
    tr = _blank_trace()
    reset = {"answer": "", "tool_results": [], "confidence": "", "confidence_rationale": ""}

    if not text.strip():
        msg = "Please type a question — e.g. *“Is 45.83.122.10 malicious?”*"
        tr["intent"] = "empty"
        return {**reset, "answer": msg, "trace": tr, "messages": [AIMessage(msg)]}

    verdict = scan_input(text)
    tr["injection_flags"] = verdict.categories
    if verdict.blocked:
        tr["blocked"] = True
        tr["intent"] = "blocked"
        log.warning("input_blocked", categories=verdict.categories)
        return {**reset, "answer": REFUSAL_MESSAGE, "confidence": "n/a",
                "trace": tr, "messages": [AIMessage(REFUSAL_MESSAGE)]}

    return {**reset, "trace": tr}


def route_and_resolve(state: dict) -> dict:
    """LLM call 1: standalone rewrite + intent + entities (structured output)."""
    tr = state.get("trace") or _blank_trace()
    t0 = time.perf_counter()
    history = state.get("messages", [])[-HISTORY_LIMIT:]
    messages = [SystemMessage(ROUTER_SYSTEM), *history]

    try:
        if not llm_available():
            raise RuntimeError("no LLM key configured")
        llm = make_llm()
        structured = llm.with_structured_output(RouteResult, include_raw=True)
        out = structured.invoke(messages)
        route: RouteResult = out["parsed"]
        raw = out.get("raw")
        if raw is not None:
            ti, to = tokens_from_response(raw)
            tr["tokens_in"] += ti
            tr["tokens_out"] += to
        if route is None:
            raise ValueError("router returned no parse")
    except Exception as exc:
        # Fallback: deterministic routing from regex IOCs so we never dead-end.
        log.error("router_failed", error=str(exc))
        tr["llm_error"] = "rate_limit" if _is_rate_limit(exc) else "unavailable"
        ents = extract_entities(_last_human_text(state))
        intent = "ioc_lookup" if ents else "out_of_scope"
        route = RouteResult(standalone_query=_last_human_text(state), intent=intent,
                            entities=ents, reasoning="router fallback (LLM unavailable)")

    tr["intent"] = route.intent
    tr["node_timings"]["route"] = round((time.perf_counter() - t0) * 1000, 1)
    return {"route": route.model_dump(), "trace": tr}


def tool_executor(state: dict) -> dict:
    """Fan out to the right APIs for the intent. Never raises."""
    tr = state.get("trace") or _blank_trace()
    t0 = time.perf_counter()
    route = state.get("route") or {}
    intent = route.get("intent", "out_of_scope")
    query = route.get("standalone_query", "")

    ents = _dedup_entities(
        [Entity(**e) for e in route.get("entities", [])] + extract_entities(query)
    )
    results: list[ToolResult] = []

    def ips():
        return [e.value for e in ents if e.type == "ip"][:MAX_ENTITIES]

    if intent == "ioc_lookup":
        handled = 0
        for e in ents:
            if handled >= MAX_ENTITIES:
                break
            if e.type == "ip":
                if is_private_ip(e.value):
                    results.append(ToolResult(
                        source="Local Analysis", status="ok",
                        data={"note": f"{e.value} is an RFC1918 private / reserved address; "
                              "it is not externally routable, so public threat-intel sources do not apply."}))
                else:
                    results += [
                        _timed(tr, virustotal.lookup_ip, e.value),
                        _timed(tr, abuseipdb.check_ip, e.value),
                        _timed(tr, otx.lookup_ip, e.value),
                        _timed(tr, shodan.host, e.value),
                    ]
                handled += 1
            elif e.type == "domain":
                results += [_timed(tr, virustotal.lookup_domain, e.value),
                            _timed(tr, otx.lookup_domain, e.value)]
                handled += 1
            elif e.type == "hash":
                results += [_timed(tr, virustotal.lookup_hash, e.value),
                            _timed(tr, otx.lookup_hash, e.value)]
                handled += 1
            elif e.type == "cve":
                results.append(_timed(tr, nvd.search, e.value))
                handled += 1
        if handled == 0:
            results.append(ToolResult(source="Local Analysis", status="no_data",
                           data={"note": "No IP, domain, or file hash was found in the request."}))

    elif intent == "pivot":
        ip_list = ips()
        if ip_list:
            ip = ip_list[0]
            results += [_timed(tr, virustotal.resolutions, ip),
                        _timed(tr, otx.passive_dns, ip),
                        _timed(tr, shodan.host, ip)]
        else:
            doms = [e.value for e in ents if e.type == "domain"][:1]
            if doms:
                results += [_timed(tr, virustotal.lookup_domain, doms[0]),
                            _timed(tr, otx.lookup_domain, doms[0])]
            else:
                results.append(ToolResult(source="Local Analysis", status="no_data",
                               data={"note": "No indicator to pivot from was resolved from context."}))

    elif intent == "actor_profile":
        actors = [e.value for e in ents if e.type == "actor"]
        name = actors[0] if actors else query
        results.append(_timed(tr, mitre.lookup_actor, name))
        if actors:
            results.append(_timed(tr, otx.search_actor, actors[0]))

    elif intent == "exposure_check":
        kw = _product_keyword(query, ents)
        results.append(_timed(tr, nvd.search, kw))

    tr["node_timings"]["tools"] = round((time.perf_counter() - t0) * 1000, 1)
    return {"tool_results": [r.model_dump() for r in results], "trace": tr}


def sanitize_evidence(state: dict) -> dict:
    """Layer-2 indirect injection neutralization on every tool result."""
    tr = state.get("trace") or _blank_trace()
    t0 = time.perf_counter()
    cleaned: list[dict] = []
    flags: list[str] = list(tr.get("injection_flags", []))
    for d in state.get("tool_results", []):
        res = sanitize_tool_result(ToolResult(**d))
        flags += res.suspicion_flags
        cleaned.append(res.model_dump())
    tr["injection_flags"] = sorted(set(flags))
    tr["node_timings"]["sanitize"] = round((time.perf_counter() - t0) * 1000, 1)
    return {"tool_results": cleaned, "trace": tr}


def grounding_synthesis(state: dict) -> dict:
    """LLM call 2: evidence-only answer with per-claim source tags."""
    tr = state.get("trace") or _blank_trace()
    t0 = time.perf_counter()
    route = state.get("route") or {}
    results = [ToolResult(**d) for d in state.get("tool_results", [])]

    blocks = "\n".join(
        evidence_block(r.source, r.status, r.data, r.suspicion_flags) for r in results
    ) or "(no evidence retrieved)"
    human = (
        f"Analyst question: {route.get('standalone_query', '')}\n\n"
        f"Evidence:\n{blocks}\n\n"
        "Write the analyst-facing answer following your rules (verdict, evidence "
        "with [source] tags, caveats)."
    )

    # If the router already hit a token/rate limit, the synthesis call would
    # too — skip it and return the grounded findings with a clear note.
    if tr.get("llm_error") == "rate_limit":
        answer = _deterministic_summary(results, note=_RATE_LIMIT_NOTE)
        tr["node_timings"]["synthesis"] = round((time.perf_counter() - t0) * 1000, 1)
        return {"answer": answer.strip(), "trace": tr}

    try:
        if not llm_available():
            raise RuntimeError("no LLM key configured")
        llm = make_llm()
        resp = llm.invoke([SystemMessage(SYNTHESIS_SYSTEM), HumanMessage(human)])
        answer = resp.content if isinstance(resp.content, str) else str(resp.content)
        ti, to = tokens_from_response(resp)
        tr["tokens_in"] += ti
        tr["tokens_out"] += to
    except Exception as exc:
        log.error("synthesis_failed", error=str(exc))
        if _is_rate_limit(exc):
            tr["llm_error"] = "rate_limit"
            answer = _deterministic_summary(results, note=_RATE_LIMIT_NOTE)
        else:
            answer = _deterministic_summary(results, note="(LLM synthesis unavailable; raw findings shown)")

    tr["node_timings"]["synthesis"] = round((time.perf_counter() - t0) * 1000, 1)
    answer = _format_caveats(answer)
    return {"answer": answer, "trace": tr}


def confidence_scorer(state: dict) -> dict:
    """Deterministic verdict + calibrated confidence, then finalize the turn."""
    tr = state.get("trace") or _blank_trace()
    results = [ToolResult(**d) for d in state.get("tool_results", [])]
    report = confidence.score(results, intent=tr.get("intent", "ioc_lookup"))
    answer = state.get("answer", "")
    tr["tokens_cost_usd"] = estimate_cost(tr.get("tokens_in", 0), tr.get("tokens_out", 0),
                                          _model_name())
    log.info("turn_complete", intent=tr.get("intent"), verdict=report.verdict,
             confidence=report.confidence, band=report.band,
             sources=[r.source for r in results if r.usable],
             injection_flags=tr.get("injection_flags"))
    return {"confidence": report.band, "confidence_rationale": report.rationale,
            "verdict": report.verdict, "confidence_score": report.confidence,
            "confidence_report": report.model_dump(),
            "trace": tr, "messages": [AIMessage(answer)]}


def scope_reply(state: dict) -> dict:
    """out_of_scope terminal — canned, no LLM call.

    If routing itself was defeated by a token/rate limit (not a genuine
    out-of-scope query), say so honestly instead of the scope boilerplate.
    """
    tr = state.get("trace") or _blank_trace()
    tr["node_timings"]["scope"] = 0.0
    if tr.get("llm_error") == "rate_limit":
        msg = (_RATE_LIMIT_NOTE.replace("Raw findings:", "").strip() +
               "\n\nI couldn't classify this request while rate-limited — please retry shortly.")
        return {"answer": msg, "confidence": "n/a", "confidence_rationale": "",
                "trace": tr, "messages": [AIMessage(msg)]}
    return {"answer": SCOPE_REPLY, "confidence": "n/a", "confidence_rationale": "",
            "trace": tr, "messages": [AIMessage(SCOPE_REPLY)]}


def error_reply(state: dict) -> dict:
    """All sources failed — graceful degradation, names what failed. No LLM call."""
    tr = state.get("trace") or _blank_trace()
    results = [ToolResult(**d) for d in state.get("tool_results", [])]
    lines = [f"- **{r.source}**: {r.status}" + (f" — {r.error}" if r.error else "") for r in results]
    detail = "\n".join(lines) if lines else "- No sources were queried."
    msg = (
        "I couldn't retrieve usable threat intelligence for that request, so I "
        "won't guess. Here's what each source returned:\n\n"
        f"{detail}\n\n"
        "If keys are missing, add them to `.env`, or set `DEMO_MODE=true` to use "
        "bundled sample data. You can also retry shortly if a source was rate-limited."
    )
    tr["node_timings"]["error"] = 0.0
    return {"answer": msg, "confidence": "low",
            "confidence_rationale": "No source returned usable data.",
            "trace": tr, "messages": [AIMessage(msg)]}


# --- routing predicates ----------------------------------------------------
def after_guard(state: dict) -> str:
    return "end" if (state.get("trace") or {}).get("intent") in ("blocked", "empty") else "route"


def after_router(state: dict) -> str:
    return "scope" if (state.get("route") or {}).get("intent") == "out_of_scope" else "tools"


def after_tools(state: dict) -> str:
    results = state.get("tool_results", [])
    usable = any(d.get("status") == "ok" and d.get("data") for d in results)
    return "sanitize" if usable else "error"


# --- misc ------------------------------------------------------------------
def _model_name() -> str:
    try:
        return getattr(make_llm(), "model_name", None) or getattr(make_llm(), "model", "")
    except Exception:
        return ""


def _deterministic_summary(results: list[ToolResult], note: str = "") -> str:
    import json
    parts = [note] if note else []
    for r in results:
        if r.usable:
            parts.append(f"[{r.source}] {json.dumps(r.data, default=str)[:400]}")
    return "\n".join(parts) or "No usable evidence."
