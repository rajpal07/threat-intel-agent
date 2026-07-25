"""Streamlit chat UI for the Conversational Threat Intelligence Agent.

Renders the chat, per-answer source badges + confidence chip, an expandable
execution trace (the observability view), and a sidebar with API-key status,
a DEMO_MODE toggle, and a running token/cost meter.
"""
from __future__ import annotations

import os
import uuid

import streamlit as st

st.set_page_config(page_title="Threat Intel Agent", page_icon="🛡️", layout="wide")

# --- styling ---------------------------------------------------------------
st.markdown(
    """
    <style>
    .badge {display:inline-block;padding:2px 9px;margin:2px 4px 2px 0;border-radius:11px;
            font-size:0.72rem;font-weight:600;border:1px solid rgba(255,255,255,.15);}
    .b-ok{background:#153d2e;color:#5be9a6;} .b-warn{background:#4a2b0a;color:#ffb454;}
    .b-bad{background:#4a1520;color:#ff6b81;} .b-mut{background:#232838;color:#8b93a7;}
    .chip{display:inline-block;padding:2px 11px;border-radius:11px;font-size:0.74rem;font-weight:700;}
    .c-high{background:#153d2e;color:#5be9a6;} .c-med{background:#4a3b0a;color:#ffd454;}
    .c-low{background:#3a2530;color:#ff9bb0;} .c-na{background:#232838;color:#8b93a7;}
    .c-bad{background:#4a1520;color:#ff6b81;} .c-info{background:#12314a;color:#6db3ff;}
    </style>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_app():
    from src.agent.graph import build_graph, make_checkpointer

    return build_graph(make_checkpointer())


def _init_state():
    if "thread_id" not in st.session_state:
        st.session_state.thread_id = str(uuid.uuid4())
    st.session_state.setdefault("history", [])   # [{role, content, meta}]
    st.session_state.setdefault("tokens_in", 0)
    st.session_state.setdefault("tokens_out", 0)
    st.session_state.setdefault("cost", 0.0)


_init_state()

# --- source badge helpers --------------------------------------------------
_STATUS_CLASS = {"ok": "b-ok", "rate_limited": "b-warn", "error": "b-bad",
                 "unavailable": "b-mut", "no_data": "b-mut"}


def _source_badges(results: list[dict]) -> str:
    spans = []
    for r in results:
        cls = _STATUS_CLASS.get(r.get("status", ""), "b-mut")
        label = r.get("source", "?")
        if r.get("cached"):
            label += " · cached"
        if r.get("suspicion_flags"):
            label += " ⚠"
            cls = "b-warn"
        spans.append(f'<span class="badge {cls}">{label}: {r.get("status")}</span>')
    return "".join(spans)


_VERDICT_CLASS = {
    "Malicious": "c-bad", "Suspicious": "c-med", "Benign": "c-high",
    "Exposed — Critical/High CVEs": "c-bad", "Exposed - Critical/High CVEs": "c-bad",
    "Exposed — Medium severity": "c-med", "Exposed - Medium severity": "c-med",
    "Low-risk CVEs": "c-med", "No known CVEs": "c-high",
    "Profiled — known actor": "c-info", "Profiled - known actor": "c-info",
    "Informational": "c-info", "No ATT&CK match": "c-na", "Inconclusive": "c-na",
}
_BAND_CLASS = {"high": "c-high", "medium": "c-med", "low": "c-low"}


def _verdict_confidence_chips(meta: dict) -> str:
    """Deterministic verdict chip + calibrated confidence-% chip."""
    verdict = meta.get("verdict") or ""
    band = meta.get("confidence") or ""
    score = meta.get("confidence_score")
    tip = (meta.get("confidence_rationale") or "").replace('"', "'")
    tipattr = f' title="{tip}"' if tip else ""
    out = []
    if verdict:
        vcls = _VERDICT_CLASS.get(verdict, "c-na")
        out.append(f'<span class="chip {vcls}"{tipattr}>{verdict}</span>')
    if band in _BAND_CLASS and score is not None:
        out.append(f'<span class="chip {_BAND_CLASS[band]}"{tipattr}>confidence {score}% · {band}</span>')
    return " ".join(out)


def _render_trace(meta: dict):
    tr = meta.get("trace", {})
    with st.expander("🔍 Agent steps (trace)"):
        cols = st.columns(3)
        cols[0].metric("Intent", tr.get("intent", "—"))
        cols[1].metric("Tokens", f"{tr.get('tokens_in',0)}→{tr.get('tokens_out',0)}")
        cols[2].metric("Injection flags", len(tr.get("injection_flags", [])) or 0)
        timings = tr.get("node_timings", {})
        if timings:
            st.caption("Node timings (ms): " + ", ".join(f"{k}={v}" for k, v in timings.items()))
        calls = tr.get("api_calls", [])
        if calls:
            st.dataframe(calls, width="stretch", hide_index=True)
        if tr.get("injection_flags"):
            st.warning("Sanitizer/guard flagged: " + ", ".join(tr["injection_flags"]))
        report = meta.get("confidence_report") or {}
        if report.get("sources"):
            st.caption("**Confidence model — per-source evidence weight**")
            rows = [{
                "source": s.get("source"),
                "weight": round(s.get("weight", 0), 2),
                "maliciousness": ("—" if s.get("maliciousness") is None else round(s["maliciousness"], 2)),
                "flagged": "⚠" if s.get("flagged") else "",
                "note": s.get("note", ""),
            } for s in report["sources"]]
            st.dataframe(rows, width="stretch", hide_index=True)
            st.caption(f"Verdict **{report.get('verdict')}** (risk {report.get('verdict_score')}) · "
                       f"confidence **{report.get('confidence')}%** — {meta.get('confidence_rationale','')}")
        elif meta.get("confidence_rationale"):
            st.caption("Confidence: " + meta["confidence_rationale"])


# --- sidebar ---------------------------------------------------------------
with st.sidebar:
    st.header("🛡️ Threat Intel Agent")
    from src.config import API_KEYS, demo_mode, llm_available

    demo_toggle = st.toggle("DEMO_MODE (bundled fixtures)", value=demo_mode(),
                            help="Serve recorded sample data instead of live APIs.")
    os.environ["DEMO_MODE"] = "true" if demo_toggle else "false"

    st.subheader("LLM")
    if llm_available() or demo_toggle:
        st.markdown('<span class="badge b-ok">LLM key detected</span>' if llm_available()
                    else '<span class="badge b-warn">no LLM key — routing/synthesis limited</span>',
                    unsafe_allow_html=True)
    else:
        st.markdown('<span class="badge b-bad">no LLM key set</span>', unsafe_allow_html=True)
        st.caption("Add GROQ_API_KEY to .env (or Streamlit secrets) for full routing + synthesis.")

    st.subheader("Threat-intel sources")
    for name, key in API_KEYS.items():
        cls = "b-ok" if key else "b-mut"
        state = "ready" if key else "no key"
        st.markdown(f'<span class="badge {cls}">{name}: {state}</span>', unsafe_allow_html=True)
    if demo_toggle:
        st.caption("DEMO_MODE on — sources above are bypassed for fixtures.")

    st.subheader("Session cost")
    st.metric("Tokens", f"{st.session_state.tokens_in}→{st.session_state.tokens_out}")
    st.metric("Est. cost (USD)", f"${st.session_state.cost:.5f}")

    if st.button("🧹 New session", width="stretch"):
        st.session_state.thread_id = str(uuid.uuid4())
        st.session_state.history = []
        st.session_state.tokens_in = st.session_state.tokens_out = 0
        st.session_state.cost = 0.0
        st.rerun()

    st.divider()
    st.caption("Try:")
    for ex in ["Is 45.83.122.10 malicious?",
               "What TTPs is APT29 known for?",
               "We run Confluence 7.13 — are we exposed?",
               "Pivot from that IP to related domains",
               "and what's its ASN?"]:
        st.caption(f"• {ex}")

# --- main chat -------------------------------------------------------------
st.title("Conversational Threat Intelligence Analyst")
st.caption("Ask about IPs, domains, hashes, threat actors, software exposure, or pivot between indicators.")

for turn in st.session_state.history:
    with st.chat_message(turn["role"]):
        if turn["role"] == "assistant":
            meta = turn.get("meta", {})
            chips = _verdict_confidence_chips(meta)
            badges = _source_badges(meta.get("tool_results", []))
            if chips or badges:
                st.markdown(chips + " " + badges, unsafe_allow_html=True)
            st.markdown(turn["content"])
            if meta.get("trace"):
                _render_trace(meta)
        else:
            st.markdown(turn["content"])

prompt = st.chat_input("Ask a threat-intelligence question…")
if prompt:
    st.session_state.history.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Analyzing…"):
            from src.agent.graph import run_turn

            state = run_turn(get_app(), prompt, st.session_state.thread_id)

        tr = state.get("trace", {})
        meta = {
            "confidence": state.get("confidence", ""),
            "confidence_score": state.get("confidence_score"),
            "confidence_rationale": state.get("confidence_rationale", ""),
            "verdict": state.get("verdict", ""),
            "confidence_report": state.get("confidence_report", {}),
            "tool_results": state.get("tool_results", []),
            "trace": tr,
        }
        chips = _verdict_confidence_chips(meta)
        badges = _source_badges(meta["tool_results"])
        if chips or badges:
            st.markdown(chips + " " + badges, unsafe_allow_html=True)
        st.markdown(state.get("answer", "*(no answer)*"))
        _render_trace(meta)

    # accumulate cost meter
    st.session_state.tokens_in += tr.get("tokens_in", 0)
    st.session_state.tokens_out += tr.get("tokens_out", 0)
    st.session_state.cost += tr.get("tokens_cost_usd", 0.0)
    st.session_state.history.append({"role": "assistant", "content": state.get("answer", ""), "meta": meta})
    st.rerun()
