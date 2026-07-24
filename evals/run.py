"""Eval harness: routes the golden set through the graph, N times, and reports
intent accuracy, entity extraction, citation presence, and cross-run consistency.

Usage:
    python -m evals.run            # 3 runs (default), DEMO_MODE forced on
    python -m evals.run --runs 1

Requires an LLM key (this tests the LLM router/synthesis). Tools run in
DEMO_MODE so no threat-intel quota is consumed.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import uuid
from pathlib import Path

import yaml

os.environ["DEMO_MODE"] = "true"  # tools use fixtures; LLM still live

from src.agent.graph import build_graph, make_checkpointer, run_turn  # noqa: E402
from src.config import llm_available  # noqa: E402

CITE_RE = re.compile(r"\[(VirusTotal|AbuseIPDB|AlienVault OTX|Shodan|NVD|MITRE ATT&CK|Local Analysis)\]")


def _load_cases() -> list[dict]:
    data = yaml.safe_load((Path(__file__).parent / "golden.yaml").read_text(encoding="utf-8"))
    return data["cases"]


def _run_case(app, case: dict) -> dict:
    tid = str(uuid.uuid4())
    for prior in case.get("context", []):
        run_turn(app, prior, tid)
    state = run_turn(app, case["query"], tid)
    tr = state.get("trace", {})
    answer = state.get("answer", "")
    got_intent = tr.get("intent", "")

    intent_ok = got_intent == case["expected_intent"]
    # entity check
    ent_ok = True
    for e in case.get("expect_entities", []):
        found = any(
            x.get("value", "").lower() == e["value"].lower() and x.get("type") == e["type"]
            for x in (state.get("route") or {}).get("entities", [])
        )
        # accept if the value simply appears in the standalone rewrite too
        rewrite = (state.get("route") or {}).get("standalone_query", "")
        ent_ok = ent_ok and (found or e["value"].lower() in rewrite.lower())
    cite_ok = (not case.get("must_cite")) or bool(CITE_RE.search(answer))

    return {"intent": got_intent, "intent_ok": intent_ok, "ent_ok": ent_ok,
            "cite_ok": cite_ok, "passed": intent_ok and ent_ok and cite_ok}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    args = ap.parse_args()

    if not llm_available():
        print("✗ No LLM key detected. Set GROQ_API_KEY (or Ollama Cloud) in .env, "
              "then re-run. The eval harness needs the live router/synthesis.")
        return 2

    cases = _load_cases()
    app = build_graph(make_checkpointer())
    per_run_intent: list[dict[str, str]] = []
    totals = {"intent": 0, "ent": 0, "cite": 0, "pass": 0, "n": 0}

    for run_i in range(args.runs):
        print(f"\n=== RUN {run_i + 1}/{args.runs} ===")
        intents: dict[str, str] = {}
        for case in cases:
            r = _run_case(app, case)
            intents[case["id"]] = r["intent"]
            totals["n"] += 1
            totals["intent"] += r["intent_ok"]
            totals["ent"] += r["ent_ok"]
            totals["cite"] += r["cite_ok"]
            totals["pass"] += r["passed"]
            mark = "✓" if r["passed"] else "✗"
            print(f"  {mark} {case['id']:24s} intent={r['intent']:14s} "
                  f"(want {case['expected_intent']:14s}) ent={r['ent_ok']} cite={r['cite_ok']}")
        per_run_intent.append(intents)

    n = totals["n"] or 1
    print("\n=== SUMMARY ===")
    print(f"  Intent accuracy : {totals['intent']}/{n}  ({100*totals['intent']/n:.1f}%)")
    print(f"  Entity extract  : {totals['ent']}/{n}  ({100*totals['ent']/n:.1f}%)")
    print(f"  Citation present: {totals['cite']}/{n}  ({100*totals['cite']/n:.1f}%)")
    print(f"  Full pass       : {totals['pass']}/{n}  ({100*totals['pass']/n:.1f}%)")

    # consistency: same intent for each case across runs?
    consistent = 0
    ids = [c["id"] for c in cases]
    for cid in ids:
        vals = {run[cid] for run in per_run_intent}
        consistent += len(vals) == 1
    print(f"  Intent consistency across {args.runs} runs: {consistent}/{len(ids)} cases stable")
    return 0 if totals["pass"] == n else 1


if __name__ == "__main__":
    sys.exit(main())
