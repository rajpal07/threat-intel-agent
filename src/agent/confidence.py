"""Deterministic confidence scoring (bonus: confidence scoring).

Confidence reflects how well-corroborated the *finding* is, not how malicious
the indicator is. Two independent sources agreeing (malicious OR clean) is
high confidence; a single source is medium; disagreement caps at medium.
"""
from __future__ import annotations

from collections.abc import Sequence

from ..schemas import ToolResult

_AUTHORITATIVE = {"MITRE ATT&CK", "NVD"}


def _signal(r: ToolResult) -> tuple[str, str]:
    """Return (strength, human_note). strength in strong|moderate|clean."""
    d = r.data or {}
    s = r.source
    if s == "VirusTotal":
        mal = (d.get("stats") or {}).get("malicious", 0) or 0
        return (("strong" if mal >= 3 else "moderate" if mal >= 1 else "clean"),
                f"VirusTotal: {mal} engines malicious")
    if s == "AbuseIPDB":
        sc = d.get("abuse_confidence_score") or 0
        return (("strong" if sc >= 75 else "moderate" if sc >= 25 else "clean"),
                f"AbuseIPDB: {sc}% abuse confidence")
    if s == "AlienVault OTX":
        pc = d.get("pulse_count") or 0
        return (("strong" if pc >= 3 else "moderate" if pc >= 1 else "clean"),
                f"OTX: {pc} threat pulses")
    if s == "NVD":
        cves = d.get("cves") or []
        sev = {(c.get("severity") or "").upper() for c in cves}
        strong = bool(sev & {"CRITICAL", "HIGH"})
        return (("strong" if strong else "moderate" if cves else "clean"),
                f"NVD: {len(cves)} matching CVEs")
    if s == "MITRE ATT&CK":
        return ("strong", "MITRE ATT&CK: group profile matched")
    if s == "Shodan":
        return ("moderate", "Shodan: host exposure data")
    return ("moderate", s)


def score(results: Sequence[ToolResult]) -> tuple[str, str]:
    """Return (level, rationale). level in high|medium|low."""
    usable = [r for r in results if r.usable]
    if not usable:
        return "low", "No source returned usable data."

    signals = [(_signal(r), r.source) for r in usable]
    strengths = [sig[0][0] for sig in signals]
    n = len(usable)

    # conflict among reputation sources (some flag threat, some say clean)
    rep = [sig[0][0] for sig in signals if sig[1] in {"VirusTotal", "AbuseIPDB", "AlienVault OTX"}]
    conflict = ("strong" in rep or "moderate" in rep) and "clean" in rep and len(rep) >= 2

    authoritative_single = n == 1 and usable[0].source in _AUTHORITATIVE and strengths[0] == "strong"

    if n >= 2 or authoritative_single:
        level = "high"
    else:
        level = "medium"

    notes = "; ".join(sig[0][1] for sig in signals)
    if conflict and level == "high":
        level = "medium"
        return level, f"Sources disagree — {notes}. Corroboration reduced."
    corr = f"{n} source(s) corroborate" if n >= 2 else "single source"
    return level, f"{corr}. {notes}."
