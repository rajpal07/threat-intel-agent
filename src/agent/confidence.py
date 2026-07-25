"""Production-grade confidence & verdict scoring (deterministic).

Design
------
Two separate axes, computed from the sanitized tool evidence:

  * **Verdict**     — WHAT the evidence says (Malicious / Suspicious / Benign,
                      Vulnerable / No-known-CVEs, Profiled / No-match). A
                      trust-weighted mean of each source's risk reading.
  * **Confidence**  — HOW SURE we are of that verdict, as a 0–100 score, driven
                      by (a) how much corroborating evidence weight exists,
                      (b) whether sources agree, (c) freshness, and
                      (d) whether any source was tampered with (injection flag).

Each source contributes an *effective weight*:

    weight = trust[source] × self_confidence × freshness × injection_penalty

`trust` encodes that a 70-engine VirusTotal consensus outweighs a single OTX
pulse; `self_confidence` is how decisive that source's own reading is (e.g. VT
engine volume and how lopsided the vote is, AbuseIPDB report count); `freshness`
decays stale intel; `injection_penalty` slashes the weight of any source Layer-2
flagged as tampered — a poisoned source must never raise certainty.

Corroboration saturates: 1 − e^(−ΣW / K), so two solid independent sources give
high confidence and a lone source is capped. Disagreement between sources
(spread in their risk readings) lowers confidence. Authoritative sources (NVD
for exposure, MITRE for actors) are not penalised for being single.

The model is fully deterministic and unit-tested; thresholds live in one block
below so they can be tuned/calibrated against a labelled set.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import datetime, timezone

from ..schemas import ConfidenceReport, SourceScore, ToolResult

# --- tunables --------------------------------------------------------------
TRUST = {
    "VirusTotal": 1.00,
    "AbuseIPDB": 0.90,
    "NVD": 1.00,            # authoritative for exposure
    "MITRE ATT&CK": 1.00,   # authoritative for actors
    "AlienVault OTX": 0.70,
    "Shodan": 0.45,         # exposure context, weak verdict signal
    "Local Analysis": 0.60,
}
K_SATURATION = 1.25        # ΣW at which corroboration ≈ 0.55; 2×solid ≈ 0.80
INJECTION_PENALTY = 0.30   # multiply a tampered source's weight by this
BAND_HIGH, BAND_MED = 70, 40
MAL_THRESH, SUSP_THRESH = 0.55, 0.25          # verdict cut-offs (reputation)
_AUTHORITATIVE = {"NVD", "MITRE ATT&CK"}
_REPUTATION = {"VirusTotal", "AbuseIPDB", "AlienVault OTX", "Shodan"}


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def _freshness(r: ToolResult) -> float:
    """Decay factor in [0.8, 1.0] from report age / cache."""
    f = 0.98 if r.cached else 1.0
    d = r.data or {}
    last = d.get("last_reported_at")
    if isinstance(last, str) and last:
        try:
            ts = datetime.fromisoformat(last.replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - ts).days
            if age > 365:
                f *= 0.85
            elif age > 90:
                f *= 0.93
        except Exception:
            pass
    return round(f, 3)


# --- per-source assessment -------------------------------------------------
def _assess(r: ToolResult) -> SourceScore:
    """Map one tool result to (maliciousness, self_confidence, note)."""
    d = r.data or {}
    s = r.source
    m: float | None = None
    self_conf = 0.5
    note = s

    if s == "VirusTotal":
        st = d.get("stats") or {}
        mal = int(st.get("malicious", 0) or 0)
        susp = int(st.get("suspicious", 0) or 0)
        harm = int(st.get("harmless", 0) or 0)
        det = mal + 0.5 * susp
        # maliciousness rises with detections (denominator-independent: VT
        # 'harmless' are mostly no-signature engines, not clean assertions)
        m = _clamp(det / 6.0) if det else 0.0
        if det >= 10:
            m = _clamp(0.8 + det / 100)
        voters = det + harm
        volume = _clamp(voters / 25.0)
        if det > 0:                       # contradiction lowers self-confidence
            contradiction = harm / voters if voters else 0.0
            self_conf = _clamp(0.35 + 0.65 * volume * (1 - 0.5 * contradiction))
        else:                             # confident-benign scales with clean voters
            self_conf = _clamp(0.25 + 0.75 * volume)
        note = f"VirusTotal {mal} malicious / {susp} suspicious / {harm} harmless"

    elif s == "AbuseIPDB":
        sc = int(d.get("abuse_confidence_score") or 0)
        reports = int(d.get("total_reports") or 0)
        m = _clamp(sc / 100.0)
        self_conf = _clamp(0.2 + 0.8 * min(1.0, reports / 20.0)) if reports else 0.2
        note = f"AbuseIPDB {sc}% abuse ({reports} reports)"

    elif s == "AlienVault OTX":
        pc = int(d.get("pulse_count") or 0)
        m = _clamp(pc / 4.0)
        self_conf = _clamp(pc / 4.0) if pc else 0.25
        note = f"OTX {pc} threat pulses"

    elif s == "Shodan":
        ports = set(d.get("ports") or [])
        risky = ports & {23, 3389, 4444, 5900, 445, 1433, 3306}
        m = 0.35 if risky else 0.12
        self_conf = 0.45
        note = f"Shodan {len(ports)} ports" + (f", risky: {sorted(risky)}" if risky else "")

    elif s == "NVD":
        cves = d.get("cves") or []
        sev = {(c.get("severity") or "").upper() for c in cves}
        if "CRITICAL" in sev:
            m = 0.95
        elif "HIGH" in sev:
            m = 0.8
        elif "MEDIUM" in sev:
            m = 0.5
        elif cves:
            m = 0.3
        else:
            m = 0.0
        self_conf = _clamp(0.6 + 0.08 * len(cves))
        note = f"NVD {len(cves)} CVEs (max sev {max(sev) if sev else 'none'})"

    elif s == "MITRE ATT&CK":
        m = None                          # informational, not a risk verdict
        self_conf = 0.9
        note = f"MITRE group: {d.get('group', 'matched')}"

    elif s == "Local Analysis":
        m = 0.0
        self_conf = 0.7
        note = str(d.get("note", "local analysis"))[:80]

    freshness = _freshness(r)
    flagged = bool(r.suspicion_flags)
    weight = TRUST.get(s, 0.5) * self_conf * freshness * (INJECTION_PENALTY if flagged else 1.0)
    return SourceScore(source=s, weight=round(weight, 3), maliciousness=m, note=note, flagged=flagged)


# --- verdict labelling -----------------------------------------------------
def _verdict_label(intent: str, v: float | None, has_data: bool) -> str:
    if intent == "exposure_check":
        if v is None or not has_data:
            return "No known CVEs"
        if v >= 0.75:
            return "Exposed — Critical/High CVEs"
        if v >= 0.45:
            return "Exposed — Medium severity"
        if v > 0:
            return "Low-risk CVEs"
        return "No known CVEs"
    if intent == "actor_profile":
        return "Profiled — known actor" if has_data else "No ATT&CK match"
    # ioc_lookup / pivot (reputation)
    if v is None:
        return "Informational"
    if v >= MAL_THRESH:
        return "Malicious"
    if v >= SUSP_THRESH:
        return "Suspicious"
    return "Benign"


# --- main ------------------------------------------------------------------
def score(results: Sequence[ToolResult], intent: str = "ioc_lookup") -> ConfidenceReport:
    usable = [r for r in results if r.usable]
    if not usable:
        return ConfidenceReport(verdict="Inconclusive", confidence=8, band="low",
                                rationale="No source returned usable data.")

    assessed = [_assess(r) for r in usable]
    risk = [a for a in assessed if a.maliciousness is not None and a.weight > 0]

    # ---- verdict (trust-weighted mean risk) ----
    if risk:
        wsum = sum(a.weight for a in risk) or 1e-9
        v = sum((a.maliciousness or 0) * a.weight for a in risk) / wsum
    else:
        v = None
    verdict = _verdict_label(intent, v, has_data=bool(usable))

    # ---- confidence ----
    authoritative = any(a.source in _AUTHORITATIVE for a in assessed)
    W = sum(a.weight for a in (risk or assessed))
    corroboration = 1 - math.exp(-W / K_SATURATION)

    # agreement: spread of risk readings across independent sources
    if len(risk) >= 2:
        ms = [a.maliciousness or 0 for a in risk]
        agree = 1 - (max(ms) - min(ms))
    else:
        agree = 0.72                       # single source → inherent ceiling
    if authoritative:                      # authoritative single source is trustworthy
        agree = max(agree, 0.9)

    conf01 = corroboration * (0.5 + 0.5 * agree)
    confidence = int(round(100 * _clamp(conf01)))

    # authoritative exact match shouldn't read as "medium single source"
    if authoritative and any(a.source in _AUTHORITATIVE and a.weight > 0 for a in assessed):
        floor = 72 if (v is None or v >= 0.75 or intent == "actor_profile") else 60
        confidence = max(confidence, floor)

    # injection: a tampered source caps how sure we allow ourselves to be
    flagged = [a.source for a in assessed if a.flagged]
    if flagged:
        confidence = min(confidence, 60)

    confidence = int(_clamp(confidence, 0, 100))
    band = "high" if confidence >= BAND_HIGH else "medium" if confidence >= BAND_MED else "low"

    # ---- rationale ----
    parts = [a.note for a in assessed]
    corr = f"{len(risk) or len(usable)} source(s)"
    extra = []
    if len(risk) >= 2 and (max(a.maliciousness or 0 for a in risk) - min(a.maliciousness or 0 for a in risk)) > 0.4:
        extra.append("sources disagree")
    if flagged:
        extra.append(f"⚠ tampered source down-weighted ({', '.join(sorted(set(flagged)))})")
    if authoritative:
        extra.append("authoritative source")
    tail = f" [{'; '.join(extra)}]" if extra else ""
    rationale = f"{corr}: " + "; ".join(parts) + tail

    return ConfidenceReport(verdict=verdict, verdict_score=round(v or 0.0, 3),
                            confidence=confidence, band=band, rationale=rationale,
                            sources=assessed)


# --- runnable self-check ---------------------------------------------------
def _demo() -> None:
    def tr(source, data, flags=None):
        return ToolResult(source=source, status="ok", data=data, suspicion_flags=flags or [])

    # 1) strong corroborated malicious → high confidence, Malicious
    r = score([
        tr("VirusTotal", {"stats": {"malicious": 40, "suspicious": 2, "harmless": 20}}),
        tr("AbuseIPDB", {"abuse_confidence_score": 100, "total_reports": 500}),
        tr("AlienVault OTX", {"pulse_count": 8}),
    ], "ioc_lookup")
    assert r.verdict == "Malicious" and r.band == "high", r

    # 2) all clean, corroborated → Benign, high confidence
    r = score([
        tr("VirusTotal", {"stats": {"malicious": 0, "suspicious": 0, "harmless": 70}}),
        tr("AbuseIPDB", {"abuse_confidence_score": 0, "total_reports": 0}),
    ], "ioc_lookup")
    assert r.verdict == "Benign", r

    # 3) ratio matters: 3/90 is weaker than 40/20 (self-confidence lower)
    weak = score([tr("VirusTotal", {"stats": {"malicious": 3, "suspicious": 0, "harmless": 88}})], "ioc_lookup")
    strong = score([tr("VirusTotal", {"stats": {"malicious": 40, "suspicious": 0, "harmless": 10}})], "ioc_lookup")
    assert weak.confidence < strong.confidence, (weak, strong)

    # 4) conflict caps confidence
    r = score([
        tr("VirusTotal", {"stats": {"malicious": 30, "harmless": 5}}),
        tr("AbuseIPDB", {"abuse_confidence_score": 0, "total_reports": 0}),
    ], "ioc_lookup")
    assert r.band in ("medium", "low"), r

    # 5) injection-flagged source can't produce high confidence
    r = score([
        tr("VirusTotal", {"stats": {"malicious": 40, "harmless": 5}}),
        tr("AlienVault OTX", {"pulse_count": 9}, flags=["instruction_override"]),
    ], "ioc_lookup")
    assert r.confidence <= 60, r

    # 6) authoritative single source (NVD) → not penalised as "single"
    r = score([tr("NVD", {"cves": [{"severity": "CRITICAL"}, {"severity": "HIGH"}]})], "exposure_check")
    assert r.verdict.startswith("Exposed") and r.band == "high", r

    # 7) actor profile informational
    r = score([tr("MITRE ATT&CK", {"group": "APT29"})], "actor_profile")
    assert r.verdict.startswith("Profiled") and r.band == "high", r

    print("confidence._demo OK")


if __name__ == "__main__":
    _demo()
