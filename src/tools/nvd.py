"""NVD 2.0 — map a product/version keyword to known CVEs with CVSS severity."""
from __future__ import annotations

from ..config import API_KEYS
from ..schemas import ToolResult
from .base import request_json

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SOURCE = "NVD"


def _cvss(metrics: dict) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData") or {}
            score = d.get("baseScore")
            sev = d.get("baseSeverity") or arr[0].get("baseSeverity")
            return score, sev
    return None, None


def search(keyword: str, limit: int = 8) -> ToolResult:
    res = request_json(
        SOURCE, "cves", url=BASE,
        api_key=API_KEYS.get("nvd"), cache_id=keyword, require_key=False,
        headers={"apiKey": API_KEYS.get("nvd") or ""} if API_KEYS.get("nvd") else None,
        params={"keywordSearch": keyword, "resultsPerPage": 20},
    )
    if res.usable:
        vulns = res.data.get("vulnerabilities") or []
        out = []
        for v in vulns:
            cve = v.get("cve") or {}
            desc = ""
            for d in cve.get("descriptions") or []:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score, sev = _cvss(cve.get("metrics") or {})
            out.append({
                "id": cve.get("id"),
                "cvss": score,
                "severity": sev,
                "summary": desc[:240],
            })
        out.sort(key=lambda c: c["cvss"] or 0, reverse=True)
        res.data = {"total": res.data.get("totalResults", len(out)), "cves": out[:limit]}
    return res
